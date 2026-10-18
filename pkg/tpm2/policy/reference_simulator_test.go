// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build tpm_simulator

package policy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"github.com/veraison/go-cose"
	"github.com/veraison/swid"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/evidence"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
)

// referenceImages are the digests of the image a platform boots into the
// test PCR: the one it booted, the one a signed CoRIM registers, and one
// nobody registered.
var (
	bootedImage     = sha256.Sum256([]byte("bootloader-v1"))
	registeredImage = sha256.Sum256([]byte("bootloader-v2"))
	unknownImage    = sha256.Sum256([]byte("bootloader-v3"))
)

// referenceFixture is a simulator fixture whose service trusts signer for
// reference values and reads a boot event log extending bootedImage into the
// test PCR, which the simulator has booted.
func referenceFixture(t *testing.T, signer *ecdsa.PrivateKey) *fixture {
	t.Helper()
	log := &evidence.EventLog{
		SpecID: evidence.SpecID{DigestSizes: map[tpm2.TPMAlgID]int{tpm2.TPMAlgSHA256: sha256.Size}},
		Events: []evidence.Event{{
			Index:   1,
			PCR:     testPCR,
			Type:    1,
			Digests: map[tpm2.TPMAlgID][]byte{tpm2.TPMAlgSHA256: bootedImage[:]},
		}},
	}
	f := newSimFixture(t, func(c *Config) {
		c.ReferenceSigner = &refvalue.VerifyOptions{PublicKey: &signer.PublicKey}
		c.EventLog = func() (*evidence.EventLog, error) { return log, nil }
	})
	boot(t, f.tpm.Transport(), bootedImage[:])
	return f
}

// boot resets the test PCR and extends image into it, as booting image does.
func boot(t *testing.T, tpm transport.TPM, image []byte) {
	t.Helper()
	handle := tpm2.AuthHandle{Handle: tpm2.TPMHandle(testPCR), Auth: tpm2.PasswordAuth(nil)}
	_, err := tpm2.PCRReset{PCRHandle: handle}.Execute(tpm)
	require.NoError(t, err)
	_, err = tpm2.PCRExtend{
		PCRHandle: handle,
		Digests:   tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{HashAlg: tpm2.TPMAlgSHA256, Digest: image}}},
	}.Execute(tpm)
	require.NoError(t, err)
}

func newSigner(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// unsignedReference is a CoRIM registering image as the first event of the
// test PCR.
func unsignedReference(t *testing.T, image []byte) []byte {
	t.Helper()
	class := comid.NewClassOID("1.3.6.1.4.1.29377.200.1").SetIndex(0)
	m, err := comid.NewMeasurement(uint64(testPCR), comid.UintType)
	require.NoError(t, err)
	m.AddDigest(swid.Sha256, image)
	c := comid.NewComid().SetTagIdentity("boot-image", 0).AddReferenceValue(comid.ReferenceValue{
		Environment:  comid.Environment{Class: class},
		Measurements: *comid.NewMeasurements().AddMeasurement(m),
	})
	require.NotNil(t, c)
	u := corim.NewUnsignedCorim().SetID("boot-image-v2").AddComid(*c)
	require.NotNil(t, u)
	payload, err := u.ToCBOR()
	require.NoError(t, err)
	return payload
}

// signedReference is unsignedReference signed by key as a COSE_Sign1 CoRIM.
func signedReference(t *testing.T, key *ecdsa.PrivateKey, image []byte) []byte {
	t.Helper()
	meta, err := corim.NewMeta().SetSigner("Example Reference Value Provider", nil).ToCBOR()
	require.NoError(t, err)
	msg := cose.NewSign1Message()
	msg.Payload = unsignedReference(t, image)
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	msg.Headers.Protected[cose.HeaderLabelContentType] = corim.ContentType
	msg.Headers.Protected[corim.HeaderLabelCorimMeta] = meta
	signer, err := cose.NewSigner(cose.AlgorithmES256, key)
	require.NoError(t, err)
	require.NoError(t, msg.Sign(rand.Reader, nil, signer))
	out, err := msg.MarshalCBOR()
	require.NoError(t, err)
	return out
}

func TestService_UpdateBranchFromReferenceValues(t *testing.T) {
	signer := newSigner(t)
	f := referenceFixture(t, signer)
	f.createComposite("acme", "boot", named(pcrBranch(), "current"), named(pcrBranch(), "next"))
	sealed := f.sealObject("acme", "disk-key", "boot", []byte("secret"))
	_, err := f.unseal("acme", sealed)
	require.NoError(t, err)

	corim := signedReference(t, signer, registeredImage[:])
	updated, err := f.svc.UpdateBranch(f.ctx, "acme", "boot", "next", corim)
	require.NoError(t, err)
	predicted := sha256.Sum256(append(make([]byte, sha256.Size), registeredImage[:]...))
	assert.Equal(t, predicted[:], updated.Branches[1].Conditions[0].PCRValues[testPCR])
	assert.NotEqual(t, predicted[:], updated.Branches[0].Conditions[0].PCRValues[testPCR], "only the named branch is updated")
	assert.Nil(t, updated.Branches[0].Reference)
	digest := sha256.Sum256(corim)
	assert.Equal(t, &Reference{
		ID:     "boot-image-v2",
		Signer: "Example Reference Value Provider",
		Digest: digest[:],
	}, updated.Branches[1].Reference)

	_, err = f.unseal("acme", sealed)
	require.NoError(t, err, "the booted image still satisfies the current branch")
	v, err := f.svc.VerifyPolicy(f.ctx, "acme", "boot")
	require.NoError(t, err)
	assert.Equal(t, []BranchVerification{
		{Name: "current", Match: true, Approved: true},
		{Name: "next", Match: false, Mismatched: []uint{testPCR}, Approved: true, Reference: updated.Branches[1].Reference},
	}, v.Branches, "verify reports the next branch approved for the registered image")

	boot(t, f.tpm.Transport(), registeredImage[:])
	secret, err := f.unseal("acme", sealed)
	require.NoError(t, err, "the registered image unseals through the next branch")
	assert.Equal(t, []byte("secret"), secret)

	boot(t, f.tpm.Transport(), unknownImage[:])
	_, err = f.unseal("acme", sealed)
	require.Error(t, err, "an image the CoRIM does not register stays refused")

	boot(t, f.tpm.Transport(), registeredImage[:])
	captured, err := f.svc.UpdatePolicy(f.ctx, "acme", "boot")
	require.NoError(t, err)
	assert.Nil(t, captured.Branches[1].Reference, "a live capture drops the reference")
}

func TestService_UpdateBranchRefusals(t *testing.T) {
	signer := newSigner(t)
	f := referenceFixture(t, signer)
	f.createComposite("acme", "boot", pcrBranch(), authValueBranch())
	valid := signedReference(t, signer, registeredImage[:])
	tampered := signedReference(t, signer, registeredImage[:])
	tampered[len(tampered)-1] ^= 0xff

	tests := []struct {
		name   string
		branch string
		corim  []byte
		want   error
	}{
		{"unsigned", "branch-1", unsignedReference(t, registeredImage[:]), refvalue.ErrMalformed},
		{"wrong signer", "branch-1", signedReference(t, newSigner(t), registeredImage[:]), refvalue.ErrSignature},
		{"tampered", "branch-1", tampered, refvalue.ErrSignature},
		{"no such branch", "next", valid, ErrNoSuchBranch},
		{"no branch name", "", valid, ErrNoSuchBranch},
		{"branch without a pcr condition", "branch-2", valid, ErrNoPCRCondition},
	}
	before, err := f.svc.Approvals("acme", "boot")
	require.NoError(t, err)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := f.svc.UpdateBranch(f.ctx, "acme", "boot", tt.branch, tt.corim)
			require.ErrorIs(t, err, tt.want)
		})
	}
	after, err := f.svc.Approvals("acme", "boot")
	require.NoError(t, err)
	assert.Equal(t, before, after, "a refused update leaves the approvals at their epoch")

	var branchErr *InvalidBranchError
	_, err = f.svc.UpdateBranch(f.ctx, "acme", "boot", "next", valid)
	require.ErrorAs(t, err, &branchErr)
	assert.Equal(t, "next", branchErr.Branch)
	var refErr *ReferenceValuesError
	_, err = f.svc.UpdateBranch(f.ctx, "acme", "boot", "branch-1", tampered)
	require.ErrorAs(t, err, &refErr)
	_, err = f.svc.UpdateBranch(f.ctx, "acme", "missing", "branch-1", valid)
	require.ErrorIs(t, err, ErrPolicyNotFound)
}

func TestService_UpdateBranchPredictionFailures(t *testing.T) {
	signer := newSigner(t)
	logErr := errors.New("event log unavailable")
	f := newSimFixture(t, func(c *Config) {
		c.ReferenceSigner = &refvalue.VerifyOptions{PublicKey: &signer.PublicKey}
		c.EventLog = func() (*evidence.EventLog, error) { return nil, logErr }
	})
	boot(t, f.tpm.Transport(), bootedImage[:])
	f.createPolicy("acme", "boot")

	_, err := f.svc.UpdateBranch(f.ctx, "acme", "boot", "branch-1", signedReference(t, signer, registeredImage[:]))
	var refErr *ReferenceValuesError
	require.ErrorAs(t, err, &refErr)
	require.ErrorIs(t, err, logErr, "the log read failure explains the absent log")
	var evErr *evidence.Error
	require.ErrorAs(t, err, &evErr)
	assert.Equal(t, evidence.ClassAbsent, evErr.Class)
}

// The default event log is the kernel's, which never describes the
// simulator's PCRs, so a component update on it is refused.
func TestService_UpdateBranchKernelEventLog(t *testing.T) {
	signer := newSigner(t)
	f := newSimFixture(t, func(c *Config) {
		c.ReferenceSigner = &refvalue.VerifyOptions{PublicKey: &signer.PublicKey}
	})
	boot(t, f.tpm.Transport(), bootedImage[:])
	f.createPolicy("acme", "boot")

	_, err := f.svc.UpdateBranch(f.ctx, "acme", "boot", "branch-1", signedReference(t, signer, registeredImage[:]))
	var refErr *ReferenceValuesError
	require.ErrorAs(t, err, &refErr)
}
