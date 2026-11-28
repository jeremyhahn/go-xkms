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

package localtpm_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"github.com/veraison/go-cose"
	"github.com/veraison/swid"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
	"github.com/jeremyhahn/go-xkms/pkg/localtpm"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/localtpmtest"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

// signedPCRReference is a CoRIM signed by key that gives pcr the final
// sha256 value digest.
func signedPCRReference(t *testing.T, key *ecdsa.PrivateKey, pcr uint64, digest []byte) []byte {
	t.Helper()
	class := comid.NewClassOID("1.3.6.1.4.1.29377.200.1")
	m, err := comid.NewMeasurement(pcr, comid.UintType)
	require.NoError(t, err)
	m.AddDigest(swid.Sha256, digest)
	c := comid.NewComid().SetTagIdentity("boot-pcr", 0).AddReferenceValue(comid.ReferenceValue{
		Environment:  comid.Environment{Class: class},
		Measurements: *comid.NewMeasurements().AddMeasurement(m),
	})
	require.NotNil(t, c)
	u := corim.NewUnsignedCorim().SetID("boot-pcr-v2").AddComid(*c)
	require.NotNil(t, u)
	payload, err := u.ToCBOR()
	require.NoError(t, err)
	meta, err := corim.NewMeta().SetSigner("Example Reference Value Provider", nil).ToCBOR()
	require.NoError(t, err)
	msg := cose.NewSign1Message()
	msg.Payload = payload
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

// A host opened with a reference signer updates a named branch from a CoRIM
// that signer signed.
func TestOpen_ReferenceSignerServesSignedBranchUpdates(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	device, err := localtpm.OpenDevice(localtpm.DeviceParams{DataDir: dir, UseSimulator: true, Logger: logger})
	require.NoError(t, err)
	cfg := pkgtpm2.DefaultConfig
	cfg.UseSimulator = true
	require.NoError(t, pkgtpm2.ProvisionFresh(device.TPM(), &cfg))
	policies, err := localtpm.Open(localtpm.Params{
		TPM: device.TPM(), Keys: device.Keys(), DataDir: dir, OpenStore: localtpmtest.MemoryStores, Logger: logger,
		ReferenceSigner: &refvalue.VerifyOptions{PublicKey: &key.PublicKey},
	})
	require.NoError(t, err)
	host := &localtpm.Host{Policies: policies, Device: device}
	t.Cleanup(func() { require.NoError(t, host.Close()) })
	ctx := t.Context()

	_, err = host.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{
		Name:     "boot",
		Branches: []transport.TPMPolicyBranch{transport.TPMPolicyPCRBranch("sha256", []uint{simPCR})},
	})
	require.NoError(t, err)
	next := sha256.Sum256([]byte("bootloader-v2"))
	updated, err := host.TPMPolicyUpdate(ctx, &transport.TPMPolicyUpdateRequest{
		Name: "boot", Branch: "branch-1", ReferenceValues: signedPCRReference(t, key, uint64(simPCR), next[:]),
	})
	require.NoError(t, err)
	assert.True(t, updated.Approved)
	require.Len(t, updated.Branches, 1)
	require.NotNil(t, updated.Branches[0].Reference)
}
