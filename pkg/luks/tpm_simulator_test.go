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

package luks

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"

	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/tpm2test"

	libtpm2 "github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/require"
)

// simLock serialises access to the go-tpm-tools simulator singleton: the
// library itself allows one simulator per process and hands the next caller
// a lock that only Close releases.
var simLock sync.Mutex

// newLUKSSimHarness opens a fresh TPM simulator, provisions it (EK, SSRK,
// Platform SRK) and returns the resulting *pkgtpm2.TPM2, satisfying
// TPMSealUnsealer. The Platform SRK is created with empty auth (no PIN),
// matching pkg/tpm2/tpm2test.EnrollPlatformSRK's documented first-boot
// shape; TPMSealer sets no password on the Platform SRK parent or on the
// sealed objects, so this is sufficient to exercise both SealParentPSRK and
// SealParentSSRK.
func newLUKSSimHarness(t *testing.T) *pkgtpm2.TPM2 {
	t.Helper()
	simLock.Lock()
	sim, err := pkgtpm2.OpenSimulator()
	require.NoError(t, err, "TPM simulator must be available; build with -tags tpm_simulator")
	t.Cleanup(func() {
		_ = sim.Close()
		simLock.Unlock()
	})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	storageFactory, err := store.NewStorageFactory(logger, dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageFactory.Close() })

	config := &pkgtpm2.Config{
		UseSimulator: false, // Transport is supplied explicitly below.
		Hash:         "SHA-256",
		EK: &pkgtpm2.EKConfig{
			Handle:       0x81010001,
			KeyAlgorithm: "RSA",
			RSAConfig:    &store.RSAConfig{KeySize: 2048},
		},
		IAK: &pkgtpm2.IAKConfig{
			CN:                 "luks-test-iak",
			Hash:               crypto.SHA256.String(),
			Handle:             0x81010002,
			KeyAlgorithm:       x509.RSA.String(),
			RSAConfig:          &store.RSAConfig{KeySize: 2048},
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		},
		SSRK: &pkgtpm2.SRKConfig{
			Handle:       0x81000001,
			KeyAlgorithm: "RSA",
			RSAConfig:    &store.RSAConfig{KeySize: 2048},
		},
		PlatformSRK: &pkgtpm2.PlatformSRKConfig{
			SRKHandle:      0x81000002,
			PlatformPolicy: true,
		},
		PlatformPCR:     pkgtpm2.DefaultPlatformPCR,
		PlatformPCRBank: pkgtpm2.PCRBankSHA256,
	}

	params := &pkgtpm2.Params{
		Logger:    logger,
		Config:    config,
		BlobStore: storageFactory.BlobStore(),
		Backend:   storageFactory.KeyBackend(),
		Transport: sim.Transport(),
		FQDN:      "luks-test.example.com",
	}

	tpmIface, err := pkgtpm2.NewTPM2(params)
	if errors.Is(err, pkgtpm2.ErrNotInitialized) {
		require.NotNil(t, tpmIface)
		require.NoError(t, tpmIface.Provision(nil), "provisioning the simulator must succeed")
	} else {
		require.NoError(t, err)
	}
	require.NoError(t, tpm2test.EnrollPlatformSRK(tpmIface, config))

	tpm, ok := tpmIface.(*pkgtpm2.TPM2)
	require.True(t, ok, "NewTPM2 must return *pkgtpm2.TPM2")
	t.Cleanup(func() { _ = tpmIface.Close() })
	return tpm
}

// ---------------------------------------------------------------------------
// SealParentPSRK — bound to go-xkms's platform PCR policy
// ---------------------------------------------------------------------------

// TestTPMSealer_PSRK_SealUnsealRoundTrip proves a passphrase sealed under
// the Platform SRK, with the platform's current PCR state, unseals correctly
// through the same sealer.
func TestTPMSealer_PSRK_SealUnsealRoundTrip(t *testing.T) {
	tpm := newLUKSSimHarness(t)
	s, err := NewTPMSealer(tpm, TPMSealerConfig{Parent: SealParentPSRK})
	require.NoError(t, err)

	res, err := s.SealPassphrase(context.Background(), nil)
	require.NoError(t, err)
	defer res.Passphrase.Destroy()
	require.Equal(t, XKMSTPMTokenType, res.Token.Type)

	unsealed, err := s.UnsealPassphrase(context.Background(), res.Token)
	require.NoError(t, err)
	require.True(t, bytes.Equal(unsealed, res.Passphrase.Bytes()))
}

// TestTPMSealer_PSRK_Seal_PolicyBindsPCRState proves that extending a
// platform PCR after sealing makes the subsequent unseal fail: the sealed
// object is genuinely bound to the live platform measurement, not merely
// labelled as if it were.
func TestTPMSealer_PSRK_Seal_PolicyBindsPCRState(t *testing.T) {
	tpm := newLUKSSimHarness(t)
	s, err := NewTPMSealer(tpm, TPMSealerConfig{Parent: SealParentPSRK})
	require.NoError(t, err)

	res, err := s.SealPassphrase(context.Background(), nil)
	require.NoError(t, err)
	defer res.Passphrase.Destroy()

	// Perturb the platform PCR so the policy digest no longer matches.
	_, err = (libtpm2.PCRExtend{
		PCRHandle: libtpm2.AuthHandle{
			Handle: libtpm2.TPMHandle(pkgtpm2.DefaultPlatformPCR),
			Auth:   libtpm2.PasswordAuth(nil),
		},
		Digests: libtpm2.TPMLDigestValues{
			Digests: []libtpm2.TPMTHA{{
				HashAlg: libtpm2.TPMAlgSHA256,
				Digest:  bytes.Repeat([]byte{0xAB}, 32),
			}},
		},
	}).Execute(tpm.Transport())
	require.NoError(t, err)

	_, err = s.UnsealPassphrase(context.Background(), res.Token)
	require.Error(t, err, "unseal must fail once the platform PCR state has moved")
	require.ErrorIs(t, err, ErrTPMUnsealFailed)
}

// ---------------------------------------------------------------------------
// SealParentSSRK — plain PolicyPCR, systemd-tpm2 compatible
// ---------------------------------------------------------------------------

// TestTPMSealer_SSRK_Seal_Success proves SealPassphrase produces a
// systemd-tpm2 shaped token under the Shared SRK.
func TestTPMSealer_SSRK_Seal_Success(t *testing.T) {
	tpm := newLUKSSimHarness(t)
	s, err := NewTPMSealer(tpm, TPMSealerConfig{Parent: SealParentSSRK})
	require.NoError(t, err)

	res, err := s.SealPassphrase(context.Background(), []int32{7})
	require.NoError(t, err)
	defer res.Passphrase.Destroy()

	require.Equal(t, TPMTokenType, res.Token.Type)
	members := mustReadTPMTokenMembers(t, res.Token)
	require.Equal(t, "sha256", members.PCRBank)
	require.Equal(t, []int{7}, members.PCRs)
	require.Equal(t, uint64(0x81000001), members.KeyHandle)
	require.NotEmpty(t, members.PolicyHash)
	require.Equal(t, 32, res.Passphrase.Size())
}

// TestTPMSealer_SSRK_Unseal_Unsupported proves go-xkms refuses to unseal its
// own SSRK-parented tokens, by design (see ErrTPMSSRKUnsealUnsupported):
// systemd-cryptsetup is the only intended unsealer for this mode.
func TestTPMSealer_SSRK_Unseal_Unsupported(t *testing.T) {
	tpm := newLUKSSimHarness(t)
	s, err := NewTPMSealer(tpm, TPMSealerConfig{Parent: SealParentSSRK})
	require.NoError(t, err)

	res, err := s.SealPassphrase(context.Background(), []int32{7})
	require.NoError(t, err)
	defer res.Passphrase.Destroy()

	_, err = s.UnsealPassphrase(context.Background(), res.Token)
	require.ErrorIs(t, err, ErrTPMSSRKUnsealUnsupported)
}

// TestTPMSealer_SSRK_SealedObjectEnforcesPCRPolicy proves the SSRK-sealed
// object genuinely requires a correct PolicyPCR session to unseal. The object
// carries its PolicyPCR digest with USERWITHAUTH clear, so a plain
// empty-password TPM2_Unseal is refused by the attribute
// (TPM_RC_AUTH_UNAVAILABLE), while the PolicyPCR session systemd-cryptsetup
// builds from the token's PCR list unseals the passphrase.
func TestTPMSealer_SSRK_SealedObjectEnforcesPCRPolicy(t *testing.T) {
	tpm := newLUKSSimHarness(t)
	s, err := NewTPMSealer(tpm, TPMSealerConfig{Parent: SealParentSSRK})
	require.NoError(t, err)

	res, err := s.SealPassphrase(context.Background(), []int32{7})
	require.NoError(t, err)
	defer res.Passphrase.Destroy()

	members := mustReadTPMTokenMembers(t, res.Token)
	publicBlob, privateBlob, err := DecodeTPMSealBlobs(members.Blob)
	require.NoError(t, err)

	ssrkAttrs, err := tpm.SSRKAttributes()
	require.NoError(t, err)
	ssrkName, _, err := tpm.ReadHandle(libtpm2.TPMHandle(ssrkAttrs.TPMAttributes.Handle))
	require.NoError(t, err)

	pub := libtpm2.BytesAs2B[libtpm2.TPMTPublic](publicBlob)
	loadRsp, err := (libtpm2.Load{
		ParentHandle: libtpm2.AuthHandle{
			Handle: libtpm2.TPMHandle(ssrkAttrs.TPMAttributes.Handle),
			Name:   ssrkName,
			Auth:   libtpm2.PasswordAuth(nil),
		},
		InPrivate: libtpm2.TPM2BPrivate{Buffer: privateBlob},
		InPublic:  pub,
	}).Execute(tpm.Transport())
	require.NoError(t, err)
	defer func() {
		_, _ = (libtpm2.FlushContext{FlushHandle: loadRsp.ObjectHandle}).Execute(tpm.Transport())
	}()

	public, err := pub.Contents()
	require.NoError(t, err)
	require.False(t, public.ObjectAttributes.UserWithAuth,
		"a PCR-gated object must answer only a policy session")
	require.Equal(t, members.PolicyHash, base64.StdEncoding.EncodeToString(public.AuthPolicy.Buffer))

	_, err = (libtpm2.Unseal{
		ItemHandle: libtpm2.AuthHandle{
			Handle: loadRsp.ObjectHandle,
			Name:   loadRsp.Name,
			Auth:   libtpm2.PasswordAuth(nil),
		},
	}).Execute(tpm.Transport())
	require.ErrorIs(t, err, libtpm2.TPMRCAuthUnavailable,
		"an empty-password TPM2_Unseal must not satisfy a PCR-gated object")

	// The unseal systemd-cryptsetup performs: a PolicyPCR session over the
	// PCRs the token records.
	session, closeSession, err := libtpm2.PolicySession(tpm.Transport(), libtpm2.TPMAlgSHA256, 16)
	require.NoError(t, err)
	defer func() { _ = closeSession() }()
	_, err = (libtpm2.PolicyPCR{
		PolicySession: session.Handle(),
		Pcrs:          buildPCRSelection(libtpm2.TPMAlgSHA256, []int32{7}),
	}).Execute(tpm.Transport())
	require.NoError(t, err)
	out, err := (libtpm2.Unseal{
		ItemHandle: libtpm2.AuthHandle{
			Handle: loadRsp.ObjectHandle,
			Name:   loadRsp.Name,
			Auth:   session,
		},
	}).Execute(tpm.Transport())
	require.NoError(t, err, "the PolicyPCR session must unseal the passphrase")
	require.True(t, bytes.Equal(res.Passphrase.Bytes(), out.OutData.Buffer))
}
