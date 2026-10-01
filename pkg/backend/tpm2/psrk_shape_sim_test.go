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

package tpm2

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// go-xkms#997: the Platform SRK is the single storage parent go-xkms ever
// seals or signs under (go-xkms#677: authValue = user PIN, authPolicy =
// platform PCR policy), so every path that can create one -- this backend's
// simulator first-boot autodetect (pkg/tpm2.ProvisionFresh) and the
// operator-facing enrollment ceremony (pkg/tpm2's
// PlatformKeyStore.EnrollPlatformSRK) -- must derive the exact same shape.
// Before the fix, ToTPMConfig hardcoded PlatformPolicy: false into the
// config this backend built its PlatformSRKConfig from, so the autodetected
// Platform SRK carried no AuthPolicy in its template at all while the
// enrolled one did; pkg/server/platform_store.go's buildTPM2PlatformSealer
// then papered over the mismatch by forcing the reported KeyAttributes'
// PlatformPolicy to true regardless of what was actually on the TPM,
// hiding the disagreement instead of fixing it. These tests provision two
// independent simulators, one through each path, and compare the persisted
// AuthPolicy digest.

// psrkShapeTestPCR/psrkShapeTestBank pin both provisioning paths to the same
// platform PCR selection, so a digest mismatch below can only mean a real
// difference in the two paths' derivation, never a difference in which PCR
// each happened to read.
const psrkShapeTestPCR uint = 7

// psrkShapeTestBank is not a constant: pkgtpm2.PCRBankSHA256 is itself a
// package-level var, not a compile-time constant.
var psrkShapeTestBank = pkgtpm2.PCRBankSHA256

// autodetectedPlatformSRKAuthPolicy provisions a fresh simulator through
// exactly the code path go-xkms#997 fixed -- NewBackend's first-boot
// simulator recipe (pkg/tpm2.ProvisionFresh) -- and returns the resulting
// Platform SRK's AuthPolicy digest as persisted on the TPM. The simulator is
// closed before returning: go-tpm-tools' simulator is a single process-wide
// singleton, so only one may be open at a time.
func autodetectedPlatformSRKAuthPolicy(t *testing.T) []byte {
	t.Helper()

	cfg := &Config{
		UseSimulator:    true,
		KeyStorage:      storage.NewMemory(),
		CN:              "psrk-shape-autodetect",
		PlatformPCR:     psrkShapeTestPCR,
		PlatformPCRBank: psrkShapeTestBank,
	}
	backend, err := NewBackend(cfg)
	require.NoError(t, err, "backend autodetect must provision the Platform SRK on a fresh simulator")
	defer func() { require.NoError(t, backend.Close()) }()

	handle := backend.SRKAttributes().TPMAttributes.Handle
	_, pub, err := backend.TPM().ReadHandle(handle)
	require.NoError(t, err, "the autodetected Platform SRK must be readable off the TPM")
	return pub.AuthPolicy.Buffer
}

// enrolledPlatformSRKAuthPolicy provisions a second, independent simulator
// through the production first-boot enrollment path
// (pkg/tpm2.PlatformKeyStore.EnrollPlatformSRK) and returns its Platform
// SRK's AuthPolicy digest the same way.
func enrolledPlatformSRKAuthPolicy(t *testing.T) []byte {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	keyBackend, err := NewFileKeyBackend(logger, t.TempDir())
	require.NoError(t, err)

	tpmConfig := &pkgtpm2.Config{
		UseSimulator:    true,
		Hash:            "SHA-256",
		PlatformPCR:     psrkShapeTestPCR,
		PlatformPCRBank: psrkShapeTestBank,
		PlatformSRK: &pkgtpm2.PlatformSRKConfig{
			SRKHandle:      platformSRKHandle,
			PlatformPolicy: true,
		},
	}

	tpmIface, err := pkgtpm2.NewTPM2(&pkgtpm2.Params{
		Logger:  logger,
		Config:  tpmConfig,
		Backend: keyBackend,
	})
	// A fresh simulator has no endorsement key yet, which NewTPM2 reports as
	// ErrNotInitialized while still returning a usable handle -- enrollment
	// needs no EK at all (CreateSRK against the Owner hierarchy does not
	// depend on one), so this is expected and not provisioned further here.
	if err != nil {
		require.ErrorIs(t, err, pkgtpm2.ErrNotInitialized)
	}
	require.NotNil(t, tpmIface)
	defer func() { require.NoError(t, tpmIface.Close()) }()

	pks, err := pkgtpm2.NewPlatformKeyStore(
		logger, tpmIface, keyBackend, tpmConfig,
		filepath.Join(t.TempDir(), "pin-state.json"),
	)
	require.NoError(t, err)
	require.NoError(t, pks.EnrollPlatformSRK("", "enroll-test-pin"))

	_, pub, err := tpmIface.ReadHandle(tpm2.TPMHandle(platformSRKHandle))
	require.NoError(t, err, "the enrolled Platform SRK must be readable off the TPM")
	return pub.AuthPolicy.Buffer
}

// TestPlatformSRK_AutodetectAndEnrollmentAgreeOnAuthPolicy is go-xkms#997's
// verification for the parent-shape half of the bug: see the file doc
// comment above.
func TestPlatformSRK_AutodetectAndEnrollmentAgreeOnAuthPolicy(t *testing.T) {
	autoPolicy := autodetectedPlatformSRKAuthPolicy(t)
	enrolledPolicy := enrolledPlatformSRKAuthPolicy(t)

	require.NotEmpty(t, autoPolicy, "an autodetected Platform SRK must carry a non-empty AuthPolicy")
	require.NotEmpty(t, enrolledPolicy, "an enrolled Platform SRK must carry a non-empty AuthPolicy")
	require.True(t, bytes.Equal(autoPolicy, enrolledPolicy),
		"backend autodetect and enrollment must derive the same Platform SRK AuthPolicy from the same platform PCR state")
}

// TestPlatformSRK_AutodetectWithoutPlatformPolicyConfigStillBindsAuthPolicy
// proves the fix is unconditional: a caller that builds this backend's
// Config with the zero-value PlatformPCR/PlatformPCRBank (i.e. never touches
// platform-policy settings at all) still gets a Platform SRK whose AuthPolicy
// is baked in -- the design settled in go-xkms#677 has no plain
// password-only shape for the Platform SRK to fall back to.
func TestPlatformSRK_AutodetectWithoutPlatformPolicyConfigStillBindsAuthPolicy(t *testing.T) {
	cfg := &Config{
		UseSimulator: true,
		KeyStorage:   storage.NewMemory(),
		CN:           "psrk-shape-defaults",
	}
	backend, err := NewBackend(cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, backend.Close()) }()

	handle := backend.SRKAttributes().TPMAttributes.Handle
	_, pub, err := backend.TPM().ReadHandle(handle)
	require.NoError(t, err)
	require.NotEmpty(t, pub.AuthPolicy.Buffer,
		"the Platform SRK must always carry a PCR-policy AuthPolicy, even with a bare-minimum simulator config")
}

// TestBackend_SealUnseal_PINEnrolledPlatformSRK proves key operations under
// the Platform SRK still work through the password (PIN) branch once it
// carries a real operator PIN -- the PolicyOR compound policy CreateSRK bakes
// in (pkg/tpm2/key.go's CreateSession) offers both a PCR branch and a
// password branch, and go-xkms#997's fix must not have broken the latter
// while fixing the former. The Platform SRK is enrolled here exactly as
// production enrollment does (PlatformKeyStore.EnrollPlatformSRK), then a
// *Backend is built over that same TPM (NewBackendWithTPM) and used to seal
// and unseal data, presenting the enrolled PIN as the parent's auth on both
// calls.
func TestBackend_SealUnseal_PINEnrolledPlatformSRK(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	keyBackend, err := NewFileKeyBackend(logger, t.TempDir())
	require.NoError(t, err)

	tpmConfig := &pkgtpm2.Config{
		UseSimulator:    true,
		Hash:            "SHA-256",
		PlatformPCR:     psrkShapeTestPCR,
		PlatformPCRBank: psrkShapeTestBank,
		PlatformSRK: &pkgtpm2.PlatformSRKConfig{
			SRKHandle:      platformSRKHandle,
			PlatformPolicy: true,
		},
	}

	tpmIface, err := pkgtpm2.NewTPM2(&pkgtpm2.Params{
		Logger:  logger,
		Config:  tpmConfig,
		Backend: keyBackend,
	})
	if err != nil {
		require.ErrorIs(t, err, pkgtpm2.ErrNotInitialized)
	}
	require.NotNil(t, tpmIface)
	defer func() { require.NoError(t, tpmIface.Close()) }()

	pks, err := pkgtpm2.NewPlatformKeyStore(
		logger, tpmIface, keyBackend, tpmConfig,
		filepath.Join(t.TempDir(), "pin-state.json"),
	)
	require.NoError(t, err)

	const userPIN = "backend-pin-branch-test-9137"
	require.NoError(t, pks.EnrollPlatformSRK("", userPIN))

	// Attaching the PlatformKeyStore is what makes TPM2.PlatformSRKAttributes
	// (and so resolveSRKAttributes/NewBackendWithTPM below) return a parent
	// carrying the enrolled PIN as its Password, selecting the compound
	// policy's password branch instead of the PCR-only branch (pkg/tpm2's
	// CreateSession doc comment).
	concreteTPM, ok := tpmIface.(*pkgtpm2.TPM2)
	require.True(t, ok, "the simulator-backed TrustedPlatformModule must be a *pkgtpm2.TPM2")
	concreteTPM.SetPlatformKeyStore(pks)

	backend, err := NewBackendWithTPM(&ExternalTPMConfig{
		TPM:        tpmIface,
		KeyBackend: keyBackend,
		Logger:     logger,
	})
	require.NoError(t, err)
	defer func() { require.NoError(t, backend.Close()) }()

	require.NotNil(t, backend.SRKAttributes().Password,
		"precondition: the backend's resolved Platform SRK must carry the enrolled PIN")

	ctx := context.Background()
	plaintext := []byte("pin-branch-round-trip-secret")

	// The object carries a password of its own: a seal bound to neither a
	// policy nor a password is refused (pkgtpm2.ErrSealUnprotected).
	objectAuth, err := types.NewPasswordFromString("pin-branch-object-auth")
	require.NoError(t, err)
	sealed, err := backend.Seal(ctx, plaintext, &types.SealOptions{
		KeyAttributes: &types.KeyAttributes{
			CN:     "pin-branch-seal-test",
			Parent: backend.SRKAttributes(),
		},
		Password: objectAuth,
	})
	require.NoError(t, err, "Seal must succeed via the password branch of a PIN-enrolled Platform SRK")

	got, err := backend.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{
			CN:     "pin-branch-seal-test",
			Parent: backend.SRKAttributes(),
		},
		Password: objectAuth,
	})
	require.NoError(t, err, "Unseal must succeed via the password branch of a PIN-enrolled Platform SRK")
	require.Equal(t, plaintext, got)
}
