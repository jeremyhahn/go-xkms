//go:build tpm_simulator

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package server

import (
	"context"
	"crypto/x509"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	sealedstorage "github.com/jeremyhahn/go-xkms/pkg/storage/sealed"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	tpm2store "github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// ============================================================================
// Tests — tpm2 strategy (in-process simulator, tag tpm_simulator)
//
// go-xkms seals under the Platform SRK only (owner ruling; PR #681 removes
// every Shared-SRK fallback). A Platform SRK is not enrolled automatically
// by opening a TPM -- it is a deliberate, separate enrollment step
// (pkg/tpm2's PlatformKeyStore.EnrollPlatformSRK) -- so most of these tests
// enroll one by hand, mirroring pkg/tpm2's own simulator harness
// (pkg/tpm2/seal_pcr_policy_simulator_test.go's createPlatformPolicySRK) and
// the not-yet-merged go-xkms#681's tpm2test.EnrollPlatformSRK, exactly as
// instructed. No PIN is presented anywhere here, matching production
// (buildTPM2PlatformSealer/platformPolicySealer never has one to present),
// so authorization always takes the live-PCR PolicyPCR branch.
//
// This whole file needs a working TPM simulator (pkg/tpm2's tpm_simulator
// build tag) and is excluded from CI's Race Detector job, which builds
// pkg/server without it -- see platform_store_test.go's
// TestInitializePlatformStore_TPM2WithoutEnrolledPSRKFailsClosed for the one
// tpm2 case that runs there instead.
// ============================================================================

// enrollPlatformSRKForTest opens a fresh in-process TPM simulator,
// provisions it (EK, SSRK, IAK -- Provision requires all three), and
// enrolls its Platform SRK with no PIN. Returns the resulting
// *tpm2backend.Backend, ready to assign to s.nodeSealTPM so
// buildTPM2PlatformSealer's reuse path adopts it without opening a second
// TPM.
func enrollPlatformSRKForTest(t *testing.T, platformPCR uint) *tpm2backend.Backend {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	keyBackend, err := tpm2backend.NewFileKeyBackend(logger, t.TempDir())
	require.NoError(t, err)

	tpmConfig := &pkgtpm2.Config{
		UseSimulator:                 true,
		Hash:                         "SHA-256",
		PlatformPCR:                  platformPCR,
		PlatformPCRBank:              pkgtpm2.PCRBankSHA256,
		IdentityProvisioningStrategy: string(pkgtpm2.EnrollmentStrategyIAK),
		EK: &pkgtpm2.EKConfig{
			CertHandle:   0x01C00002,
			Handle:       0x81010001,
			KeyAlgorithm: x509.RSA.String(),
			RSAConfig:    &tpm2store.RSAConfig{KeySize: 2048},
		},
		SSRK: &pkgtpm2.SRKConfig{
			Handle:       0x81000001,
			KeyAlgorithm: x509.RSA.String(),
			RSAConfig:    &tpm2store.RSAConfig{KeySize: 2048},
		},
		IAK: &pkgtpm2.IAKConfig{
			CN:                 "xkms-platform-store-test",
			Hash:               "SHA-256",
			Handle:             0x81010002,
			KeyAlgorithm:       x509.RSA.String(),
			RSAConfig:          &tpm2store.RSAConfig{KeySize: 2048},
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		},
		PlatformSRK: &pkgtpm2.PlatformSRKConfig{
			SRKHandle:      0x81000002,
			PlatformPolicy: true,
		},
	}

	tpmIface, err := pkgtpm2.NewTPM2(&pkgtpm2.Params{
		Logger:  logger,
		Config:  tpmConfig,
		Backend: keyBackend,
	})
	// A fresh simulator has no endorsement key yet, which NewTPM2 reports as
	// ErrNotInitialized while still returning a usable handle.
	if err != nil {
		require.ErrorIs(t, err, pkgtpm2.ErrNotInitialized)
	}
	require.NotNil(t, tpmIface)
	t.Cleanup(func() { _ = tpmIface.Close() })
	require.NoError(t, tpmIface.Provision(nil), "simulator must provision EK, SSRK and IAK")

	// PlatformSRKAttributesFromConfig is the exported entry point to the
	// same construction NewPlatformKeyStore/EnrollPlatformSRK use internally
	// (pkg/tpm2/platform_keystore.go's PlatformSRKAttributesFromConfig). Neither
	// config.SSRK nor config.PlatformSRK above set a Password/HierarchyAuth,
	// so the resulting attrs already carry none -- matching production,
	// which never presents a PIN either.
	srkAttrs, err := pkgtpm2.PlatformSRKAttributesFromConfig(tpmConfig)
	require.NoError(t, err)
	require.NoError(t, tpmIface.CreateSRK(srkAttrs))

	backend, err := tpm2backend.NewBackendWithTPM(&tpm2backend.ExternalTPMConfig{
		TPM:        tpmIface,
		KeyBackend: keyBackend,
		Logger:     logger,
	})
	require.NoError(t, err)
	return backend
}

// tpm2EnrolledServer builds a minimal *Server whose s.nodeSealTPM is a
// simulator with an enrolled Platform SRK, ready for
// s.initializePlatformStore() to reuse without a second TPM open.
func tpm2EnrolledServer(t *testing.T, platformPolicy bool, platformPCR uint) *Server {
	t.Helper()

	s := newMinimalServer(t, &config.Config{
		Datastore:   config.DatastoreConfig{Engine: "memory"},
		Credentials: config.CredentialsConfig{SealStrategy: "tpm2"},
		Backends: config.BackendsConfig{
			TPM2: &config.TPM2Config{
				PlatformPolicy:  platformPolicy,
				PlatformPCR:     platformPCR,
				PlatformPCRBank: "SHA256",
			},
		},
	})
	s.nodeSealTPM = enrollPlatformSRKForTest(t, platformPCR)
	// newMinimalServer bypasses New(), so s.qrdbStorage -- the one shared
	// datastore createStorage now always resolves through -- is never
	// built; give this test a real one.
	var err error
	s.qrdbStorage, err = storage.NewMemoryBackend()
	require.NoError(t, err)
	return s
}

func TestInitializePlatformStore_TPM2BuildsWorkingStore(t *testing.T) {
	s := tpm2EnrolledServer(t, false, 0)

	require.NoError(t, s.initializePlatformStore())
	require.NotNil(t, s.platformStore)
	assert.Nil(t, s.platformStoreTPMClose, "the pre-enrolled backend was injected, not opened by buildTPM2PlatformSealer")

	ctx := context.Background()
	require.NoError(t, s.platformStore.Put(ctx, "tpm-secret", []byte("tpm-sealed-value")))

	got, err := s.platformStore.Get(ctx, "tpm-secret")
	require.NoError(t, err)
	assert.Equal(t, []byte("tpm-sealed-value"), got)

	require.NoError(t, s.platformStore.Reseal(ctx, "tpm-secret"))
	got, err = s.platformStore.Get(ctx, "tpm-secret")
	require.NoError(t, err)
	assert.Equal(t, []byte("tpm-sealed-value"), got)
}

// TestCredentialService_TPM2Strategy_StoresAndLoadsThroughPlatformStore
// proves the credential service stores and loads through the platform store
// end to end for the tpm2 strategy once the Platform SRK is enrolled.
func TestCredentialService_TPM2Strategy_StoresAndLoadsThroughPlatformStore(t *testing.T) {
	s := tpm2EnrolledServer(t, false, 0)
	require.NoError(t, s.initializePlatformStore())
	require.NoError(t, s.initializeCredentialService())
	require.NotNil(t, s.credentialService)

	ctx := context.Background()
	require.NoError(t, s.credentialService.StoreCredential(ctx, "pkcs11-user-pin", []byte("1234")))

	got, err := s.credentialService.RetrieveCredential(ctx, "pkcs11-user-pin")
	require.NoError(t, err)
	assert.Equal(t, []byte("1234"), got)

	names, err := s.credentialService.ListCredentials(ctx)
	require.NoError(t, err)
	assert.Contains(t, names, "pkcs11-user-pin")
}

// TestInitializePlatformStore_TPM2ReusesNodeSealFlip proves the tpm2
// credential strategy reuses the node-seal flip's single TPM open
// (s.nodeSealTPM) rather than opening a second one, when both the barrier
// and the credential strategy are tpm2 on an embedded-qrdb deployment. A
// second independent simulator open would otherwise be attempted -- and a
// real swtpm hangs on that -- so platformStoreTPMClose must stay nil and
// s.platformStoreTPM must be the exact same backend as s.nodeSealTPM: the
// point under test is the absence of a double open and a hang.
//
// New(cfg) succeeds here, not fails closed: the flip's autodetect
// (resolveNodeSeal) opens the TPM through the same tpm2backend.NewBackend
// every simulator-backed open in this codebase goes through, and NewBackend's
// first-boot path (pkg/backend/tpm2/backend.go's provisionSimulatorEKSRK,
// added by go-xkms#681 -- "seal only under the Platform SRK") provisions the
// EK, SSRK AND Platform SRK together on a fresh simulator, deliberately, so
// every simulator-backed test in this codebase gets a seal-capable device
// without a separate enrollment step. A physical TPM is never
// auto-provisioned this way (see NewBackend's own comment); this convenience
// is simulator-only. So by the time initializePlatformStore reuses
// s.nodeSealTPM, its Platform SRK already exists and the platform store
// builds successfully -- unlike the standalone (non-flip) probe path
// TestInitializePlatformStore_TPM2WithoutEnrolledPSRKFailsClosed in
// platform_store_test.go exercises, where nothing provisions the device
// first.
func TestInitializePlatformStore_TPM2ReusesNodeSealFlip(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := qrdbBarrierConfig(t)
	cfg.Barrier = config.BarrierConfig{Enabled: true, Strategy: "tpm2"}
	cfg.Backends.TPM2 = &config.TPM2Config{UseSimulator: true}
	cfg.Credentials = config.CredentialsConfig{SealStrategy: "tpm2"}

	// Registered unconditionally, before any assertion, so a future
	// assertion failure here can never leak a live server (and its open TPM
	// simulator handle -- go-tpm-tools' simulator.Get() is a single global
	// process-wide lock) the way an assertion positioned before this defer
	// once did, hanging every later simulator-backed test in the package.
	s, err := New(cfg)
	if s != nil {
		defer func() { _ = s.Shutdown() }()
	}
	require.NoError(t, err, "the flip's simulator open provisions the Platform SRK as part of its first-boot recipe, so the platform store should build")
	require.NotNil(t, s)

	assert.Nil(t, s.platformStoreTPMClose, "the flip's TPM open must be reused, not duplicated")
	assert.Same(t, s.nodeSealTPM, s.platformStoreTPM, "the platform store must reuse the exact flip backend, not open a second one")
}

// TestInitializePlatformStore_TPM2PlatformPolicy_PCRExtendBreaksGet proves
// the platform-policy-bound tpm2 sealer (Backends.TPM2.PlatformPolicy) ties
// Get to the live platform PCR: extending it after Put makes a subsequent
// Get fail with a typed error, exactly the property a measured-boot
// deployment relies on.
func TestInitializePlatformStore_TPM2PlatformPolicy_PCRExtendBreaksGet(t *testing.T) {
	const testPCR = 16 // resettable/debug PCR, safe to extend in a test

	s := tpm2EnrolledServer(t, true, testPCR)
	require.NoError(t, s.initializePlatformStore())
	require.NotNil(t, s.platformStore)

	ctx := context.Background()
	require.NoError(t, s.platformStore.Put(ctx, "pcr-bound", []byte("bound-to-pcr16")))

	got, err := s.platformStore.Get(ctx, "pcr-bound")
	require.NoError(t, err, "Get must succeed while the platform PCR is unchanged")
	assert.Equal(t, []byte("bound-to-pcr16"), got)

	backend, ok := s.platformStoreTPM.(*tpm2backend.Backend)
	require.True(t, ok, "buildTPM2PlatformSealer must record the raw TPM2 backend")
	require.NoError(t, backend.TPM().ExtendPCR(testPCR, "sha256", []byte("measured-boot-event")))

	_, err = s.platformStore.Get(ctx, "pcr-bound")
	require.Error(t, err, "Get must fail once the platform PCR no longer matches the sealed state")
	assert.ErrorIs(t, err, sealedstorage.ErrUnsealFailed)

	// Reseal's own contract (pkg/seal/platform_store.go) reads the current
	// plaintext first, deletes the old sealed copy, then writes it back --
	// so it cannot recover a secret Get itself cannot read: there is no
	// plaintext left to re-seal once the PCR-bound object no longer opens.
	// This is the empirically-verified boundary documented in
	// docs/platform-secrets/architecture.md's Trust boundaries: Reseal
	// refreshes a seal that still opens, it does not restore one that no
	// longer does.
	resealErr := s.platformStore.Reseal(ctx, "pcr-bound")
	require.Error(t, resealErr, "Reseal cannot recover a secret it can no longer read the plaintext of")
	assert.ErrorIs(t, resealErr, seal.ErrResealFailed)
}

// TestInitializePlatformStore_BuildsWithoutBarrier proves a non-skip
// strategy (tpm2, with its Platform SRK already enrolled -- see
// tpm2EnrolledServer above) builds a working platform store even when
// s.barrier is nil, since the platform store is sealed by its own strategy,
// never by the barrier. Moved here from server_extra2_test.go because it
// needs the simulator-backed enrollment harness.
func TestInitializePlatformStore_BuildsWithoutBarrier(t *testing.T) {
	s := tpm2EnrolledServer(t, false, 0)
	s.barrier = nil
	err := s.initializePlatformStore()
	require.NoError(t, err)
	assert.NotNil(t, s.platformStore)
}
