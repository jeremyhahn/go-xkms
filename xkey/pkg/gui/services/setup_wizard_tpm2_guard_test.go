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

package services

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// refuseUnavailableStrategyPersist (unit-level, no wizard flow involved)
// ---------------------------------------------------------------------------

// TestRefuseUnavailableStrategyPersist_TPM2NoSealer_ReturnsTypedError verifies
// that the guard refuses "tpm2" with ErrSetupSealStrategyUnavailable when the
// barrier service has no TPM sealer function wired in at all (#510 item 1).
func TestRefuseUnavailableStrategyPersist_TPM2NoSealer_ReturnsTypedError(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})
	tw.svc.SetBarrierService(NewBarrierService(t.TempDir(), slog.Default()))

	err := tw.svc.refuseUnavailableStrategyPersist(string(xkms.StrategyTPM2))

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSetupSealStrategyUnavailable),
		"guard must return the typed sentinel, got: %v", err)
}

// TestRefuseUnavailableStrategyPersist_TPM2CanSealFalse_ReturnsTypedError
// verifies the guard also refuses "tpm2" when a TPM sealer function IS wired
// but the sealer itself reports CanSeal() == false (e.g. no provisioned SRK
// on this host) -- the same condition assembleStrategy treats as unavailable.
func TestRefuseUnavailableStrategyPersist_TPM2CanSealFalse_ReturnsTypedError(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})
	barrierSvc := NewBarrierService(t.TempDir(), slog.Default())
	barrierSvc.SetTPMSealerFunc(func() xkms.Sealer {
		return &mockSealer{canSeal: false}
	})
	tw.svc.SetBarrierService(barrierSvc)

	err := tw.svc.refuseUnavailableStrategyPersist(string(xkms.StrategyTPM2))

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSetupSealStrategyUnavailable),
		"guard must return the typed sentinel when CanSeal() is false, got: %v", err)
}

// TestRefuseUnavailableStrategyPersist_TPM2SealerAvailable_ReturnsNil verifies
// that the guard allows "tpm2" through (returns nil) once a working TPM
// sealer is injected -- the guard must not block a build/host that genuinely
// has hardware sealing available.
func TestRefuseUnavailableStrategyPersist_TPM2SealerAvailable_ReturnsNil(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})
	barrierSvc := NewBarrierService(t.TempDir(), slog.Default())
	barrierSvc.SetTPMSealerFunc(func() xkms.Sealer {
		return &mockSealer{canSeal: true}
	})
	tw.svc.SetBarrierService(barrierSvc)

	err := tw.svc.refuseUnavailableStrategyPersist(string(xkms.StrategyTPM2))

	assert.NoError(t, err, "guard must allow tpm2 when a working sealer is injected")
}

// TestRefuseUnavailableStrategyPersist_Passphrase_NeverBlocked verifies the
// guard is scoped to "tpm2" only -- the passphrase strategy is never refused,
// regardless of TPM sealer wiring.
func TestRefuseUnavailableStrategyPersist_Passphrase_NeverBlocked(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})
	tw.svc.SetBarrierService(NewBarrierService(t.TempDir(), slog.Default()))

	err := tw.svc.refuseUnavailableStrategyPersist(string(xkms.StrategyPassphrase))

	assert.NoError(t, err, "guard must never block the passphrase strategy")
}

// TestRefuseUnavailableStrategyPersist_NoBarrierService_ReturnsNil verifies
// the guard is a no-op (defensive, not a false positive) when no barrier
// service is wired at all -- the legacy test-only ApplySetup path relies on
// this never firing.
func TestRefuseUnavailableStrategyPersist_NoBarrierService_ReturnsNil(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	err := tw.svc.refuseUnavailableStrategyPersist(string(xkms.StrategyTPM2))

	assert.NoError(t, err, "guard must not fire when no barrier service is wired")
}

// ---------------------------------------------------------------------------
// ApplySetup integration: the guard wired into the config-commit switch
// ---------------------------------------------------------------------------

// TestApplySetup_TPM2Unavailable_RefusesToPersistStrategy reproduces the
// exact shape of #510 item 1: a barrier already exists (as it would after an
// earlier successful run), the wizard is re-run explicitly requesting "tpm2"
// on a build/host with no TPM sealer wired in, and the resulting unseal
// attempt fails with ErrBarrierStrategyUnavailable (sealedShut).
//
// Before the guard, ApplySetup's config-commit switch unconditionally wrote
// updated.BarrierStrategy = choices.SealerBackend ("tpm2") into config even
// though the attempt failed -- a config the GUI could never unseal itself on
// this build again. The guard must refuse that write and report the typed
// error instead.
func TestApplySetup_TPM2Unavailable_RefusesToPersistStrategy(t *testing.T) {
	const barrierPassword = "correct-horse-battery-staple"

	dir := t.TempDir()

	// A barrier already exists, sealed under passphrase (as it would be after
	// a prior successful run before this build lost its TPM sealer wiring).
	preInit := NewBarrierService(dir, slog.Default())
	require.NoError(t, preInit.Initialize(barrierPassword, "passphrase"))

	cfg := &GUIConfigData{}
	tw := newTestSetupWizard(cfg)
	barrierSvc := NewBarrierService(dir, slog.Default())
	barrierSvc.SetContext(context.Background())
	// No TPM sealer wired: tpm2 is unavailable on this build/host.
	tw.svc.SetBarrierService(barrierSvc)
	tw.svc.initDataDirFunc = func() error { return nil }

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:              "standalone",
		SOPin:             "so-pin-value",
		UserPin:           barrierPassword,
		SealerBackend:     "tpm2",
		PasswordStoreMode: "none",
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.False(t, result.Success, "a barrier that cannot be opened under the unavailable strategy is a failed run")
	assert.False(t, result.SetupComplete, "setup must not be marked complete")
	assert.True(t, containsSubstring(result.Errors, ErrSetupSealStrategyUnavailable.Error()),
		"the typed guard error must be reported, got errors=%v", result.Errors)

	saved := tw.configFunc()
	require.NotNil(t, saved)
	assert.False(t, saved.SetupComplete, "persisted SetupComplete must stay false")
	assert.False(t, saved.BarrierInitialized, "persisted BarrierInitialized must stay false")
	assert.Empty(t, saved.BarrierStrategy,
		"the config must not be written with barrier_strategy: tpm2 when no TPM sealer is available (#510 item 1)")
}

// TestApplySetup_TPM2Unavailable_PreservesPriorBarrierStrategy verifies the
// guard does not clobber an existing, unrelated BarrierStrategy value in
// config when it refuses to persist the newly-requested (unavailable) one --
// only the specific write is skipped, nothing else in config is touched.
func TestApplySetup_TPM2Unavailable_PreservesPriorBarrierStrategy(t *testing.T) {
	const barrierPassword = "correct-horse-battery-staple"

	dir := t.TempDir()
	preInit := NewBarrierService(dir, slog.Default())
	require.NoError(t, preInit.Initialize(barrierPassword, "passphrase"))

	// Config already records the strategy this barrier was actually sealed
	// with. A failed tpm2 attempt must not overwrite it.
	cfg := &GUIConfigData{BarrierStrategy: "passphrase"}
	tw := newTestSetupWizard(cfg)
	barrierSvc := NewBarrierService(dir, slog.Default())
	barrierSvc.SetContext(context.Background())
	tw.svc.SetBarrierService(barrierSvc)
	tw.svc.initDataDirFunc = func() error { return nil }

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:              "standalone",
		SOPin:             "so-pin-value",
		UserPin:           barrierPassword,
		SealerBackend:     "tpm2",
		PasswordStoreMode: "none",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)

	saved := tw.configFunc()
	require.NotNil(t, saved)
	assert.Equal(t, "passphrase", saved.BarrierStrategy,
		"the guard must leave the prior config value untouched rather than overwrite or clear it")
}

// failingUnsealSealer reports itself available (CanSeal() == true, so
// assembleStrategy proceeds to build a real TPM2Strategy) but always fails
// to unseal -- simulating a hardware failure distinct from "no sealer wired"
// (e.g. TPM_RC_BAD_AUTH against a barrier that genuinely is tpm2-sealed).
type failingUnsealSealer struct{}

func (f *failingUnsealSealer) Seal(_ context.Context, data []byte, _ *xkms.SealOptions) (*xkms.SealedData, error) {
	return &xkms.SealedData{
		Backend:    xkms.BackendTypeTPM2,
		Ciphertext: data,
		TPMPublic:  []byte("pub"),
		TPMPrivate: []byte("priv"),
	}, nil
}

func (f *failingUnsealSealer) Unseal(_ context.Context, _ *xkms.SealedData, _ *xkms.UnsealOptions) ([]byte, error) {
	return nil, errors.New("simulated hardware unseal failure")
}

func (f *failingUnsealSealer) CanSeal() bool {
	return true
}

// TestApplySetup_TPM2Available_PersistsStrategyOnSealedShutFailure verifies
// the guard does NOT interfere with a genuine hardware/credential failure
// against an AVAILABLE tpm2 strategy: when a TPM sealer is wired in and
// reports CanSeal() == true, but the unseal itself fails for some other
// reason, the requested strategy is still persisted for retry, matching the
// pre-existing (and still correct) behavior for every failure reason other
// than "strategy unavailable".
func TestApplySetup_TPM2Available_PersistsStrategyOnSealedShutFailure(t *testing.T) {
	const password = "correct-horse-battery-staple"

	dir := t.TempDir()

	// Pre-initialize a real tpm2 barrier with a working sealer.
	preInit := NewBarrierService(dir, slog.Default())
	preInit.SetTPMSealerFunc(func() xkms.Sealer {
		return &mockSealer{canSeal: true}
	})
	preInit.SetContext(context.Background())
	require.NoError(t, preInit.Initialize(password, "tpm2"))

	cfg := &GUIConfigData{}
	tw := newTestSetupWizard(cfg)
	barrierSvc := NewBarrierService(dir, slog.Default())
	// CanSeal() is true (tpm2 is "available"), but Unseal itself fails.
	barrierSvc.SetTPMSealerFunc(func() xkms.Sealer {
		return &failingUnsealSealer{}
	})
	barrierSvc.SetContext(context.Background())
	tw.svc.SetBarrierService(barrierSvc)
	tw.svc.initDataDirFunc = func() error { return nil }

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:              "standalone",
		SOPin:             "so-pin-value",
		UserPin:           password,
		SealerBackend:     "tpm2",
		PasswordStoreMode: "none",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.False(t,
		containsSubstring(result.Errors, ErrSetupSealStrategyUnavailable.Error()),
		"a genuine hardware failure against an available strategy must not report strategy-unavailable, got: %v",
		result.Errors)

	saved := tw.configFunc()
	require.NotNil(t, saved)
	assert.Equal(t, "tpm2", saved.BarrierStrategy,
		"the strategy is available and the failure is not availability-related, so it is still persisted for retry")
}

// TestApplySetup_PassphraseStrategy_UnaffectedByTPM2Guard verifies the
// passphrase path behaves exactly as before the guard was added: a failed
// passphrase attempt still persists "passphrase" for retry, since the guard
// is scoped to tpm2 only.
func TestApplySetup_PassphraseStrategy_UnaffectedByTPM2Guard(t *testing.T) {
	const (
		correctPassword = "correct-horse-battery-staple"
		wrongPassword   = "not-the-password"
	)

	dir := t.TempDir()
	preInit := NewBarrierService(dir, slog.Default())
	require.NoError(t, preInit.Initialize(correctPassword, "passphrase"))

	cfg := &GUIConfigData{}
	tw := newTestSetupWizard(cfg)
	barrierSvc := NewBarrierService(dir, slog.Default())
	barrierSvc.SetContext(context.Background())
	tw.svc.SetBarrierService(barrierSvc)
	tw.svc.initDataDirFunc = func() error { return nil }

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:              "standalone",
		SOPin:             "so-pin-value",
		UserPin:           wrongPassword,
		SealerBackend:     "passphrase",
		PasswordStoreMode: "none",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.False(t,
		containsSubstring(result.Errors, ErrSetupSealStrategyUnavailable.Error()),
		"the passphrase path must never trip the tpm2 guard, got: %v", result.Errors)

	saved := tw.configFunc()
	require.NotNil(t, saved)
	assert.Equal(t, "passphrase", saved.BarrierStrategy,
		"the passphrase strategy is unaffected by the tpm2 guard and is still persisted for retry")
}
