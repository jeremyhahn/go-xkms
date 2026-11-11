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
	"log/slog"
	"path/filepath"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestBarrierService creates a BarrierService backed by a temporary directory.
func newTestBarrierService(t *testing.T) *BarrierService {
	t.Helper()
	return NewBarrierService(t.TempDir(), slog.Default())
}

// The seal-state hook fires once per successful transition, after the state
// has changed, so a listener reading IsSealed sees the new state.
func TestBarrierService_SealStateHookFollowsTransitions(t *testing.T) {
	svc := newTestBarrierService(t)
	var seen []bool
	svc.SetSealStateHook(func() { seen = append(seen, svc.IsSealed()) })

	require.NoError(t, svc.Initialize("hook-test-password", "passphrase"))
	require.NoError(t, svc.Seal())
	require.NoError(t, svc.Unseal("hook-test-password", ""))

	assert.Equal(t, []bool{false, true, false}, seen)
}

// A failed transition leaves the state unchanged and must not notify.
func TestBarrierService_SealStateHookSkipsFailures(t *testing.T) {
	svc := newTestBarrierService(t)
	calls := 0
	svc.SetSealStateHook(func() { calls++ })

	require.ErrorIs(t, svc.Seal(), ErrBarrierNotInitialized)
	assert.False(t, svc.IsSealed(), "no barrier held, so not sealed")

	require.NoError(t, svc.Initialize("hook-test-password", "passphrase"))
	require.NoError(t, svc.Seal())
	calls = 0
	require.Error(t, svc.Unseal("wrong-password", ""))
	assert.Zero(t, calls)
	assert.True(t, svc.IsSealed())
}

// mockSealer is a minimal types.Sealer that always reports CanSeal as true.
// It stores the data in the SealedData ciphertext field so Unseal can return it.
type mockSealer struct {
	canSeal bool
}

func (m *mockSealer) Seal(_ context.Context, data []byte, _ *xkms.SealOptions) (*xkms.SealedData, error) {
	return &xkms.SealedData{
		Backend:    xkms.BackendTypeTPM2,
		Ciphertext: data,
		TPMPublic:  []byte("pub"),
		TPMPrivate: []byte("priv"),
	}, nil
}

func (m *mockSealer) Unseal(_ context.Context, sealed *xkms.SealedData, _ *xkms.UnsealOptions) ([]byte, error) {
	return sealed.Ciphertext, nil
}

func (m *mockSealer) CanSeal() bool {
	return m.canSeal
}

// ---------------------------------------------------------------------------
// ProbeStrategies
// ---------------------------------------------------------------------------

func TestBarrierService_ProbeStrategies(t *testing.T) {
	svc := newTestBarrierService(t)

	strategies := svc.ProbeStrategies()

	require.Len(t, strategies, 1, "without TPM sealer, only software strategy expected")
	assert.Equal(t, string(xkms.StrategyPassphrase), strategies[0].ID)
	assert.True(t, strategies[0].Available, "software strategy must always be available")
	assert.False(t, strategies[0].HardwareBacked, "software strategy must not be hardware-backed")
	assert.NotEmpty(t, strategies[0].Label)
}

func TestBarrierService_ProbeStrategies_WithTPM(t *testing.T) {
	svc := newTestBarrierService(t)
	svc.SetTPMSealerFunc(func() xkms.Sealer {
		return &mockSealer{canSeal: true}
	})

	strategies := svc.ProbeStrategies()

	require.Len(t, strategies, 2, "with TPM sealer, both software and TPM2 expected")

	// First entry is software.
	assert.Equal(t, string(xkms.StrategyPassphrase), strategies[0].ID)
	assert.True(t, strategies[0].Available)
	assert.False(t, strategies[0].HardwareBacked)

	// Second entry is TPM2.
	assert.Equal(t, string(xkms.StrategyTPM2), strategies[1].ID)
	assert.True(t, strategies[1].Available)
	assert.True(t, strategies[1].HardwareBacked)
}

// ---------------------------------------------------------------------------
// BestStrategy
// ---------------------------------------------------------------------------

func TestBarrierService_BestStrategy(t *testing.T) {
	svc := newTestBarrierService(t)

	best, err := svc.BestStrategy()
	require.NoError(t, err)
	require.NotNil(t, best)
	assert.Equal(t, string(xkms.StrategyPassphrase), best.ID,
		"without TPM, best strategy should be software")
	assert.False(t, best.HardwareBacked)
}

func TestBarrierService_BestStrategy_TPMCanSealFalse_FallsToSoftware(t *testing.T) {
	svc := newTestBarrierService(t)
	// Sealer exists but CanSeal returns false (e.g., SRK not provisioned).
	svc.SetTPMSealerFunc(func() xkms.Sealer {
		return &mockSealer{canSeal: false}
	})

	best, err := svc.BestStrategy()
	require.NoError(t, err)
	require.NotNil(t, best)

	// TPM2 should NOT be selected when CanSeal is false.
	assert.Equal(t, string(xkms.StrategyPassphrase), best.ID,
		"TPM with CanSeal=false should fall back to software")
	assert.False(t, best.HardwareBacked)
}

func TestBarrierService_ProbeStrategies_TPMCanSealFalse(t *testing.T) {
	svc := newTestBarrierService(t)
	svc.SetTPMSealerFunc(func() xkms.Sealer {
		return &mockSealer{canSeal: false}
	})

	strategies := svc.ProbeStrategies()
	require.Len(t, strategies, 2)

	// TPM2 should be listed but marked as unavailable.
	assert.Equal(t, string(xkms.StrategyTPM2), strategies[1].ID)
	assert.False(t, strategies[1].Available,
		"TPM with CanSeal=false should be marked unavailable")
}

func TestBarrierService_BestStrategy_PrefersTPM(t *testing.T) {
	svc := newTestBarrierService(t)
	svc.SetTPMSealerFunc(func() xkms.Sealer {
		return &mockSealer{canSeal: true}
	})

	best, err := svc.BestStrategy()
	require.NoError(t, err)
	require.NotNil(t, best)

	// DefaultPreferenceOrder lists TPM2 before software.
	assert.Equal(t, string(xkms.StrategyTPM2), best.ID,
		"with TPM sealer, best strategy should be TPM2")
	assert.True(t, best.HardwareBacked)
}

// ---------------------------------------------------------------------------
// Initialize
// ---------------------------------------------------------------------------

func TestBarrierService_Initialize_SoftwareStrategy(t *testing.T) {
	svc := newTestBarrierService(t)

	err := svc.Initialize("test-password-123", "passphrase")
	require.NoError(t, err)
	assert.True(t, svc.IsUnsealed(), "barrier should be unsealed after initialization")
}

func TestBarrierService_Initialize_NoPassword_Error(t *testing.T) {
	svc := newTestBarrierService(t)

	err := svc.Initialize("", "passphrase")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBarrierPasswordRequired,
		"software strategy requires a password")
}

func TestBarrierService_Initialize_AlreadyInit_Error(t *testing.T) {
	svc := newTestBarrierService(t)

	err := svc.Initialize("first-password", "passphrase")
	require.NoError(t, err)

	err = svc.Initialize("second-password", "passphrase")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBarrierAlreadyInit,
		"initializing twice should return ErrBarrierAlreadyInit")
}

// ---------------------------------------------------------------------------
// Unseal
// ---------------------------------------------------------------------------

func TestBarrierService_UnsealAfterInitialize(t *testing.T) {
	svc := newTestBarrierService(t)

	password := "my-barrier-password"

	// Initialize.
	err := svc.Initialize(password, "passphrase")
	require.NoError(t, err)
	assert.True(t, svc.IsUnsealed())

	// Seal.
	err = svc.Seal()
	require.NoError(t, err)
	assert.False(t, svc.IsUnsealed(), "barrier should be sealed after Seal()")

	// Unseal with same password.
	err = svc.Unseal(password, "passphrase")
	require.NoError(t, err)
	assert.True(t, svc.IsUnsealed(), "barrier should be unsealed after Unseal()")
}

func TestBarrierService_Unseal_TransparentInit(t *testing.T) {
	svc := newTestBarrierService(t)

	// With the new behavior, Unseal on an uninitialized barrier
	// transparently calls Initialize, creating the barrier on the fly.
	err := svc.Unseal("some-password", "passphrase")
	require.NoError(t, err, "unseal should transparently initialize the barrier")
	assert.True(t, svc.IsUnsealed(), "barrier should be unsealed after transparent init")
}

// ---------------------------------------------------------------------------
// Seal and Status
// ---------------------------------------------------------------------------

func TestBarrierService_SealAndStatus(t *testing.T) {
	svc := newTestBarrierService(t)

	// Before initialization, status should show sealed.
	status := svc.Status()
	require.NotNil(t, status)
	assert.True(t, status.Sealed, "uninitialized barrier should report sealed")

	// Initialize.
	err := svc.Initialize("status-test-pw", "passphrase")
	require.NoError(t, err)

	// After initialization, status should show unsealed.
	status = svc.Status()
	require.NotNil(t, status)
	assert.False(t, status.Sealed, "barrier should be unsealed after Initialize")

	// Seal.
	err = svc.Seal()
	require.NoError(t, err)

	// After seal, status should show sealed.
	status = svc.Status()
	require.NotNil(t, status)
	assert.True(t, status.Sealed, "barrier should be sealed after Seal()")
}

func TestBarrierService_Seal_NotInitialized(t *testing.T) {
	svc := newTestBarrierService(t)

	err := svc.Seal()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBarrierNotInitialized,
		"seal without initialize should return ErrBarrierNotInitialized")
}

// ---------------------------------------------------------------------------
// GetBackend
// ---------------------------------------------------------------------------

func TestBarrierService_GetBackend_Nil(t *testing.T) {
	svc := newTestBarrierService(t)

	backend := svc.GetBackend()
	assert.Nil(t, backend, "GetBackend should return nil before initialization")
}

func TestBarrierService_GetBackend_AfterInit(t *testing.T) {
	svc := newTestBarrierService(t)

	err := svc.Initialize("backend-test-pw", "passphrase")
	require.NoError(t, err)

	backend := svc.GetBackend()
	assert.NotNil(t, backend, "GetBackend should return non-nil after initialization")
}

// ---------------------------------------------------------------------------
// SetContext
// ---------------------------------------------------------------------------

func TestBarrierService_SetContext(t *testing.T) {
	svc := newTestBarrierService(t)

	// Verify SetContext with a real context does not panic.
	ctx := context.Background()
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.ctx)

	// Verify SetContext with a cancellable context does not panic.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.ctx)
}

// ---------------------------------------------------------------------------
// GetSealInfo
// ---------------------------------------------------------------------------

func TestBarrierService_GetSealInfo_NotInitialized(t *testing.T) {
	svc := newTestBarrierService(t)

	info := svc.GetSealInfo()
	require.NotNil(t, info)
	assert.False(t, info.Initialized, "barrier should not be initialized")
	assert.False(t, info.Sealed, "uninitialized barrier should not report sealed")
	assert.Empty(t, info.Strategy, "uninitialized barrier should have no strategy")
	assert.NotEmpty(t, info.DataDir, "data directory should always be populated")
	assert.Equal(t, barrierRootKeyPath, info.RootKeyEntry)
}

func TestBarrierService_GetSealInfo_AfterInitialize(t *testing.T) {
	svc := newTestBarrierService(t)

	err := svc.Initialize("seal-info-password", "passphrase")
	require.NoError(t, err)

	info := svc.GetSealInfo()
	require.NotNil(t, info)
	assert.True(t, info.Initialized, "barrier should be initialized after Initialize()")
	assert.False(t, info.Sealed, "barrier should be unsealed after Initialize()")
	assert.Equal(t, string(xkms.StrategyPassphrase), info.Strategy)
	assert.NotEmpty(t, info.StrategyLabel)
	assert.False(t, info.HardwareBacked, "software strategy should not be hardware-backed")
	assert.Equal(t, "barrier/root_key", info.RootKeyEntry)
}

func TestBarrierService_GetSealInfo_AfterSeal(t *testing.T) {
	svc := newTestBarrierService(t)

	err := svc.Initialize("seal-info-sealed-pw", "passphrase")
	require.NoError(t, err)

	err = svc.Seal()
	require.NoError(t, err)

	info := svc.GetSealInfo()
	require.NotNil(t, info)
	assert.True(t, info.Initialized, "barrier should remain initialized after Seal()")
	assert.True(t, info.Sealed, "barrier should be sealed after Seal()")
	assert.NotEmpty(t, info.Strategy)
}

func TestBarrierService_GetSealInfo_SoftwareStrategyLabel(t *testing.T) {
	svc := newTestBarrierService(t)

	err := svc.Initialize("label-test-pw", "passphrase")
	require.NoError(t, err)

	info := svc.GetSealInfo()
	require.NotNil(t, info)
	assert.Equal(t, "Passphrase (AES-256-GCM)", info.StrategyLabel,
		"software strategy should have the expected human-readable label")
}

func TestBarrierService_GetSealInfo_FallbackStrategy_WhenBarrierNil(t *testing.T) {
	// Initialize a barrier, then create a fresh service pointing at the same
	// directory to simulate an app restart where the barrier object is nil
	// but the root key exists on disk.
	tmpDir := t.TempDir()
	svc1 := NewBarrierService(tmpDir, slog.Default())
	err := svc1.Initialize("fallback-test-pw", "passphrase")
	require.NoError(t, err)

	// Create a new service pointing at the same config dir (barrier == nil).
	svc2 := NewBarrierService(tmpDir, slog.Default())

	info := svc2.GetSealInfo()
	require.NotNil(t, info)
	assert.True(t, info.Initialized, "root key exists on disk, should be initialized")
	assert.True(t, info.Sealed, "barrier object is nil, should report sealed")
	assert.NotEmpty(t, info.Strategy, "should fall back to best strategy")
	assert.NotEmpty(t, info.StrategyLabel, "should have a strategy label")
}

// ---------------------------------------------------------------------------
// checkInitialized
// ---------------------------------------------------------------------------

func TestBarrierService_CheckInitialized_WithDataDir(t *testing.T) {
	// Initialize in the storageDir (dataDir), then verify checkInitialized
	// returns it.
	configDir := t.TempDir()
	dataDir := t.TempDir()

	svc := NewBarrierService(configDir, slog.Default())
	svc.SetDataDir(dataDir)

	err := svc.Initialize("primary-path-pw", "passphrase")
	require.NoError(t, err)

	// Create a fresh service with the same config to probe.
	probe := NewBarrierService(configDir, slog.Default())
	probe.SetDataDir(dataDir)

	found := probe.checkInitialized()
	assert.Equal(t, dataDir, found,
		"checkInitialized should return dataDir when root key is present")
	assert.True(t, probe.IsInitialized())
}

func TestBarrierService_CheckInitialized_NoDataDir(t *testing.T) {
	// When dataDir is not set, storageDir() is configDir/barrier/.
	configDir := t.TempDir()

	svc := NewBarrierService(configDir, slog.Default())
	err := svc.Initialize("no-datadir-pw", "passphrase")
	require.NoError(t, err)

	probe := NewBarrierService(configDir, slog.Default())

	found := probe.checkInitialized()
	expected := filepath.Join(configDir, barrierSubdir)
	assert.Equal(t, expected, found,
		"checkInitialized should return configDir/barrier/ when dataDir is empty")
	assert.True(t, probe.IsInitialized())
}

func TestBarrierService_CheckInitialized_DataDirChangeIsNotFound(t *testing.T) {
	// A root key written to configDir/barrier/ (no dataDir) is NOT found by
	// a service later given a dataDir pointing elsewhere: there is no
	// cross-directory probing, deliberately (go-xkms compat cleanup PR5).
	configDir := t.TempDir()
	dataDir := t.TempDir()

	svc := NewBarrierService(configDir, slog.Default())
	err := svc.Initialize("moved-datadir-pw", "passphrase")
	require.NoError(t, err)

	probe := NewBarrierService(configDir, slog.Default())
	probe.SetDataDir(dataDir)

	found := probe.checkInitialized()
	assert.Empty(t, found,
		"checkInitialized must not probe configDir/barrier/ once dataDir is set")
	assert.False(t, probe.IsInitialized())
}

func TestBarrierService_CheckInitialized_NotInitialized(t *testing.T) {
	// No root key at storageDir().
	configDir := t.TempDir()
	dataDir := t.TempDir()

	svc := NewBarrierService(configDir, slog.Default())
	svc.SetDataDir(dataDir)

	found := svc.checkInitialized()
	assert.Empty(t, found,
		"checkInitialized should return empty when no root key exists")
	assert.False(t, svc.IsInitialized())
}

func TestBarrierService_CheckInitialized_NotInitialized_NoDataDir(t *testing.T) {
	// No root key, no dataDir set.
	configDir := t.TempDir()

	svc := NewBarrierService(configDir, slog.Default())

	found := svc.checkInitialized()
	assert.Empty(t, found,
		"checkInitialized should return empty when configDir/barrier/ has no root key")
	assert.False(t, svc.IsInitialized())
}

// ---------------------------------------------------------------------------
// probeRootKey
// ---------------------------------------------------------------------------

func TestBarrierService_ProbeRootKey_NonexistentDir(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())

	found := svc.probeRootKey("/nonexistent/path/that/does/not/exist")
	assert.False(t, found, "probeRootKey should return false for nonexistent directory")
}

func TestBarrierService_ProbeRootKey_EmptyDir(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	emptyDir := t.TempDir()

	found := svc.probeRootKey(emptyDir)
	assert.False(t, found, "probeRootKey should return false for empty directory")
}

func TestBarrierService_ProbeRootKey_WithRootKey(t *testing.T) {
	configDir := t.TempDir()

	// Initialize to create the root key.
	svc := NewBarrierService(configDir, slog.Default())
	err := svc.Initialize("probe-key-pw", "passphrase")
	require.NoError(t, err)

	// Probe the configDir/barrier/ path.
	probe := NewBarrierService(configDir, slog.Default())
	found := probe.probeRootKey(filepath.Join(configDir, barrierSubdir))
	assert.True(t, found, "probeRootKey should return true when root key exists")
}

// ---------------------------------------------------------------------------
// GetSealInfo
// ---------------------------------------------------------------------------

func TestBarrierService_GetSealInfo_NotInitializedWithDataDir(t *testing.T) {
	// No root key anywhere. dataDir is set but empty.
	configDir := t.TempDir()
	dataDir := t.TempDir()

	svc := NewBarrierService(configDir, slog.Default())
	svc.SetDataDir(dataDir)

	info := svc.GetSealInfo()
	require.NotNil(t, info)
	assert.False(t, info.Initialized,
		"should not be initialized when no root key exists in either path")
	assert.False(t, info.Sealed)
	assert.Empty(t, info.Strategy)

	// DataDir should default to the primary (dataDir) path.
	assert.Equal(t, dataDir, info.DataDir,
		"DataDir should default to primary path when not initialized")
}

// ---------------------------------------------------------------------------
// Unseal
// ---------------------------------------------------------------------------

func TestBarrierService_Unseal_TransparentInitWhenNoRootKey(t *testing.T) {
	// No root key at storageDir(). With the new behavior, Unseal
	// transparently calls Initialize to create the barrier.
	configDir := t.TempDir()
	dataDir := t.TempDir()

	svc := NewBarrierService(configDir, slog.Default())
	svc.SetDataDir(dataDir)

	err := svc.Unseal("no-root-key-pw", "passphrase")
	require.NoError(t, err, "unseal should transparently initialize when no root key exists")
	assert.True(t, svc.IsUnsealed(), "barrier should be unsealed after transparent init")
}

// ---------------------------------------------------------------------------
// ChangePassword
// ---------------------------------------------------------------------------

func TestBarrierService_ChangePassword_Success(t *testing.T) {
	svc := newTestBarrierService(t)
	require.NoError(t, svc.Initialize("oldpass", "passphrase"))
	require.NoError(t, svc.ChangePassword("oldpass", "newpass"))
}

func TestBarrierService_Unseal_EmptyPassword_RejectedNotWrongPassword(t *testing.T) {
	// Documents the empty-password semantics across the CredentialsFor
	// migration (go-qrdb #41): an empty password against a real, passphrase-
	// sealed barrier must still fail to unseal — it must never be silently
	// treated as "no credentials requested" and succeed, and it must never
	// unseal the barrier. go-quicraft's SoftwareStrategy already rejected a
	// zero-length secret before this migration (len(creds.Secret) == 0) and
	// continues to reject the zero Credentials value the same way, so this
	// pins the observable behavior rather than the underlying sentinel.
	svc := newTestBarrierService(t)
	require.NoError(t, svc.Initialize("realpassword", "passphrase"))
	require.NoError(t, svc.Seal())

	svc2 := NewBarrierService(svc.configDir, slog.Default())
	err := svc2.Unseal("", "passphrase")
	require.Error(t, err, "empty password must not unseal a passphrase-protected barrier")
	assert.False(t, svc2.IsUnsealed())
}

func TestBarrierService_ChangePassword_NotInitialized(t *testing.T) {
	svc := newTestBarrierService(t)
	err := svc.ChangePassword("oldpass", "newpass")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBarrierNotInitialized)
}

func TestBarrierService_ChangePassword_RoundTrip(t *testing.T) {
	svc := newTestBarrierService(t)
	require.NoError(t, svc.Initialize("oldpass", "passphrase"))
	require.NoError(t, svc.ChangePassword("oldpass", "newpass"))
	require.NoError(t, svc.Seal())

	// Must unseal from scratch - new BarrierService uses same configDir
	svc2 := NewBarrierService(svc.configDir, slog.Default())
	err := svc2.Unseal("newpass", "passphrase")
	require.NoError(t, err)
	assert.True(t, svc2.IsUnsealed())
}

func TestBarrierService_ChangePassword_HardwareStrategyEmptyPasswords(t *testing.T) {
	// A hardware strategy takes no passphrase: both passwords are empty, so
	// CredentialsFor yields the zero Credentials with a nil Secret. The
	// deferred destroys must skip a nil Secret rather than panic.
	svc := NewBarrierService(t.TempDir(), slog.Default())
	svc.SetTPMSealerFunc(func() xkms.Sealer {
		return &mockSealer{canSeal: true}
	})
	require.NoError(t, svc.Initialize("", string(xkms.StrategyTPM2)))
	// go-qrdb v0.58.2 rejects the rekey itself ("passphrase must not be
	// empty"); this pins only that the error path returns without a panic.
	require.NotPanics(t, func() {
		_ = svc.ChangePassword("", "")
	})
}
