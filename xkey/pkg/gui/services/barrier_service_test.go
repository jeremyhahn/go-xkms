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

	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestBarrierService creates a BarrierService backed by a temporary directory.
func newTestBarrierService(t *testing.T) *BarrierService {
	t.Helper()
	return NewBarrierService(t.TempDir(), slog.Default())
}

// mockSealer is a minimal types.Sealer that always reports CanSeal as true.
// It stores the data in the SealedData ciphertext field so Unseal can return it.
type mockSealer struct {
	canSeal bool
}

func (m *mockSealer) Seal(_ context.Context, data []byte, _ *types.SealOptions) (*types.SealedData, error) {
	return &types.SealedData{
		Backend:    types.BackendTypeTPM2,
		Ciphertext: data,
		TPMPublic:  []byte("pub"),
		TPMPrivate: []byte("priv"),
	}, nil
}

func (m *mockSealer) Unseal(_ context.Context, sealed *types.SealedData, _ *types.UnsealOptions) ([]byte, error) {
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
	assert.Equal(t, string(seal.StrategySoftware), strategies[0].ID)
	assert.True(t, strategies[0].Available, "software strategy must always be available")
	assert.False(t, strategies[0].HardwareBacked, "software strategy must not be hardware-backed")
	assert.NotEmpty(t, strategies[0].Label)
}

func TestBarrierService_ProbeStrategies_WithTPM(t *testing.T) {
	svc := newTestBarrierService(t)
	svc.SetTPMSealerFunc(func() types.Sealer {
		return &mockSealer{canSeal: true}
	})

	strategies := svc.ProbeStrategies()

	require.Len(t, strategies, 2, "with TPM sealer, both software and TPM2 expected")

	// First entry is software.
	assert.Equal(t, string(seal.StrategySoftware), strategies[0].ID)
	assert.True(t, strategies[0].Available)
	assert.False(t, strategies[0].HardwareBacked)

	// Second entry is TPM2.
	assert.Equal(t, string(seal.StrategyTPM2), strategies[1].ID)
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
	assert.Equal(t, string(seal.StrategySoftware), best.ID,
		"without TPM, best strategy should be software")
	assert.False(t, best.HardwareBacked)
}

func TestBarrierService_BestStrategy_TPMCanSealFalse_FallsToSoftware(t *testing.T) {
	svc := newTestBarrierService(t)
	// Sealer exists but CanSeal returns false (e.g., SRK not provisioned).
	svc.SetTPMSealerFunc(func() types.Sealer {
		return &mockSealer{canSeal: false}
	})

	best, err := svc.BestStrategy()
	require.NoError(t, err)
	require.NotNil(t, best)

	// TPM2 should NOT be selected when CanSeal is false.
	assert.Equal(t, string(seal.StrategySoftware), best.ID,
		"TPM with CanSeal=false should fall back to software")
	assert.False(t, best.HardwareBacked)
}

func TestBarrierService_ProbeStrategies_TPMCanSealFalse(t *testing.T) {
	svc := newTestBarrierService(t)
	svc.SetTPMSealerFunc(func() types.Sealer {
		return &mockSealer{canSeal: false}
	})

	strategies := svc.ProbeStrategies()
	require.Len(t, strategies, 2)

	// TPM2 should be listed but marked as unavailable.
	assert.Equal(t, string(seal.StrategyTPM2), strategies[1].ID)
	assert.False(t, strategies[1].Available,
		"TPM with CanSeal=false should be marked unavailable")
}

func TestBarrierService_BestStrategy_PrefersTPM(t *testing.T) {
	svc := newTestBarrierService(t)
	svc.SetTPMSealerFunc(func() types.Sealer {
		return &mockSealer{canSeal: true}
	})

	best, err := svc.BestStrategy()
	require.NoError(t, err)
	require.NotNil(t, best)

	// DefaultPreferenceOrder lists TPM2 before software.
	assert.Equal(t, string(seal.StrategyTPM2), best.ID,
		"with TPM sealer, best strategy should be TPM2")
	assert.True(t, best.HardwareBacked)
}

// ---------------------------------------------------------------------------
// Initialize
// ---------------------------------------------------------------------------

func TestBarrierService_Initialize_SoftwareStrategy(t *testing.T) {
	svc := newTestBarrierService(t)

	err := svc.Initialize("test-password-123", "software")
	require.NoError(t, err)
	assert.True(t, svc.IsUnsealed(), "barrier should be unsealed after initialization")
}

func TestBarrierService_Initialize_NoPassword_Error(t *testing.T) {
	svc := newTestBarrierService(t)

	err := svc.Initialize("", "software")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBarrierPasswordRequired,
		"software strategy requires a password")
}

func TestBarrierService_Initialize_AlreadyInit_Error(t *testing.T) {
	svc := newTestBarrierService(t)

	err := svc.Initialize("first-password", "software")
	require.NoError(t, err)

	err = svc.Initialize("second-password", "software")
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
	err := svc.Initialize(password, "software")
	require.NoError(t, err)
	assert.True(t, svc.IsUnsealed())

	// Seal.
	err = svc.Seal()
	require.NoError(t, err)
	assert.False(t, svc.IsUnsealed(), "barrier should be sealed after Seal()")

	// Unseal with same password.
	err = svc.Unseal(password, "software")
	require.NoError(t, err)
	assert.True(t, svc.IsUnsealed(), "barrier should be unsealed after Unseal()")
}

func TestBarrierService_Unseal_TransparentInit(t *testing.T) {
	svc := newTestBarrierService(t)

	// With the new behavior, Unseal on an uninitialized barrier
	// transparently calls Initialize, creating the barrier on the fly.
	err := svc.Unseal("some-password", "software")
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
	err := svc.Initialize("status-test-pw", "software")
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

	err := svc.Initialize("backend-test-pw", "software")
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
	assert.NotEmpty(t, info.RootKeyPath, "root key path should always be populated")
}

func TestBarrierService_GetSealInfo_AfterInitialize(t *testing.T) {
	svc := newTestBarrierService(t)

	err := svc.Initialize("seal-info-password", "software")
	require.NoError(t, err)

	info := svc.GetSealInfo()
	require.NotNil(t, info)
	assert.True(t, info.Initialized, "barrier should be initialized after Initialize()")
	assert.False(t, info.Sealed, "barrier should be unsealed after Initialize()")
	assert.Equal(t, string(seal.StrategySoftware), info.Strategy)
	assert.NotEmpty(t, info.StrategyLabel)
	assert.False(t, info.HardwareBacked, "software strategy should not be hardware-backed")
	assert.Contains(t, info.RootKeyPath, "barrier/root_key")
}

func TestBarrierService_GetSealInfo_AfterSeal(t *testing.T) {
	svc := newTestBarrierService(t)

	err := svc.Initialize("seal-info-sealed-pw", "software")
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

	err := svc.Initialize("label-test-pw", "software")
	require.NoError(t, err)

	info := svc.GetSealInfo()
	require.NotNil(t, info)
	assert.Equal(t, "Software (AES-256-GCM)", info.StrategyLabel,
		"software strategy should have the expected human-readable label")
}

func TestBarrierService_GetSealInfo_FallbackStrategy_WhenBarrierNil(t *testing.T) {
	// Initialize a barrier, then create a fresh service pointing at the same
	// directory to simulate an app restart where the barrier object is nil
	// but the root key exists on disk.
	tmpDir := t.TempDir()
	svc1 := NewBarrierService(tmpDir, slog.Default())
	err := svc1.Initialize("fallback-test-pw", "software")
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
// checkInitialized (dual-path probing)
// ---------------------------------------------------------------------------

func TestBarrierService_CheckInitialized_PrimaryPath(t *testing.T) {
	// Initialize in the primary storageDir (dataDir), then verify
	// checkInitialized returns the primary path.
	configDir := t.TempDir()
	dataDir := t.TempDir()

	svc := NewBarrierService(configDir, slog.Default())
	svc.SetDataDir(dataDir)

	// Initialize writes the root key to dataDir (primary).
	err := svc.Initialize("primary-path-pw", "software")
	require.NoError(t, err)

	// Create a fresh service with the same config to probe.
	probe := NewBarrierService(configDir, slog.Default())
	probe.SetDataDir(dataDir)

	found := probe.checkInitialized()
	assert.Equal(t, dataDir, found,
		"checkInitialized should return dataDir when root key is in primary path")
	assert.True(t, probe.IsInitialized())
}

func TestBarrierService_CheckInitialized_PrimaryPath_NoDataDir(t *testing.T) {
	// When dataDir is not set, primary == fallback (configDir/barrier/).
	// Initialize without dataDir and verify it is found.
	configDir := t.TempDir()

	svc := NewBarrierService(configDir, slog.Default())
	err := svc.Initialize("no-datadir-pw", "software")
	require.NoError(t, err)

	probe := NewBarrierService(configDir, slog.Default())

	found := probe.checkInitialized()
	expected := filepath.Join(configDir, barrierSubdir)
	assert.Equal(t, expected, found,
		"checkInitialized should return configDir/barrier/ when dataDir is empty")
	assert.True(t, probe.IsInitialized())
}

func TestBarrierService_CheckInitialized_FallbackPath(t *testing.T) {
	// Initialize via configDir/barrier/ (no dataDir), then create a new
	// service with dataDir set to a directory WITHOUT a root key.
	// checkInitialized must find the root key in the fallback path.
	configDir := t.TempDir()
	dataDir := t.TempDir()

	// Initialize without dataDir -- root key goes to configDir/barrier/.
	svc := NewBarrierService(configDir, slog.Default())
	err := svc.Initialize("fallback-path-pw", "software")
	require.NoError(t, err)

	// Create a new service with dataDir set (primary path is now dataDir,
	// which has no root key). The fallback configDir/barrier/ should be found.
	probe := NewBarrierService(configDir, slog.Default())
	probe.SetDataDir(dataDir)

	found := probe.checkInitialized()
	expected := filepath.Join(configDir, barrierSubdir)
	assert.Equal(t, expected, found,
		"checkInitialized should fall back to configDir/barrier/ when primary has no root key")
	assert.True(t, probe.IsInitialized())
}

func TestBarrierService_CheckInitialized_NeitherPath(t *testing.T) {
	// No root key in either primary or fallback path.
	configDir := t.TempDir()
	dataDir := t.TempDir()

	svc := NewBarrierService(configDir, slog.Default())
	svc.SetDataDir(dataDir)

	found := svc.checkInitialized()
	assert.Empty(t, found,
		"checkInitialized should return empty when no root key exists anywhere")
	assert.False(t, svc.IsInitialized())
}

func TestBarrierService_CheckInitialized_NeitherPath_NoDataDir(t *testing.T) {
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
	err := svc.Initialize("probe-key-pw", "software")
	require.NoError(t, err)

	// Probe the configDir/barrier/ path.
	probe := NewBarrierService(configDir, slog.Default())
	found := probe.probeRootKey(filepath.Join(configDir, barrierSubdir))
	assert.True(t, found, "probeRootKey should return true when root key exists")
}

// ---------------------------------------------------------------------------
// GetSealInfo with fallback path (dual-path probing)
// ---------------------------------------------------------------------------

func TestBarrierService_GetSealInfo_InitializedViaFallback(t *testing.T) {
	// Initialize via the fallback configDir/barrier/ path (no dataDir).
	// Then create a new service with dataDir set to a different directory.
	// GetSealInfo must report Initialized=true via the fallback probe.
	configDir := t.TempDir()
	dataDir := t.TempDir()

	// Initialize without dataDir.
	svc := NewBarrierService(configDir, slog.Default())
	err := svc.Initialize("seal-info-fallback-pw", "software")
	require.NoError(t, err)

	// Create a new service with dataDir set (primary has no root key).
	probe := NewBarrierService(configDir, slog.Default())
	probe.SetDataDir(dataDir)

	info := probe.GetSealInfo()
	require.NotNil(t, info)
	assert.True(t, info.Initialized,
		"GetSealInfo should report initialized via fallback path")
	assert.True(t, info.Sealed,
		"barrier object is nil, should report sealed")
	assert.NotEmpty(t, info.Strategy,
		"should fall back to best available strategy")
	assert.NotEmpty(t, info.StrategyLabel,
		"should have a strategy label")

	// Verify the RootKeyPath points to the actual fallback location.
	expectedPath := filepath.Join(configDir, barrierSubdir, barrierRootKeyPath)
	assert.Equal(t, expectedPath, info.RootKeyPath,
		"RootKeyPath should point to the fallback location where root key was found")
}

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

	// RootKeyPath should default to the primary (dataDir) path.
	expectedPath := filepath.Join(dataDir, barrierRootKeyPath)
	assert.Equal(t, expectedPath, info.RootKeyPath,
		"RootKeyPath should default to primary path when not initialized")
}

// ---------------------------------------------------------------------------
// Unseal with fallback path (dual-path probing)
// ---------------------------------------------------------------------------

func TestBarrierService_Unseal_ViaFallbackPath(t *testing.T) {
	// Initialize via the fallback path (no dataDir). Then create a new
	// service with dataDir set, and verify Unseal succeeds by finding
	// the root key in the fallback path.
	configDir := t.TempDir()
	dataDir := t.TempDir()
	password := "unseal-fallback-pw"

	// Initialize without dataDir.
	svc := NewBarrierService(configDir, slog.Default())
	err := svc.Initialize(password, "software")
	require.NoError(t, err)

	// Create a new service with dataDir pointing somewhere else.
	svc2 := NewBarrierService(configDir, slog.Default())
	svc2.SetDataDir(dataDir)

	// Unseal should find the root key in configDir/barrier/ fallback.
	err = svc2.Unseal(password, "software")
	require.NoError(t, err)
	assert.True(t, svc2.IsUnsealed(),
		"barrier should be unsealed after finding root key in fallback path")
}

func TestBarrierService_Unseal_ViaFallbackPath_TransparentInit(t *testing.T) {
	// Neither primary nor fallback has a root key. With the new behavior,
	// Unseal transparently calls Initialize to create the barrier.
	configDir := t.TempDir()
	dataDir := t.TempDir()

	svc := NewBarrierService(configDir, slog.Default())
	svc.SetDataDir(dataDir)

	err := svc.Unseal("no-root-key-pw", "software")
	require.NoError(t, err, "unseal should transparently initialize when no root key exists")
	assert.True(t, svc.IsUnsealed(), "barrier should be unsealed after transparent init")
}

// ---------------------------------------------------------------------------
// ChangePassword
// ---------------------------------------------------------------------------

func TestBarrierService_ChangePassword_Success(t *testing.T) {
	svc := newTestBarrierService(t)
	require.NoError(t, svc.Initialize("oldpass", "software"))
	require.NoError(t, svc.ChangePassword("newpass"))
}

func TestBarrierService_ChangePassword_NotInitialized(t *testing.T) {
	svc := newTestBarrierService(t)
	err := svc.ChangePassword("newpass")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBarrierNotInitialized)
}

func TestBarrierService_ChangePassword_RoundTrip(t *testing.T) {
	svc := newTestBarrierService(t)
	require.NoError(t, svc.Initialize("oldpass", "software"))
	require.NoError(t, svc.ChangePassword("newpass"))
	require.NoError(t, svc.Seal())

	// Must unseal from scratch - new BarrierService uses same configDir
	svc2 := NewBarrierService(svc.configDir, slog.Default())
	err := svc2.Unseal("newpass", "software")
	require.NoError(t, err)
	assert.True(t, svc2.IsUnsealed())
}
