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
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test 1: Initialize then GetSealInfo shows Initialized=true
// ---------------------------------------------------------------------------

func TestBarrierService_Initialize_GetSealInfo_ShowsInitialized(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())

	err := svc.Initialize("test-password", "software")
	require.NoError(t, err)

	info := svc.GetSealInfo()
	require.NotNil(t, info)
	assert.True(t, info.Initialized,
		"GetSealInfo must report Initialized=true after successful Initialize()")
	assert.False(t, info.Sealed,
		"barrier should be unsealed immediately after Initialize()")
	assert.Equal(t, string(seal.StrategySoftware), info.Strategy,
		"strategy must match what was passed to Initialize()")
}

// TestBarrierService_Initialize_GetSealInfo_WithDataDir reproduces the
// reported bug: when SetDataDir is called before Initialize, GetSealInfo
// should still report Initialized=true after a successful Initialize().
// This simulates the real app startup flow where SetDataDir is called
// in startup() before the wizard calls Initialize().
func TestBarrierService_Initialize_GetSealInfo_WithDataDir(t *testing.T) {
	configDir := t.TempDir()
	dataDir := t.TempDir()

	svc := NewBarrierService(configDir, slog.Default())
	svc.SetDataDir(dataDir)

	err := svc.Initialize("test-password", "software")
	require.NoError(t, err)

	info := svc.GetSealInfo()
	require.NotNil(t, info)
	assert.True(t, info.Initialized,
		"GetSealInfo must report Initialized=true after Initialize() with dataDir set")
	assert.False(t, info.Sealed,
		"barrier should be unsealed immediately after Initialize()")
	assert.Equal(t, string(seal.StrategySoftware), info.Strategy)
}

// TestBarrierService_Initialize_GetSealInfo_DataDirSetAfterInit reproduces a
// scenario where SetDataDir is called AFTER Initialize(). The root key was
// written to configDir/barrier/ but GetSealInfo now probes dataDir first.
// It must still find the root key via the fallback configDir/barrier/ path.
func TestBarrierService_Initialize_GetSealInfo_DataDirSetAfterInit(t *testing.T) {
	configDir := t.TempDir()
	dataDir := t.TempDir()

	svc := NewBarrierService(configDir, slog.Default())

	// Initialize WITHOUT dataDir (root key goes to configDir/barrier/).
	err := svc.Initialize("test-password", "software")
	require.NoError(t, err)

	// Now set dataDir (simulates app restart with new config).
	svc.SetDataDir(dataDir)

	info := svc.GetSealInfo()
	require.NotNil(t, info)
	assert.True(t, info.Initialized,
		"GetSealInfo must find root key via fallback path after dataDir change")
	assert.False(t, info.Sealed,
		"barrier object is still live, should report unsealed")
}

// ---------------------------------------------------------------------------
// Test 2: Initialize then Seal then GetSealInfo shows Sealed=true
// ---------------------------------------------------------------------------

func TestBarrierService_Initialize_Seal_GetSealInfo_ShowsSealed(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())

	err := svc.Initialize("test-password", "software")
	require.NoError(t, err)

	err = svc.Seal()
	require.NoError(t, err)

	info := svc.GetSealInfo()
	require.NotNil(t, info)
	assert.True(t, info.Initialized,
		"GetSealInfo must report Initialized=true after Initialize()+Seal()")
	assert.True(t, info.Sealed,
		"GetSealInfo must report Sealed=true after Seal()")
}

// TestBarrierService_Initialize_Seal_GetSealInfo_WithDataDir tests the
// same flow but with dataDir set, to ensure the seal info still reflects
// the correct state.
func TestBarrierService_Initialize_Seal_GetSealInfo_WithDataDir(t *testing.T) {
	configDir := t.TempDir()
	dataDir := t.TempDir()

	svc := NewBarrierService(configDir, slog.Default())
	svc.SetDataDir(dataDir)

	err := svc.Initialize("test-password", "software")
	require.NoError(t, err)

	err = svc.Seal()
	require.NoError(t, err)

	info := svc.GetSealInfo()
	require.NotNil(t, info)
	assert.True(t, info.Initialized,
		"GetSealInfo must report Initialized=true with dataDir after Seal()")
	assert.True(t, info.Sealed,
		"GetSealInfo must report Sealed=true with dataDir after Seal()")
}

// ---------------------------------------------------------------------------
// Test 3: AppLockService Unlock falls back to PIN when barrier not initialized
// ---------------------------------------------------------------------------

func TestAppLockService_Unlock_InitializesBarrier_WhenNotInitialized(t *testing.T) {
	// When barrier is configured but NOT initialized, Unlock must NOT
	// auto-initialize (which would lose old encrypted data). Instead it
	// falls back to PIN verification.
	barrierSvc := NewBarrierService(t.TempDir(), slog.Default())

	pinSvc := NewPINService()
	pinSvc.SetContext(context.Background())

	backend := &mockPINBackend{
		strategy:      pin.StrategySoftware,
		soPINSet:      true,
		userPINSet:    true,
		initialized:   true,
		verifyUserErr: nil,
		lockoutStatus: &pin.LockoutStatus{MaxAttempts: 5},
	}
	pSvc := pin.NewService(backend, slog.Default())
	pinSvc.SetPINService(pSvc)

	svc := NewAppLockService(pinSvc, barrierSvc)
	svc.SetContext(context.Background())
	svc.SetBarrierStrategy("software")
	svc.LockForStartup()

	assert.True(t, svc.IsLocked(), "app should be locked after LockForStartup")

	// Verify barrier is NOT initialized before unlock.
	assert.False(t, barrierSvc.IsInitialized(),
		"barrier should not be initialized before Unlock")

	// Unlock with a PIN. Since barrier is not initialized, this falls
	// back to PIN verification instead of calling Initialize.
	err := svc.Unlock("test-pin")
	require.NoError(t, err)

	assert.False(t, svc.IsLocked(), "app should be unlocked after Unlock")
	assert.False(t, barrierSvc.IsInitialized(),
		"barrier must NOT be auto-initialized by Unlock")
}

// ---------------------------------------------------------------------------
// Test 4: PostBarrierUnseal hook fires after Initialize
// ---------------------------------------------------------------------------

func TestBarrierService_Initialize_FiresPostUnsealHook(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())

	hookCalled := false
	svc.SetPostUnsealHook(func() error {
		hookCalled = true
		return nil
	})

	err := svc.Initialize("password", "software")
	require.NoError(t, err)

	assert.True(t, hookCalled,
		"post-unseal hook must be called after Initialize() since barrier is unsealed")
}

// TestBarrierService_Initialize_FiresPostUnsealHook_ErrorLogged verifies
// that an error from the post-unseal hook does not cause Initialize to fail.
func TestBarrierService_Initialize_FiresPostUnsealHook_ErrorLogged(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())

	hookCalled := false
	svc.SetPostUnsealHook(func() error {
		hookCalled = true
		return ErrBarrierNotInitialized // arbitrary error
	})

	err := svc.Initialize("password", "software")
	require.NoError(t, err, "Initialize must succeed even if post-unseal hook returns error")
	assert.True(t, hookCalled)
}

// ---------------------------------------------------------------------------
// Test 5: GetSealInfo before Initialize shows not initialized
// ---------------------------------------------------------------------------

func TestBarrierService_GetSealInfo_BeforeInitialize_NotInitialized(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())

	info := svc.GetSealInfo()
	require.NotNil(t, info)
	assert.False(t, info.Initialized,
		"GetSealInfo must report Initialized=false before Initialize() is called")
}

// TestBarrierService_GetSealInfo_BeforeInitialize_WithDataDir tests the
// same thing but with dataDir configured.
func TestBarrierService_GetSealInfo_BeforeInitialize_WithDataDir(t *testing.T) {
	configDir := t.TempDir()
	dataDir := t.TempDir()

	svc := NewBarrierService(configDir, slog.Default())
	svc.SetDataDir(dataDir)

	info := svc.GetSealInfo()
	require.NotNil(t, info)
	assert.False(t, info.Initialized,
		"GetSealInfo must report Initialized=false before Initialize() when dataDir is set")
}

// ---------------------------------------------------------------------------
// Restart simulation: fresh service pointing at same storage
// ---------------------------------------------------------------------------

// TestBarrierService_GetSealInfo_FreshServiceAfterInit simulates an app
// restart where a new BarrierService is created pointing at the same
// configDir. The barrier object is nil but the root key exists on disk.
// GetSealInfo must still report Initialized=true.
func TestBarrierService_GetSealInfo_FreshServiceAfterInit(t *testing.T) {
	configDir := t.TempDir()

	// First session: initialize the barrier.
	svc1 := NewBarrierService(configDir, slog.Default())
	err := svc1.Initialize("password", "software")
	require.NoError(t, err)

	// Second session: fresh service, barrier==nil.
	svc2 := NewBarrierService(configDir, slog.Default())

	info := svc2.GetSealInfo()
	require.NotNil(t, info)
	assert.True(t, info.Initialized,
		"fresh service must detect root key on disk and report Initialized=true")
	assert.True(t, info.Sealed,
		"fresh service has no live barrier, must report Sealed=true")
}

// TestBarrierService_GetSealInfo_FreshServiceAfterInit_WithDataDir tests
// the restart scenario when dataDir was used for storage.
func TestBarrierService_GetSealInfo_FreshServiceAfterInit_WithDataDir(t *testing.T) {
	configDir := t.TempDir()
	dataDir := t.TempDir()

	// First session: set dataDir and initialize.
	svc1 := NewBarrierService(configDir, slog.Default())
	svc1.SetDataDir(dataDir)
	err := svc1.Initialize("password", "software")
	require.NoError(t, err)

	// Second session: fresh service with same dataDir.
	svc2 := NewBarrierService(configDir, slog.Default())
	svc2.SetDataDir(dataDir)

	info := svc2.GetSealInfo()
	require.NotNil(t, info)
	assert.True(t, info.Initialized,
		"fresh service with dataDir must detect root key and report Initialized=true")
	assert.True(t, info.Sealed,
		"fresh service has no live barrier, must report Sealed=true")
}

// TestBarrierService_GetSealInfo_FreshServiceAfterInit_DataDirMismatch
// simulates the case where the first session used configDir/barrier/ but
// the second session has dataDir set to a different location. The root
// key must be found via the fallback path.
func TestBarrierService_GetSealInfo_FreshServiceAfterInit_DataDirMismatch(t *testing.T) {
	configDir := t.TempDir()
	dataDir := t.TempDir() // different from where root key is

	// First session: initialize WITHOUT dataDir.
	svc1 := NewBarrierService(configDir, slog.Default())
	err := svc1.Initialize("password", "software")
	require.NoError(t, err)

	// Second session: fresh service with dataDir set to a DIFFERENT dir.
	svc2 := NewBarrierService(configDir, slog.Default())
	svc2.SetDataDir(dataDir)

	info := svc2.GetSealInfo()
	require.NotNil(t, info)
	assert.True(t, info.Initialized,
		"root key in configDir/barrier/ must be found via fallback path")
	assert.True(t, info.Sealed,
		"fresh service has no live barrier, must report Sealed=true")
}

// ---------------------------------------------------------------------------
// SetLastStrategy affects GetSealInfo
// ---------------------------------------------------------------------------

func TestBarrierService_SetLastStrategy_ReflectedInGetSealInfo(t *testing.T) {
	configDir := t.TempDir()

	// Initialize to create root key.
	svc1 := NewBarrierService(configDir, slog.Default())
	err := svc1.Initialize("password", "software")
	require.NoError(t, err)

	// Fresh service with lastStrategy set (simulates config-loaded strategy).
	svc2 := NewBarrierService(configDir, slog.Default())
	svc2.SetLastStrategy("software")

	info := svc2.GetSealInfo()
	require.NotNil(t, info)
	assert.True(t, info.Initialized)
	assert.True(t, info.Sealed)
	assert.Equal(t, "software", info.Strategy,
		"GetSealInfo should use lastStrategy when barrier object is nil")
	assert.Equal(t, "Software (AES-256-GCM)", info.StrategyLabel)
}

// ---------------------------------------------------------------------------
// Barrier not initialized: Unlock falls back to PIN, does NOT initialize
// ---------------------------------------------------------------------------

// TestAppLockService_Unlock_UninitializedBarrier_InitializesAndFiresHook
// verifies that when the barrier is not initialized, Unlock falls back to
// PIN verification. The barrier must NOT be auto-initialized (which would
// create a new empty barrier and lose previously encrypted data).
func TestAppLockService_Unlock_UninitializedBarrier_InitializesAndFiresHook(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())
	svc.SetContext(context.Background())

	// Track hook invocation - should NOT be called since we don't initialize.
	hookCalled := false
	svc.SetPostUnsealHook(func() error {
		hookCalled = true
		return nil
	})

	// Verify barrier is NOT initialized.
	info := svc.GetSealInfo()
	require.False(t, info.Initialized)

	// Create PINService with a configured PIN backend so PIN verification
	// succeeds as a fallback.
	pinSvc := NewPINService()
	pinSvc.SetContext(context.Background())
	backend := &mockPINBackend{
		strategy:      pin.StrategySoftware,
		soPINSet:      true,
		userPINSet:    true,
		initialized:   true,
		verifyUserErr: nil,
		lockoutStatus: &pin.LockoutStatus{MaxAttempts: 5},
	}
	pSvc := pin.NewService(backend, slog.Default())
	pinSvc.SetPINService(pSvc)

	appLock := NewAppLockService(pinSvc, svc)
	appLock.SetBarrierStrategy("software")
	appLock.SetContext(context.Background())
	appLock.LockForStartup()

	// Unlock should fall back to PIN verification (not initialize barrier).
	err := appLock.Unlock("my-secret-pin")
	require.NoError(t, err)

	// Barrier must NOT have been initialized.
	info = svc.GetSealInfo()
	assert.False(t, info.Initialized, "barrier must NOT be auto-initialized by Unlock")

	// Post-unseal hook must NOT have been called.
	assert.False(t, hookCalled, "post-unseal hook must not fire when barrier is not initialized")

	// Verify app is unlocked.
	status := appLock.GetStatus()
	assert.False(t, status.IsLocked)
}

// ---------------------------------------------------------------------------
// Bug regression: After Initialize + Seal + restart, GetSealInfo still
// reports initialized=true
// ---------------------------------------------------------------------------

// TestBarrierService_GetSealInfo_AfterInitAndSeal_StillInitialized simulates
// an app restart after the barrier was initialized and then sealed. A fresh
// BarrierService pointing at the same directory must detect the root key on
// disk and report Initialized=true even though the barrier object is nil.
func TestBarrierService_GetSealInfo_AfterInitAndSeal_StillInitialized(t *testing.T) {
	dir := t.TempDir()

	// First session: initialize and seal.
	svc1 := NewBarrierService(dir, slog.Default())
	svc1.SetContext(context.Background())
	require.NoError(t, svc1.Initialize("password", "software"))
	require.NoError(t, svc1.Seal())

	// Simulate restart: new BarrierService, same dir.
	svc2 := NewBarrierService(dir, slog.Default())
	svc2.SetContext(context.Background())

	info := svc2.GetSealInfo()
	assert.True(t, info.Initialized, "barrier should still be initialized after restart")
	assert.True(t, info.Sealed, "barrier should be sealed after restart")
}

// ---------------------------------------------------------------------------
// Bug regression: AppLockService Unlock with already-initialized sealed
// barrier unseals it via the Unseal path
// ---------------------------------------------------------------------------

// TestAppLockService_Unlock_SealedBarrier_Unseals verifies the returning-user
// flow where the barrier was initialized in a previous session, sealed, and
// now the user provides their PIN to unseal. The Unlock call must delegate to
// BarrierService.Unseal (not Initialize) and leave the barrier unsealed.
func TestAppLockService_Unlock_SealedBarrier_Unseals(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())
	svc.SetContext(context.Background())

	// Initialize barrier first.
	require.NoError(t, svc.Initialize("my-password", "software"))
	require.NoError(t, svc.Seal())

	// Simulate fresh service (restart).
	svc2 := NewBarrierService(dir, slog.Default())
	svc2.SetContext(context.Background())

	pinSvc := NewPINService()
	appLock := NewAppLockService(pinSvc, svc2)
	appLock.SetBarrierStrategy("software")
	appLock.SetContext(context.Background())
	appLock.LockForStartup()

	// Unlock should unseal the barrier.
	err := appLock.Unlock("my-password")
	require.NoError(t, err)

	info := svc2.GetSealInfo()
	assert.True(t, info.Initialized)
	assert.False(t, info.Sealed)
}

// ---------------------------------------------------------------------------
// Seal/unseal cycle: barrier initialized explicitly, then locked/unlocked
// ---------------------------------------------------------------------------

// TestAppLockService_Unlock_UninitializedBarrier_UsesProvidedPIN verifies
// the seal/unseal cycle when the barrier is initialized explicitly (not via
// Unlock auto-init). After sealing and re-locking, only the original
// password can unseal the barrier.
func TestAppLockService_Unlock_UninitializedBarrier_UsesProvidedPIN(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())
	svc.SetContext(context.Background())

	// Initialize the barrier explicitly with a known password.
	require.NoError(t, svc.Initialize("first-pin", "software"))

	pinSvc := NewPINService()
	appLock := NewAppLockService(pinSvc, svc)
	appLock.SetBarrierStrategy("software")
	appLock.SetContext(context.Background())

	// Seal the barrier and lock the app.
	require.NoError(t, svc.Seal())
	appLock.LockForStartup()

	// Unlock with wrong pin should fail.
	err := appLock.Unlock("wrong-pin")
	assert.Error(t, err)

	// Unlock with correct pin should succeed.
	err = appLock.Unlock("first-pin")
	assert.NoError(t, err)
}
