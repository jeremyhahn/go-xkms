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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestAppLockService creates an AppLockService with a PINService backed
// by a mockPINBackend. When verifyErr is nil, VerifyUserPIN succeeds for
// any PIN; otherwise it returns verifyErr. The barrierSvc is nil (no barrier).
func newTestAppLockService(t *testing.T, verifyErr error) *AppLockService {
	t.Helper()

	pinSvc := NewPINService()
	pinSvc.SetContext(context.Background())

	backend := &mockPINBackend{
		strategy:      qrdbsdk.PINStrategySoftware,
		soPINSet:      true,
		userPINSet:    true,
		initialized:   true,
		verifyUserErr: verifyErr,
		lockoutStatus: &qrdbsdk.PINLockoutStatus{MaxAttempts: 5},
	}
	pSvc := qrdbsdk.NewPINService(backend, slog.Default())
	pinSvc.SetPINService(pSvc)

	svc := NewAppLockService(pinSvc, nil)
	svc.SetContext(context.Background())

	return svc
}

// newLockedTestAppLockService creates a test service and sets it to the
// locked state via LockForStartup. This simulates the returning-user path
// where startupReturningUser() locks the app before the frontend loads.
func newLockedTestAppLockService(t *testing.T, verifyErr error) *AppLockService {
	t.Helper()
	svc := newTestAppLockService(t, verifyErr)
	svc.LockForStartup()
	return svc
}

// ---------------------------------------------------------------------------
// NewAppLockService defaults
// ---------------------------------------------------------------------------

func TestAppLockService_New_StartsUnlocked(t *testing.T) {
	svc := newTestAppLockService(t, nil)
	assert.False(t, svc.IsLocked())
}

func TestAppLockService_LockForStartup(t *testing.T) {
	svc := newTestAppLockService(t, nil)
	assert.False(t, svc.IsLocked())

	svc.LockForStartup()
	assert.True(t, svc.IsLocked())

	// Timer should be nil after LockForStartup.
	svc.autoLockMu.Lock()
	timer := svc.autoLockTimer
	svc.autoLockMu.Unlock()
	assert.Nil(t, timer)
}

func TestAppLockService_LockForStartup_NoEvent(t *testing.T) {
	svc := newTestAppLockService(t, nil)

	var emitted bool
	svc.SetEmitFunc(func(event string, data any) {
		emitted = true
	})

	svc.LockForStartup()
	assert.True(t, svc.IsLocked())
	assert.False(t, emitted, "LockForStartup should not emit events")
}

func TestAppLockService_New_DefaultAutoLockMinutes(t *testing.T) {
	svc := newTestAppLockService(t, nil)
	assert.Equal(t, int32(15), svc.autoLockMinutes.Load())
}

func TestAppLockService_New_DefaultLockOnScreenLock(t *testing.T) {
	svc := newTestAppLockService(t, nil)
	assert.True(t, svc.lockOnScreenLock.Load())
}

// ---------------------------------------------------------------------------
// SetContext
// ---------------------------------------------------------------------------

func TestAppLockService_SetContext(t *testing.T) {
	svc := newTestAppLockService(t, nil)
	ctx := context.Background()
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.ctx)
}

func TestAppLockService_SetContext_Nil(t *testing.T) {
	svc := newTestAppLockService(t, nil)
	svc.SetContext(nil) //nolint:staticcheck // SA1012: intentionally testing nil-context handling
	assert.Nil(t, svc.ctx)
}

// ---------------------------------------------------------------------------
// SetEmitFunc
// ---------------------------------------------------------------------------

func TestAppLockService_SetEmitFunc(t *testing.T) {
	svc := newTestAppLockService(t, nil)

	var emitted bool
	svc.SetEmitFunc(func(event string, data any) {
		emitted = true
		assert.Equal(t, "app:locked", event)
	})

	assert.NotNil(t, svc.emitFunc)
	svc.emitFunc("app:locked", nil)
	assert.True(t, emitted)
}

func TestAppLockService_SetEmitFunc_Nil(t *testing.T) {
	svc := newTestAppLockService(t, nil)
	svc.SetEmitFunc(nil)
	assert.Nil(t, svc.emitFunc)
}

// ---------------------------------------------------------------------------
// Lock
// ---------------------------------------------------------------------------

func TestAppLockService_Lock_WhenUnlocked(t *testing.T) {
	svc := newTestAppLockService(t, nil)
	assert.False(t, svc.IsLocked())

	err := svc.Lock()
	require.NoError(t, err)
	assert.True(t, svc.IsLocked())
}

func TestAppLockService_Lock_AlreadyLocked(t *testing.T) {
	svc := newTestAppLockService(t, nil)

	err := svc.Lock()
	require.NoError(t, err)

	err = svc.Lock()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrAppLockAlreadyLocked))
}

func TestAppLockService_Lock_EmitsEvent(t *testing.T) {
	svc := newTestAppLockService(t, nil)

	var emittedEvent string
	svc.SetEmitFunc(func(event string, data any) {
		emittedEvent = event
	})

	err := svc.Lock()
	require.NoError(t, err)
	assert.Equal(t, "app:locked", emittedEvent)
}

func TestAppLockService_Lock_StopsAutoLockTimer(t *testing.T) {
	svc := newTestAppLockService(t, nil)

	svc.SetAutoLockMinutes(10)

	svc.autoLockMu.Lock()
	timer := svc.autoLockTimer
	svc.autoLockMu.Unlock()
	require.NotNil(t, timer)

	err := svc.Lock()
	require.NoError(t, err)

	svc.autoLockMu.Lock()
	timer = svc.autoLockTimer
	svc.autoLockMu.Unlock()
	assert.Nil(t, timer)
}

// ---------------------------------------------------------------------------
// Unlock
// ---------------------------------------------------------------------------

func TestAppLockService_Unlock_WithValidPIN(t *testing.T) {
	svc := newTestAppLockService(t, nil) // nil verifyErr = success

	err := svc.Lock()
	require.NoError(t, err)
	assert.True(t, svc.IsLocked())

	err = svc.Unlock("123456")
	require.NoError(t, err)
	assert.False(t, svc.IsLocked())
}

// An unlock against a service that is already fully unlocked has nothing to
// converge, so it succeeds without touching the credential backend. It used
// to be an error, which is what stranded a sealed barrier behind an open app
// lock.
func TestAppLockService_Unlock_AlreadyUnlocked(t *testing.T) {
	svc := newTestAppLockService(t, nil)
	assert.False(t, svc.IsLocked())

	err := svc.Unlock("123456")
	require.NoError(t, err)
	assert.False(t, svc.IsLocked())
}

func TestAppLockService_Unlock_EmptyPIN(t *testing.T) {
	svc := newLockedTestAppLockService(t, nil)
	assert.True(t, svc.IsLocked())

	err := svc.Unlock("")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrAppLockPINRequired))
	assert.True(t, svc.IsLocked())
}

func TestAppLockService_Unlock_BadPIN(t *testing.T) {
	svc := newTestAppLockService(t, qrdbsdk.ErrPINInvalid)

	err := svc.Lock()
	require.NoError(t, err)

	err = svc.Unlock("wrong-pin")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, qrdbsdk.ErrPINInvalid))
	assert.True(t, svc.IsLocked())
}

func TestAppLockService_Unlock_StartsAutoLockTimer(t *testing.T) {
	svc := newTestAppLockService(t, nil)
	svc.SetAutoLockMinutes(5)

	err := svc.Lock()
	require.NoError(t, err)

	// Timer should not exist while locked.
	svc.autoLockMu.Lock()
	timer := svc.autoLockTimer
	svc.autoLockMu.Unlock()
	assert.Nil(t, timer)

	err = svc.Unlock("123456")
	require.NoError(t, err)

	// Unlock calls resetAutoLockTimer, which should create a timer.
	svc.autoLockMu.Lock()
	timer = svc.autoLockTimer
	svc.autoLockMu.Unlock()
	assert.NotNil(t, timer)
}

// ---------------------------------------------------------------------------
// AutoUnlock
// ---------------------------------------------------------------------------

func TestAppLockService_AutoUnlock(t *testing.T) {
	svc := newLockedTestAppLockService(t, nil)
	assert.True(t, svc.IsLocked())

	svc.AutoUnlock()

	assert.False(t, svc.IsLocked())
}

func TestAppLockService_AutoUnlock_StartsTimer(t *testing.T) {
	svc := newLockedTestAppLockService(t, nil)
	svc.autoLockMinutes.Store(10)

	svc.AutoUnlock()

	svc.autoLockMu.Lock()
	timer := svc.autoLockTimer
	svc.autoLockMu.Unlock()
	assert.NotNil(t, timer)
}

func TestAppLockService_AutoUnlock_WhenAlreadyUnlocked(t *testing.T) {
	svc := newTestAppLockService(t, nil)
	assert.False(t, svc.IsLocked())

	// AutoUnlock should be safe to call even when already unlocked.
	svc.AutoUnlock()
	assert.False(t, svc.IsLocked())
}

func TestAppLockService_AutoUnlock_EmitsEvent(t *testing.T) {
	var emittedEvent string
	svc := newLockedTestAppLockService(t, nil)
	svc.SetEmitFunc(func(event string, data any) {
		emittedEvent = event
	})
	assert.True(t, svc.IsLocked())

	svc.AutoUnlock()

	assert.False(t, svc.IsLocked())
	assert.Equal(t, "app:unlocked", emittedEvent)
}

func TestAppLockService_AutoUnlock_NoEmitWithoutEmitFunc(t *testing.T) {
	svc := newLockedTestAppLockService(t, nil)
	assert.Nil(t, svc.emitFunc)
	assert.True(t, svc.IsLocked())

	// Should not panic when emitFunc is nil.
	assert.NotPanics(t, func() {
		svc.AutoUnlock()
	})

	assert.False(t, svc.IsLocked())
}

// ---------------------------------------------------------------------------
// Unlock -- Barrier path
// ---------------------------------------------------------------------------

func TestAppLockService_Unlock_BarrierPath(t *testing.T) {
	// Create a mock barrier service that starts sealed and reports unsealed
	// after Unseal is called. We use a real PINService with a mock backend
	// that will fail, but the barrier path should never reach PINService.
	pinSvc := NewPINService()
	pinSvc.SetContext(context.Background())

	backend := &mockPINBackend{
		strategy:      qrdbsdk.PINStrategySoftware,
		soPINSet:      true,
		userPINSet:    true,
		initialized:   true,
		verifyUserErr: qrdbsdk.ErrPINNotSet, // PINService would fail
		lockoutStatus: &qrdbsdk.PINLockoutStatus{MaxAttempts: 5},
	}
	pSvc := qrdbsdk.NewPINService(backend, slog.Default())
	pinSvc.SetPINService(pSvc)

	barrierSvc := &mockBarrierService{initialized: true, sealed: true}

	svc := NewAppLockService(pinSvc, barrierSvc)
	svc.SetContext(context.Background())
	svc.LockForStartup()

	assert.True(t, svc.IsLocked())

	err := svc.Unlock("barrier-password")
	require.NoError(t, err)
	assert.False(t, svc.IsLocked())
	assert.True(t, barrierSvc.unsealCalled)
	assert.Equal(t, "barrier-password", barrierSvc.unsealPassword)
}

func TestAppLockService_Unlock_PINInvalid_BarrierPath(t *testing.T) {
	pinSvc := NewPINService()
	pinSvc.SetContext(context.Background())

	backend := &mockPINBackend{
		strategy:      qrdbsdk.PINStrategySoftware,
		soPINSet:      true,
		userPINSet:    true,
		initialized:   true,
		verifyUserErr: nil,
		lockoutStatus: &qrdbsdk.PINLockoutStatus{MaxAttempts: 5},
	}
	pSvc := qrdbsdk.NewPINService(backend, slog.Default())
	pinSvc.SetPINService(pSvc)

	barrierSvc := &mockBarrierService{initialized: true, sealed: true, unsealErr: errors.New("bad password")}

	svc := NewAppLockService(pinSvc, barrierSvc)
	svc.SetContext(context.Background())
	svc.LockForStartup()

	assert.True(t, svc.IsLocked())

	err := svc.Unlock("wrong-password")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrAppLockPINInvalid))
	assert.True(t, svc.IsLocked())
}

func TestAppLockService_Unlock_BarrierAlreadyUnsealed_UsesPINService(t *testing.T) {
	// When the barrier is already unsealed, Unlock should use PINService.
	pinSvc := NewPINService()
	pinSvc.SetContext(context.Background())

	backend := &mockPINBackend{
		strategy:      qrdbsdk.PINStrategySoftware,
		soPINSet:      true,
		userPINSet:    true,
		initialized:   true,
		verifyUserErr: nil, // PIN verification succeeds
		lockoutStatus: &qrdbsdk.PINLockoutStatus{MaxAttempts: 5},
	}
	pSvc := qrdbsdk.NewPINService(backend, slog.Default())
	pinSvc.SetPINService(pSvc)

	barrierSvc := &mockBarrierService{initialized: true, sealed: false} // Already unsealed

	svc := NewAppLockService(pinSvc, barrierSvc)
	svc.SetContext(context.Background())
	svc.LockForStartup()

	assert.True(t, svc.IsLocked())

	err := svc.Unlock("user-pin")
	require.NoError(t, err)
	assert.False(t, svc.IsLocked())
	assert.False(t, barrierSvc.unsealCalled) // Barrier should NOT be called
}

func TestAppLockService_Unlock_BarrierNotInitialized_VerifiesPINAndInitializes(t *testing.T) {
	// When barrier is configured but NOT initialized (directory doesn't exist),
	// Unlock first verifies the PIN against PINService, then initializes the
	// barrier with the same PIN so the next restart can take the unseal path.
	// This is the recovery flow when the wizard's barrier init failed but the
	// User PIN was successfully persisted.
	pinSvc := NewPINService()
	pinSvc.SetContext(context.Background())

	backend := &mockPINBackend{
		strategy:      qrdbsdk.PINStrategySoftware,
		soPINSet:      true,
		userPINSet:    true,
		initialized:   true,
		verifyUserErr: nil,
		lockoutStatus: &qrdbsdk.PINLockoutStatus{MaxAttempts: 5},
	}
	pSvc := qrdbsdk.NewPINService(backend, slog.Default())
	pinSvc.SetPINService(pSvc)

	// Barrier is configured but NOT initialized (directory doesn't exist).
	barrierSvc := &mockBarrierService{initialized: false, sealed: true}

	svc := NewAppLockService(pinSvc, barrierSvc)
	svc.SetContext(context.Background())
	svc.LockForStartup()

	assert.True(t, svc.IsLocked())

	// PIN verifies, then Initialize is called on the barrier with the PIN.
	err := svc.Unlock("user-pin")
	require.NoError(t, err)
	assert.False(t, svc.IsLocked())
	assert.True(t, barrierSvc.unsealCalled, "barrier Initialize should be called after PIN verify")
	assert.Equal(t, "user-pin", barrierSvc.unsealPassword)
}

func TestAppLockService_Unlock_SetupIncomplete_BarrierNotInitializedAndPINNotSet(t *testing.T) {
	// When barrier is not initialized AND user PIN is not set, we have an
	// incomplete setup state. This should return ErrAppLockSetupIncomplete
	// with a clear message to reset config and re-run the wizard.
	pinSvc := NewPINService()
	pinSvc.SetContext(context.Background())

	backend := &mockPINBackend{
		strategy:    qrdbsdk.PINStrategySoftware,
		soPINSet:    false,
		userPINSet:  false, // PIN not set - setup incomplete
		initialized: false,
		// The canonical sentinel every real backend returns when it holds no
		// credential; an ad-hoc error here would not model any of them.
		verifyUserErr: qrdbsdk.ErrPINNotSet,
		lockoutStatus: &qrdbsdk.PINLockoutStatus{MaxAttempts: 5},
	}
	pSvc := qrdbsdk.NewPINService(backend, slog.Default())
	pinSvc.SetPINService(pSvc)

	// Barrier is configured but NOT initialized.
	barrierSvc := &mockBarrierService{initialized: false, sealed: true}

	svc := NewAppLockService(pinSvc, barrierSvc)
	svc.SetContext(context.Background())
	svc.LockForStartup()

	assert.True(t, svc.IsLocked())

	// Unlock should fail with ErrAppLockSetupIncomplete.
	err := svc.Unlock("any-pin")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrAppLockSetupIncomplete), "expected ErrAppLockSetupIncomplete, got: %v", err)
	assert.True(t, svc.IsLocked())
	assert.False(t, barrierSvc.unsealCalled, "should not attempt barrier unseal")
}

// mockBarrierService satisfies the barrierUnsealer interface for app lock tests.
type mockBarrierService struct {
	initialized    bool
	sealed         bool
	unsealCalled   bool
	unsealPassword string
	unsealErr      error
	sealCalled     bool
	sealErr        error

	// sealHook, when set, runs at the start of Seal so a test can observe
	// the service's state at the instant the barrier is being closed.
	sealHook func()
}

// IsInitialized returns whether the mock barrier storage directory exists.
func (m *mockBarrierService) IsInitialized() bool {
	return m.initialized
}

// IsUnsealed returns whether the mock barrier is unsealed.
func (m *mockBarrierService) IsUnsealed() bool {
	return !m.sealed
}

// Initialize simulates initializing the barrier.
func (m *mockBarrierService) Initialize(password, _ string) error {
	m.unsealCalled = true
	m.unsealPassword = password
	if m.unsealErr != nil {
		return m.unsealErr
	}
	m.initialized = true
	m.sealed = false
	return nil
}

// Seal simulates sealing the barrier, zeroing its data encryption key.
func (m *mockBarrierService) Seal() error {
	if m.sealHook != nil {
		m.sealHook()
	}
	m.sealCalled = true
	if m.sealErr != nil {
		return m.sealErr
	}
	m.sealed = true
	return nil
}

// Unseal simulates unsealing the barrier.
func (m *mockBarrierService) Unseal(password, _ string) error {
	m.unsealCalled = true
	m.unsealPassword = password
	if m.unsealErr != nil {
		return m.unsealErr
	}
	m.sealed = false
	return nil
}

// ---------------------------------------------------------------------------
// IsLocked
// ---------------------------------------------------------------------------

func TestAppLockService_IsLocked_DefaultFalse(t *testing.T) {
	svc := newTestAppLockService(t, nil)
	assert.False(t, svc.IsLocked())
}

func TestAppLockService_IsLocked_AfterLockForStartup(t *testing.T) {
	svc := newTestAppLockService(t, nil)
	svc.LockForStartup()
	assert.True(t, svc.IsLocked())
}

func TestAppLockService_IsLocked_AfterAutoUnlock(t *testing.T) {
	svc := newLockedTestAppLockService(t, nil)
	svc.AutoUnlock()
	assert.False(t, svc.IsLocked())
}

func TestAppLockService_IsLocked_AfterLockUnlock(t *testing.T) {
	svc := newTestAppLockService(t, nil)

	err := svc.Lock()
	require.NoError(t, err)

	err = svc.Unlock("123456")
	require.NoError(t, err)
	assert.False(t, svc.IsLocked())
}

// ---------------------------------------------------------------------------
// GetStatus
// ---------------------------------------------------------------------------

func TestAppLockService_GetStatus_Defaults(t *testing.T) {
	svc := newTestAppLockService(t, nil)

	status := svc.GetStatus()
	assert.False(t, status.IsLocked) // Starts unlocked
	assert.Equal(t, 15, status.AutoLockMinutes)
	assert.True(t, status.LockOnScreenLock)
}

func TestAppLockService_GetStatus_AfterLockForStartup(t *testing.T) {
	svc := newTestAppLockService(t, nil)
	svc.LockForStartup()

	status := svc.GetStatus()
	assert.True(t, status.IsLocked)
}

func TestAppLockService_GetStatus_AfterAutoUnlock(t *testing.T) {
	svc := newLockedTestAppLockService(t, nil)
	svc.AutoUnlock()

	status := svc.GetStatus()
	assert.False(t, status.IsLocked)
}

func TestAppLockService_GetStatus_AfterLock(t *testing.T) {
	svc := newTestAppLockService(t, nil)

	err := svc.Lock()
	require.NoError(t, err)

	status := svc.GetStatus()
	assert.True(t, status.IsLocked)
	assert.Equal(t, 15, status.AutoLockMinutes)
	assert.True(t, status.LockOnScreenLock)
}

func TestAppLockService_GetStatus_AfterConfigChanges(t *testing.T) {
	svc := newTestAppLockService(t, nil)

	svc.SetAutoLockMinutes(30)
	svc.SetLockOnScreenLock(false)

	status := svc.GetStatus()
	assert.False(t, status.IsLocked)
	assert.Equal(t, 30, status.AutoLockMinutes)
	assert.False(t, status.LockOnScreenLock)
}

// ---------------------------------------------------------------------------
// SetAutoLockMinutes
// ---------------------------------------------------------------------------

func TestAppLockService_SetAutoLockMinutes(t *testing.T) {
	svc := newTestAppLockService(t, nil)

	svc.SetAutoLockMinutes(30)
	assert.Equal(t, int32(30), svc.autoLockMinutes.Load())

	svc.SetAutoLockMinutes(0)
	assert.Equal(t, int32(0), svc.autoLockMinutes.Load())
}

func TestAppLockService_SetAutoLockMinutes_WhileUnlocked_StartsTimer(t *testing.T) {
	svc := newTestAppLockService(t, nil)
	assert.False(t, svc.IsLocked())

	svc.SetAutoLockMinutes(10)

	svc.autoLockMu.Lock()
	timer := svc.autoLockTimer
	svc.autoLockMu.Unlock()
	assert.NotNil(t, timer)
}

func TestAppLockService_SetAutoLockMinutes_WhileLocked_NoTimer(t *testing.T) {
	svc := newLockedTestAppLockService(t, nil)
	assert.True(t, svc.IsLocked())

	svc.SetAutoLockMinutes(10)

	// Timer should not be started because service is locked.
	svc.autoLockMu.Lock()
	timer := svc.autoLockTimer
	svc.autoLockMu.Unlock()
	assert.Nil(t, timer)
}

func TestAppLockService_SetAutoLockMinutes_Zero_DisablesTimer(t *testing.T) {
	svc := newTestAppLockService(t, nil)

	// Set auto-lock, then disable it.
	svc.SetAutoLockMinutes(5)

	svc.autoLockMu.Lock()
	timer := svc.autoLockTimer
	svc.autoLockMu.Unlock()
	assert.NotNil(t, timer)

	svc.SetAutoLockMinutes(0)

	svc.autoLockMu.Lock()
	timer = svc.autoLockTimer
	svc.autoLockMu.Unlock()
	assert.Nil(t, timer)
}

// ---------------------------------------------------------------------------
// SetLockOnScreenLock
// ---------------------------------------------------------------------------

func TestAppLockService_SetLockOnScreenLock(t *testing.T) {
	svc := newTestAppLockService(t, nil)
	assert.True(t, svc.lockOnScreenLock.Load())

	svc.SetLockOnScreenLock(false)
	assert.False(t, svc.lockOnScreenLock.Load())

	svc.SetLockOnScreenLock(true)
	assert.True(t, svc.lockOnScreenLock.Load())
}

// ---------------------------------------------------------------------------
// RecordActivity
// ---------------------------------------------------------------------------

func TestAppLockService_RecordActivity_NoOpWhenLocked(t *testing.T) {
	svc := newLockedTestAppLockService(t, nil)
	assert.True(t, svc.IsLocked())

	svc.autoLockMinutes.Store(5)

	// RecordActivity should be a no-op when locked.
	svc.RecordActivity()

	svc.autoLockMu.Lock()
	timer := svc.autoLockTimer
	svc.autoLockMu.Unlock()
	assert.Nil(t, timer)
}

func TestAppLockService_RecordActivity_ResetsTimerWhenUnlocked(t *testing.T) {
	svc := newTestAppLockService(t, nil)

	svc.SetAutoLockMinutes(10)

	svc.autoLockMu.Lock()
	timerBefore := svc.autoLockTimer
	svc.autoLockMu.Unlock()
	require.NotNil(t, timerBefore)

	// RecordActivity should reset the timer (create a new one).
	svc.RecordActivity()

	svc.autoLockMu.Lock()
	timerAfter := svc.autoLockTimer
	svc.autoLockMu.Unlock()
	assert.NotNil(t, timerAfter)
}

// ---------------------------------------------------------------------------
// Auto-lock timer fires
// ---------------------------------------------------------------------------

func TestAppLockService_AutoLock_FiresAndLocks(t *testing.T) {
	svc := newTestAppLockService(t, nil)
	assert.False(t, svc.IsLocked())

	svc.autoLockMinutes.Store(1)

	svc.autoLockMu.Lock()
	if svc.autoLockTimer != nil {
		svc.autoLockTimer.Stop()
	}
	svc.autoLockTimer = time.AfterFunc(50*time.Millisecond, func() {
		_ = svc.Lock()
	})
	svc.autoLockMu.Unlock()

	// The 50ms AfterFunc fire is the behavior under test; poll rather than
	// bet a fixed sleep is long enough under a loaded scheduler.
	require.Eventually(t, svc.IsLocked, 5*time.Second, 10*time.Millisecond, "auto-lock timer did not fire")
}

func TestAppLockService_AutoLock_EmitsEvent(t *testing.T) {
	svc := newTestAppLockService(t, nil)

	var emittedEvent atomic.Value

	svc.SetEmitFunc(func(event string, data any) {
		emittedEvent.Store(event)
	})

	svc.autoLockMinutes.Store(1)
	svc.autoLockMu.Lock()
	if svc.autoLockTimer != nil {
		svc.autoLockTimer.Stop()
	}
	svc.autoLockTimer = time.AfterFunc(50*time.Millisecond, func() {
		_ = svc.Lock()
	})
	svc.autoLockMu.Unlock()

	// The 50ms AfterFunc fire is the behavior under test; poll for the
	// emitted event itself (Lock sets locked before emitting, so polling
	// IsLocked alone would race the emit) rather than bet a fixed sleep is
	// long enough under a loaded scheduler.
	require.Eventually(t, func() bool {
		return emittedEvent.Load() != nil
	}, 5*time.Second, 10*time.Millisecond, "auto-lock timer did not emit")

	assert.True(t, svc.IsLocked())
	ev, ok := emittedEvent.Load().(string)
	assert.True(t, ok)
	assert.Equal(t, "app:locked", ev)
}

func TestAppLockService_AutoLock_NoEmitWhenAlreadyLocked(t *testing.T) {
	svc := newTestAppLockService(t, nil)

	var emitCount atomic.Int32
	svc.SetEmitFunc(func(event string, data any) {
		emitCount.Add(1)
	})

	// Lock the app first.
	err := svc.Lock()
	require.NoError(t, err)
	initialCount := emitCount.Load()

	// Set up a timer that tries to auto-lock again, and signal on a channel
	// instead of sleeping a fixed duration so the assertion below only runs
	// once the attempt has actually completed.
	done := make(chan struct{})
	svc.autoLockMu.Lock()
	svc.autoLockTimer = time.AfterFunc(50*time.Millisecond, func() {
		_ = svc.Lock() // Should return ErrAppLockAlreadyLocked, no emit.
		close(done)
	})
	svc.autoLockMu.Unlock()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("auto-lock timer did not fire")
	}

	// Lock returned ErrAppLockAlreadyLocked, so no additional emit should fire.
	assert.Equal(t, initialCount, emitCount.Load())
}

// ---------------------------------------------------------------------------
// Lock / Unlock transitions
// ---------------------------------------------------------------------------

func TestAppLockService_LockUnlockCycle(t *testing.T) {
	svc := newTestAppLockService(t, nil)

	for i := 0; i < 5; i++ {
		err := svc.Lock()
		require.NoError(t, err, "iteration %d: lock failed", i)
		assert.True(t, svc.IsLocked(), "iteration %d: expected locked", i)

		err = svc.Unlock("123456")
		require.NoError(t, err, "iteration %d: unlock failed", i)
		assert.False(t, svc.IsLocked(), "iteration %d: expected unlocked", i)
	}
}

func TestAppLockService_StatusReflectsLockState(t *testing.T) {
	svc := newTestAppLockService(t, nil)

	status := svc.GetStatus()
	assert.False(t, status.IsLocked)

	err := svc.Lock()
	require.NoError(t, err)

	status = svc.GetStatus()
	assert.True(t, status.IsLocked)

	err = svc.Unlock("123456")
	require.NoError(t, err)

	status = svc.GetStatus()
	assert.False(t, status.IsLocked)
}

// ---------------------------------------------------------------------------
// stopAutoLockTimer edge cases
// ---------------------------------------------------------------------------

func TestAppLockService_StopAutoLockTimer_NilTimer(t *testing.T) {
	svc := newTestAppLockService(t, nil)

	// Should not panic when timer is nil.
	svc.stopAutoLockTimer()

	svc.autoLockMu.Lock()
	timer := svc.autoLockTimer
	svc.autoLockMu.Unlock()
	assert.Nil(t, timer)
}

func TestAppLockService_StopAutoLockTimer_StopsExistingTimer(t *testing.T) {
	svc := newTestAppLockService(t, nil)

	svc.SetAutoLockMinutes(10)

	svc.autoLockMu.Lock()
	timer := svc.autoLockTimer
	svc.autoLockMu.Unlock()
	require.NotNil(t, timer)

	svc.stopAutoLockTimer()

	svc.autoLockMu.Lock()
	timer = svc.autoLockTimer
	svc.autoLockMu.Unlock()
	assert.Nil(t, timer)
}

// ---------------------------------------------------------------------------
// resetAutoLockTimer edge cases
// ---------------------------------------------------------------------------

func TestAppLockService_ResetAutoLockTimer_ZeroMinutes(t *testing.T) {
	svc := newTestAppLockService(t, nil)

	svc.autoLockMinutes.Store(0)
	svc.resetAutoLockTimer()

	svc.autoLockMu.Lock()
	timer := svc.autoLockTimer
	svc.autoLockMu.Unlock()
	assert.Nil(t, timer)
}

func TestAppLockService_ResetAutoLockTimer_NegativeMinutes(t *testing.T) {
	svc := newTestAppLockService(t, nil)

	svc.autoLockMinutes.Store(-1)
	svc.resetAutoLockTimer()

	svc.autoLockMu.Lock()
	timer := svc.autoLockTimer
	svc.autoLockMu.Unlock()
	assert.Nil(t, timer)
}

func TestAppLockService_ResetAutoLockTimer_ReplacesExisting(t *testing.T) {
	svc := newTestAppLockService(t, nil)

	svc.autoLockMinutes.Store(5)
	svc.resetAutoLockTimer()

	svc.autoLockMu.Lock()
	timerFirst := svc.autoLockTimer
	svc.autoLockMu.Unlock()
	require.NotNil(t, timerFirst)

	// Reset again; the old timer should be replaced.
	svc.resetAutoLockTimer()

	svc.autoLockMu.Lock()
	timerSecond := svc.autoLockTimer
	svc.autoLockMu.Unlock()
	require.NotNil(t, timerSecond)
}

// ---------------------------------------------------------------------------
// Concurrent access
// ---------------------------------------------------------------------------

func TestAppLockService_ConcurrentLockUnlock(t *testing.T) {
	svc := newTestAppLockService(t, nil)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = svc.Lock()
				_ = svc.Unlock("123456")
				svc.RecordActivity()
				_ = svc.IsLocked()
				_ = svc.GetStatus()
			}
		}()
	}

	wg.Wait()

	// Service should be in a valid state -- either locked or unlocked.
	locked := svc.IsLocked()
	assert.True(t, locked || !locked) // trivially true, verifies no panic/deadlock
}

func TestAppLockService_ConcurrentRecordActivity(t *testing.T) {
	svc := newTestAppLockService(t, nil)

	svc.SetAutoLockMinutes(10)

	const goroutines = 30
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				svc.RecordActivity()
			}
		}()
	}

	wg.Wait()

	// Service should still be unlocked since auto-lock is 10 minutes.
	assert.False(t, svc.IsLocked())
}

// ---------------------------------------------------------------------------
// Full lifecycle
// ---------------------------------------------------------------------------

func TestAppLockService_FullLifecycle(t *testing.T) {
	svc := newTestAppLockService(t, nil)

	// 1. Starts unlocked (first-run path).
	assert.False(t, svc.IsLocked())

	status := svc.GetStatus()
	assert.False(t, status.IsLocked)
	assert.Equal(t, 15, status.AutoLockMinutes)
	assert.True(t, status.LockOnScreenLock)

	// 2. Simulate returning-user path: lock for startup, then auto-unlock.
	svc.LockForStartup()
	assert.True(t, svc.IsLocked())
	svc.AutoUnlock()
	assert.False(t, svc.IsLocked())

	// 3. Lock the app.
	err := svc.Lock()
	require.NoError(t, err)
	assert.True(t, svc.IsLocked())

	// 4. Unlock with valid PIN.
	err = svc.Unlock("123456")
	require.NoError(t, err)
	assert.False(t, svc.IsLocked())

	// 5. Configure auto-lock and record activity.
	svc.SetAutoLockMinutes(30)
	svc.SetLockOnScreenLock(false)
	svc.RecordActivity()

	status = svc.GetStatus()
	assert.False(t, status.IsLocked)
	assert.Equal(t, 30, status.AutoLockMinutes)
	assert.False(t, status.LockOnScreenLock)

	// 6. Lock again.
	err = svc.Lock()
	require.NoError(t, err)
	assert.True(t, svc.IsLocked())

	// 7. Try empty PIN.
	err = svc.Unlock("")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrAppLockPINRequired))

	// 8. Unlock with correct PIN.
	err = svc.Unlock("123456")
	require.NoError(t, err)
	assert.False(t, svc.IsLocked())

	// 9. Disable auto-lock.
	svc.SetAutoLockMinutes(0)

	svc.autoLockMu.Lock()
	timer := svc.autoLockTimer
	svc.autoLockMu.Unlock()
	assert.Nil(t, timer)
}

// ---------------------------------------------------------------------------
// AppLockStatus struct
// ---------------------------------------------------------------------------

func TestAppLockStatus_Fields(t *testing.T) {
	status := AppLockStatus{
		IsLocked:         true,
		AutoLockMinutes:  10,
		LockOnScreenLock: false,
	}
	assert.True(t, status.IsLocked)
	assert.Equal(t, 10, status.AutoLockMinutes)
	assert.False(t, status.LockOnScreenLock)
}

// ---------------------------------------------------------------------------
// UnlockVerified / HandleUnlock (go-xkms #250 defect 2)
// ---------------------------------------------------------------------------

// newBarrierBackedAppLockService builds a locked service wired to a barrier
// double, the shape the headless daemon and the GUI both run in.
func newBarrierBackedAppLockService(t *testing.T, barrier *mockBarrierService, verifyErr error) *AppLockService {
	t.Helper()

	pinSvc := NewPINService()
	pinSvc.SetContext(context.Background())

	backend := &mockPINBackend{
		strategy:      qrdbsdk.PINStrategySoftware,
		soPINSet:      true,
		userPINSet:    true,
		initialized:   true,
		verifyUserErr: verifyErr,
		lockoutStatus: &qrdbsdk.PINLockoutStatus{MaxAttempts: 5},
	}
	pinSvc.SetPINService(qrdbsdk.NewPINService(backend, slog.Default()))

	svc := NewAppLockService(pinSvc, barrier)
	svc.SetContext(context.Background())
	svc.LockForStartup()
	return svc
}

// A PIN that cannot unseal the barrier must be reported as a barrier that is
// still locked, not as a successful unlock. This is the state the reported
// defect ran in: the ceremony proceeded against a sealed barrier and failed
// much later as "operation denied".
func TestAppLockService_UnlockVerified_SealedBarrierStaysLocked(t *testing.T) {
	barrier := &mockBarrierService{initialized: true, sealed: true, unsealErr: errors.New("wrong password")}
	svc := newBarrierBackedAppLockService(t, barrier, nil)

	outcome, err := svc.UnlockVerified("123456")
	require.Error(t, err)
	require.NotNil(t, outcome)
	assert.Empty(t, outcome.Unlocked, "nothing was unlocked")
	assert.Contains(t, outcome.StillLocked, SubsystemAppLock)
	assert.Contains(t, outcome.StillLocked, SubsystemBarrier)
	assert.True(t, svc.IsLocked())
}

// A successful unseal releases both the app lock and the barrier, and both
// are named.
func TestAppLockService_UnlockVerified_NamesEverythingItReleased(t *testing.T) {
	barrier := &mockBarrierService{initialized: true, sealed: true}
	svc := newBarrierBackedAppLockService(t, barrier, nil)

	outcome, err := svc.UnlockVerified("123456")
	require.NoError(t, err)
	assert.Equal(t, []string{SubsystemAppLock, SubsystemBarrier}, outcome.Unlocked)
	assert.Empty(t, outcome.StillLocked)
	assert.False(t, svc.IsLocked())
}

// With no barrier configured the app lock is the only subsystem in play, and
// it is the only one reported — an absent barrier is not a locked barrier.
func TestAppLockService_UnlockVerified_NoBarrierReportsAppLockOnly(t *testing.T) {
	svc := newLockedTestAppLockService(t, nil)

	outcome, err := svc.UnlockVerified("123456")
	require.NoError(t, err)
	assert.Equal(t, []string{SubsystemAppLock}, outcome.Unlocked)
	assert.Empty(t, outcome.StillLocked)
}

// HandleUnlock renders the outcome for the IPC callers. A rejected unlock is
// never Success, and the daemon's reason is carried through.
func TestAppLockService_HandleUnlock_RejectedIsNotSuccess(t *testing.T) {
	barrier := &mockBarrierService{initialized: true, sealed: true, unsealErr: errors.New("wrong password")}
	svc := newBarrierBackedAppLockService(t, barrier, nil)

	result := svc.HandleUnlock("123456")
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotEmpty(t, result.Error)
	assert.Contains(t, result.StillLocked, SubsystemBarrier)
	assert.Empty(t, result.Unlocked)
}

// An unlock against a service with nothing locked releases nothing and is
// still a success: the caller asked for an unlocked daemon and that is what
// it has. Unlocked stays empty so the report does not claim work it did not
// do.
func TestAppLockService_HandleUnlock_AlreadyUnlockedIsIdempotentSuccess(t *testing.T) {
	svc := newTestAppLockService(t, nil)

	result := svc.HandleUnlock("123456")
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Empty(t, result.Error)
	assert.Empty(t, result.Unlocked)
	assert.Empty(t, result.StillLocked)
}

// A genuine unlock is a success that names what it released.
func TestAppLockService_HandleUnlock_SuccessNamesSubsystems(t *testing.T) {
	barrier := &mockBarrierService{initialized: true, sealed: true}
	svc := newBarrierBackedAppLockService(t, barrier, nil)

	result := svc.HandleUnlock("123456")
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Empty(t, result.Error)
	assert.Equal(t, []string{SubsystemAppLock, SubsystemBarrier}, result.Unlocked)
	assert.Empty(t, result.StillLocked)
}

// An empty PIN never reaches the barrier and is not a success.
func TestAppLockService_HandleUnlock_EmptyPIN(t *testing.T) {
	barrier := &mockBarrierService{initialized: true, sealed: true}
	svc := newBarrierBackedAppLockService(t, barrier, nil)

	result := svc.HandleUnlock("")
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "PIN required")
	assert.False(t, barrier.unsealCalled)
}
