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
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// mockPINBackend implements qrdbsdk.PINBackend for testing.
type mockPINBackend struct {
	strategy    qrdbsdk.PINStrategyID
	soPINSet    bool
	userPINSet  bool
	initialized bool

	setSOPINErr     error
	setUserPINErr   error
	changeSOPINErr  error
	changeUserErr   error
	verifySOErr     error
	verifyUserErr   error
	resetLockoutErr error

	lockoutStatus *qrdbsdk.PINLockoutStatus

	// verifyUserCalls counts VerifyUserPIN calls so a test can assert that
	// an unlock never reached the PIN verification path.
	verifyUserCalls atomic.Int32
}

func (m *mockPINBackend) Strategy() qrdbsdk.PINStrategyID             { return m.strategy }
func (m *mockPINBackend) SOPINSet() bool                              { return m.soPINSet }
func (m *mockPINBackend) UserPINSet() bool                            { return m.userPINSet }
func (m *mockPINBackend) IsInitialized() bool                         { return m.initialized }
func (m *mockPINBackend) GetLockoutStatus() *qrdbsdk.PINLockoutStatus { return m.lockoutStatus }

func (m *mockPINBackend) SetSOPIN(_, _ string) error      { return m.setSOPINErr }
func (m *mockPINBackend) SetUserPIN(_, _ string) error    { return m.setUserPINErr }
func (m *mockPINBackend) ChangeSOPIN(_, _ string) error   { return m.changeSOPINErr }
func (m *mockPINBackend) ChangeUserPIN(_, _ string) error { return m.changeUserErr }
func (m *mockPINBackend) VerifySOPIN(_ string) error      { return m.verifySOErr }
func (m *mockPINBackend) VerifyUserPIN(_ string) error {
	m.verifyUserCalls.Add(1)
	return m.verifyUserErr
}
func (m *mockPINBackend) ResetLockout(_ string) error { return m.resetLockoutErr }
func (m *mockPINBackend) SetMaxAttempts(_ int)        {}

// mockPINBackendWithFIDO2 extends mockPINBackend to implement the
// qrdbsdk.FIDO2HashVerifier interface. It stores a reference hash and compares
// incoming hashes using constant-time comparison.
type mockPINBackendWithFIDO2 struct {
	mockPINBackend
	fido2Hash []byte // the expected SHA-256(PIN)[:16]
}

// VerifyFIDO2Hash implements qrdbsdk.FIDO2HashVerifier.
func (m *mockPINBackendWithFIDO2) VerifyFIDO2Hash(hash []byte) bool {
	if len(hash) != qrdbsdk.FIDO2PINHashSize || len(m.fido2Hash) != qrdbsdk.FIDO2PINHashSize {
		return false
	}
	return subtle.ConstantTimeCompare(hash, m.fido2Hash) == 1
}

func newTestPINService(backend qrdbsdk.PINBackend) *PINService {
	svc := NewPINService()
	svc.SetContext(context.Background())
	if backend != nil {
		pinSvc := qrdbsdk.NewPINService(backend, slog.Default())
		svc.SetPINService(pinSvc)
	}
	return svc
}

// mockAppLockAttemptsResetter implements appLockAttemptsResetter, recording
// whether ResetAttempts was called and optionally failing it, so a test can
// assert PINService reaches (or does not reach) the app lock's own
// unlock-attempt budget (go-xkms#272) on a given code path.
type mockAppLockAttemptsResetter struct {
	resetCalls atomic.Int32
	resetErr   error
}

func (m *mockAppLockAttemptsResetter) ResetAttempts() error {
	m.resetCalls.Add(1)
	return m.resetErr
}

func TestPINService_GetPINStatus(t *testing.T) {
	backend := &mockPINBackend{
		strategy:    qrdbsdk.PINStrategySoftware,
		soPINSet:    true,
		userPINSet:  true,
		initialized: true,
	}
	svc := newTestPINService(backend)

	status, err := svc.GetPINStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.SOPINSet)
	assert.True(t, status.UserPINSet)
	assert.True(t, status.Initialized)
	assert.Equal(t, string(qrdbsdk.PINStrategySoftware), status.Strategy)
}

func TestPINService_GetPINStatus_NotConfigured(t *testing.T) {
	svc := newTestPINService(nil)

	status, err := svc.GetPINStatus()
	assert.Nil(t, status)
	assert.True(t, errors.Is(err, ErrPINServiceNotConfigured))
}

func TestPINService_SetSOPIN(t *testing.T) {
	backend := &mockPINBackend{strategy: qrdbsdk.PINStrategySoftware}
	svc := newTestPINService(backend)

	err := svc.SetSOPIN("", "123456")
	assert.NoError(t, err)
}

func TestPINService_SetSOPIN_NotConfigured(t *testing.T) {
	svc := newTestPINService(nil)

	err := svc.SetSOPIN("", "123456")
	assert.True(t, errors.Is(err, ErrPINServiceNotConfigured))
}

func TestPINService_SetSOPIN_ManagerError(t *testing.T) {
	errTest := errors.New("test: so pin error")
	backend := &mockPINBackend{
		strategy:    qrdbsdk.PINStrategySoftware,
		setSOPINErr: errTest,
	}
	svc := newTestPINService(backend)

	err := svc.SetSOPIN("", "123456")
	assert.Equal(t, errTest, err)
}

func TestPINService_SetUserPIN(t *testing.T) {
	backend := &mockPINBackend{strategy: qrdbsdk.PINStrategySoftware}
	svc := newTestPINService(backend)

	err := svc.SetUserPIN("so-pin-123456", "user-pin-123456")
	assert.NoError(t, err)
}

func TestPINService_SetUserPIN_NotConfigured(t *testing.T) {
	svc := newTestPINService(nil)

	err := svc.SetUserPIN("so-pin", "user-pin")
	assert.True(t, errors.Is(err, ErrPINServiceNotConfigured))
}

func TestPINService_SetUserPIN_ManagerError(t *testing.T) {
	errTest := errors.New("test: user pin error")
	backend := &mockPINBackend{
		strategy:      qrdbsdk.PINStrategySoftware,
		setUserPINErr: errTest,
	}
	svc := newTestPINService(backend)

	err := svc.SetUserPIN("so-pin-123456", "user-pin-123456")
	assert.Equal(t, errTest, err)
}

// TestPINService_SetUserPIN_ResetsAppLockAttempts proves setting the user
// PIN -- which requires and just verified the SO PIN -- also clears a
// wired AppLockService's own unlock-attempt budget (go-xkms#272): the same
// authority as an explicit lockout reset.
func TestPINService_SetUserPIN_ResetsAppLockAttempts(t *testing.T) {
	backend := &mockPINBackend{strategy: qrdbsdk.PINStrategySoftware}
	svc := newTestPINService(backend)
	appLock := &mockAppLockAttemptsResetter{}
	svc.SetAppLockService(appLock)

	require.NoError(t, svc.SetUserPIN("so-pin-123456", "user-pin-123456"))
	assert.Equal(t, int32(1), appLock.resetCalls.Load())
}

// TestPINService_SetUserPIN_FailureDoesNotResetAppLockAttempts is the
// control: an SO PIN that was never verified must not reset anything.
func TestPINService_SetUserPIN_FailureDoesNotResetAppLockAttempts(t *testing.T) {
	errTest := errors.New("test: user pin error")
	backend := &mockPINBackend{strategy: qrdbsdk.PINStrategySoftware, setUserPINErr: errTest}
	svc := newTestPINService(backend)
	appLock := &mockAppLockAttemptsResetter{}
	svc.SetAppLockService(appLock)

	require.Error(t, svc.SetUserPIN("so-pin-123456", "user-pin-123456"))
	assert.Equal(t, int32(0), appLock.resetCalls.Load())
}

// TestPINService_SetUserPIN_NoAppLockServiceWired proves the reset is
// opt-in: a headless CLI invocation of PINService, with no AppLockService
// ever wired, must not panic or fail the PIN operation.
func TestPINService_SetUserPIN_NoAppLockServiceWired(t *testing.T) {
	backend := &mockPINBackend{strategy: qrdbsdk.PINStrategySoftware}
	svc := newTestPINService(backend)

	assert.NoError(t, svc.SetUserPIN("so-pin-123456", "user-pin-123456"))
}

// TestPINService_SetUserPIN_AppLockResetFailureDoesNotFailThePINChange
// proves a failure resetting the app lock's budget is logged, not
// propagated: the SO PIN was verified and the user PIN was set, so the
// call already did what it promised.
func TestPINService_SetUserPIN_AppLockResetFailureDoesNotFailThePINChange(t *testing.T) {
	backend := &mockPINBackend{strategy: qrdbsdk.PINStrategySoftware}
	svc := newTestPINService(backend)
	appLock := &mockAppLockAttemptsResetter{resetErr: errors.New("counter unavailable")}
	svc.SetAppLockService(appLock)

	assert.NoError(t, svc.SetUserPIN("so-pin-123456", "user-pin-123456"))
	assert.Equal(t, int32(1), appLock.resetCalls.Load())
}

func TestPINService_ChangeSOPIN(t *testing.T) {
	backend := &mockPINBackend{strategy: qrdbsdk.PINStrategySoftware}
	svc := newTestPINService(backend)

	err := svc.ChangeSOPIN("old-so-pin-123456", "new-so-pin-123456")
	assert.NoError(t, err)
}

func TestPINService_ChangeSOPIN_NotConfigured(t *testing.T) {
	svc := newTestPINService(nil)

	err := svc.ChangeSOPIN("old", "new")
	assert.True(t, errors.Is(err, ErrPINServiceNotConfigured))
}

func TestPINService_ChangeSOPIN_ManagerError(t *testing.T) {
	errTest := errors.New("test: change so pin error")
	backend := &mockPINBackend{
		strategy:       qrdbsdk.PINStrategySoftware,
		changeSOPINErr: errTest,
	}
	svc := newTestPINService(backend)

	err := svc.ChangeSOPIN("old-123456", "new-123456")
	assert.Equal(t, errTest, err)
}

func TestPINService_ChangeUserPIN(t *testing.T) {
	backend := &mockPINBackend{strategy: qrdbsdk.PINStrategySoftware}
	svc := newTestPINService(backend)

	err := svc.ChangeUserPIN("old-user-pin-123456", "new-user-pin-123456")
	assert.NoError(t, err)
}

func TestPINService_ChangeUserPIN_NotConfigured(t *testing.T) {
	svc := newTestPINService(nil)

	err := svc.ChangeUserPIN("old", "new")
	assert.True(t, errors.Is(err, ErrPINServiceNotConfigured))
}

func TestPINService_ChangeUserPIN_ManagerError(t *testing.T) {
	errTest := errors.New("test: change user pin error")
	backend := &mockPINBackend{
		strategy:      qrdbsdk.PINStrategySoftware,
		changeUserErr: errTest,
	}
	svc := newTestPINService(backend)

	err := svc.ChangeUserPIN("old-123456", "new-123456")
	assert.Equal(t, errTest, err)
}

func TestPINService_VerifyUserPIN(t *testing.T) {
	backend := &mockPINBackend{strategy: qrdbsdk.PINStrategySoftware}
	svc := newTestPINService(backend)

	err := svc.VerifyUserPIN("user-pin-123456")
	assert.NoError(t, err)
}

func TestPINService_VerifyUserPIN_NotConfigured(t *testing.T) {
	svc := newTestPINService(nil)

	err := svc.VerifyUserPIN("user-pin")
	assert.True(t, errors.Is(err, ErrPINServiceNotConfigured))
}

func TestPINService_VerifyUserPIN_ManagerError(t *testing.T) {
	backend := &mockPINBackend{
		strategy:      qrdbsdk.PINStrategySoftware,
		verifyUserErr: qrdbsdk.ErrPINInvalid,
	}
	svc := newTestPINService(backend)

	err := svc.VerifyUserPIN("wrong-pin")
	assert.True(t, errors.Is(err, qrdbsdk.ErrPINInvalid))
}

func TestPINService_GetLockoutStatus(t *testing.T) {
	expected := &qrdbsdk.PINLockoutStatus{
		FailedAttempts:  3,
		MaxAttempts:     5,
		IsLocked:        false,
		LockoutUntil:    time.Time{},
		RecoverySeconds: 300,
	}
	backend := &mockPINBackend{
		strategy:      qrdbsdk.PINStrategySoftware,
		lockoutStatus: expected,
	}
	svc := newTestPINService(backend)

	status, err := svc.GetLockoutStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.Equal(t, 3, status.FailedAttempts)
	assert.Equal(t, 5, status.MaxAttempts)
	assert.False(t, status.IsLocked)
	assert.Equal(t, 300, status.RecoverySeconds)
}

func TestPINService_GetLockoutStatus_NotConfigured(t *testing.T) {
	svc := newTestPINService(nil)

	status, err := svc.GetLockoutStatus()
	assert.Nil(t, status)
	assert.True(t, errors.Is(err, ErrPINServiceNotConfigured))
}

// TestPINService_GetLockoutStatus_SoftwareBackend_ReturnsZeroStatus verifies
// that when the backend returns nil (software backend has no native lockout),
// GetLockoutStatus returns a non-nil zero-value status instead of nil so the
// frontend never receives JSON null and the Settings panel never spins forever.
func TestPINService_GetLockoutStatus_SoftwareBackend_ReturnsZeroStatus(t *testing.T) {
	// mockPINBackend.lockoutStatus is nil by default, matching the software
	// backend contract (no native lockout → nil).
	backend := &mockPINBackend{strategy: qrdbsdk.PINStrategySoftware}
	svc := newTestPINService(backend)

	status, err := svc.GetLockoutStatus()
	require.NoError(t, err)
	require.NotNil(t, status, "GetLockoutStatus must never return nil when service is configured")
	assert.Equal(t, 0, status.FailedAttempts)
	assert.Equal(t, 0, status.MaxAttempts)
	assert.False(t, status.IsLocked)
	assert.Equal(t, 0, status.RecoverySeconds)
}

// TestPINService_GetLockoutStatus_Error verifies the error path when the
// PIN service is not configured.
func TestPINService_GetLockoutStatus_Error(t *testing.T) {
	// Service with no backend wired: getPINService returns ErrPINServiceNotConfigured.
	svc := NewPINService()
	svc.SetContext(context.Background())

	status, err := svc.GetLockoutStatus()
	assert.Nil(t, status, "nil expected on error path")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPINServiceNotConfigured)
}

func TestPINService_ResetLockout(t *testing.T) {
	backend := &mockPINBackend{strategy: qrdbsdk.PINStrategySoftware}
	svc := newTestPINService(backend)

	err := svc.ResetLockout("so-pin-123456")
	assert.NoError(t, err)
}

func TestPINService_ResetLockout_NotConfigured(t *testing.T) {
	svc := newTestPINService(nil)

	err := svc.ResetLockout("so-pin")
	assert.True(t, errors.Is(err, ErrPINServiceNotConfigured))
}

func TestPINService_ResetLockout_ManagerError(t *testing.T) {
	errTest := errors.New("test: reset lockout error")
	backend := &mockPINBackend{
		strategy:        qrdbsdk.PINStrategySoftware,
		resetLockoutErr: errTest,
	}
	svc := newTestPINService(backend)

	err := svc.ResetLockout("so-pin-123456")
	assert.Equal(t, errTest, err)
}

// TestPINService_ResetLockout_ResetsAppLockAttempts proves resetting the
// PIN backend's own lockout also clears a wired AppLockService's
// independent unlock-attempt budget (go-xkms#272): an operator who has
// just proven they hold the SO PIN should not be left blocked by a
// counter this call would otherwise not touch.
func TestPINService_ResetLockout_ResetsAppLockAttempts(t *testing.T) {
	backend := &mockPINBackend{strategy: qrdbsdk.PINStrategySoftware}
	svc := newTestPINService(backend)
	appLock := &mockAppLockAttemptsResetter{}
	svc.SetAppLockService(appLock)

	require.NoError(t, svc.ResetLockout("so-pin-123456"))
	assert.Equal(t, int32(1), appLock.resetCalls.Load())
}

// TestPINService_ResetLockout_FailureDoesNotResetAppLockAttempts is the
// control: a rejected SO PIN must not reset anything.
func TestPINService_ResetLockout_FailureDoesNotResetAppLockAttempts(t *testing.T) {
	errTest := errors.New("test: reset lockout error")
	backend := &mockPINBackend{strategy: qrdbsdk.PINStrategySoftware, resetLockoutErr: errTest}
	svc := newTestPINService(backend)
	appLock := &mockAppLockAttemptsResetter{}
	svc.SetAppLockService(appLock)

	require.Error(t, svc.ResetLockout("so-pin-123456"))
	assert.Equal(t, int32(0), appLock.resetCalls.Load())
}

// TestPINService_SetAppLockService_NilIsIgnored proves SetAppLockService is
// safe to call with a nil interface, leaving the field unset rather than
// storing a pointer to a nil interface value that getAppLockService would
// later dereference into a non-nil-looking, unusable resetter.
func TestPINService_SetAppLockService_NilIsIgnored(t *testing.T) {
	backend := &mockPINBackend{strategy: qrdbsdk.PINStrategySoftware}
	svc := newTestPINService(backend)

	svc.SetAppLockService(nil)
	assert.Nil(t, svc.getAppLockService())
}

func TestPINService_GetPINStatus_Uninitialized(t *testing.T) {
	backend := &mockPINBackend{
		strategy:    qrdbsdk.PINStrategyTPM2,
		soPINSet:    false,
		userPINSet:  false,
		initialized: false,
	}
	svc := newTestPINService(backend)

	status, err := svc.GetPINStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.SOPINSet)
	assert.False(t, status.UserPINSet)
	assert.False(t, status.Initialized)
	assert.Equal(t, string(qrdbsdk.PINStrategyTPM2), status.Strategy)
}

func TestPINService_SetContext(t *testing.T) {
	svc := NewPINService()
	ctx := context.Background()
	svc.SetContext(ctx)
	// No panic means success; context is internal.
}

func TestNewPINService(t *testing.T) {
	svc := NewPINService()
	assert.NotNil(t, svc)
	assert.NotNil(t, svc.log)
}

func TestPINService_IsPINSet_True(t *testing.T) {
	backend := &mockPINBackend{strategy: qrdbsdk.PINStrategySoftware, userPINSet: true}
	svc := newTestPINService(backend)
	assert.True(t, svc.IsPINSet())
}

func TestPINService_IsPINSet_False(t *testing.T) {
	backend := &mockPINBackend{strategy: qrdbsdk.PINStrategySoftware, userPINSet: false}
	svc := newTestPINService(backend)
	assert.False(t, svc.IsPINSet())
}

func TestPINService_IsPINSet_NilService(t *testing.T) {
	svc := newTestPINService(nil)
	assert.False(t, svc.IsPINSet())
}

func TestPINService_VerifyFIDO2Hash_NilService(t *testing.T) {
	svc := newTestPINService(nil)
	assert.False(t, svc.VerifyFIDO2Hash([]byte("test")))
}

// TestPINService_VerifyFIDO2Hash_Success verifies that VerifyFIDO2Hash returns
// true when the service is configured with a FIDO2-capable backend and the
// provided hash matches the stored FIDO2 PIN hash (SHA-256(PIN)[:16]).
func TestPINService_VerifyFIDO2Hash_Success(t *testing.T) {
	t.Parallel()

	rawPIN := "my-secure-pin"
	fullHash := sha256.Sum256([]byte(rawPIN))
	expectedHash := fullHash[:qrdbsdk.FIDO2PINHashSize]

	backend := &mockPINBackendWithFIDO2{
		mockPINBackend: mockPINBackend{
			strategy:   qrdbsdk.PINStrategySoftware,
			userPINSet: true,
		},
		fido2Hash: expectedHash,
	}
	svc := newTestPINService(backend)

	result := svc.VerifyFIDO2Hash(expectedHash)
	assert.True(t, result, "VerifyFIDO2Hash should return true for a matching hash")
}

// TestPINService_VerifyFIDO2Hash_InvalidHash verifies that VerifyFIDO2Hash
// returns false when the provided hash does not match the stored FIDO2 PIN hash.
func TestPINService_VerifyFIDO2Hash_InvalidHash(t *testing.T) {
	t.Parallel()

	rawPIN := "correct-pin"
	fullHash := sha256.Sum256([]byte(rawPIN))
	correctHash := fullHash[:qrdbsdk.FIDO2PINHashSize]

	wrongFullHash := sha256.Sum256([]byte("wrong-pin"))
	wrongHash := wrongFullHash[:qrdbsdk.FIDO2PINHashSize]

	backend := &mockPINBackendWithFIDO2{
		mockPINBackend: mockPINBackend{
			strategy:   qrdbsdk.PINStrategySoftware,
			userPINSet: true,
		},
		fido2Hash: correctHash,
	}
	svc := newTestPINService(backend)

	result := svc.VerifyFIDO2Hash(wrongHash)
	assert.False(t, result, "VerifyFIDO2Hash should return false for a non-matching hash")
}

// ---------------------------------------------------------------------------
// Concurrent SetPINService vs. verification (go-xkms#640)
// ---------------------------------------------------------------------------

// TestPINService_ConcurrentSetPINServiceNeverReturnsWrongResult drives
// IsPINSet/VerifyFIDO2Hash concurrently with SetPINService under -race. It
// models the window go-xkms#640 closes: the authenticator can publish a
// PINService as its PINVerifier before initPINService populates it. Readers
// hammer both the correct and an incorrect hash throughout the transition;
// the wrong hash must never verify (a false positive would be a security
// bug, not just a start-up glitch), and once verification of the correct
// hash succeeds it must never regress — the underlying handoff is a single
// nil-to-populated atomic.Pointer store, so once observed populated it
// stays populated for the rest of the test.
func TestPINService_ConcurrentSetPINServiceNeverReturnsWrongResult(t *testing.T) {
	svc := NewPINService()

	rawPIN := "concurrent-pin"
	fullHash := sha256.Sum256([]byte(rawPIN))
	hash := fullHash[:qrdbsdk.FIDO2PINHashSize]

	wrongFullHash := sha256.Sum256([]byte("not-the-pin"))
	wrongHash := wrongFullHash[:qrdbsdk.FIDO2PINHashSize]

	backend := &mockPINBackendWithFIDO2{
		mockPINBackend: mockPINBackend{strategy: qrdbsdk.PINStrategySoftware, userPINSet: true},
		fido2Hash:      hash,
	}

	var falsePositive atomic.Bool
	var regressed atomic.Bool
	done := make(chan struct{})
	var readers sync.WaitGroup

	readers.Add(4)
	for i := 0; i < 4; i++ {
		go func() {
			defer readers.Done()
			// verifiedBefore is per reader: only within one goroutine are
			// successive reads ordered, so a regression is a success
			// followed by a failure in the same reader.
			verifiedBefore := false
			for {
				select {
				case <-done:
					return
				default:
				}
				if svc.VerifyFIDO2Hash(wrongHash) {
					falsePositive.Store(true)
				}
				if svc.VerifyFIDO2Hash(hash) {
					verifiedBefore = true
				} else if verifiedBefore {
					regressed.Store(true)
				}
			}
		}()
	}

	// Populate the backend once, simulating initPINService() completing
	// after the authenticator has already published this PINService as its
	// PINVerifier.
	time.Sleep(time.Millisecond)
	pinSvc := qrdbsdk.NewPINService(backend, slog.Default())
	svc.SetPINService(pinSvc)

	// Wait for the readers to observe the now-configured backend before
	// tearing them down, and confirm verification succeeds reliably.
	deadline := time.Now().Add(50 * time.Millisecond)
	for time.Now().Before(deadline) && !svc.VerifyFIDO2Hash(hash) {
	}
	require.True(t, svc.VerifyFIDO2Hash(hash), "verification must succeed once SetPINService has run")

	close(done)
	readers.Wait()

	require.False(t, falsePositive.Load(), "an incorrect hash must never verify")
	require.False(t, regressed.Load(), "verification must never regress once it has succeeded")
}

// ---------------------------------------------------------------------------
// ChangeUserPIN barrier re-seal integration
// ---------------------------------------------------------------------------

func TestPINService_ChangeUserPIN_ResealsBarrier(t *testing.T) {
	backend := &mockPINBackend{
		strategy:   qrdbsdk.PINStrategySoftware,
		userPINSet: true,
	}
	svc := newTestPINService(backend)

	// Create and initialize a real barrier service
	barrierSvc := NewBarrierService(t.TempDir(), slog.Default())
	require.NoError(t, barrierSvc.Initialize("old-pin", "passphrase"))

	svc.SetBarrierService(barrierSvc)

	err := svc.ChangeUserPIN("old-pin", "new-pin")
	require.NoError(t, err)

	// Verify the barrier can be unsealed with the new PIN
	require.NoError(t, barrierSvc.Seal())
	svc2 := NewBarrierService(barrierSvc.configDir, slog.Default())
	require.NoError(t, svc2.Unseal("new-pin", "passphrase"))
	assert.True(t, svc2.IsUnsealed())
}

func TestPINService_ChangeUserPIN_BarrierResealFails(t *testing.T) {
	backend := &mockPINBackend{
		strategy:   qrdbsdk.PINStrategySoftware,
		userPINSet: true,
	}
	svc := newTestPINService(backend)

	// Create barrier service WITHOUT initializing it
	barrierSvc := NewBarrierService(t.TempDir(), slog.Default())
	svc.SetBarrierService(barrierSvc)

	err := svc.ChangeUserPIN("old-pin", "new-pin")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBarrierResealFailed)
}

func TestPINService_ChangeUserPIN_NoBarrierService(t *testing.T) {
	backend := &mockPINBackend{
		strategy:   qrdbsdk.PINStrategySoftware,
		userPINSet: true,
	}
	svc := newTestPINService(backend)
	// Do NOT call SetBarrierService

	err := svc.ChangeUserPIN("old-pin", "new-pin")
	require.NoError(t, err)
}

func TestPINService_SetBarrierService_NilSafe(t *testing.T) {
	svc := NewPINService()
	svc.SetBarrierService(nil) // should not panic
	assert.Nil(t, svc.barrierSvc.Load())
}

func TestPINService_ChangeSOPIN_DoesNotTouchBarrier(t *testing.T) {
	backend := &mockPINBackend{
		strategy: qrdbsdk.PINStrategySoftware,
		soPINSet: true,
	}
	svc := newTestPINService(backend)

	// Wire a barrier that is not initialized - if touched, it would fail
	barrierSvc := NewBarrierService(t.TempDir(), slog.Default())
	svc.SetBarrierService(barrierSvc)

	err := svc.ChangeSOPIN("old-so", "new-so")
	require.NoError(t, err) // proves barrier was NOT touched
}

// ---------------------------------------------------------------------------
// SO PIN capability tests
// ---------------------------------------------------------------------------

func TestPINService_GetPINStatus_SOPINSupported_Software(t *testing.T) {
	backend := &mockPINBackend{strategy: qrdbsdk.PINStrategySoftware}
	svc := newTestPINService(backend)

	status, err := svc.GetPINStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.SOPINSupported)
}

func TestPINService_GetPINStatus_SOPINSupported_TPM2(t *testing.T) {
	backend := &mockPINBackend{strategy: qrdbsdk.PINStrategyTPM2}
	svc := newTestPINService(backend)

	status, err := svc.GetPINStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.SOPINSupported)
}

func TestPINService_SOPINSupported_NotConfigured(t *testing.T) {
	svc := newTestPINService(nil)
	assert.True(t, svc.SOPINSupported(), "an unconfigured service should default to supported")
}

func TestPINService_SOPINSupported_TPM2(t *testing.T) {
	backend := &mockPINBackend{strategy: qrdbsdk.PINStrategyTPM2}
	svc := newTestPINService(backend)
	assert.False(t, svc.SOPINSupported())
}

func TestPINService_SOPINSupported_Software(t *testing.T) {
	backend := &mockPINBackend{strategy: qrdbsdk.PINStrategySoftware}
	svc := newTestPINService(backend)
	assert.True(t, svc.SOPINSupported())
}

func TestPINService_Strategy(t *testing.T) {
	backend := &mockPINBackend{strategy: qrdbsdk.PINStrategyTPM2}
	svc := newTestPINService(backend)
	assert.Equal(t, string(qrdbsdk.PINStrategyTPM2), svc.Strategy())
}

func TestPINService_Strategy_NotConfigured(t *testing.T) {
	svc := newTestPINService(nil)
	assert.Equal(t, "", svc.Strategy())
}

// TestPINService_SetSOPIN_TPM2MapsToNotSupported verifies that the raw
// "pin: PIN not set" error the tpm2 backend always returns from SetSOPIN
// is rewritten into the clearer, actionable ErrSOPINNotSupported.
func TestPINService_SetSOPIN_TPM2MapsToNotSupported(t *testing.T) {
	backend := &mockPINBackend{
		strategy:    qrdbsdk.PINStrategyTPM2,
		setSOPINErr: qrdbsdk.ErrPINNotSet,
	}
	svc := newTestPINService(backend)

	err := svc.SetSOPIN("", "123456")
	assert.True(t, errors.Is(err, ErrSOPINNotSupported))
}

// TestPINService_SetSOPIN_SoftwareErrPINNotSet_NotRemapped verifies that an
// ErrPINNotSet from a strategy that DOES support SO PINs is left untouched
// (a software backend should never actually return this from SetSOPIN, but
// the mapping is strategy-gated defensively).
func TestPINService_SetSOPIN_SoftwareErrPINNotSet_NotRemapped(t *testing.T) {
	backend := &mockPINBackend{
		strategy:    qrdbsdk.PINStrategySoftware,
		setSOPINErr: qrdbsdk.ErrPINNotSet,
	}
	svc := newTestPINService(backend)

	err := svc.SetSOPIN("", "123456")
	assert.True(t, errors.Is(err, qrdbsdk.ErrPINNotSet))
	assert.False(t, errors.Is(err, ErrSOPINNotSupported))
}

func TestPINService_ChangeSOPIN_TPM2MapsToNotSupported(t *testing.T) {
	backend := &mockPINBackend{
		strategy:       qrdbsdk.PINStrategyTPM2,
		changeSOPINErr: qrdbsdk.ErrPINNotSet,
	}
	svc := newTestPINService(backend)

	err := svc.ChangeSOPIN("old-123456", "new-123456")
	assert.True(t, errors.Is(err, ErrSOPINNotSupported))
}

func TestPINService_VerifySOPIN_TPM2MapsToNotSupported(t *testing.T) {
	backend := &mockPINBackend{
		strategy:    qrdbsdk.PINStrategyTPM2,
		verifySOErr: qrdbsdk.ErrPINNotSet,
	}
	svc := newTestPINService(backend)

	err := svc.VerifySOPIN("123456")
	assert.True(t, errors.Is(err, ErrSOPINNotSupported))
}
