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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/pin"
)

// mockPINBackend implements pin.PINBackend for testing.
type mockPINBackend struct {
	strategy    pin.StrategyID
	soPINSet    bool
	userPINSet  bool
	initialized bool

	setSOPINErr     error
	setUserPINErr   error
	changeSOPINErr  error
	changeUserErr   error
	verifyUserErr   error
	resetLockoutErr error

	lockoutStatus *pin.LockoutStatus
}

func (m *mockPINBackend) Strategy() pin.StrategyID             { return m.strategy }
func (m *mockPINBackend) SOPINSet() bool                       { return m.soPINSet }
func (m *mockPINBackend) UserPINSet() bool                     { return m.userPINSet }
func (m *mockPINBackend) IsInitialized() bool                  { return m.initialized }
func (m *mockPINBackend) GetLockoutStatus() *pin.LockoutStatus { return m.lockoutStatus }

func (m *mockPINBackend) SetSOPIN(_, _ string) error      { return m.setSOPINErr }
func (m *mockPINBackend) SetUserPIN(_, _ string) error    { return m.setUserPINErr }
func (m *mockPINBackend) ChangeSOPIN(_, _ string) error   { return m.changeSOPINErr }
func (m *mockPINBackend) ChangeUserPIN(_, _ string) error { return m.changeUserErr }
func (m *mockPINBackend) VerifySOPIN(_ string) error      { return nil }
func (m *mockPINBackend) VerifyUserPIN(_ string) error    { return m.verifyUserErr }
func (m *mockPINBackend) ResetLockout(_ string) error     { return m.resetLockoutErr }
func (m *mockPINBackend) SetMaxAttempts(_ int)            {}

// mockPINBackendWithFIDO2 extends mockPINBackend to implement the
// pin.FIDO2HashVerifier interface. It stores a reference hash and compares
// incoming hashes using constant-time comparison.
type mockPINBackendWithFIDO2 struct {
	mockPINBackend
	fido2Hash []byte // the expected SHA-256(PIN)[:16]
}

// VerifyFIDO2Hash implements pin.FIDO2HashVerifier.
func (m *mockPINBackendWithFIDO2) VerifyFIDO2Hash(hash []byte) bool {
	if len(hash) != pin.FIDO2PINHashSize || len(m.fido2Hash) != pin.FIDO2PINHashSize {
		return false
	}
	return subtle.ConstantTimeCompare(hash, m.fido2Hash) == 1
}

func newTestPINService(backend pin.PINBackend) *PINService {
	svc := NewPINService()
	svc.SetContext(context.Background())
	if backend != nil {
		pinSvc := pin.NewService(backend, slog.Default())
		svc.SetPINService(pinSvc)
	}
	return svc
}

func TestPINService_GetPINStatus(t *testing.T) {
	backend := &mockPINBackend{
		strategy:    pin.StrategySoftware,
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
	assert.Equal(t, string(pin.StrategySoftware), status.Strategy)
}

func TestPINService_GetPINStatus_NotConfigured(t *testing.T) {
	svc := newTestPINService(nil)

	status, err := svc.GetPINStatus()
	assert.Nil(t, status)
	assert.True(t, errors.Is(err, ErrPINServiceNotConfigured))
}

func TestPINService_SetSOPIN(t *testing.T) {
	backend := &mockPINBackend{strategy: pin.StrategySoftware}
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
		strategy:    pin.StrategySoftware,
		setSOPINErr: errTest,
	}
	svc := newTestPINService(backend)

	err := svc.SetSOPIN("", "123456")
	assert.Equal(t, errTest, err)
}

func TestPINService_SetUserPIN(t *testing.T) {
	backend := &mockPINBackend{strategy: pin.StrategySoftware}
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
		strategy:      pin.StrategySoftware,
		setUserPINErr: errTest,
	}
	svc := newTestPINService(backend)

	err := svc.SetUserPIN("so-pin-123456", "user-pin-123456")
	assert.Equal(t, errTest, err)
}

func TestPINService_ChangeSOPIN(t *testing.T) {
	backend := &mockPINBackend{strategy: pin.StrategySoftware}
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
		strategy:       pin.StrategySoftware,
		changeSOPINErr: errTest,
	}
	svc := newTestPINService(backend)

	err := svc.ChangeSOPIN("old-123456", "new-123456")
	assert.Equal(t, errTest, err)
}

func TestPINService_ChangeUserPIN(t *testing.T) {
	backend := &mockPINBackend{strategy: pin.StrategySoftware}
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
		strategy:      pin.StrategySoftware,
		changeUserErr: errTest,
	}
	svc := newTestPINService(backend)

	err := svc.ChangeUserPIN("old-123456", "new-123456")
	assert.Equal(t, errTest, err)
}

func TestPINService_VerifyUserPIN(t *testing.T) {
	backend := &mockPINBackend{strategy: pin.StrategySoftware}
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
		strategy:      pin.StrategySoftware,
		verifyUserErr: pin.ErrPINInvalid,
	}
	svc := newTestPINService(backend)

	err := svc.VerifyUserPIN("wrong-pin")
	assert.True(t, errors.Is(err, pin.ErrPINInvalid))
}

func TestPINService_GetLockoutStatus(t *testing.T) {
	expected := &pin.LockoutStatus{
		FailedAttempts:  3,
		MaxAttempts:     5,
		IsLocked:        false,
		LockoutUntil:    time.Time{},
		RecoverySeconds: 300,
	}
	backend := &mockPINBackend{
		strategy:      pin.StrategySoftware,
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

func TestPINService_ResetLockout(t *testing.T) {
	backend := &mockPINBackend{strategy: pin.StrategySoftware}
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
		strategy:        pin.StrategySoftware,
		resetLockoutErr: errTest,
	}
	svc := newTestPINService(backend)

	err := svc.ResetLockout("so-pin-123456")
	assert.Equal(t, errTest, err)
}

func TestPINService_GetPINStatus_Uninitialized(t *testing.T) {
	backend := &mockPINBackend{
		strategy:    pin.StrategyTPM2,
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
	assert.Equal(t, string(pin.StrategyTPM2), status.Strategy)
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
	backend := &mockPINBackend{strategy: pin.StrategySoftware, userPINSet: true}
	svc := newTestPINService(backend)
	assert.True(t, svc.IsPINSet())
}

func TestPINService_IsPINSet_False(t *testing.T) {
	backend := &mockPINBackend{strategy: pin.StrategySoftware, userPINSet: false}
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
	expectedHash := fullHash[:pin.FIDO2PINHashSize]

	backend := &mockPINBackendWithFIDO2{
		mockPINBackend: mockPINBackend{
			strategy:   pin.StrategySoftware,
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
	correctHash := fullHash[:pin.FIDO2PINHashSize]

	wrongFullHash := sha256.Sum256([]byte("wrong-pin"))
	wrongHash := wrongFullHash[:pin.FIDO2PINHashSize]

	backend := &mockPINBackendWithFIDO2{
		mockPINBackend: mockPINBackend{
			strategy:   pin.StrategySoftware,
			userPINSet: true,
		},
		fido2Hash: correctHash,
	}
	svc := newTestPINService(backend)

	result := svc.VerifyFIDO2Hash(wrongHash)
	assert.False(t, result, "VerifyFIDO2Hash should return false for a non-matching hash")
}

// ---------------------------------------------------------------------------
// ChangeUserPIN barrier re-seal integration
// ---------------------------------------------------------------------------

func TestPINService_ChangeUserPIN_ResealsBarrier(t *testing.T) {
	backend := &mockPINBackend{
		strategy:   pin.StrategySoftware,
		userPINSet: true,
	}
	svc := newTestPINService(backend)

	// Create and initialize a real barrier service
	barrierSvc := NewBarrierService(t.TempDir(), slog.Default())
	require.NoError(t, barrierSvc.Initialize("old-pin", "software"))

	svc.SetBarrierService(barrierSvc)

	err := svc.ChangeUserPIN("old-pin", "new-pin")
	require.NoError(t, err)

	// Verify the barrier can be unsealed with the new PIN
	require.NoError(t, barrierSvc.Seal())
	svc2 := NewBarrierService(barrierSvc.configDir, slog.Default())
	require.NoError(t, svc2.Unseal("new-pin", "software"))
	assert.True(t, svc2.IsUnsealed())
}

func TestPINService_ChangeUserPIN_BarrierResealFails(t *testing.T) {
	backend := &mockPINBackend{
		strategy:   pin.StrategySoftware,
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
		strategy:   pin.StrategySoftware,
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
		strategy: pin.StrategySoftware,
		soPINSet: true,
	}
	svc := newTestPINService(backend)

	// Wire a barrier that is not initialized - if touched, it would fail
	barrierSvc := NewBarrierService(t.TempDir(), slog.Default())
	svc.SetBarrierService(barrierSvc)

	err := svc.ChangeSOPIN("old-so", "new-so")
	require.NoError(t, err) // proves barrier was NOT touched
}
