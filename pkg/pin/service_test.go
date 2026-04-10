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

package pin

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
)

// mockBackend implements PINBackend and FIDO2HashVerifier for testing.
type mockBackend struct {
	strategy     StrategyID
	soPIN        string
	userPIN      string
	soPINSetFlag bool
	userPINSetF  bool
	initialized  bool
	lockout      *LockoutStatus

	// Error injection.
	setSOPINErr      error
	setUserPINErr    error
	changeSOPINErr   error
	changeUserPINErr error
	verifySOPINErr   error
	verifyUserPINErr error
	resetLockoutErr  error

	// FIDO2 hash tracking.
	fido2Hash atomic.Pointer[[]byte]
}

func newMockBackend(strategy StrategyID) *mockBackend {
	return &mockBackend{
		strategy: strategy,
	}
}

func (m *mockBackend) Strategy() StrategyID { return m.strategy }

func (m *mockBackend) SetSOPIN(currentSOPIN, newSOPIN string) error {
	if m.setSOPINErr != nil {
		return m.setSOPINErr
	}
	if m.soPINSetFlag && currentSOPIN != m.soPIN {
		return ErrInvalidCurrentPIN
	}
	m.soPIN = newSOPIN
	m.soPINSetFlag = true
	m.initialized = true
	return nil
}

func (m *mockBackend) SetUserPIN(soPIN, newUserPIN string) error {
	if m.setUserPINErr != nil {
		return m.setUserPINErr
	}
	if !m.soPINSetFlag {
		return ErrSOPINRequired
	}
	if soPIN != m.soPIN {
		return ErrPINInvalid
	}
	if m.userPINSetF {
		return ErrPINAlreadySet
	}
	m.userPIN = newUserPIN
	m.userPINSetF = true
	hash := ComputeFIDO2PINHash(newUserPIN)
	m.fido2Hash.Store(&hash)
	return nil
}

func (m *mockBackend) ChangeSOPIN(currentSOPIN, newSOPIN string) error {
	if m.changeSOPINErr != nil {
		return m.changeSOPINErr
	}
	if currentSOPIN != m.soPIN {
		return ErrInvalidCurrentPIN
	}
	m.soPIN = newSOPIN
	return nil
}

func (m *mockBackend) ChangeUserPIN(currentUserPIN, newUserPIN string) error {
	if m.changeUserPINErr != nil {
		return m.changeUserPINErr
	}
	if currentUserPIN != m.userPIN {
		return ErrInvalidCurrentPIN
	}
	m.userPIN = newUserPIN
	hash := ComputeFIDO2PINHash(newUserPIN)
	m.fido2Hash.Store(&hash)
	return nil
}

func (m *mockBackend) VerifySOPIN(pin string) error {
	if m.verifySOPINErr != nil {
		return m.verifySOPINErr
	}
	if !m.soPINSetFlag {
		return ErrPINNotSet
	}
	if pin != m.soPIN {
		return ErrPINInvalid
	}
	return nil
}

func (m *mockBackend) VerifyUserPIN(pin string) error {
	if m.verifyUserPINErr != nil {
		return m.verifyUserPINErr
	}
	if !m.userPINSetF {
		return ErrPINNotSet
	}
	if pin != m.userPIN {
		return ErrPINInvalid
	}
	return nil
}

func (m *mockBackend) IsInitialized() bool { return m.initialized }
func (m *mockBackend) SOPINSet() bool      { return m.soPINSetFlag }
func (m *mockBackend) UserPINSet() bool    { return m.userPINSetF }

func (m *mockBackend) GetLockoutStatus() *LockoutStatus {
	return m.lockout
}

func (m *mockBackend) ResetLockout(soPIN string) error {
	if m.resetLockoutErr != nil {
		return m.resetLockoutErr
	}
	if soPIN != m.soPIN {
		return ErrPINInvalid
	}
	m.lockout = nil
	return nil
}

func (m *mockBackend) VerifyFIDO2Hash(hash []byte) bool {
	stored := m.fido2Hash.Load()
	if stored == nil {
		return false
	}
	return subtle.ConstantTimeCompare(*stored, hash) == 1
}

// --- Service Tests ---

func TestNewService_NilLogger(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	svc := NewService(backend, nil)
	if svc == nil {
		t.Fatal("NewService returned nil")
	}
	if svc.Strategy() != StrategySoftware {
		t.Errorf("Strategy() = %s, want %s", svc.Strategy(), StrategySoftware)
	}
}

func TestNewService_WithLogger(t *testing.T) {
	backend := newMockBackend(StrategyTPM2)
	log := slog.Default()
	svc := NewService(backend, log)
	if svc == nil {
		t.Fatal("NewService returned nil")
	}
	if svc.Backend() != backend {
		t.Error("Backend() did not return the expected backend")
	}
}

func TestService_SetSOPIN_Success(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	svc := NewService(backend, nil)

	if err := svc.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN() error = %v", err)
	}
	if !svc.SOPINSet() {
		t.Error("SOPINSet() = false after SetSOPIN")
	}
	if !svc.IsInitialized() {
		t.Error("IsInitialized() = false after SetSOPIN")
	}
}

func TestService_SetSOPIN_TooShort(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	svc := NewService(backend, nil)

	err := svc.SetSOPIN("", "short")
	if !errors.Is(err, ErrPINTooShort) {
		t.Errorf("SetSOPIN(short) = %v, want ErrPINTooShort", err)
	}
}

func TestService_SetSOPIN_BackendError(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	backend.setSOPINErr = ErrStateCorrupted
	svc := NewService(backend, nil)

	err := svc.SetSOPIN("", "sopin123456")
	if !errors.Is(err, ErrStateCorrupted) {
		t.Errorf("SetSOPIN() = %v, want ErrStateCorrupted", err)
	}
}

func TestService_SetUserPIN_Success(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	svc := NewService(backend, nil)

	// Track FIDO2 hash updates.
	var receivedHash []byte
	svc.SetFIDO2HashSetter(func(hash []byte) {
		receivedHash = make([]byte, len(hash))
		copy(receivedHash, hash)
	})

	if err := svc.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN() error = %v", err)
	}
	if err := svc.SetUserPIN("sopin123456", "userpin123456"); err != nil {
		t.Fatalf("SetUserPIN() error = %v", err)
	}

	if !svc.UserPINSet() {
		t.Error("UserPINSet() = false after SetUserPIN")
	}
	if !svc.IsPINSet() {
		t.Error("IsPINSet() = false after SetUserPIN")
	}

	// Verify FIDO2 hash was pushed.
	if receivedHash == nil {
		t.Fatal("FIDO2 hash setter was not called")
	}
	expected := ComputeFIDO2PINHash("userpin123456")
	if subtle.ConstantTimeCompare(receivedHash, expected) != 1 {
		t.Error("FIDO2 hash does not match expected value")
	}
}

func TestService_SetUserPIN_TooShort(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	svc := NewService(backend, nil)

	err := svc.SetUserPIN("sopin", "short")
	if !errors.Is(err, ErrPINTooShort) {
		t.Errorf("SetUserPIN(short) = %v, want ErrPINTooShort", err)
	}
}

func TestService_SetUserPIN_BackendError(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	backend.setUserPINErr = ErrSOPINRequired
	svc := NewService(backend, nil)

	err := svc.SetUserPIN("sopin123456", "userpin123456")
	if !errors.Is(err, ErrSOPINRequired) {
		t.Errorf("SetUserPIN() = %v, want ErrSOPINRequired", err)
	}
}

func TestService_SetUserPIN_NoFIDO2Setter(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	svc := NewService(backend, nil)
	// No FIDO2 hash setter registered — should not panic.

	if err := svc.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN() error = %v", err)
	}
	if err := svc.SetUserPIN("sopin123456", "userpin123456"); err != nil {
		t.Fatalf("SetUserPIN() error = %v", err)
	}
}

func TestService_ChangeSOPIN_Success(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	svc := NewService(backend, nil)

	if err := svc.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN() error = %v", err)
	}
	if err := svc.ChangeSOPIN("sopin123456", "newsopin123456"); err != nil {
		t.Fatalf("ChangeSOPIN() error = %v", err)
	}
}

func TestService_ChangeSOPIN_TooShort(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	svc := NewService(backend, nil)

	err := svc.ChangeSOPIN("sopin123456", "short")
	if !errors.Is(err, ErrPINTooShort) {
		t.Errorf("ChangeSOPIN(short) = %v, want ErrPINTooShort", err)
	}
}

func TestService_ChangeSOPIN_WrongCurrent(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	svc := NewService(backend, nil)

	if err := svc.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN() error = %v", err)
	}
	err := svc.ChangeSOPIN("wrongpin123456", "newsopin123456")
	if !errors.Is(err, ErrInvalidCurrentPIN) {
		t.Errorf("ChangeSOPIN(wrong) = %v, want ErrInvalidCurrentPIN", err)
	}
}

func TestService_ChangeUserPIN_Success(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	svc := NewService(backend, nil)

	var receivedHash []byte
	svc.SetFIDO2HashSetter(func(hash []byte) {
		receivedHash = make([]byte, len(hash))
		copy(receivedHash, hash)
	})

	if err := svc.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN() error = %v", err)
	}
	if err := svc.SetUserPIN("sopin123456", "userpin123456"); err != nil {
		t.Fatalf("SetUserPIN() error = %v", err)
	}
	if err := svc.ChangeUserPIN("userpin123456", "newuserpin123456"); err != nil {
		t.Fatalf("ChangeUserPIN() error = %v", err)
	}

	// Verify new FIDO2 hash.
	expected := ComputeFIDO2PINHash("newuserpin123456")
	if subtle.ConstantTimeCompare(receivedHash, expected) != 1 {
		t.Error("FIDO2 hash after change does not match new PIN")
	}
}

func TestService_ChangeUserPIN_TooShort(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	svc := NewService(backend, nil)

	err := svc.ChangeUserPIN("current123456", "short")
	if !errors.Is(err, ErrPINTooShort) {
		t.Errorf("ChangeUserPIN(short) = %v, want ErrPINTooShort", err)
	}
}

func TestService_VerifySOPIN_Success(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	svc := NewService(backend, nil)

	if err := svc.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN() error = %v", err)
	}
	if err := svc.VerifySOPIN("sopin123456"); err != nil {
		t.Errorf("VerifySOPIN() = %v, want nil", err)
	}
}

func TestService_VerifySOPIN_Invalid(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	svc := NewService(backend, nil)

	if err := svc.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN() error = %v", err)
	}
	err := svc.VerifySOPIN("wrongpin123456")
	if !errors.Is(err, ErrPINInvalid) {
		t.Errorf("VerifySOPIN(wrong) = %v, want ErrPINInvalid", err)
	}
}

func TestService_VerifySOPIN_NotSet(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	svc := NewService(backend, nil)

	err := svc.VerifySOPIN("anything")
	if !errors.Is(err, ErrPINNotSet) {
		t.Errorf("VerifySOPIN(not set) = %v, want ErrPINNotSet", err)
	}
}

func TestService_VerifyUserPIN_Success(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	svc := NewService(backend, nil)

	if err := svc.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN() error = %v", err)
	}
	if err := svc.SetUserPIN("sopin123456", "userpin123456"); err != nil {
		t.Fatalf("SetUserPIN() error = %v", err)
	}
	if err := svc.VerifyUserPIN("userpin123456"); err != nil {
		t.Errorf("VerifyUserPIN() = %v, want nil", err)
	}
}

func TestService_VerifyUserPIN_Invalid(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	svc := NewService(backend, nil)

	if err := svc.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN() error = %v", err)
	}
	if err := svc.SetUserPIN("sopin123456", "userpin123456"); err != nil {
		t.Fatalf("SetUserPIN() error = %v", err)
	}
	err := svc.VerifyUserPIN("wrongpin123456")
	if !errors.Is(err, ErrPINInvalid) {
		t.Errorf("VerifyUserPIN(wrong) = %v, want ErrPINInvalid", err)
	}
}

func TestService_VerifyUserPIN_NotSet(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	svc := NewService(backend, nil)

	err := svc.VerifyUserPIN("anything")
	if !errors.Is(err, ErrPINNotSet) {
		t.Errorf("VerifyUserPIN(not set) = %v, want ErrPINNotSet", err)
	}
}

func TestService_GetLockoutStatus_Nil(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	svc := NewService(backend, nil)

	if status := svc.GetLockoutStatus(); status != nil {
		t.Errorf("GetLockoutStatus() = %v, want nil", status)
	}
}

func TestService_GetLockoutStatus_WithLockout(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	backend.lockout = &LockoutStatus{
		FailedAttempts: 3,
		MaxAttempts:    5,
		IsLocked:       false,
	}
	svc := NewService(backend, nil)

	status := svc.GetLockoutStatus()
	if status == nil {
		t.Fatal("GetLockoutStatus() = nil, want lockout info")
	}
	if status.FailedAttempts != 3 {
		t.Errorf("FailedAttempts = %d, want 3", status.FailedAttempts)
	}
}

func TestService_ResetLockout_Success(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	svc := NewService(backend, nil)

	if err := svc.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN() error = %v", err)
	}
	backend.lockout = &LockoutStatus{IsLocked: true}
	if err := svc.ResetLockout("sopin123456"); err != nil {
		t.Errorf("ResetLockout() = %v, want nil", err)
	}
	if backend.lockout != nil {
		t.Error("lockout should be nil after reset")
	}
}

func TestService_ResetLockout_WrongSOPIN(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	svc := NewService(backend, nil)

	if err := svc.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN() error = %v", err)
	}
	err := svc.ResetLockout("wrongpin123456")
	if !errors.Is(err, ErrPINInvalid) {
		t.Errorf("ResetLockout(wrong) = %v, want ErrPINInvalid", err)
	}
}

func TestService_VerifyFIDO2Hash_Success(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	svc := NewService(backend, nil)

	if err := svc.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN() error = %v", err)
	}
	if err := svc.SetUserPIN("sopin123456", "userpin123456"); err != nil {
		t.Fatalf("SetUserPIN() error = %v", err)
	}

	hash := ComputeFIDO2PINHash("userpin123456")
	if !svc.VerifyFIDO2Hash(hash) {
		t.Error("VerifyFIDO2Hash() = false, want true")
	}
}

func TestService_VerifyFIDO2Hash_WrongHash(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	svc := NewService(backend, nil)

	if err := svc.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN() error = %v", err)
	}
	if err := svc.SetUserPIN("sopin123456", "userpin123456"); err != nil {
		t.Fatalf("SetUserPIN() error = %v", err)
	}

	wrongHash := ComputeFIDO2PINHash("wrongpin123456")
	if svc.VerifyFIDO2Hash(wrongHash) {
		t.Error("VerifyFIDO2Hash(wrong) = true, want false")
	}
}

func TestService_VerifyFIDO2Hash_WrongLength(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	svc := NewService(backend, nil)

	if svc.VerifyFIDO2Hash([]byte{1, 2, 3}) {
		t.Error("VerifyFIDO2Hash(short) = true, want false")
	}
}

func TestService_VerifyFIDO2Hash_NoBackendSupport(t *testing.T) {
	// Backend that doesn't implement FIDO2HashVerifier.
	backend := &minimalBackend{}
	svc := NewService(backend, nil)

	hash := make([]byte, FIDO2PINHashSize)
	if svc.VerifyFIDO2Hash(hash) {
		t.Error("VerifyFIDO2Hash(no verifier) = true, want false")
	}
}

func TestComputeFIDO2PINHash(t *testing.T) {
	hash := ComputeFIDO2PINHash("testpin123456")
	if len(hash) != FIDO2PINHashSize {
		t.Fatalf("ComputeFIDO2PINHash() len = %d, want %d", len(hash), FIDO2PINHashSize)
	}

	// Verify it matches SHA-256[:16].
	fullHash := sha256.Sum256([]byte("testpin123456"))
	if subtle.ConstantTimeCompare(hash, fullHash[:FIDO2PINHashSize]) != 1 {
		t.Error("ComputeFIDO2PINHash does not match SHA-256[:16]")
	}
}

func TestComputeFIDO2PINHash_Deterministic(t *testing.T) {
	hash1 := ComputeFIDO2PINHash("deterministic_test")
	hash2 := ComputeFIDO2PINHash("deterministic_test")
	if subtle.ConstantTimeCompare(hash1, hash2) != 1 {
		t.Error("ComputeFIDO2PINHash is not deterministic")
	}
}

func TestVerifyFIDO2PINHash_Match(t *testing.T) {
	hash := ComputeFIDO2PINHash("testpin123456")
	if !VerifyFIDO2PINHash(hash, hash) {
		t.Error("VerifyFIDO2PINHash(same) = false, want true")
	}
}

func TestVerifyFIDO2PINHash_Mismatch(t *testing.T) {
	hash1 := ComputeFIDO2PINHash("testpin123456")
	hash2 := ComputeFIDO2PINHash("otherpin123456")
	if VerifyFIDO2PINHash(hash1, hash2) {
		t.Error("VerifyFIDO2PINHash(different) = true, want false")
	}
}

func TestVerifyFIDO2PINHash_WrongSize(t *testing.T) {
	hash := ComputeFIDO2PINHash("testpin123456")
	if VerifyFIDO2PINHash(hash, []byte{1, 2, 3}) {
		t.Error("VerifyFIDO2PINHash(short) = true, want false")
	}
	if VerifyFIDO2PINHash([]byte{1, 2, 3}, hash) {
		t.Error("VerifyFIDO2PINHash(short expected) = true, want false")
	}
}

func TestService_FIDO2HashSetterCalledOnChange(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	svc := NewService(backend, nil)

	var callCount int
	svc.SetFIDO2HashSetter(func(hash []byte) {
		callCount++
	})

	if err := svc.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN() error = %v", err)
	}
	if err := svc.SetUserPIN("sopin123456", "userpin123456"); err != nil {
		t.Fatalf("SetUserPIN() error = %v", err)
	}
	if callCount != 1 {
		t.Errorf("FIDO2 hash setter call count = %d after SetUserPIN, want 1", callCount)
	}

	if err := svc.ChangeUserPIN("userpin123456", "newuserpin123456"); err != nil {
		t.Fatalf("ChangeUserPIN() error = %v", err)
	}
	if callCount != 2 {
		t.Errorf("FIDO2 hash setter call count = %d after ChangeUserPIN, want 2", callCount)
	}
}

func TestService_FIDO2HashNotCalledOnError(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	backend.setUserPINErr = ErrSOPINRequired
	svc := NewService(backend, nil)

	var callCount int
	svc.SetFIDO2HashSetter(func(hash []byte) {
		callCount++
	})

	_ = svc.SetUserPIN("sopin", "userpin123456")
	if callCount != 0 {
		t.Errorf("FIDO2 hash setter called %d times on error, want 0", callCount)
	}
}

// TestService_VerifyUserPIN_PushesFIDO2Hash is a regression test ensuring that
// VerifyUserPIN pushes the FIDO2 hash to the authenticator on successful
// verification. A previous version returned backend.VerifyUserPIN directly
// without calling pushFIDO2Hash, which broke CTAP2 PIN verification after
// application restart.
func TestService_VerifyUserPIN_PushesFIDO2Hash(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	svc := NewService(backend, nil)

	var receivedHash []byte
	var callCount int
	svc.SetFIDO2HashSetter(func(hash []byte) {
		callCount++
		receivedHash = make([]byte, len(hash))
		copy(receivedHash, hash)
	})

	// Initialize: set SO PIN, then set user PIN.
	if err := svc.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN() error = %v", err)
	}
	if err := svc.SetUserPIN("sopin123456", "userpin123456"); err != nil {
		t.Fatalf("SetUserPIN() error = %v", err)
	}

	// SetUserPIN should have called the setter once; reset tracking.
	callCount = 0
	receivedHash = nil

	// VerifyUserPIN must push the FIDO2 hash on success.
	if err := svc.VerifyUserPIN("userpin123456"); err != nil {
		t.Fatalf("VerifyUserPIN() error = %v", err)
	}

	if callCount != 1 {
		t.Fatalf("FIDO2 hash setter call count = %d after VerifyUserPIN, want 1", callCount)
	}
	if receivedHash == nil {
		t.Fatal("FIDO2 hash setter was not called with hash data")
	}

	expected := ComputeFIDO2PINHash("userpin123456")
	if subtle.ConstantTimeCompare(receivedHash, expected) != 1 {
		t.Error("FIDO2 hash pushed by VerifyUserPIN does not match expected value")
	}
}

// TestService_VerifyUserPIN_DoesNotPushOnFailure is a regression test ensuring
// that VerifyUserPIN does NOT push a FIDO2 hash when verification fails. Only
// a successful verification should update the authenticator's PIN hash.
func TestService_VerifyUserPIN_DoesNotPushOnFailure(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	svc := NewService(backend, nil)

	var callCount int
	svc.SetFIDO2HashSetter(func(hash []byte) {
		callCount++
	})

	// Initialize: set SO PIN, then set user PIN.
	if err := svc.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN() error = %v", err)
	}
	if err := svc.SetUserPIN("sopin123456", "userpin123456"); err != nil {
		t.Fatalf("SetUserPIN() error = %v", err)
	}

	// SetUserPIN should have called the setter once; reset tracking.
	callCount = 0

	// VerifyUserPIN with wrong PIN must NOT push a FIDO2 hash.
	err := svc.VerifyUserPIN("wrongpin123456")
	if !errors.Is(err, ErrPINInvalid) {
		t.Fatalf("VerifyUserPIN(wrong) = %v, want ErrPINInvalid", err)
	}

	if callCount != 0 {
		t.Errorf("FIDO2 hash setter called %d times on failed VerifyUserPIN, want 0", callCount)
	}
}

// minimalBackend implements PINBackend without FIDO2HashVerifier.
type minimalBackend struct{}

func (m *minimalBackend) Strategy() StrategyID             { return StrategySoftware }
func (m *minimalBackend) SetSOPIN(_, _ string) error       { return nil }
func (m *minimalBackend) SetUserPIN(_, _ string) error     { return nil }
func (m *minimalBackend) ChangeSOPIN(_, _ string) error    { return nil }
func (m *minimalBackend) ChangeUserPIN(_, _ string) error  { return nil }
func (m *minimalBackend) VerifySOPIN(_ string) error       { return nil }
func (m *minimalBackend) VerifyUserPIN(_ string) error     { return nil }
func (m *minimalBackend) IsInitialized() bool              { return false }
func (m *minimalBackend) SOPINSet() bool                   { return false }
func (m *minimalBackend) UserPINSet() bool                 { return false }
func (m *minimalBackend) GetLockoutStatus() *LockoutStatus { return nil }
func (m *minimalBackend) ResetLockout(_ string) error      { return nil }
