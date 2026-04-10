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
	"crypto/subtle"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

// mockPlatformAuth implements PlatformAuthProvider for TPM2Backend unit tests.
// It simulates a TPM platform key store backed by a single SRK auth value.
// Thread safety is provided by sync.RWMutex for the auth value and
// atomic.Bool for the provisioned state.
type mockPlatformAuth struct {
	mu        sync.RWMutex
	authValue string

	provisioned atomic.Bool

	failedAttempts int
	maxFail        int
	interval       int
	recovery       int

	lockoutInfoErr error
	daResetErr     error
	verifyErr      error
	changeErr      error

	verifyCalls  atomic.Int32
	changeCalls  atomic.Int32
	daResetCalls atomic.Int32
}

func newMockPlatformAuth(authValue string, provisioned bool) *mockPlatformAuth {
	m := &mockPlatformAuth{
		authValue: authValue,
		maxFail:   10,
	}
	m.provisioned.Store(provisioned)
	return m
}

func (m *mockPlatformAuth) VerifyAuth(pin string) error {
	m.verifyCalls.Add(1)
	if m.verifyErr != nil {
		return m.verifyErr
	}
	m.mu.RLock()
	match := subtle.ConstantTimeCompare([]byte(pin), []byte(m.authValue)) == 1
	m.mu.RUnlock()
	if !match {
		return errors.New("TPM_RC_BAD_AUTH (session 1): authorization failure without DA implications")
	}
	return nil
}

func (m *mockPlatformAuth) ChangeAuth(currentPIN, newPIN string) error {
	m.changeCalls.Add(1)
	if m.changeErr != nil {
		return m.changeErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if subtle.ConstantTimeCompare([]byte(currentPIN), []byte(m.authValue)) != 1 {
		return errors.New("TPM_RC_BAD_AUTH (session 1): authorization failure without DA implications")
	}
	m.authValue = newPIN
	return nil
}

func (m *mockPlatformAuth) GetLockoutInfo() (int, int, int, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.lockoutInfoErr != nil {
		return 0, 0, 0, 0, m.lockoutInfoErr
	}
	return m.failedAttempts, m.maxFail, m.interval, m.recovery, nil
}

func (m *mockPlatformAuth) DictionaryAttackLockoutReset(lockoutAuth []byte) error {
	m.daResetCalls.Add(1)
	if m.daResetErr != nil {
		return m.daResetErr
	}
	m.mu.Lock()
	m.failedAttempts = 0
	m.mu.Unlock()
	return nil
}

func (m *mockPlatformAuth) IsProvisioned() bool {
	return m.provisioned.Load()
}

func (m *mockPlatformAuth) setLockoutInfo(failed, maxFail, interval, recovery int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failedAttempts = failed
	m.maxFail = maxFail
	m.interval = interval
	m.recovery = recovery
}

func newProvisionedTPM2Backend(t *testing.T, userPIN string) (*TPM2Backend, *mockPlatformAuth) {
	t.Helper()
	mock := newMockPlatformAuth(userPIN, true)
	b := NewTPM2Backend(mock)
	if err := b.SetUserPIN("", userPIN); err != nil {
		t.Fatalf("setup: SetUserPIN failed: %v", err)
	}
	return b, mock
}

func TestTPM2Backend_NewTPM2Backend_Provisioned(t *testing.T) {
	mock := newMockPlatformAuth("srk-password", true)
	b := NewTPM2Backend(mock)
	if !b.userPINSet.Load() {
		t.Fatal("userPINSet should be true when platform is provisioned")
	}
	if !b.IsInitialized() {
		t.Fatal("IsInitialized should be true when platform is provisioned")
	}
}

func TestTPM2Backend_NewTPM2Backend_Unprovisioned(t *testing.T) {
	mock := newMockPlatformAuth("", false)
	b := NewTPM2Backend(mock)
	if b.userPINSet.Load() {
		t.Fatal("userPINSet should be false when platform is not provisioned")
	}
	if b.IsInitialized() {
		t.Fatal("IsInitialized should be false when platform is not provisioned")
	}
}

func TestTPM2Backend_Strategy_ReturnsTPM2(t *testing.T) {
	b := NewTPM2Backend(newMockPlatformAuth("", false))
	if got := b.Strategy(); got != StrategyTPM2 {
		t.Fatalf("Strategy() = %q, want %q", got, StrategyTPM2)
	}
}

func TestTPM2Backend_Strategy_ReturnsTPM2_Provisioned(t *testing.T) {
	b := NewTPM2Backend(newMockPlatformAuth("pin", true))
	if got := b.Strategy(); got != StrategyTPM2 {
		t.Fatalf("Strategy() = %q, want %q", got, StrategyTPM2)
	}
}

func TestTPM2Backend_SetSOPIN_ReturnsNotSet(t *testing.T) {
	b := NewTPM2Backend(newMockPlatformAuth("", false))
	if err := b.SetSOPIN("", "123456"); !errors.Is(err, ErrPINNotSet) {
		t.Fatalf("SetSOPIN() = %v, want %v", err, ErrPINNotSet)
	}
}

func TestTPM2Backend_SetSOPIN_WithValues_ReturnsNotSet(t *testing.T) {
	b := NewTPM2Backend(newMockPlatformAuth("pin123", true))
	if err := b.SetSOPIN("old-pin", "new-pin-123"); !errors.Is(err, ErrPINNotSet) {
		t.Fatalf("SetSOPIN() = %v, want %v", err, ErrPINNotSet)
	}
}

func TestTPM2Backend_ChangeSOPIN_ReturnsNotSet(t *testing.T) {
	b := NewTPM2Backend(newMockPlatformAuth("", false))
	if err := b.ChangeSOPIN("old-pin", "new-pin"); !errors.Is(err, ErrPINNotSet) {
		t.Fatalf("ChangeSOPIN() = %v, want %v", err, ErrPINNotSet)
	}
}

func TestTPM2Backend_ChangeSOPIN_Provisioned_ReturnsNotSet(t *testing.T) {
	b := NewTPM2Backend(newMockPlatformAuth("pin123", true))
	if err := b.ChangeSOPIN("pin123", "new-pin-123"); !errors.Is(err, ErrPINNotSet) {
		t.Fatalf("ChangeSOPIN() = %v, want %v", err, ErrPINNotSet)
	}
}

func TestTPM2Backend_VerifySOPIN_ReturnsNotSet(t *testing.T) {
	b := NewTPM2Backend(newMockPlatformAuth("", false))
	if err := b.VerifySOPIN("123456"); !errors.Is(err, ErrPINNotSet) {
		t.Fatalf("VerifySOPIN() = %v, want %v", err, ErrPINNotSet)
	}
}

func TestTPM2Backend_VerifySOPIN_Provisioned_ReturnsNotSet(t *testing.T) {
	b := NewTPM2Backend(newMockPlatformAuth("pin123", true))
	if err := b.VerifySOPIN("pin123"); !errors.Is(err, ErrPINNotSet) {
		t.Fatalf("VerifySOPIN() = %v, want %v", err, ErrPINNotSet)
	}
}

func TestTPM2Backend_SOPINSet_AlwaysFalse_Provisioned(t *testing.T) {
	b := NewTPM2Backend(newMockPlatformAuth("pin123", true))
	if b.SOPINSet() {
		t.Fatal("SOPINSet() should always return false for TPM2Backend")
	}
}

func TestTPM2Backend_SOPINSet_AlwaysFalse_Unprovisioned(t *testing.T) {
	b := NewTPM2Backend(newMockPlatformAuth("", false))
	if b.SOPINSet() {
		t.Fatal("SOPINSet() should always return false for TPM2Backend")
	}
}

func TestTPM2Backend_SetUserPIN_Success(t *testing.T) {
	mock := newMockPlatformAuth("user-pin-123", true)
	b := NewTPM2Backend(mock)
	if err := b.SetUserPIN("ignored-so-pin", "user-pin-123"); err != nil {
		t.Fatalf("SetUserPIN() = %v, want nil", err)
	}
	if !b.UserPINSet() {
		t.Fatal("UserPINSet should be true after successful SetUserPIN")
	}
	if mock.verifyCalls.Load() != 1 {
		t.Fatalf("VerifyAuth called %d times, want 1", mock.verifyCalls.Load())
	}
}

func TestTPM2Backend_SetUserPIN_WrongPIN(t *testing.T) {
	mock := newMockPlatformAuth("correct-pin", true)
	b := NewTPM2Backend(mock)
	err := b.SetUserPIN("ignored", "wrong-pin-value")
	if !errors.Is(err, ErrPINInvalid) {
		t.Fatalf("SetUserPIN() = %v, want %v", err, ErrPINInvalid)
	}
}

func TestTPM2Backend_SetUserPIN_TooShort(t *testing.T) {
	b := NewTPM2Backend(newMockPlatformAuth("pin", true))
	if err := b.SetUserPIN("ignored", "12345"); !errors.Is(err, ErrPINTooShort) {
		t.Fatalf("SetUserPIN() = %v, want %v", err, ErrPINTooShort)
	}
}

func TestTPM2Backend_SetUserPIN_ExactMinLength(t *testing.T) {
	mock := newMockPlatformAuth("abcdef", true)
	b := NewTPM2Backend(mock)
	if err := b.SetUserPIN("ignored", "abcdef"); err != nil {
		t.Fatalf("SetUserPIN() with exact min length: %v", err)
	}
}

func TestTPM2Backend_SetUserPIN_OneUnderMinLength(t *testing.T) {
	b := NewTPM2Backend(newMockPlatformAuth("", true))
	if err := b.SetUserPIN("ignored", "abcde"); !errors.Is(err, ErrPINTooShort) {
		t.Fatalf("SetUserPIN() = %v, want %v", err, ErrPINTooShort)
	}
}

func TestTPM2Backend_SetUserPIN_EmptyPIN(t *testing.T) {
	b := NewTPM2Backend(newMockPlatformAuth("", true))
	if err := b.SetUserPIN("ignored", ""); !errors.Is(err, ErrPINTooShort) {
		t.Fatalf("SetUserPIN() = %v, want %v", err, ErrPINTooShort)
	}
}

func TestTPM2Backend_SetUserPIN_LongPIN(t *testing.T) {
	longPIN := "this-is-a-very-long-user-pin-for-testing-purposes-abcdefghijklmnopqrstuvwxyz"
	mock := newMockPlatformAuth(longPIN, true)
	b := NewTPM2Backend(mock)
	if err := b.SetUserPIN("ignored", longPIN); err != nil {
		t.Fatalf("SetUserPIN with long PIN: %v", err)
	}
	if err := b.VerifyUserPIN(longPIN); err != nil {
		t.Fatalf("VerifyUserPIN with long PIN: %v", err)
	}
}

func TestTPM2Backend_SetUserPIN_CachesFIDO2Hash(t *testing.T) {
	mock := newMockPlatformAuth("user-pin-123", true)
	b := NewTPM2Backend(mock)
	if err := b.SetUserPIN("ignored", "user-pin-123"); err != nil {
		t.Fatalf("SetUserPIN() = %v", err)
	}
	expected := ComputeFIDO2PINHash("user-pin-123")
	if !b.VerifyFIDO2Hash(expected) {
		t.Fatal("FIDO2 hash should match after SetUserPIN")
	}
}

func TestTPM2Backend_SetUserPIN_NonAuthPlatformError(t *testing.T) {
	mock := newMockPlatformAuth("", true)
	mock.verifyErr = errors.New("tpm device i/o error")
	b := NewTPM2Backend(mock)
	err := b.SetUserPIN("ignored", "any-valid-pin")
	if err == nil || err.Error() != "tpm device i/o error" {
		t.Fatalf("SetUserPIN() = %v, want 'tpm device i/o error'", err)
	}
}

func TestTPM2Backend_SetUserPIN_SOPINParamIgnored(t *testing.T) {
	mock := newMockPlatformAuth("correct-pin", true)
	b := NewTPM2Backend(mock)
	if err := b.SetUserPIN("totally-wrong-so-pin", "correct-pin"); err != nil {
		t.Fatalf("SetUserPIN should ignore soPIN param, got: %v", err)
	}
}

func TestTPM2Backend_VerifyUserPIN_Success(t *testing.T) {
	b, _ := newProvisionedTPM2Backend(t, "user-pin")
	if err := b.VerifyUserPIN("user-pin"); err != nil {
		t.Fatalf("VerifyUserPIN() = %v, want nil", err)
	}
}

func TestTPM2Backend_VerifyUserPIN_WrongPIN_WithDAStatus(t *testing.T) {
	b, mock := newProvisionedTPM2Backend(t, "correct-pin")
	mock.setLockoutInfo(3, 10, 0, 60)
	err := b.VerifyUserPIN("wrong-pin-value")
	if err == nil {
		t.Fatal("VerifyUserPIN() should fail with wrong PIN")
	}
	var pinInvalidStatus *ErrPINInvalidWithStatus
	if !errors.As(err, &pinInvalidStatus) {
		t.Fatalf("expected ErrPINInvalidWithStatus, got: %T %v", err, err)
	}
	if pinInvalidStatus.Status.FailedAttempts != 3 {
		t.Fatalf("FailedAttempts = %d, want 3", pinInvalidStatus.Status.FailedAttempts)
	}
	if pinInvalidStatus.Status.MaxAttempts != 10 {
		t.Fatalf("MaxAttempts = %d, want 10", pinInvalidStatus.Status.MaxAttempts)
	}
}

func TestTPM2Backend_VerifyUserPIN_NotSet(t *testing.T) {
	b := NewTPM2Backend(newMockPlatformAuth("pin", false))
	if err := b.VerifyUserPIN("any-pin-here"); !errors.Is(err, ErrPINNotSet) {
		t.Fatalf("VerifyUserPIN() = %v, want %v", err, ErrPINNotSet)
	}
}

func TestTPM2Backend_VerifyUserPIN_LazyFIDO2HashCaching(t *testing.T) {
	mock := newMockPlatformAuth("srk-auth-val", true)
	b := NewTPM2Backend(mock)
	hash := ComputeFIDO2PINHash("srk-auth-val")
	if b.VerifyFIDO2Hash(hash) {
		t.Fatal("FIDO2 hash should not be cached before VerifyUserPIN")
	}
	if err := b.VerifyUserPIN("srk-auth-val"); err != nil {
		t.Fatalf("VerifyUserPIN() = %v", err)
	}
	if !b.VerifyFIDO2Hash(hash) {
		t.Fatal("FIDO2 hash should be cached after successful VerifyUserPIN")
	}
}

func TestTPM2Backend_VerifyUserPIN_NonAuthPlatformError(t *testing.T) {
	b, mock := newProvisionedTPM2Backend(t, "user-pin")
	mock.verifyErr = errors.New("tpm transport timeout")
	err := b.VerifyUserPIN("user-pin")
	if err == nil || err.Error() != "tpm transport timeout" {
		t.Fatalf("VerifyUserPIN() = %v, want 'tpm transport timeout'", err)
	}
}

func TestTPM2Backend_VerifyUserPIN_WrongPIN_DeviceLocked(t *testing.T) {
	b, mock := newProvisionedTPM2Backend(t, "correct-pin")
	mock.setLockoutInfo(10, 10, 0, 300)
	err := b.VerifyUserPIN("wrong-pin-value")
	if err == nil {
		t.Fatal("VerifyUserPIN() should fail with wrong PIN")
	}
	var tpmLocked *ErrTPMLocked
	if !errors.As(err, &tpmLocked) {
		t.Fatalf("expected ErrTPMLocked, got: %T %v", err, err)
	}
	if tpmLocked.Status.RecoverySeconds != 300 {
		t.Fatalf("RecoverySeconds = %d, want 300", tpmLocked.Status.RecoverySeconds)
	}
	if !tpmLocked.Status.IsLocked {
		t.Fatal("status should be locked")
	}
}

func TestTPM2Backend_VerifyUserPIN_WrongPIN_LockoutInfoFails(t *testing.T) {
	b, mock := newProvisionedTPM2Backend(t, "correct-pin")
	mock.lockoutInfoErr = errors.New("tpm capability query failed")
	err := b.VerifyUserPIN("wrong-pin-value")
	if !errors.Is(err, ErrPINInvalid) {
		t.Fatalf("expected ErrPINInvalid when lockout info fails, got: %v", err)
	}
}

func TestTPM2Backend_VerifyUserPIN_FIDO2HashNotRecachedIfPresent(t *testing.T) {
	b, _ := newProvisionedTPM2Backend(t, "user-pin")
	guard1 := b.fido2Guard.Load()
	if guard1 == nil {
		t.Fatal("FIDO2 guard should be set after SetUserPIN")
	}
	if err := b.VerifyUserPIN("user-pin"); err != nil {
		t.Fatalf("VerifyUserPIN: %v", err)
	}
	guard2 := b.fido2Guard.Load()
	if guard1 != guard2 {
		t.Fatal("FIDO2 guard should not be replaced when already cached")
	}
}

func TestTPM2Backend_ChangeUserPIN_Success(t *testing.T) {
	b, _ := newProvisionedTPM2Backend(t, "old-user-pin")
	if err := b.ChangeUserPIN("old-user-pin", "new-user-pin"); err != nil {
		t.Fatalf("ChangeUserPIN() = %v, want nil", err)
	}
	if err := b.VerifyUserPIN("new-user-pin"); err != nil {
		t.Fatalf("VerifyUserPIN(new) = %v", err)
	}
}

func TestTPM2Backend_ChangeUserPIN_WrongCurrent(t *testing.T) {
	b, mock := newProvisionedTPM2Backend(t, "correct-pin")
	mock.setLockoutInfo(1, 10, 0, 60)
	err := b.ChangeUserPIN("wrong-current", "new-pin-123")
	if err == nil {
		t.Fatal("ChangeUserPIN() should fail with wrong current PIN")
	}
	var pinInvalidStatus *ErrPINInvalidWithStatus
	if !errors.As(err, &pinInvalidStatus) {
		t.Fatalf("expected ErrPINInvalidWithStatus, got: %T %v", err, err)
	}
}

func TestTPM2Backend_ChangeUserPIN_TooShort(t *testing.T) {
	b, _ := newProvisionedTPM2Backend(t, "correct-pin")
	if err := b.ChangeUserPIN("correct-pin", "short"); !errors.Is(err, ErrPINTooShort) {
		t.Fatalf("ChangeUserPIN() = %v, want %v", err, ErrPINTooShort)
	}
}

func TestTPM2Backend_ChangeUserPIN_ExactMinLength(t *testing.T) {
	b, _ := newProvisionedTPM2Backend(t, "user-pin")
	if err := b.ChangeUserPIN("user-pin", "abcdef"); err != nil {
		t.Fatalf("ChangeUserPIN with exact min length: %v", err)
	}
}

func TestTPM2Backend_ChangeUserPIN_NotSet(t *testing.T) {
	b := NewTPM2Backend(newMockPlatformAuth("pin", false))
	if err := b.ChangeUserPIN("any-pin", "new-pin-123"); !errors.Is(err, ErrPINNotSet) {
		t.Fatalf("ChangeUserPIN() = %v, want %v", err, ErrPINNotSet)
	}
}

func TestTPM2Backend_ChangeUserPIN_DALockoutOnFailure(t *testing.T) {
	b, mock := newProvisionedTPM2Backend(t, "correct-pin")
	mock.setLockoutInfo(5, 5, 0, 120)
	err := b.ChangeUserPIN("wrong-current", "new-pin-123")
	var tpmLocked *ErrTPMLocked
	if !errors.As(err, &tpmLocked) {
		t.Fatalf("expected ErrTPMLocked when DA lockout reached, got: %T %v", err, err)
	}
	if !tpmLocked.Status.IsLocked {
		t.Fatal("lockout status should be locked")
	}
}

func TestTPM2Backend_ChangeUserPIN_NonAuthPlatformError(t *testing.T) {
	b, mock := newProvisionedTPM2Backend(t, "user-pin")
	mock.changeErr = errors.New("tpm bus error")
	err := b.ChangeUserPIN("user-pin", "new-pin-123")
	if err == nil || err.Error() != "tpm bus error" {
		t.Fatalf("ChangeUserPIN() = %v, want 'tpm bus error'", err)
	}
}

func TestTPM2Backend_ChangeUserPIN_UpdatesFIDO2Hash(t *testing.T) {
	b, _ := newProvisionedTPM2Backend(t, "old-user-pin")
	oldHash := ComputeFIDO2PINHash("old-user-pin")
	if !b.VerifyFIDO2Hash(oldHash) {
		t.Fatal("FIDO2 hash should match old PIN before change")
	}
	if err := b.ChangeUserPIN("old-user-pin", "new-user-pin"); err != nil {
		t.Fatalf("ChangeUserPIN() = %v", err)
	}
	newHash := ComputeFIDO2PINHash("new-user-pin")
	if !b.VerifyFIDO2Hash(newHash) {
		t.Fatal("FIDO2 hash should match new PIN after change")
	}
	if b.VerifyFIDO2Hash(oldHash) {
		t.Fatal("FIDO2 hash should not match old PIN after change")
	}
}

func TestTPM2Backend_IsInitialized_DelegatesToProvider(t *testing.T) {
	mock := newMockPlatformAuth("", false)
	b := NewTPM2Backend(mock)
	if b.IsInitialized() {
		t.Fatal("IsInitialized should be false when not provisioned")
	}
	mock.provisioned.Store(true)
	if !b.IsInitialized() {
		t.Fatal("IsInitialized should be true when provisioned")
	}
}

func TestTPM2Backend_IsInitialized_AlwaysDelegates(t *testing.T) {
	mock := newMockPlatformAuth("pin", true)
	b := NewTPM2Backend(mock)
	if !b.IsInitialized() {
		t.Fatal("IsInitialized should be true when provisioned")
	}
	mock.provisioned.Store(false)
	if b.IsInitialized() {
		t.Fatal("IsInitialized should reflect current provider state")
	}
}

func TestTPM2Backend_UserPINSet_BeforeAndAfterSetup(t *testing.T) {
	b := NewTPM2Backend(newMockPlatformAuth("pin-value", false))
	if b.UserPINSet() {
		t.Fatal("UserPINSet should be false before provisioning")
	}
	b2 := NewTPM2Backend(newMockPlatformAuth("pin-value", true))
	if !b2.UserPINSet() {
		t.Fatal("UserPINSet should be true when provisioned")
	}
}

func TestTPM2Backend_UserPINSet_AfterSetUserPIN(t *testing.T) {
	mock := newMockPlatformAuth("pin-value", true)
	b := NewTPM2Backend(mock)
	if err := b.SetUserPIN("", "pin-value"); err != nil {
		t.Fatalf("SetUserPIN: %v", err)
	}
	if !b.UserPINSet() {
		t.Fatal("UserPINSet should be true after SetUserPIN")
	}
}

func TestTPM2Backend_GetLockoutStatus_Normal(t *testing.T) {
	mock := newMockPlatformAuth("", true)
	mock.setLockoutInfo(2, 10, 30, 60)
	b := NewTPM2Backend(mock)
	status := b.GetLockoutStatus()
	if status == nil {
		t.Fatal("GetLockoutStatus returned nil")
	}
	if status.FailedAttempts != 2 {
		t.Fatalf("FailedAttempts = %d, want 2", status.FailedAttempts)
	}
	if status.MaxAttempts != 10 {
		t.Fatalf("MaxAttempts = %d, want 10", status.MaxAttempts)
	}
	if status.IsLocked {
		t.Fatal("IsLocked should be false when failedAttempts < maxFail")
	}
	if status.RecoverySeconds != 60 {
		t.Fatalf("RecoverySeconds = %d, want 60", status.RecoverySeconds)
	}
}

func TestTPM2Backend_GetLockoutStatus_Locked(t *testing.T) {
	mock := newMockPlatformAuth("", true)
	mock.setLockoutInfo(10, 10, 0, 120)
	b := NewTPM2Backend(mock)
	status := b.GetLockoutStatus()
	if status == nil {
		t.Fatal("GetLockoutStatus returned nil")
	}
	if !status.IsLocked {
		t.Fatal("IsLocked should be true when failedAttempts >= maxFail")
	}
}

func TestTPM2Backend_GetLockoutStatus_ExceedsMax(t *testing.T) {
	mock := newMockPlatformAuth("", true)
	mock.setLockoutInfo(15, 10, 0, 120)
	b := NewTPM2Backend(mock)
	status := b.GetLockoutStatus()
	if status == nil {
		t.Fatal("GetLockoutStatus returned nil")
	}
	if !status.IsLocked {
		t.Fatal("IsLocked should be true when failedAttempts > maxFail")
	}
}

func TestTPM2Backend_GetLockoutStatus_ZeroMaxFail(t *testing.T) {
	mock := newMockPlatformAuth("", true)
	mock.setLockoutInfo(5, 0, 0, 0)
	b := NewTPM2Backend(mock)
	status := b.GetLockoutStatus()
	if status == nil {
		t.Fatal("GetLockoutStatus returned nil")
	}
	if status.IsLocked {
		t.Fatal("IsLocked should be false when maxFail is 0 (DA disabled)")
	}
}

func TestTPM2Backend_GetLockoutStatus_TPMError(t *testing.T) {
	mock := newMockPlatformAuth("", true)
	mock.lockoutInfoErr = errors.New("tpm not available")
	b := NewTPM2Backend(mock)
	if status := b.GetLockoutStatus(); status != nil {
		t.Fatal("GetLockoutStatus should return nil on TPM error")
	}
}

func TestTPM2Backend_GetLockoutStatus_ZeroAttempts(t *testing.T) {
	mock := newMockPlatformAuth("", true)
	mock.setLockoutInfo(0, 10, 0, 0)
	b := NewTPM2Backend(mock)
	status := b.GetLockoutStatus()
	if status == nil {
		t.Fatal("GetLockoutStatus returned nil")
	}
	if status.FailedAttempts != 0 {
		t.Fatalf("FailedAttempts = %d, want 0", status.FailedAttempts)
	}
	if status.IsLocked {
		t.Fatal("IsLocked should be false with zero failed attempts")
	}
}

func TestTPM2Backend_ResetLockout_Success(t *testing.T) {
	mock := newMockPlatformAuth("", true)
	mock.setLockoutInfo(8, 10, 0, 0)
	b := NewTPM2Backend(mock)
	if err := b.ResetLockout("lockout-auth"); err != nil {
		t.Fatalf("ResetLockout() = %v, want nil", err)
	}
	if mock.daResetCalls.Load() != 1 {
		t.Fatalf("DictionaryAttackLockoutReset called %d times, want 1", mock.daResetCalls.Load())
	}
}

func TestTPM2Backend_ResetLockout_Error(t *testing.T) {
	mock := newMockPlatformAuth("", true)
	mock.daResetErr = errors.New("da reset failed")
	b := NewTPM2Backend(mock)
	err := b.ResetLockout("lockout-auth")
	if err == nil || err.Error() != "da reset failed" {
		t.Fatalf("ResetLockout() = %v, want 'da reset failed'", err)
	}
}

func TestTPM2Backend_ResetLockout_PassesLockoutAuth(t *testing.T) {
	mock := newMockPlatformAuth("", true)
	b := NewTPM2Backend(mock)
	if err := b.ResetLockout("my-lockout-auth"); err != nil {
		t.Fatalf("ResetLockout() = %v", err)
	}
	if mock.daResetCalls.Load() != 1 {
		t.Fatalf("expected 1 DA reset call, got %d", mock.daResetCalls.Load())
	}
}

func TestTPM2Backend_VerifyFIDO2Hash_Success(t *testing.T) {
	b, _ := newProvisionedTPM2Backend(t, "user-pin")
	hash := ComputeFIDO2PINHash("user-pin")
	if !b.VerifyFIDO2Hash(hash) {
		t.Fatal("VerifyFIDO2Hash should return true for correct hash")
	}
}

func TestTPM2Backend_VerifyFIDO2Hash_WrongHash(t *testing.T) {
	b, _ := newProvisionedTPM2Backend(t, "user-pin")
	if b.VerifyFIDO2Hash(ComputeFIDO2PINHash("wrong-pin")) {
		t.Fatal("VerifyFIDO2Hash should return false for wrong hash")
	}
}

func TestTPM2Backend_VerifyFIDO2Hash_NoCachedHash(t *testing.T) {
	b := NewTPM2Backend(newMockPlatformAuth("", false))
	if b.VerifyFIDO2Hash(ComputeFIDO2PINHash("any-pin")) {
		t.Fatal("VerifyFIDO2Hash should return false when no hash is cached")
	}
}

func TestTPM2Backend_VerifyFIDO2Hash_WrongLength_Short(t *testing.T) {
	b, _ := newProvisionedTPM2Backend(t, "user-pin")
	if b.VerifyFIDO2Hash([]byte("too-short")) {
		t.Fatal("VerifyFIDO2Hash should return false for short hash")
	}
}

func TestTPM2Backend_VerifyFIDO2Hash_WrongLength_Long(t *testing.T) {
	b, _ := newProvisionedTPM2Backend(t, "user-pin")
	if b.VerifyFIDO2Hash(make([]byte, FIDO2PINHashSize+10)) {
		t.Fatal("VerifyFIDO2Hash should return false for long hash")
	}
}

func TestTPM2Backend_VerifyFIDO2Hash_EmptySlice(t *testing.T) {
	b, _ := newProvisionedTPM2Backend(t, "user-pin")
	if b.VerifyFIDO2Hash([]byte{}) {
		t.Fatal("VerifyFIDO2Hash should return false for empty slice")
	}
}

func TestTPM2Backend_VerifyFIDO2Hash_NilSlice(t *testing.T) {
	b, _ := newProvisionedTPM2Backend(t, "user-pin")
	if b.VerifyFIDO2Hash(nil) {
		t.Fatal("VerifyFIDO2Hash should return false for nil slice")
	}
}

func TestTPM2Backend_VerifyFIDO2Hash_ExactSizeAllZeros(t *testing.T) {
	b, _ := newProvisionedTPM2Backend(t, "user-pin")
	if b.VerifyFIDO2Hash(make([]byte, FIDO2PINHashSize)) {
		t.Fatal("VerifyFIDO2Hash should return false for all-zero hash")
	}
}

func TestTPM2Backend_VerifyFIDO2Hash_AfterPINChange(t *testing.T) {
	b, _ := newProvisionedTPM2Backend(t, "old-user-pin")
	if err := b.ChangeUserPIN("old-user-pin", "new-user-pin"); err != nil {
		t.Fatalf("ChangeUserPIN: %v", err)
	}
	if !b.VerifyFIDO2Hash(ComputeFIDO2PINHash("new-user-pin")) {
		t.Fatal("FIDO2 hash should match new PIN after change")
	}
	if b.VerifyFIDO2Hash(ComputeFIDO2PINHash("old-user-pin")) {
		t.Fatal("FIDO2 hash should not match old PIN after change")
	}
}

func TestTPM2Backend_Close_FreesGuardedBuffer(t *testing.T) {
	b, _ := newProvisionedTPM2Backend(t, "user-pin")
	guard := b.fido2Guard.Load()
	if guard == nil {
		t.Fatal("expected fido2Guard to be set")
	}
	if guard.IsFreed() {
		t.Fatal("fido2Guard should not be freed yet")
	}
	b.Close()
	if !guard.IsFreed() {
		t.Fatal("fido2Guard should be freed after Close")
	}
	hash := ComputeFIDO2PINHash("user-pin")
	if b.VerifyFIDO2Hash(hash) {
		t.Fatal("VerifyFIDO2Hash should return false after Close")
	}
}

func TestTPM2Backend_Close_Idempotent(t *testing.T) {
	b, _ := newProvisionedTPM2Backend(t, "user-pin")
	b.Close()
	b.Close()
	b.Close()
}

func TestTPM2Backend_Close_NilGuardedBuffer(t *testing.T) {
	b := NewTPM2Backend(newMockPlatformAuth("", false))
	b.Close()
}

func TestTPM2Backend_BuildAuthFailureError_InvalidWithStatus(t *testing.T) {
	mock := newMockPlatformAuth("correct-pin", true)
	mock.setLockoutInfo(3, 10, 0, 60)
	b := NewTPM2Backend(mock)
	err := b.buildAuthFailureError()
	var pinInvalidStatus *ErrPINInvalidWithStatus
	if !errors.As(err, &pinInvalidStatus) {
		t.Fatalf("expected ErrPINInvalidWithStatus, got: %T %v", err, err)
	}
	remaining := pinInvalidStatus.Status.MaxAttempts - pinInvalidStatus.Status.FailedAttempts
	if remaining != 7 {
		t.Fatalf("remaining attempts = %d, want 7", remaining)
	}
}

func TestTPM2Backend_BuildAuthFailureError_TPMLocked(t *testing.T) {
	mock := newMockPlatformAuth("correct-pin", true)
	mock.setLockoutInfo(10, 10, 0, 300)
	b := NewTPM2Backend(mock)
	err := b.buildAuthFailureError()
	var tpmLocked *ErrTPMLocked
	if !errors.As(err, &tpmLocked) {
		t.Fatalf("expected ErrTPMLocked, got: %T %v", err, err)
	}
	if !tpmLocked.Status.IsLocked {
		t.Fatal("status should be locked")
	}
	if tpmLocked.Status.RecoverySeconds != 300 {
		t.Fatalf("RecoverySeconds = %d, want 300", tpmLocked.Status.RecoverySeconds)
	}
}

func TestTPM2Backend_BuildAuthFailureError_LockoutInfoFails(t *testing.T) {
	mock := newMockPlatformAuth("correct-pin", true)
	mock.lockoutInfoErr = errors.New("tpm capability read error")
	b := NewTPM2Backend(mock)
	err := b.buildAuthFailureError()
	if !errors.Is(err, ErrPINInvalid) {
		t.Fatalf("expected ErrPINInvalid when lockout info fails, got: %v", err)
	}
}

func TestTPM2Backend_ConcurrentVerifyUserPIN(t *testing.T) {
	b, _ := newProvisionedTPM2Backend(t, "user-pin")
	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			errs <- b.VerifyUserPIN("user-pin")
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent VerifyUserPIN failed: %v", err)
		}
	}
}

func TestTPM2Backend_ConcurrentVerifyFIDO2Hash(t *testing.T) {
	b, _ := newProvisionedTPM2Backend(t, "user-pin")
	hash := ComputeFIDO2PINHash("user-pin")
	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	results := make(chan bool, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			results <- b.VerifyFIDO2Hash(hash)
		}()
	}
	wg.Wait()
	close(results)
	for ok := range results {
		if !ok {
			t.Fatal("concurrent VerifyFIDO2Hash returned false for valid hash")
		}
	}
}

func TestTPM2Backend_ConcurrentStateReads(t *testing.T) {
	b, _ := newProvisionedTPM2Backend(t, "user-pin")
	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 4)
	for i := 0; i < goroutines; i++ {
		go func() { defer wg.Done(); b.IsInitialized() }()
		go func() { defer wg.Done(); b.SOPINSet() }()
		go func() { defer wg.Done(); b.UserPINSet() }()
		go func() { defer wg.Done(); b.Strategy() }()
	}
	wg.Wait()
}

func TestTPM2Backend_ConcurrentGetLockoutStatus(t *testing.T) {
	mock := newMockPlatformAuth("", true)
	mock.setLockoutInfo(3, 10, 0, 60)
	b := NewTPM2Backend(mock)
	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if status := b.GetLockoutStatus(); status == nil {
				t.Error("GetLockoutStatus returned nil")
			}
		}()
	}
	wg.Wait()
}

func TestTPM2Backend_ConcurrentMixedOperations(t *testing.T) {
	b, _ := newProvisionedTPM2Backend(t, "user-pin")
	hash := ComputeFIDO2PINHash("user-pin")
	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines * 3)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_ = b.VerifyUserPIN("user-pin")
		}()
		go func() {
			defer wg.Done()
			_ = b.VerifyFIDO2Hash(hash)
		}()
		go func() {
			defer wg.Done()
			_ = b.GetLockoutStatus()
		}()
	}
	wg.Wait()
}

func TestTPM2Backend_ImplementsPINBackend(t *testing.T) {
	var _ PINBackend = (*TPM2Backend)(nil)
}

func TestTPM2Backend_ImplementsFIDO2HashVerifier(t *testing.T) {
	var _ FIDO2HashVerifier = (*TPM2Backend)(nil)
}

func TestTPM2Backend_FullLifecycle(t *testing.T) {
	mock := newMockPlatformAuth("srk-password", true)
	b := NewTPM2Backend(mock)

	if !b.IsInitialized() {
		t.Fatal("should be initialized (provisioned)")
	}
	if b.SOPINSet() {
		t.Fatal("SOPINSet should always be false")
	}
	if !b.UserPINSet() {
		t.Fatal("UserPINSet should be true (provisioned)")
	}

	if err := b.SetUserPIN("ignored", "srk-password"); err != nil {
		t.Fatalf("SetUserPIN: %v", err)
	}
	if err := b.VerifyUserPIN("srk-password"); err != nil {
		t.Fatalf("VerifyUserPIN: %v", err)
	}
	if !b.VerifyFIDO2Hash(ComputeFIDO2PINHash("srk-password")) {
		t.Fatal("FIDO2 hash should match after SetUserPIN + VerifyUserPIN")
	}

	if err := b.ChangeUserPIN("srk-password", "new-srk-pass"); err != nil {
		t.Fatalf("ChangeUserPIN: %v", err)
	}
	if err := b.VerifyUserPIN("new-srk-pass"); err != nil {
		t.Fatalf("VerifyUserPIN after change: %v", err)
	}
	if err := b.VerifyUserPIN("srk-password"); err == nil {
		t.Fatal("old PIN should be invalid after change")
	}
	if !b.VerifyFIDO2Hash(ComputeFIDO2PINHash("new-srk-pass")) {
		t.Fatal("FIDO2 hash should match new PIN")
	}
	if b.VerifyFIDO2Hash(ComputeFIDO2PINHash("srk-password")) {
		t.Fatal("FIDO2 hash should not match old PIN")
	}

	if status := b.GetLockoutStatus(); status == nil {
		t.Fatal("lockout status should not be nil")
	}
	if err := b.ResetLockout("lockout-auth"); err != nil {
		t.Fatalf("ResetLockout: %v", err)
	}

	if err := b.SetSOPIN("", "123456"); !errors.Is(err, ErrPINNotSet) {
		t.Fatalf("SetSOPIN: %v, want %v", err, ErrPINNotSet)
	}
	if err := b.ChangeSOPIN("old", "new123"); !errors.Is(err, ErrPINNotSet) {
		t.Fatalf("ChangeSOPIN: %v, want %v", err, ErrPINNotSet)
	}
	if err := b.VerifySOPIN("123456"); !errors.Is(err, ErrPINNotSet) {
		t.Fatalf("VerifySOPIN: %v, want %v", err, ErrPINNotSet)
	}

	b.Close()
	if b.VerifyFIDO2Hash(ComputeFIDO2PINHash("new-srk-pass")) {
		t.Fatal("FIDO2 hash should not match after Close")
	}
}

func TestTPM2Backend_MultipleUserPINChanges(t *testing.T) {
	b, _ := newProvisionedTPM2Backend(t, "user-000")
	pins := []string{"user-001", "user-002", "user-003", "user-004", "user-005"}
	current := "user-000"
	for _, newPIN := range pins {
		if err := b.ChangeUserPIN(current, newPIN); err != nil {
			t.Fatalf("ChangeUserPIN from %q to %q: %v", current, newPIN, err)
		}
		if err := b.VerifyUserPIN(newPIN); err != nil {
			t.Fatalf("VerifyUserPIN for %q: %v", newPIN, err)
		}
		if !b.VerifyFIDO2Hash(ComputeFIDO2PINHash(newPIN)) {
			t.Fatalf("FIDO2 hash should match after change to %q", newPIN)
		}
		current = newPIN
	}
	if err := b.VerifyUserPIN("user-000"); err == nil {
		t.Fatal("original PIN should be invalid after multiple changes")
	}
}

// TestTPM2Backend_VerifyUserPIN_SentinelAuthError verifies that the
// ErrAuthFailed sentinel from TPM2.VerifyAuth ("tpm2: auth verification
// failed") is correctly recognized as an auth failure and wrapped as
// ErrPINInvalidWithStatus instead of leaking the raw TPM error.
func TestTPM2Backend_VerifyUserPIN_SentinelAuthError(t *testing.T) {
	b, mock := newProvisionedTPM2Backend(t, "correct-pin")
	mock.setLockoutInfo(1, 10, 0, 60)

	// Simulate the exact error that TPM2.VerifyAuth returns when the
	// auth value doesn't match — a sentinel error, NOT a raw TPM error
	// containing "BAD_AUTH".
	mock.verifyErr = errors.New("tpm2: auth verification failed")

	err := b.VerifyUserPIN("wrong-pin")
	if err == nil {
		t.Fatal("VerifyUserPIN() should fail")
	}

	// Must be wrapped as ErrPINInvalidWithStatus, not the raw sentinel.
	var pinInvalidStatus *ErrPINInvalidWithStatus
	if !errors.As(err, &pinInvalidStatus) {
		t.Fatalf("expected ErrPINInvalidWithStatus, got: %T %v", err, err)
	}
	if pinInvalidStatus.Status.FailedAttempts != 1 {
		t.Fatalf("FailedAttempts = %d, want 1", pinInvalidStatus.Status.FailedAttempts)
	}
}

// TestIsAuthError_SentinelError verifies that isAuthError matches the
// ErrAuthFailed sentinel string "tpm2: auth verification failed".
func TestIsAuthError_SentinelError(t *testing.T) {
	sentinel := errors.New("tpm2: auth verification failed")
	if !isAuthError(sentinel) {
		t.Fatal("isAuthError must match 'auth verification failed' sentinel")
	}
}

// TestIsAuthError_RawTPMErrors verifies that isAuthError matches raw
// TPM error strings containing BAD_AUTH or AUTH_FAIL.
func TestIsAuthError_RawTPMErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unrelated", errors.New("tpm transport timeout"), false},
		{"bad_auth", errors.New("TPM_RC_BAD_AUTH (session 1)"), true},
		{"auth_fail", errors.New("TPM_RC_AUTH_FAIL"), true},
		{"sentinel", errors.New("tpm2: auth verification failed"), true},
		{"wrapped_sentinel", errors.New("something: tpm2: auth verification failed"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isAuthError(tc.err)
			if got != tc.want {
				t.Fatalf("isAuthError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
