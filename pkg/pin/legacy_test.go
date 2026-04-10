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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- Mock TPM Provider ---

type mockTPMProvider struct {
	provisioned     bool
	hierarchyAuths  map[string]string // hierarchy -> auth value
	installErr      error
	setAuthErr      error
	lockoutInfoErr  error
	daResetErr      error
	failedAttempts  int
	maxFail         int
	interval        int
	recovery        int
	installCalled   bool
	setAuthCalls    []setAuthCall
	daResetCalls    int
}

type setAuthCall struct {
	hierarchy, oldAuth, newAuth string
}

func newMockTPMProvider() *mockTPMProvider {
	return &mockTPMProvider{
		hierarchyAuths: map[string]string{
			hierarchyEndorsement: "",
			hierarchyOwner:       "",
		},
		maxFail: 5,
	}
}

func (m *mockTPMProvider) Install(soPIN string) error {
	m.installCalled = true
	if m.installErr != nil {
		return m.installErr
	}
	m.provisioned = true
	m.hierarchyAuths[hierarchyEndorsement] = soPIN
	return nil
}

func (m *mockTPMProvider) SetHierarchyAuth(hierarchy, oldAuth, newAuth string) error {
	m.setAuthCalls = append(m.setAuthCalls, setAuthCall{hierarchy, oldAuth, newAuth})
	if m.setAuthErr != nil {
		return m.setAuthErr
	}
	current := m.hierarchyAuths[hierarchy]
	if current != oldAuth {
		return errors.New("TPM_RC_BAD_AUTH")
	}
	m.hierarchyAuths[hierarchy] = newAuth
	return nil
}

func (m *mockTPMProvider) GetLockoutInfo() (failedAttempts, maxFail, interval, recovery int, err error) {
	if m.lockoutInfoErr != nil {
		return 0, 0, 0, 0, m.lockoutInfoErr
	}
	return m.failedAttempts, m.maxFail, m.interval, m.recovery, nil
}

func (m *mockTPMProvider) DictionaryAttackLockoutReset(lockoutAuth []byte) error {
	m.daResetCalls++
	if m.daResetErr != nil {
		return m.daResetErr
	}
	m.failedAttempts = 0
	return nil
}

func (m *mockTPMProvider) IsProvisioned() bool {
	return m.provisioned
}

// --- Helper ---

func newTestLockoutConfig() LockoutConfig {
	return LockoutConfig{
		MaxAttempts:     3,
		LockoutDuration: 10 * time.Minute,
		Backoff:         false,
	}
}

// --- legacyLoadState / legacySaveState ---

func TestLegacyLoadState_FileNotExist(t *testing.T) {
	state, err := legacyLoadState(filepath.Join(t.TempDir(), "nonexistent"))
	if err != nil {
		t.Fatalf("legacyLoadState should return default state, got error: %v", err)
	}
	if state.Version != 1 {
		t.Errorf("Version = %d, want 1", state.Version)
	}
	if state.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
}

func TestLegacyLoadState_ValidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	state := &PINState{
		SOPINSet: true,
		Version:  2,
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	loaded, err := legacyLoadState(path)
	if err != nil {
		t.Fatalf("legacyLoadState: %v", err)
	}
	if !loaded.SOPINSet {
		t.Error("SOPINSet should be true")
	}
	if loaded.Version != 2 {
		t.Errorf("Version = %d, want 2", loaded.Version)
	}
}

func TestLegacyLoadState_CorruptedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("{invalid json}"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := legacyLoadState(path)
	if !errors.Is(err, ErrStateCorrupted) {
		t.Errorf("expected ErrStateCorrupted, got %v", err)
	}
}

func TestLegacyLoadState_PermissionDenied(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(path, 0000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0600) })

	_, err := legacyLoadState(path)
	if err == nil {
		t.Error("expected permission error, got nil")
	}
	if errors.Is(err, ErrStateCorrupted) {
		t.Error("should not be ErrStateCorrupted for permission errors")
	}
}

func TestLegacySaveState_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	original := &PINState{
		SOPINSet:       true,
		FailedAttempts: 2,
		Version:        1,
	}
	if err := legacySaveState(path, original); err != nil {
		t.Fatalf("legacySaveState: %v", err)
	}

	loaded, err := legacyLoadState(path)
	if err != nil {
		t.Fatalf("legacyLoadState: %v", err)
	}
	if !loaded.SOPINSet {
		t.Error("SOPINSet mismatch")
	}
	if loaded.FailedAttempts != 2 {
		t.Errorf("FailedAttempts = %d, want 2", loaded.FailedAttempts)
	}
	if loaded.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should be set by legacySaveState")
	}
}

func TestLegacySaveState_CreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "dir")
	path := filepath.Join(dir, "state.json")

	state := &PINState{Version: 1}
	if err := legacySaveState(path, state); err != nil {
		t.Fatalf("legacySaveState should create dir: %v", err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("state file should exist after save")
	}
}

// --- legacyHashPIN / legacyVerifyPIN ---

func TestLegacyHashPIN_ProducesSaltAndHash(t *testing.T) {
	hash, salt, err := legacyHashPIN("testpin123")
	if err != nil {
		t.Fatalf("legacyHashPIN: %v", err)
	}
	if len(hash) != legacyArgon2KeyLen {
		t.Errorf("hash len = %d, want %d", len(hash), legacyArgon2KeyLen)
	}
	if len(salt) != legacyArgon2SaltLen {
		t.Errorf("salt len = %d, want %d", len(salt), legacyArgon2SaltLen)
	}
}

func TestLegacyHashPIN_DifferentSalts(t *testing.T) {
	_, salt1, _ := legacyHashPIN("pin123")
	_, salt2, _ := legacyHashPIN("pin123")
	if string(salt1) == string(salt2) {
		t.Error("consecutive calls should produce different salts")
	}
}

func TestLegacyVerifyPIN_Correct(t *testing.T) {
	hash, salt, _ := legacyHashPIN("correct-pin")
	if !legacyVerifyPIN("correct-pin", hash, salt) {
		t.Error("expected verification to succeed")
	}
}

func TestLegacyVerifyPIN_Wrong(t *testing.T) {
	hash, salt, _ := legacyHashPIN("correct-pin")
	if legacyVerifyPIN("wrong-pin", hash, salt) {
		t.Error("expected verification to fail")
	}
}

// --- copyBytes ---

func TestCopyBytes_Nil(t *testing.T) {
	if result := copyBytes(nil); result != nil {
		t.Errorf("copyBytes(nil) = %v, want nil", result)
	}
}

func TestCopyBytes_NonNil(t *testing.T) {
	original := []byte{1, 2, 3}
	cp := copyBytes(original)
	if len(cp) != 3 || cp[0] != 1 || cp[1] != 2 || cp[2] != 3 {
		t.Errorf("copyBytes mismatch: %v", cp)
	}
	// Mutating the copy should not affect the original.
	cp[0] = 99
	if original[0] == 99 {
		t.Error("copy should be independent of original")
	}
}

// ============================================================
// FilePINManager Tests
// ============================================================

func newTestFilePINManager(t *testing.T) *FilePINManager {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pin-state.json")
	mgr, err := NewFilePINManager(path, newTestLockoutConfig())
	if err != nil {
		t.Fatalf("NewFilePINManager: %v", err)
	}
	return mgr
}

func TestNewFilePINManager_FreshState(t *testing.T) {
	mgr := newTestFilePINManager(t)
	if mgr.Strategy() != StrategySoftware {
		t.Errorf("Strategy() = %s, want %s", mgr.Strategy(), StrategySoftware)
	}
	if mgr.IsInitialized() {
		t.Error("fresh manager should not be initialized")
	}
	if mgr.SOPINSet() {
		t.Error("SO PIN should not be set")
	}
	if mgr.UserPINSet() {
		t.Error("user PIN should not be set")
	}
}

func TestNewFilePINManager_CorruptedState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("not-json"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := NewFilePINManager(path, newTestLockoutConfig())
	if !errors.Is(err, ErrStateCorrupted) {
		t.Errorf("expected ErrStateCorrupted, got %v", err)
	}
}

func TestFilePINManager_SetMaxAttempts(t *testing.T) {
	mgr := newTestFilePINManager(t)
	mgr.SetMaxAttempts(10)
	if mgr.lockoutCfg.MaxAttempts != 10 {
		t.Errorf("MaxAttempts = %d, want 10", mgr.lockoutCfg.MaxAttempts)
	}
}

func TestFilePINManager_SetSOPIN_FirstTime(t *testing.T) {
	mgr := newTestFilePINManager(t)
	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	if !mgr.SOPINSet() {
		t.Error("SOPINSet should be true")
	}
	if !mgr.IsInitialized() {
		t.Error("IsInitialized should be true")
	}
}

func TestFilePINManager_SetSOPIN_TooShort(t *testing.T) {
	mgr := newTestFilePINManager(t)
	err := mgr.SetSOPIN("", "short")
	if !errors.Is(err, ErrPINTooShort) {
		t.Errorf("expected ErrPINTooShort, got %v", err)
	}
}

func TestFilePINManager_SetSOPIN_AlreadySet(t *testing.T) {
	mgr := newTestFilePINManager(t)
	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	// Attempting to set without providing current should fail.
	err := mgr.SetSOPIN("", "newsopin123456")
	if !errors.Is(err, ErrPINAlreadySet) {
		t.Errorf("expected ErrPINAlreadySet, got %v", err)
	}
}

func TestFilePINManager_SetSOPIN_ChangeWithCurrent(t *testing.T) {
	mgr := newTestFilePINManager(t)
	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("first SetSOPIN: %v", err)
	}
	if err := mgr.SetSOPIN("sopin123456", "newsopin123456"); err != nil {
		t.Fatalf("SetSOPIN with current: %v", err)
	}
}

func TestFilePINManager_SetSOPIN_WrongCurrent(t *testing.T) {
	mgr := newTestFilePINManager(t)
	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	err := mgr.SetSOPIN("wrongpin123456", "newsopin123456")
	if !errors.Is(err, ErrInvalidCurrentPIN) {
		t.Errorf("expected ErrInvalidCurrentPIN, got %v", err)
	}
}

func TestFilePINManager_SetSOPIN_NotSetButCurrentProvided(t *testing.T) {
	mgr := newTestFilePINManager(t)
	err := mgr.SetSOPIN("something12345", "newsopin123456")
	if !errors.Is(err, ErrPINNotSet) {
		t.Errorf("expected ErrPINNotSet, got %v", err)
	}
}

func TestFilePINManager_SetUserPIN_Success(t *testing.T) {
	mgr := newTestFilePINManager(t)
	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	if err := mgr.SetUserPIN("sopin123456", "userpin123456"); err != nil {
		t.Fatalf("SetUserPIN: %v", err)
	}
	if !mgr.UserPINSet() {
		t.Error("UserPINSet should be true")
	}
}

func TestFilePINManager_SetUserPIN_TooShort(t *testing.T) {
	mgr := newTestFilePINManager(t)
	err := mgr.SetUserPIN("sopin", "short")
	if !errors.Is(err, ErrPINTooShort) {
		t.Errorf("expected ErrPINTooShort, got %v", err)
	}
}

func TestFilePINManager_SetUserPIN_NoSOPIN(t *testing.T) {
	mgr := newTestFilePINManager(t)
	err := mgr.SetUserPIN("sopin123456", "userpin123456")
	if !errors.Is(err, ErrSOPINRequired) {
		t.Errorf("expected ErrSOPINRequired, got %v", err)
	}
}

func TestFilePINManager_SetUserPIN_WrongSOPIN(t *testing.T) {
	mgr := newTestFilePINManager(t)
	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	err := mgr.SetUserPIN("wrongpin123456", "userpin123456")
	if !errors.Is(err, ErrPINInvalid) {
		t.Errorf("expected ErrPINInvalid, got %v", err)
	}
}

func TestFilePINManager_ChangeSOPIN_Success(t *testing.T) {
	mgr := newTestFilePINManager(t)
	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	if err := mgr.ChangeSOPIN("sopin123456", "newsopin123456"); err != nil {
		t.Fatalf("ChangeSOPIN: %v", err)
	}
	// Verify new SO PIN works.
	if err := mgr.VerifySOPIN("newsopin123456"); err != nil {
		t.Errorf("VerifySOPIN after change: %v", err)
	}
}

func TestFilePINManager_ChangeSOPIN_NotSet(t *testing.T) {
	mgr := newTestFilePINManager(t)
	err := mgr.ChangeSOPIN("current123456", "newsopin123456")
	if !errors.Is(err, ErrPINNotSet) {
		t.Errorf("expected ErrPINNotSet, got %v", err)
	}
}

func TestFilePINManager_ChangeSOPIN_WrongCurrent(t *testing.T) {
	mgr := newTestFilePINManager(t)
	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	err := mgr.ChangeSOPIN("wrongpin123456", "newsopin123456")
	if !errors.Is(err, ErrInvalidCurrentPIN) {
		t.Errorf("expected ErrInvalidCurrentPIN, got %v", err)
	}
}

func TestFilePINManager_ChangeSOPIN_TooShort(t *testing.T) {
	mgr := newTestFilePINManager(t)
	err := mgr.ChangeSOPIN("current", "short")
	if !errors.Is(err, ErrPINTooShort) {
		t.Errorf("expected ErrPINTooShort, got %v", err)
	}
}

func TestFilePINManager_ChangeUserPIN_Success(t *testing.T) {
	mgr := newTestFilePINManager(t)
	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	if err := mgr.SetUserPIN("sopin123456", "userpin123456"); err != nil {
		t.Fatalf("SetUserPIN: %v", err)
	}
	if err := mgr.ChangeUserPIN("userpin123456", "newuserpin123456"); err != nil {
		t.Fatalf("ChangeUserPIN: %v", err)
	}
	if err := mgr.VerifyUserPIN("newuserpin123456"); err != nil {
		t.Errorf("VerifyUserPIN after change: %v", err)
	}
}

func TestFilePINManager_ChangeUserPIN_NotSet(t *testing.T) {
	mgr := newTestFilePINManager(t)
	err := mgr.ChangeUserPIN("current123456", "newpin123456")
	if !errors.Is(err, ErrPINNotSet) {
		t.Errorf("expected ErrPINNotSet, got %v", err)
	}
}

func TestFilePINManager_ChangeUserPIN_WrongCurrent(t *testing.T) {
	mgr := newTestFilePINManager(t)
	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	if err := mgr.SetUserPIN("sopin123456", "userpin123456"); err != nil {
		t.Fatalf("SetUserPIN: %v", err)
	}
	err := mgr.ChangeUserPIN("wrongpin123456", "newuserpin123456")
	if !errors.Is(err, ErrInvalidCurrentPIN) {
		t.Errorf("expected ErrInvalidCurrentPIN, got %v", err)
	}
}

func TestFilePINManager_ChangeUserPIN_TooShort(t *testing.T) {
	mgr := newTestFilePINManager(t)
	err := mgr.ChangeUserPIN("current", "short")
	if !errors.Is(err, ErrPINTooShort) {
		t.Errorf("expected ErrPINTooShort, got %v", err)
	}
}

func TestFilePINManager_VerifySOPIN_Success(t *testing.T) {
	mgr := newTestFilePINManager(t)
	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	if err := mgr.VerifySOPIN("sopin123456"); err != nil {
		t.Errorf("VerifySOPIN: %v", err)
	}
}

func TestFilePINManager_VerifySOPIN_NotSet(t *testing.T) {
	mgr := newTestFilePINManager(t)
	err := mgr.VerifySOPIN("anything123")
	if !errors.Is(err, ErrPINNotSet) {
		t.Errorf("expected ErrPINNotSet, got %v", err)
	}
}

func TestFilePINManager_VerifySOPIN_Invalid(t *testing.T) {
	mgr := newTestFilePINManager(t)
	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	err := mgr.VerifySOPIN("wrongpin123456")
	if !errors.Is(err, ErrPINInvalid) {
		t.Errorf("expected ErrPINInvalid, got %v", err)
	}
}

func TestFilePINManager_VerifyUserPIN_Success(t *testing.T) {
	mgr := newTestFilePINManager(t)
	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	if err := mgr.SetUserPIN("sopin123456", "userpin123456"); err != nil {
		t.Fatalf("SetUserPIN: %v", err)
	}
	if err := mgr.VerifyUserPIN("userpin123456"); err != nil {
		t.Errorf("VerifyUserPIN: %v", err)
	}
}

func TestFilePINManager_VerifyUserPIN_NotSet(t *testing.T) {
	mgr := newTestFilePINManager(t)
	err := mgr.VerifyUserPIN("anything123")
	if !errors.Is(err, ErrPINNotSet) {
		t.Errorf("expected ErrPINNotSet, got %v", err)
	}
}

func TestFilePINManager_VerifyUserPIN_Invalid(t *testing.T) {
	mgr := newTestFilePINManager(t)
	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	if err := mgr.SetUserPIN("sopin123456", "userpin123456"); err != nil {
		t.Fatalf("SetUserPIN: %v", err)
	}
	err := mgr.VerifyUserPIN("wrongpin123456")
	if !errors.Is(err, ErrPINInvalid) {
		t.Errorf("expected ErrPINInvalid, got %v", err)
	}
}

func TestFilePINManager_GetLockoutStatus_NoLockout(t *testing.T) {
	mgr := newTestFilePINManager(t)
	status := mgr.GetLockoutStatus()
	if status.IsLocked {
		t.Error("should not be locked initially")
	}
	if status.FailedAttempts != 0 {
		t.Errorf("FailedAttempts = %d, want 0", status.FailedAttempts)
	}
	if status.MaxAttempts != 3 {
		t.Errorf("MaxAttempts = %d, want 3", status.MaxAttempts)
	}
}

func TestFilePINManager_LockoutAfterMaxAttempts(t *testing.T) {
	mgr := newTestFilePINManager(t)
	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}

	// Fail 3 times (MaxAttempts = 3).
	for i := 0; i < 3; i++ {
		err := mgr.VerifySOPIN("wrongpin123456")
		if !errors.Is(err, ErrPINInvalid) {
			t.Fatalf("attempt %d: expected ErrPINInvalid, got %v", i+1, err)
		}
	}

	// Fourth attempt should be locked out.
	err := mgr.VerifySOPIN("sopin123456")
	if !errors.Is(err, ErrPINLocked) {
		t.Errorf("expected ErrPINLocked after max attempts, got %v", err)
	}

	status := mgr.GetLockoutStatus()
	if !status.IsLocked {
		t.Error("should be locked after max attempts")
	}
}

func TestFilePINManager_ResetLockout_Success(t *testing.T) {
	mgr := newTestFilePINManager(t)
	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}

	// Trigger lockout.
	for i := 0; i < 3; i++ {
		_ = mgr.VerifySOPIN("wrongpin123456")
	}

	if err := mgr.ResetLockout("sopin123456"); err != nil {
		t.Fatalf("ResetLockout: %v", err)
	}

	// Should work again.
	if err := mgr.VerifySOPIN("sopin123456"); err != nil {
		t.Errorf("VerifySOPIN after reset: %v", err)
	}
}

func TestFilePINManager_ResetLockout_NoSOPIN(t *testing.T) {
	mgr := newTestFilePINManager(t)
	err := mgr.ResetLockout("anything123")
	if !errors.Is(err, ErrPINNotSet) {
		t.Errorf("expected ErrPINNotSet, got %v", err)
	}
}

func TestFilePINManager_ResetLockout_WrongSOPIN(t *testing.T) {
	mgr := newTestFilePINManager(t)
	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	err := mgr.ResetLockout("wrongpin123456")
	if !errors.Is(err, ErrPINInvalid) {
		t.Errorf("expected ErrPINInvalid, got %v", err)
	}
}

func TestFilePINManager_SeedUserPIN_Success(t *testing.T) {
	mgr := newTestFilePINManager(t)
	if err := mgr.SeedUserPIN("seedpin123456"); err != nil {
		t.Fatalf("SeedUserPIN: %v", err)
	}
	if !mgr.UserPINSet() {
		t.Error("UserPINSet should be true after seed")
	}
	if err := mgr.VerifyUserPIN("seedpin123456"); err != nil {
		t.Errorf("VerifyUserPIN after seed: %v", err)
	}
}

func TestFilePINManager_SeedUserPIN_TooShort(t *testing.T) {
	mgr := newTestFilePINManager(t)
	err := mgr.SeedUserPIN("short")
	if !errors.Is(err, ErrPINTooShort) {
		t.Errorf("expected ErrPINTooShort, got %v", err)
	}
}

func TestFilePINManager_SeedUserPIN_AlreadySet(t *testing.T) {
	mgr := newTestFilePINManager(t)
	if err := mgr.SeedUserPIN("seedpin123456"); err != nil {
		t.Fatalf("first SeedUserPIN: %v", err)
	}
	// Second call should be a no-op (not error).
	if err := mgr.SeedUserPIN("another123456"); err != nil {
		t.Fatalf("second SeedUserPIN should no-op: %v", err)
	}
	// Original PIN should still work.
	if err := mgr.VerifyUserPIN("seedpin123456"); err != nil {
		t.Errorf("original PIN should still verify: %v", err)
	}
}

func TestFilePINManager_VerifySOPIN_ResetsOnSuccess(t *testing.T) {
	mgr := newTestFilePINManager(t)
	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	// Fail once.
	_ = mgr.VerifySOPIN("wrongpin123456")
	// Succeed to reset counter.
	if err := mgr.VerifySOPIN("sopin123456"); err != nil {
		t.Fatalf("VerifySOPIN: %v", err)
	}
	status := mgr.GetLockoutStatus()
	if status.FailedAttempts != 0 {
		t.Errorf("FailedAttempts = %d, want 0 after success", status.FailedAttempts)
	}
}

func TestFilePINManager_VerifyUserPIN_ResetsOnSuccess(t *testing.T) {
	mgr := newTestFilePINManager(t)
	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	if err := mgr.SetUserPIN("sopin123456", "userpin123456"); err != nil {
		t.Fatalf("SetUserPIN: %v", err)
	}
	// Fail once.
	_ = mgr.VerifyUserPIN("wrongpin123456")
	// Succeed to reset.
	if err := mgr.VerifyUserPIN("userpin123456"); err != nil {
		t.Fatalf("VerifyUserPIN: %v", err)
	}
	status := mgr.GetLockoutStatus()
	if status.FailedAttempts != 0 {
		t.Errorf("FailedAttempts = %d, want 0", status.FailedAttempts)
	}
}

func TestFilePINManager_ComputeLockoutDuration_NoBackoff(t *testing.T) {
	mgr := newTestFilePINManager(t)
	mgr.lockoutCfg.Backoff = false

	d := mgr.computeLockoutDuration(5)
	if d != mgr.lockoutCfg.LockoutDuration {
		t.Errorf("duration = %v, want %v", d, mgr.lockoutCfg.LockoutDuration)
	}
}

func TestFilePINManager_ComputeLockoutDuration_WithBackoff(t *testing.T) {
	mgr := newTestFilePINManager(t)
	mgr.lockoutCfg.Backoff = true
	mgr.lockoutCfg.MaxAttempts = 3
	mgr.lockoutCfg.LockoutDuration = time.Minute

	// At exactly MaxAttempts, exponent = 0, duration = base.
	d := mgr.computeLockoutDuration(3)
	if d != time.Minute {
		t.Errorf("at max: duration = %v, want %v", d, time.Minute)
	}

	// 1 over max, exponent = 1, duration = 2*base.
	d = mgr.computeLockoutDuration(4)
	if d != 2*time.Minute {
		t.Errorf("max+1: duration = %v, want %v", d, 2*time.Minute)
	}

	// 2 over max, exponent = 2, duration = 4*base.
	d = mgr.computeLockoutDuration(5)
	if d != 4*time.Minute {
		t.Errorf("max+2: duration = %v, want %v", d, 4*time.Minute)
	}
}

func TestFilePINManager_ComputeLockoutDuration_CapsAtMax(t *testing.T) {
	mgr := newTestFilePINManager(t)
	mgr.lockoutCfg.Backoff = true
	mgr.lockoutCfg.MaxAttempts = 3
	mgr.lockoutCfg.LockoutDuration = 30 * time.Minute

	// Large exponent should cap at maxBackoffDuration (1 hour).
	d := mgr.computeLockoutDuration(100)
	if d > maxBackoffDuration {
		t.Errorf("duration %v exceeds max %v", d, maxBackoffDuration)
	}
	if d != maxBackoffDuration {
		t.Errorf("expected cap at %v, got %v", maxBackoffDuration, d)
	}
}

func TestFilePINManager_GetLockoutStatus_WhenLocked(t *testing.T) {
	mgr := newTestFilePINManager(t)
	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}

	// Trigger lockout.
	for i := 0; i < 3; i++ {
		_ = mgr.VerifySOPIN("wrongpin123456")
	}

	status := mgr.GetLockoutStatus()
	if !status.IsLocked {
		t.Error("should be locked")
	}
	if status.RecoverySeconds <= 0 {
		t.Error("RecoverySeconds should be positive when locked")
	}
}

func TestFilePINManager_Persistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pin-state.json")

	// Create manager and set SO PIN.
	mgr1, err := NewFilePINManager(path, newTestLockoutConfig())
	if err != nil {
		t.Fatalf("NewFilePINManager: %v", err)
	}
	if err := mgr1.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	if err := mgr1.SetUserPIN("sopin123456", "userpin123456"); err != nil {
		t.Fatalf("SetUserPIN: %v", err)
	}

	// Create a new manager from the same file.
	mgr2, err := NewFilePINManager(path, newTestLockoutConfig())
	if err != nil {
		t.Fatalf("NewFilePINManager reload: %v", err)
	}
	if !mgr2.SOPINSet() {
		t.Error("SO PIN should be set after reload")
	}
	if !mgr2.UserPINSet() {
		t.Error("user PIN should be set after reload")
	}
	// Verify PINs from reloaded state.
	if err := mgr2.VerifySOPIN("sopin123456"); err != nil {
		t.Errorf("VerifySOPIN after reload: %v", err)
	}
	if err := mgr2.VerifyUserPIN("userpin123456"); err != nil {
		t.Errorf("VerifyUserPIN after reload: %v", err)
	}
}

// ============================================================
// TPMPINManager Tests
// ============================================================

func newTestTPMPINManager(t *testing.T, tpm *mockTPMProvider) *TPMPINManager {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pin-state.json")
	mgr, err := NewTPMPINManager(tpm, path, newTestLockoutConfig())
	if err != nil {
		t.Fatalf("NewTPMPINManager: %v", err)
	}
	return mgr
}

func TestNewTPMPINManager_Success(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)
	if mgr.Strategy() != StrategyTPM2 {
		t.Errorf("Strategy() = %s, want %s", mgr.Strategy(), StrategyTPM2)
	}
}

func TestNewTPMPINManager_CorruptedState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("not-json"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tpm := newMockTPMProvider()
	_, err := NewTPMPINManager(tpm, path, newTestLockoutConfig())
	if !errors.Is(err, ErrStateCorrupted) {
		t.Errorf("expected ErrStateCorrupted, got %v", err)
	}
}

func TestTPMPINManager_SetMaxAttempts(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)
	mgr.SetMaxAttempts(10)
	if mgr.lockoutCfg.MaxAttempts != 10 {
		t.Errorf("MaxAttempts = %d, want 10", mgr.lockoutCfg.MaxAttempts)
	}
}

func TestTPMPINManager_SetSOPIN_NotProvisioned(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)

	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN on unprovisioned TPM: %v", err)
	}
	if !tpm.installCalled {
		t.Error("Install should be called for unprovisioned TPM")
	}
	if !mgr.SOPINSet() {
		t.Error("SOPINSet should be true")
	}
}

func TestTPMPINManager_SetSOPIN_NotProvisionedWithCurrent(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)

	err := mgr.SetSOPIN("current123456", "sopin123456")
	if !errors.Is(err, ErrPINNotSet) {
		t.Errorf("expected ErrPINNotSet, got %v", err)
	}
}

func TestTPMPINManager_SetSOPIN_NotProvisionedInstallError(t *testing.T) {
	tpm := newMockTPMProvider()
	tpm.installErr = errors.New("TPM install failed")
	mgr := newTestTPMPINManager(t, tpm)

	err := mgr.SetSOPIN("", "sopin123456")
	if err == nil || err.Error() != "TPM install failed" {
		t.Errorf("expected install error, got %v", err)
	}
}

func TestTPMPINManager_SetSOPIN_Provisioned_FirstTime(t *testing.T) {
	tpm := newMockTPMProvider()
	tpm.provisioned = true
	mgr := newTestTPMPINManager(t, tpm)

	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	if !mgr.SOPINSet() {
		t.Error("SOPINSet should be true")
	}
}

func TestTPMPINManager_SetSOPIN_Provisioned_HierarchyBound_NoCurrent(t *testing.T) {
	tpm := newMockTPMProvider()
	tpm.provisioned = true
	mgr := newTestTPMPINManager(t, tpm)

	// First set makes it hierarchy-bound.
	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("first SetSOPIN: %v", err)
	}

	// Second set without current should fail.
	err := mgr.SetSOPIN("", "newsopin123456")
	if !errors.Is(err, ErrPINAlreadySet) {
		t.Errorf("expected ErrPINAlreadySet, got %v", err)
	}
}

func TestTPMPINManager_SetSOPIN_Provisioned_HierarchyBound_WrongCurrent(t *testing.T) {
	tpm := newMockTPMProvider()
	tpm.provisioned = true
	mgr := newTestTPMPINManager(t, tpm)

	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("first SetSOPIN: %v", err)
	}

	err := mgr.SetSOPIN("wrongpin123456", "newsopin123456")
	if !errors.Is(err, ErrInvalidCurrentPIN) {
		t.Errorf("expected ErrInvalidCurrentPIN, got %v", err)
	}
}

func TestTPMPINManager_SetSOPIN_TooShort(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)
	err := mgr.SetSOPIN("", "short")
	if !errors.Is(err, ErrPINTooShort) {
		t.Errorf("expected ErrPINTooShort, got %v", err)
	}
}

func TestTPMPINManager_SetSOPIN_Provisioned_LegacyHash(t *testing.T) {
	tpm := newMockTPMProvider()
	tpm.provisioned = true
	mgr := newTestTPMPINManager(t, tpm)

	// Manually set legacy SO PIN hash (not hierarchy-bound).
	hash, salt, err := legacyHashPIN("legacyso123456")
	if err != nil {
		t.Fatalf("legacyHashPIN: %v", err)
	}
	state := mgr.loadStateCopy()
	state.SOPINHash = hash
	state.SOPINSalt = salt
	if err := mgr.persistState(state); err != nil {
		t.Fatalf("persistState: %v", err)
	}

	// Should require current and verify against legacy hash.
	err = mgr.SetSOPIN("", "newsopin123456")
	if !errors.Is(err, ErrPINAlreadySet) {
		t.Errorf("expected ErrPINAlreadySet, got %v", err)
	}

	// With wrong current.
	err = mgr.SetSOPIN("wrongpin123456", "newsopin123456")
	if !errors.Is(err, ErrInvalidCurrentPIN) {
		t.Errorf("expected ErrInvalidCurrentPIN, got %v", err)
	}

	// With correct current.
	if err := mgr.SetSOPIN("legacyso123456", "newsopin123456"); err != nil {
		t.Fatalf("SetSOPIN with legacy current: %v", err)
	}
}

func TestTPMPINManager_SetSOPIN_HierarchyAuthMismatch(t *testing.T) {
	tpm := newMockTPMProvider()
	tpm.provisioned = true
	// Pre-set hierarchy auth to simulate mismatch.
	tpm.hierarchyAuths[hierarchyEndorsement] = "preexisting-auth"
	mgr := newTestTPMPINManager(t, tpm)

	err := mgr.SetSOPIN("", "sopin123456")
	if !errors.Is(err, ErrHierarchyAuthMismatch) {
		t.Errorf("expected ErrHierarchyAuthMismatch, got %v", err)
	}
}

func TestTPMPINManager_SetUserPIN_Success(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)

	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	if err := mgr.SetUserPIN("sopin123456", "userpin123456"); err != nil {
		t.Fatalf("SetUserPIN: %v", err)
	}
	if !mgr.UserPINSet() {
		t.Error("UserPINSet should be true")
	}
}

func TestTPMPINManager_SetUserPIN_TooShort(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)
	err := mgr.SetUserPIN("sopin", "short")
	if !errors.Is(err, ErrPINTooShort) {
		t.Errorf("expected ErrPINTooShort, got %v", err)
	}
}

func TestTPMPINManager_SetUserPIN_NoSOPIN(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)
	err := mgr.SetUserPIN("sopin123456", "userpin123456")
	if !errors.Is(err, ErrSOPINRequired) {
		t.Errorf("expected ErrSOPINRequired, got %v", err)
	}
}

func TestTPMPINManager_SetUserPIN_WrongSOPIN(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)

	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}

	err := mgr.SetUserPIN("wrongpin123456", "userpin123456")
	if !errors.Is(err, ErrPINInvalid) {
		t.Errorf("expected ErrPINInvalid, got %v", err)
	}
}

func TestTPMPINManager_SetUserPIN_HierarchyAuthMismatch(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)

	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	// Pre-set owner hierarchy auth to simulate mismatch.
	tpm.hierarchyAuths[hierarchyOwner] = "preexisting-owner"

	err := mgr.SetUserPIN("sopin123456", "userpin123456")
	if !errors.Is(err, ErrHierarchyAuthMismatch) {
		t.Errorf("expected ErrHierarchyAuthMismatch, got %v", err)
	}
}

func TestTPMPINManager_ChangeSOPIN_Success(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)

	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	if err := mgr.ChangeSOPIN("sopin123456", "newsopin123456"); err != nil {
		t.Fatalf("ChangeSOPIN: %v", err)
	}
}

func TestTPMPINManager_ChangeSOPIN_NotSet(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)
	err := mgr.ChangeSOPIN("current123456", "newsopin123456")
	if !errors.Is(err, ErrPINNotSet) {
		t.Errorf("expected ErrPINNotSet, got %v", err)
	}
}

func TestTPMPINManager_ChangeSOPIN_TooShort(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)
	err := mgr.ChangeSOPIN("current", "short")
	if !errors.Is(err, ErrPINTooShort) {
		t.Errorf("expected ErrPINTooShort, got %v", err)
	}
}

func TestTPMPINManager_ChangeSOPIN_WrongCurrent(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)

	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	err := mgr.ChangeSOPIN("wrongpin123456", "newsopin123456")
	if !errors.Is(err, ErrInvalidCurrentPIN) {
		t.Errorf("expected ErrInvalidCurrentPIN, got %v", err)
	}
}

func TestTPMPINManager_ChangeSOPIN_LegacyHash(t *testing.T) {
	tpm := newMockTPMProvider()
	tpm.provisioned = true
	mgr := newTestTPMPINManager(t, tpm)

	// Set legacy hash.
	hash, salt, err := legacyHashPIN("legacyso123456")
	if err != nil {
		t.Fatalf("legacyHashPIN: %v", err)
	}
	state := mgr.loadStateCopy()
	state.SOPINHash = hash
	state.SOPINSalt = salt
	if err := mgr.persistState(state); err != nil {
		t.Fatalf("persistState: %v", err)
	}

	// Wrong current against legacy hash.
	err = mgr.ChangeSOPIN("wrongpin123456", "newsopin123456")
	if !errors.Is(err, ErrInvalidCurrentPIN) {
		t.Errorf("expected ErrInvalidCurrentPIN, got %v", err)
	}

	// Correct current against legacy hash.
	if err := mgr.ChangeSOPIN("legacyso123456", "newsopin123456"); err != nil {
		t.Fatalf("ChangeSOPIN with legacy: %v", err)
	}
}

func TestTPMPINManager_ChangeUserPIN_Success(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)

	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	if err := mgr.SetUserPIN("sopin123456", "userpin123456"); err != nil {
		t.Fatalf("SetUserPIN: %v", err)
	}
	if err := mgr.ChangeUserPIN("userpin123456", "newuserpin123456"); err != nil {
		t.Fatalf("ChangeUserPIN: %v", err)
	}
}

func TestTPMPINManager_ChangeUserPIN_NotSet(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)
	err := mgr.ChangeUserPIN("current123456", "newpin123456")
	if !errors.Is(err, ErrPINNotSet) {
		t.Errorf("expected ErrPINNotSet, got %v", err)
	}
}

func TestTPMPINManager_ChangeUserPIN_TooShort(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)
	err := mgr.ChangeUserPIN("current", "short")
	if !errors.Is(err, ErrPINTooShort) {
		t.Errorf("expected ErrPINTooShort, got %v", err)
	}
}

func TestTPMPINManager_ChangeUserPIN_WrongCurrent(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)

	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	if err := mgr.SetUserPIN("sopin123456", "userpin123456"); err != nil {
		t.Fatalf("SetUserPIN: %v", err)
	}
	err := mgr.ChangeUserPIN("wrongpin123456", "newuserpin123456")
	if !errors.Is(err, ErrInvalidCurrentPIN) {
		t.Errorf("expected ErrInvalidCurrentPIN, got %v", err)
	}
}

func TestTPMPINManager_VerifySOPIN_HierarchyBound(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)

	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	if err := mgr.VerifySOPIN("sopin123456"); err != nil {
		t.Errorf("VerifySOPIN: %v", err)
	}
}

func TestTPMPINManager_VerifySOPIN_HierarchyBound_Invalid(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)

	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	err := mgr.VerifySOPIN("wrongpin123456")
	if !errors.Is(err, ErrPINInvalid) {
		t.Errorf("expected ErrPINInvalid, got %v", err)
	}
}

func TestTPMPINManager_VerifySOPIN_LegacyHash(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)

	hash, salt, err := legacyHashPIN("legacyso123456")
	if err != nil {
		t.Fatalf("legacyHashPIN: %v", err)
	}
	state := mgr.loadStateCopy()
	state.SOPINHash = hash
	state.SOPINSalt = salt
	if err := mgr.persistState(state); err != nil {
		t.Fatalf("persistState: %v", err)
	}

	if err := mgr.VerifySOPIN("legacyso123456"); err != nil {
		t.Errorf("VerifySOPIN (legacy): %v", err)
	}
	err = mgr.VerifySOPIN("wrongpin123456")
	if !errors.Is(err, ErrPINInvalid) {
		t.Errorf("expected ErrPINInvalid, got %v", err)
	}
}

func TestTPMPINManager_VerifySOPIN_NotSet(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)
	err := mgr.VerifySOPIN("anything123")
	if !errors.Is(err, ErrPINNotSet) {
		t.Errorf("expected ErrPINNotSet, got %v", err)
	}
}

func TestTPMPINManager_VerifyUserPIN_Success(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)

	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	if err := mgr.SetUserPIN("sopin123456", "userpin123456"); err != nil {
		t.Fatalf("SetUserPIN: %v", err)
	}
	if err := mgr.VerifyUserPIN("userpin123456"); err != nil {
		t.Errorf("VerifyUserPIN: %v", err)
	}
}

func TestTPMPINManager_VerifyUserPIN_NotSet(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)
	err := mgr.VerifyUserPIN("anything123")
	if !errors.Is(err, ErrPINNotSet) {
		t.Errorf("expected ErrPINNotSet, got %v", err)
	}
}

func TestTPMPINManager_VerifyUserPIN_Invalid(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)

	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	if err := mgr.SetUserPIN("sopin123456", "userpin123456"); err != nil {
		t.Fatalf("SetUserPIN: %v", err)
	}
	err := mgr.VerifyUserPIN("wrongpin123456")
	if !errors.Is(err, ErrPINInvalid) {
		t.Errorf("expected ErrPINInvalid, got %v", err)
	}
}

func TestTPMPINManager_GetLockoutStatus_WithTPMInfo(t *testing.T) {
	tpm := newMockTPMProvider()
	tpm.failedAttempts = 2
	tpm.maxFail = 5
	tpm.recovery = 60
	mgr := newTestTPMPINManager(t, tpm)

	status := mgr.GetLockoutStatus()
	if status.FailedAttempts != 2 {
		t.Errorf("FailedAttempts = %d, want 2", status.FailedAttempts)
	}
	if status.MaxAttempts != 3 { // min of tpmMaxFail(5) and lockoutCfg(3)
		t.Errorf("MaxAttempts = %d, want 3", status.MaxAttempts)
	}
	if status.RecoverySeconds != 60 {
		t.Errorf("RecoverySeconds = %d, want 60", status.RecoverySeconds)
	}
}

func TestTPMPINManager_GetLockoutStatus_TPMError(t *testing.T) {
	tpm := newMockTPMProvider()
	tpm.lockoutInfoErr = errors.New("TPM error")
	mgr := newTestTPMPINManager(t, tpm)

	// Should fall back to local status.
	status := mgr.GetLockoutStatus()
	if status == nil {
		t.Fatal("GetLockoutStatus should return non-nil even on TPM error")
	}
	if status.MaxAttempts != 3 {
		t.Errorf("MaxAttempts = %d, want 3", status.MaxAttempts)
	}
}

func TestTPMPINManager_GetLockoutStatus_TPMFailedHigherThanLocal(t *testing.T) {
	tpm := newMockTPMProvider()
	tpm.failedAttempts = 10
	tpm.maxFail = 10
	mgr := newTestTPMPINManager(t, tpm)

	status := mgr.GetLockoutStatus()
	// TPM failed(10) > local(0), use TPM's.
	if status.FailedAttempts != 10 {
		t.Errorf("FailedAttempts = %d, want 10", status.FailedAttempts)
	}
	if !status.IsLocked {
		t.Error("should be locked when failedAttempts >= maxAttempts")
	}
}

func TestTPMPINManager_ResetLockout_Success(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)

	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}

	// Trigger some failed attempts.
	_ = mgr.VerifySOPIN("wrongpin123456")

	if err := mgr.ResetLockout("sopin123456"); err != nil {
		t.Fatalf("ResetLockout: %v", err)
	}
	if tpm.daResetCalls != 1 {
		t.Errorf("DA reset should be called once, got %d", tpm.daResetCalls)
	}
}

func TestTPMPINManager_ResetLockout_NoSOPIN(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)
	err := mgr.ResetLockout("anything123")
	if !errors.Is(err, ErrPINNotSet) {
		t.Errorf("expected ErrPINNotSet, got %v", err)
	}
}

func TestTPMPINManager_ResetLockout_WrongSOPIN(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)

	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	err := mgr.ResetLockout("wrongpin123456")
	if !errors.Is(err, ErrPINInvalid) {
		t.Errorf("expected ErrPINInvalid, got %v", err)
	}
}

func TestTPMPINManager_ResetLockout_DAResetError(t *testing.T) {
	tpm := newMockTPMProvider()
	tpm.daResetErr = errors.New("DA reset failed")
	mgr := newTestTPMPINManager(t, tpm)

	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	err := mgr.ResetLockout("sopin123456")
	if err == nil || err.Error() != "DA reset failed" {
		t.Errorf("expected DA reset error, got %v", err)
	}
}

func TestTPMPINManager_ResetLockout_LegacyHash(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)

	// Set legacy hash for SO PIN (not hierarchy-bound).
	hash, salt, err := legacyHashPIN("legacyso123456")
	if err != nil {
		t.Fatalf("legacyHashPIN: %v", err)
	}
	state := mgr.loadStateCopy()
	state.SOPINHash = hash
	state.SOPINSalt = salt
	if err := mgr.persistState(state); err != nil {
		t.Fatalf("persistState: %v", err)
	}

	// Wrong SO PIN.
	err = mgr.ResetLockout("wrongpin123456")
	if !errors.Is(err, ErrPINInvalid) {
		t.Errorf("expected ErrPINInvalid, got %v", err)
	}

	// Correct SO PIN.
	if err := mgr.ResetLockout("legacyso123456"); err != nil {
		t.Fatalf("ResetLockout with legacy: %v", err)
	}
}

func TestTPMPINManager_IsInitialized(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)

	if mgr.IsInitialized() {
		t.Error("should not be initialized before SetSOPIN")
	}

	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	if !mgr.IsInitialized() {
		t.Error("should be initialized after SetSOPIN")
	}
}

func TestTPMPINManager_SeedUserPIN_Success(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)
	if err := mgr.SeedUserPIN("seedpin123456"); err != nil {
		t.Fatalf("SeedUserPIN: %v", err)
	}
	if !mgr.UserPINSet() {
		t.Error("UserPINSet should be true after seed")
	}
}

func TestTPMPINManager_SeedUserPIN_TooShort(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)
	err := mgr.SeedUserPIN("short")
	if !errors.Is(err, ErrPINTooShort) {
		t.Errorf("expected ErrPINTooShort, got %v", err)
	}
}

func TestTPMPINManager_SeedUserPIN_AlreadySet(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)
	if err := mgr.SeedUserPIN("seedpin123456"); err != nil {
		t.Fatalf("first SeedUserPIN: %v", err)
	}
	// Should no-op.
	if err := mgr.SeedUserPIN("another123456"); err != nil {
		t.Fatalf("second SeedUserPIN should no-op: %v", err)
	}
}

func TestTPMPINManager_LockoutAfterMaxAttempts(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)

	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}

	// Fail MaxAttempts (3) times.
	for i := 0; i < 3; i++ {
		err := mgr.VerifySOPIN("wrongpin123456")
		if !errors.Is(err, ErrPINInvalid) {
			t.Fatalf("attempt %d: expected ErrPINInvalid, got %v", i+1, err)
		}
	}

	// Next attempt should be locked.
	err := mgr.VerifySOPIN("sopin123456")
	if !errors.Is(err, ErrPINLocked) {
		t.Errorf("expected ErrPINLocked, got %v", err)
	}
}

func TestTPMPINManager_SetUserPIN_LegacySOPIN(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)

	// Set legacy SO PIN hash (not hierarchy-bound).
	hash, salt, err := legacyHashPIN("legacyso123456")
	if err != nil {
		t.Fatalf("legacyHashPIN: %v", err)
	}
	state := mgr.loadStateCopy()
	state.SOPINHash = hash
	state.SOPINSalt = salt
	if err := mgr.persistState(state); err != nil {
		t.Fatalf("persistState: %v", err)
	}

	// Wrong SO PIN.
	err = mgr.SetUserPIN("wrongpin123456", "userpin123456")
	if !errors.Is(err, ErrPINInvalid) {
		t.Errorf("expected ErrPINInvalid, got %v", err)
	}

	// Correct SO PIN.
	if err := mgr.SetUserPIN("legacyso123456", "userpin123456"); err != nil {
		t.Fatalf("SetUserPIN: %v", err)
	}
}

func TestTPMPINManager_VerifySOPIN_ResetsOnSuccess(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)

	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}

	// Fail once.
	_ = mgr.VerifySOPIN("wrongpin123456")

	// Succeed to reset.
	if err := mgr.VerifySOPIN("sopin123456"); err != nil {
		t.Fatalf("VerifySOPIN: %v", err)
	}

	status := mgr.GetLockoutStatus()
	if status.FailedAttempts != 0 {
		t.Errorf("FailedAttempts = %d, want 0", status.FailedAttempts)
	}
}

func TestTPMPINManager_VerifyUserPIN_ResetsOnSuccess(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)

	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	if err := mgr.SetUserPIN("sopin123456", "userpin123456"); err != nil {
		t.Fatalf("SetUserPIN: %v", err)
	}

	// Fail once.
	_ = mgr.VerifyUserPIN("wrongpin123456")

	// Succeed to reset.
	if err := mgr.VerifyUserPIN("userpin123456"); err != nil {
		t.Fatalf("VerifyUserPIN: %v", err)
	}

	status := mgr.GetLockoutStatus()
	if status.FailedAttempts != 0 {
		t.Errorf("FailedAttempts = %d, want 0", status.FailedAttempts)
	}
}

// ---------------------------------------------------------------------------
// checkLockout — expired lockout resets state
// ---------------------------------------------------------------------------

func TestTPMPINManager_CheckLockout_ExpiredResets(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)

	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}

	// Manually set lockout that already expired.
	state := mgr.loadStateCopy()
	state.FailedAttempts = 10
	state.LockoutUntil = time.Now().UTC().Add(-1 * time.Minute)
	state.LastFailedAt = time.Now().UTC().Add(-2 * time.Minute)
	if err := mgr.persistState(state); err != nil {
		t.Fatalf("persistState: %v", err)
	}

	// Verify should succeed because lockout expired and gets reset.
	if err := mgr.VerifySOPIN("sopin123456"); err != nil {
		t.Errorf("VerifySOPIN after expired lockout: %v", err)
	}

	afterState := mgr.loadStateCopy()
	if afterState.FailedAttempts != 0 {
		t.Errorf("FailedAttempts = %d, want 0 after lockout expiry", afterState.FailedAttempts)
	}
}

func TestTPMPINManager_CheckLockout_ActiveBlocks(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)

	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}

	state := mgr.loadStateCopy()
	state.FailedAttempts = 10
	state.LockoutUntil = time.Now().UTC().Add(10 * time.Minute)
	if err := mgr.persistState(state); err != nil {
		t.Fatalf("persistState: %v", err)
	}

	err := mgr.VerifySOPIN("sopin123456")
	if !errors.Is(err, ErrPINLocked) {
		t.Errorf("expected ErrPINLocked, got %v", err)
	}
}

func TestTPMPINManager_CheckLockout_ZeroLockoutUntil(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)

	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}

	state := mgr.loadStateCopy()
	state.FailedAttempts = 100
	state.LockoutUntil = time.Time{}
	if err := mgr.persistState(state); err != nil {
		t.Fatalf("persistState: %v", err)
	}

	if err := mgr.VerifySOPIN("sopin123456"); err != nil {
		t.Errorf("VerifySOPIN with zero LockoutUntil: %v", err)
	}
}

func TestTPMPINManager_VerifyUserPIN_LegacyHash(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)

	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	if err := mgr.SetUserPIN("sopin123456", "userpin123456"); err != nil {
		t.Fatalf("SetUserPIN: %v", err)
	}

	// Replace with legacy hash.
	hash, salt, hashErr := legacyHashPIN("userpin123456")
	if hashErr != nil {
		t.Fatalf("legacyHashPIN: %v", hashErr)
	}
	state := mgr.loadStateCopy()
	state.UserPINHash = hash
	state.UserPINSalt = salt
	if err := mgr.persistState(state); err != nil {
		t.Fatalf("persistState: %v", err)
	}

	if err := mgr.VerifyUserPIN("userpin123456"); err != nil {
		t.Errorf("VerifyUserPIN legacy: %v", err)
	}
	err := mgr.VerifyUserPIN("wrongpin123456")
	if !errors.Is(err, ErrPINInvalid) {
		t.Errorf("expected ErrPINInvalid, got %v", err)
	}
}

func TestTPMPINManager_ChangeUserPIN_LegacyHash(t *testing.T) {
	tpm := newMockTPMProvider()
	mgr := newTestTPMPINManager(t, tpm)

	if err := mgr.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	if err := mgr.SetUserPIN("sopin123456", "userpin123456"); err != nil {
		t.Fatalf("SetUserPIN: %v", err)
	}

	hash, salt, hashErr := legacyHashPIN("userpin123456")
	if hashErr != nil {
		t.Fatalf("legacyHashPIN: %v", hashErr)
	}
	state := mgr.loadStateCopy()
	state.UserPINHash = hash
	state.UserPINSalt = salt
	if err := mgr.persistState(state); err != nil {
		t.Fatalf("persistState: %v", err)
	}

	if err := mgr.ChangeUserPIN("userpin123456", "newuserpin123456"); err != nil {
		t.Errorf("ChangeUserPIN legacy: %v", err)
	}
}

func TestTPMPINManager_SetSOPIN_LegacyHash_HierarchyError(t *testing.T) {
	tpm := newMockTPMProvider()
	tpm.provisioned = true
	tpm.setAuthErr = errors.New("simulated TPM error")
	mgr := newTestTPMPINManager(t, tpm)

	hash, salt, err := legacyHashPIN("legacyso123456")
	if err != nil {
		t.Fatalf("legacyHashPIN: %v", err)
	}
	state := mgr.loadStateCopy()
	state.SOPINHash = hash
	state.SOPINSalt = salt
	if err := mgr.persistState(state); err != nil {
		t.Fatalf("persistState: %v", err)
	}

	err = mgr.SetSOPIN("legacyso123456", "newsopin123456")
	if err == nil {
		t.Error("expected error from SetHierarchyAuth, got nil")
	}
}
