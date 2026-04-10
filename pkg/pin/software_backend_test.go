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
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// testHashConfig returns a fast Argon2id hash configuration for tests.
func testHashConfig() HashConfig {
	return HashConfig{
		Algorithm: HashArgon2id,
		Time:      1,
		Memory:    64,
		Threads:   1,
		KeyLen:    32,
		SaltLen:   16,
	}
}

// testPBKDF2HashConfig returns a fast PBKDF2 hash configuration for tests.
func testPBKDF2HashConfig() HashConfig {
	return HashConfig{
		Algorithm:  HashPBKDF2,
		PBKDF2Hash: types.HashSHA256,
		Iterations: 1,
		KeyLen:     32,
		SaltLen:    16,
	}
}

// newTestSoftwareBackend creates a SoftwareBackend with fast Argon2id hashing
// and no persistence (nil store).
func newTestSoftwareBackend(t *testing.T) *SoftwareBackend {
	t.Helper()
	b, err := NewSoftwareBackend(nil, testHashConfig())
	if err != nil {
		t.Fatalf("NewSoftwareBackend failed: %v", err)
	}
	return b
}

// newTestSoftwareBackendWithStore creates a SoftwareBackend with persistence.
func newTestSoftwareBackendWithStore(t *testing.T, store storage.Backend) *SoftwareBackend {
	t.Helper()
	b, err := NewSoftwareBackend(store, testHashConfig())
	if err != nil {
		t.Fatalf("NewSoftwareBackend failed: %v", err)
	}
	return b
}

// --- NewSoftwareBackend ---

func TestNewSoftwareBackend_CreatesInstance(t *testing.T) {
	b, err := NewSoftwareBackend(nil, testHashConfig())
	if err != nil {
		t.Fatalf("NewSoftwareBackend returned error: %v", err)
	}
	if b == nil {
		t.Fatal("NewSoftwareBackend returned nil")
	}
	if b.hashConfig.Algorithm != HashArgon2id {
		t.Errorf("hashConfig.Algorithm = %q, want %q", b.hashConfig.Algorithm, HashArgon2id)
	}
}

func TestNewSoftwareBackend_InitialState(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if b.IsInitialized() {
		t.Error("expected IsInitialized false on fresh backend")
	}
	if b.SOPINSet() {
		t.Error("expected SOPINSet false on fresh backend")
	}
	if b.UserPINSet() {
		t.Error("expected UserPINSet false on fresh backend")
	}
}

// --- Strategy ---

func TestSoftwareBackend_Strategy_ReturnsSoftware(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if got := b.Strategy(); got != StrategySoftware {
		t.Errorf("expected strategy %q, got %q", StrategySoftware, got)
	}
}

// --- SetSOPIN ---

func TestSoftwareBackend_SetSOPIN_Success(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if !b.SOPINSet() {
		t.Error("SOPINSet should be true after SetSOPIN")
	}
	if !b.IsInitialized() {
		t.Error("IsInitialized should be true after SetSOPIN")
	}
}

func TestSoftwareBackend_SetSOPIN_TooShort(t *testing.T) {
	b := newTestSoftwareBackend(t)
	err := b.SetSOPIN("", "short")
	if !errors.Is(err, ErrPINTooShort) {
		t.Errorf("expected ErrPINTooShort, got: %v", err)
	}
}

func TestSoftwareBackend_SetSOPIN_AlreadySetWithoutCurrent(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	err := b.SetSOPIN("", "newsopin")
	if !errors.Is(err, ErrPINAlreadySet) {
		t.Errorf("expected ErrPINAlreadySet, got: %v", err)
	}
}

func TestSoftwareBackend_SetSOPIN_AlreadySetWithCorrectCurrent(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b.SetSOPIN("sopin123", "newsopin"); err != nil {
		t.Errorf("SetSOPIN with correct current PIN failed: %v", err)
	}
	if err := b.VerifySOPIN("newsopin"); err != nil {
		t.Errorf("VerifySOPIN failed for new PIN: %v", err)
	}
}

func TestSoftwareBackend_SetSOPIN_AlreadySetWithWrongCurrent(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	err := b.SetSOPIN("wrongpin", "newsopin")
	if !errors.Is(err, ErrInvalidCurrentPIN) {
		t.Errorf("expected ErrInvalidCurrentPIN, got: %v", err)
	}
}

// --- SetUserPIN ---

func TestSoftwareBackend_SetUserPIN_Success(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b.SetUserPIN("sopin123", "userpin1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}
	if !b.UserPINSet() {
		t.Error("UserPINSet should be true after SetUserPIN")
	}
}

func TestSoftwareBackend_SetUserPIN_TooShort(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	err := b.SetUserPIN("sopin123", "12345")
	if !errors.Is(err, ErrPINTooShort) {
		t.Errorf("expected ErrPINTooShort, got: %v", err)
	}
}

func TestSoftwareBackend_SetUserPIN_SOPINNotSet(t *testing.T) {
	b := newTestSoftwareBackend(t)
	err := b.SetUserPIN("sopin123", "userpin1")
	if !errors.Is(err, ErrSOPINRequired) {
		t.Errorf("expected ErrSOPINRequired, got: %v", err)
	}
}

func TestSoftwareBackend_SetUserPIN_WrongSOPIN(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	err := b.SetUserPIN("wrongsopin", "userpin1")
	if !errors.Is(err, ErrPINInvalid) {
		t.Errorf("expected ErrPINInvalid, got: %v", err)
	}
}

func TestSoftwareBackend_SetUserPIN_AlreadySet(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b.SetUserPIN("sopin123", "userpin1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}
	err := b.SetUserPIN("sopin123", "userpin2")
	if !errors.Is(err, ErrPINAlreadySet) {
		t.Errorf("expected ErrPINAlreadySet, got: %v", err)
	}
}

func TestSoftwareBackend_SetUserPIN_CachesFIDO2Hash(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b.SetUserPIN("sopin123", "userpin1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}
	hash := ComputeFIDO2PINHash("userpin1")
	if !b.VerifyFIDO2Hash(hash) {
		t.Error("VerifyFIDO2Hash should return true for the correct hash after SetUserPIN")
	}
}

// --- ChangeSOPIN ---

func TestSoftwareBackend_ChangeSOPIN_Success(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "oldsopin"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b.ChangeSOPIN("oldsopin", "newsopin"); err != nil {
		t.Fatalf("ChangeSOPIN failed: %v", err)
	}
	if err := b.VerifySOPIN("oldsopin"); !errors.Is(err, ErrPINInvalid) {
		t.Errorf("expected ErrPINInvalid for old PIN, got: %v", err)
	}
	if err := b.VerifySOPIN("newsopin"); err != nil {
		t.Errorf("VerifySOPIN failed for new PIN: %v", err)
	}
}

func TestSoftwareBackend_ChangeSOPIN_TooShort(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	err := b.ChangeSOPIN("sopin123", "abc")
	if !errors.Is(err, ErrPINTooShort) {
		t.Errorf("expected ErrPINTooShort, got: %v", err)
	}
}

func TestSoftwareBackend_ChangeSOPIN_NotSet(t *testing.T) {
	b := newTestSoftwareBackend(t)
	err := b.ChangeSOPIN("oldpin", "newpin123")
	if !errors.Is(err, ErrPINNotSet) {
		t.Errorf("expected ErrPINNotSet, got: %v", err)
	}
}

func TestSoftwareBackend_ChangeSOPIN_WrongCurrent(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	err := b.ChangeSOPIN("wrongpin", "newpin123")
	if !errors.Is(err, ErrInvalidCurrentPIN) {
		t.Errorf("expected ErrInvalidCurrentPIN, got: %v", err)
	}
}

// --- ChangeUserPIN ---

func TestSoftwareBackend_ChangeUserPIN_Success(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b.SetUserPIN("sopin123", "olduser1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}
	if err := b.ChangeUserPIN("olduser1", "newuser1"); err != nil {
		t.Fatalf("ChangeUserPIN failed: %v", err)
	}
	if err := b.VerifyUserPIN("olduser1"); !errors.Is(err, ErrPINInvalid) {
		t.Errorf("expected ErrPINInvalid for old PIN, got: %v", err)
	}
	if err := b.VerifyUserPIN("newuser1"); err != nil {
		t.Errorf("VerifyUserPIN failed for new PIN: %v", err)
	}
}

func TestSoftwareBackend_ChangeUserPIN_TooShort(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b.SetUserPIN("sopin123", "userpin1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}
	err := b.ChangeUserPIN("userpin1", "xy")
	if !errors.Is(err, ErrPINTooShort) {
		t.Errorf("expected ErrPINTooShort, got: %v", err)
	}
}

func TestSoftwareBackend_ChangeUserPIN_NotSet(t *testing.T) {
	b := newTestSoftwareBackend(t)
	err := b.ChangeUserPIN("oldpin", "newpin123")
	if !errors.Is(err, ErrPINNotSet) {
		t.Errorf("expected ErrPINNotSet, got: %v", err)
	}
}

func TestSoftwareBackend_ChangeUserPIN_WrongCurrent(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b.SetUserPIN("sopin123", "userpin1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}
	err := b.ChangeUserPIN("wrongpin", "newpin123")
	if !errors.Is(err, ErrInvalidCurrentPIN) {
		t.Errorf("expected ErrInvalidCurrentPIN, got: %v", err)
	}
}

func TestSoftwareBackend_ChangeUserPIN_UpdatesFIDO2Hash(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b.SetUserPIN("sopin123", "userpin1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}
	if err := b.ChangeUserPIN("userpin1", "newuser1"); err != nil {
		t.Fatalf("ChangeUserPIN failed: %v", err)
	}
	oldHash := ComputeFIDO2PINHash("userpin1")
	if b.VerifyFIDO2Hash(oldHash) {
		t.Error("VerifyFIDO2Hash should return false for old PIN hash after change")
	}
	newHash := ComputeFIDO2PINHash("newuser1")
	if !b.VerifyFIDO2Hash(newHash) {
		t.Error("VerifyFIDO2Hash should return true for new PIN hash after change")
	}
}

// --- VerifySOPIN ---

func TestSoftwareBackend_VerifySOPIN_Success(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b.VerifySOPIN("sopin123"); err != nil {
		t.Errorf("VerifySOPIN failed for correct PIN: %v", err)
	}
}

func TestSoftwareBackend_VerifySOPIN_NotSet(t *testing.T) {
	b := newTestSoftwareBackend(t)
	err := b.VerifySOPIN("somepin")
	if !errors.Is(err, ErrPINNotSet) {
		t.Errorf("expected ErrPINNotSet, got: %v", err)
	}
}

func TestSoftwareBackend_VerifySOPIN_WrongPIN(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	err := b.VerifySOPIN("wrongpin")
	if !errors.Is(err, ErrPINInvalid) {
		t.Errorf("expected ErrPINInvalid, got: %v", err)
	}
}

func TestSoftwareBackend_VerifySOPIN_NilRecord(t *testing.T) {
	b := newTestSoftwareBackend(t)
	b.soPINSet.Store(true)
	err := b.VerifySOPIN("sopin123")
	if !errors.Is(err, ErrPINNotSet) {
		t.Errorf("expected ErrPINNotSet when record is nil, got: %v", err)
	}
}

// --- VerifyUserPIN ---

func TestSoftwareBackend_VerifyUserPIN_Success(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b.SetUserPIN("sopin123", "userpin1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}
	if err := b.VerifyUserPIN("userpin1"); err != nil {
		t.Errorf("VerifyUserPIN failed for correct PIN: %v", err)
	}
}

func TestSoftwareBackend_VerifyUserPIN_NotSet(t *testing.T) {
	b := newTestSoftwareBackend(t)
	err := b.VerifyUserPIN("somepin")
	if !errors.Is(err, ErrPINNotSet) {
		t.Errorf("expected ErrPINNotSet, got: %v", err)
	}
}

func TestSoftwareBackend_VerifyUserPIN_WrongPIN(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b.SetUserPIN("sopin123", "userpin1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}
	err := b.VerifyUserPIN("wrongpin")
	if !errors.Is(err, ErrPINInvalid) {
		t.Errorf("expected ErrPINInvalid, got: %v", err)
	}
}

func TestSoftwareBackend_VerifyUserPIN_NilRecord(t *testing.T) {
	b := newTestSoftwareBackend(t)
	b.userPINSet.Store(true)
	err := b.VerifyUserPIN("userpin1")
	if !errors.Is(err, ErrPINNotSet) {
		t.Errorf("expected ErrPINNotSet when record is nil, got: %v", err)
	}
}

// --- IsInitialized / SOPINSet / UserPINSet ---

func TestSoftwareBackend_IsInitialized_Transitions(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if b.IsInitialized() {
		t.Error("expected false before SetSOPIN")
	}
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if !b.IsInitialized() {
		t.Error("expected true after SetSOPIN")
	}
}

func TestSoftwareBackend_UserPINSet_Transitions(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if b.UserPINSet() {
		t.Error("expected false before SetUserPIN")
	}
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if b.UserPINSet() {
		t.Error("expected false after SetSOPIN but before SetUserPIN")
	}
	if err := b.SetUserPIN("sopin123", "userpin1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}
	if !b.UserPINSet() {
		t.Error("expected true after SetUserPIN")
	}
}

// --- GetLockoutStatus ---

func TestSoftwareBackend_GetLockoutStatus_ReturnsNil(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if status := b.GetLockoutStatus(); status != nil {
		t.Errorf("expected nil LockoutStatus, got: %+v", status)
	}
}

func TestSoftwareBackend_GetLockoutStatus_NilAfterPINOperations(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	for i := 0; i < 10; i++ {
		_ = b.VerifySOPIN("wrongpin")
	}
	if status := b.GetLockoutStatus(); status != nil {
		t.Errorf("expected nil LockoutStatus even after failed verifications, got: %+v", status)
	}
}

// --- ResetLockout ---

func TestSoftwareBackend_ResetLockout_ReturnsNil(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.ResetLockout("anypin"); err != nil {
		t.Errorf("expected nil from ResetLockout, got: %v", err)
	}
}

func TestSoftwareBackend_ResetLockout_NilWithEmptyString(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.ResetLockout(""); err != nil {
		t.Errorf("expected nil from ResetLockout with empty string, got: %v", err)
	}
}

// --- VerifyFIDO2Hash ---

func TestSoftwareBackend_VerifyFIDO2Hash_Success(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b.SetUserPIN("sopin123", "userpin1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}
	hash := ComputeFIDO2PINHash("userpin1")
	if !b.VerifyFIDO2Hash(hash) {
		t.Error("VerifyFIDO2Hash should return true for matching hash")
	}
}

func TestSoftwareBackend_VerifyFIDO2Hash_WrongHash(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b.SetUserPIN("sopin123", "userpin1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}
	wrongHash := ComputeFIDO2PINHash("wrongpin")
	if b.VerifyFIDO2Hash(wrongHash) {
		t.Error("VerifyFIDO2Hash should return false for non-matching hash")
	}
}

func TestSoftwareBackend_VerifyFIDO2Hash_WrongSize(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b.SetUserPIN("sopin123", "userpin1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}
	if b.VerifyFIDO2Hash([]byte{1, 2, 3}) {
		t.Error("VerifyFIDO2Hash should return false for wrong-sized hash (too short)")
	}
	longHash := make([]byte, FIDO2PINHashSize+5)
	if b.VerifyFIDO2Hash(longHash) {
		t.Error("VerifyFIDO2Hash should return false for wrong-sized hash (too long)")
	}
}

func TestSoftwareBackend_VerifyFIDO2Hash_EmptyHash(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b.SetUserPIN("sopin123", "userpin1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}
	if b.VerifyFIDO2Hash(nil) {
		t.Error("VerifyFIDO2Hash should return false for nil hash")
	}
	if b.VerifyFIDO2Hash([]byte{}) {
		t.Error("VerifyFIDO2Hash should return false for empty hash")
	}
}

func TestSoftwareBackend_VerifyFIDO2Hash_NoCachedHash(t *testing.T) {
	b := newTestSoftwareBackend(t)
	hash := ComputeFIDO2PINHash("userpin1")
	if b.VerifyFIDO2Hash(hash) {
		t.Error("VerifyFIDO2Hash should return false when no hash is cached")
	}
}

func TestSoftwareBackend_VerifyFIDO2Hash_AfterChangeUserPIN(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b.SetUserPIN("sopin123", "userpin1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}
	if err := b.ChangeUserPIN("userpin1", "userpin2"); err != nil {
		t.Fatalf("ChangeUserPIN failed: %v", err)
	}
	oldHash := ComputeFIDO2PINHash("userpin1")
	if b.VerifyFIDO2Hash(oldHash) {
		t.Error("old PIN hash should not verify after ChangeUserPIN")
	}
	newHash := ComputeFIDO2PINHash("userpin2")
	if !b.VerifyFIDO2Hash(newHash) {
		t.Error("new PIN hash should verify after ChangeUserPIN")
	}
}

// --- Interface compliance ---

func TestSoftwareBackend_ImplementsPINBackend(t *testing.T) {
	var _ PINBackend = (*SoftwareBackend)(nil)
}

func TestSoftwareBackend_ImplementsFIDO2HashVerifier(t *testing.T) {
	var _ FIDO2HashVerifier = (*SoftwareBackend)(nil)
}

// --- Concurrent access ---

func TestSoftwareBackend_ConcurrentSetAndVerifyUserPIN(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b.SetUserPIN("sopin123", "userpin1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if err := b.VerifyUserPIN("userpin1"); err != nil {
				errs <- err
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent VerifyUserPIN failed: %v", err)
	}
}

func TestSoftwareBackend_ConcurrentVerifySOPIN(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if err := b.VerifySOPIN("sopin123"); err != nil {
				errs <- err
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent VerifySOPIN failed: %v", err)
	}
}

func TestSoftwareBackend_ConcurrentVerifyFIDO2Hash(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b.SetUserPIN("sopin123", "userpin1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}

	hash := ComputeFIDO2PINHash("userpin1")

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	failures := make(chan struct{}, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if !b.VerifyFIDO2Hash(hash) {
				failures <- struct{}{}
			}
		}()
	}

	wg.Wait()
	close(failures)

	for range failures {
		t.Error("concurrent VerifyFIDO2Hash returned false")
	}
}

func TestSoftwareBackend_ConcurrentMixedOperations(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b.SetUserPIN("sopin123", "userpin1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines * 4)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_ = b.VerifySOPIN("sopin123")
		}()
		go func() {
			defer wg.Done()
			_ = b.VerifyUserPIN("userpin1")
		}()
		go func() {
			defer wg.Done()
			_ = b.GetLockoutStatus()
		}()
		go func() {
			defer wg.Done()
			hash := ComputeFIDO2PINHash("userpin1")
			_ = b.VerifyFIDO2Hash(hash)
		}()
	}

	wg.Wait()
}

// --- Table-driven PIN validation tests ---

func TestSoftwareBackend_PINLengthValidation(t *testing.T) {
	tests := []struct {
		name string
		pin  string
		want error
	}{
		{"exactly_min_length", "123456", nil},
		{"above_min_length", "1234567890", nil},
		{"below_min_length_5", "12345", ErrPINTooShort},
		{"below_min_length_1", "x", ErrPINTooShort},
		{"empty_string", "", ErrPINTooShort},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newTestSoftwareBackend(t)
			err := b.SetSOPIN("", tt.pin)
			if tt.want == nil {
				if err != nil {
					t.Errorf("expected no error for PIN %q, got: %v", tt.pin, err)
				}
			} else {
				if !errors.Is(err, tt.want) {
					t.Errorf("expected %v for PIN %q, got: %v", tt.want, tt.pin, err)
				}
			}
		})
	}
}

// --- End-to-end workflow ---

func TestSoftwareBackend_FullWorkflow(t *testing.T) {
	b := newTestSoftwareBackend(t)

	if b.IsInitialized() {
		t.Fatal("should not be initialized")
	}

	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if !b.IsInitialized() {
		t.Fatal("should be initialized after SetSOPIN")
	}

	if err := b.VerifySOPIN("sopin123"); err != nil {
		t.Fatalf("VerifySOPIN failed: %v", err)
	}

	if err := b.SetUserPIN("sopin123", "userpin1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}
	if !b.UserPINSet() {
		t.Fatal("UserPINSet should be true")
	}

	if err := b.VerifyUserPIN("userpin1"); err != nil {
		t.Fatalf("VerifyUserPIN failed: %v", err)
	}

	hash := ComputeFIDO2PINHash("userpin1")
	if !b.VerifyFIDO2Hash(hash) {
		t.Fatal("FIDO2 hash verification failed")
	}

	if err := b.ChangeSOPIN("sopin123", "newso456"); err != nil {
		t.Fatalf("ChangeSOPIN failed: %v", err)
	}
	if err := b.VerifySOPIN("newso456"); err != nil {
		t.Fatalf("VerifySOPIN failed after change: %v", err)
	}

	if err := b.ChangeUserPIN("userpin1", "newuser2"); err != nil {
		t.Fatalf("ChangeUserPIN failed: %v", err)
	}
	if err := b.VerifyUserPIN("newuser2"); err != nil {
		t.Fatalf("VerifyUserPIN failed after change: %v", err)
	}

	newHash := ComputeFIDO2PINHash("newuser2")
	if !b.VerifyFIDO2Hash(newHash) {
		t.Fatal("FIDO2 hash verification failed after user PIN change")
	}

	if status := b.GetLockoutStatus(); status != nil {
		t.Fatalf("expected nil LockoutStatus, got: %+v", status)
	}
	if err := b.ResetLockout("newso456"); err != nil {
		t.Fatalf("ResetLockout should return nil, got: %v", err)
	}
}

// --- Persistence tests ---

func TestSoftwareBackend_PersistsBothPINRecords(t *testing.T) {
	store := storage.NewMemory()

	b1 := newTestSoftwareBackendWithStore(t, store)
	if err := b1.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b1.SetUserPIN("sopin123", "userpin1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}

	if _, err := store.Get(context.Background(), soPINStorageKey); err != nil {
		t.Fatalf("SO PIN record not found in storage: %v", err)
	}
	if _, err := store.Get(context.Background(), userPINStorageKey); err != nil {
		t.Fatalf("user PIN record not found in storage: %v", err)
	}

	b2 := newTestSoftwareBackendWithStore(t, store)

	if !b2.SOPINSet() {
		t.Fatal("SOPINSet should be true after loading from storage")
	}
	if !b2.UserPINSet() {
		t.Fatal("UserPINSet should be true after loading from storage")
	}
	if !b2.IsInitialized() {
		t.Fatal("IsInitialized should be true after loading from storage")
	}

	if err := b2.VerifySOPIN("sopin123"); err != nil {
		t.Fatalf("VerifySOPIN failed after restart: %v", err)
	}
	if err := b2.VerifyUserPIN("userpin1"); err != nil {
		t.Fatalf("VerifyUserPIN failed after restart: %v", err)
	}
}

func TestSoftwareBackend_PersistsSOPIN(t *testing.T) {
	store := storage.NewMemory()

	b1 := newTestSoftwareBackendWithStore(t, store)
	if err := b1.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}

	b2 := newTestSoftwareBackendWithStore(t, store)

	if !b2.SOPINSet() {
		t.Error("SOPINSet should be true after restart")
	}
	if !b2.IsInitialized() {
		t.Error("IsInitialized should be true after restart")
	}
	if err := b2.VerifySOPIN("sopin123"); err != nil {
		t.Errorf("VerifySOPIN failed after restart: %v", err)
	}
}

func TestSoftwareBackend_StorageWriteFailure(t *testing.T) {
	store := storage.NewMemory()

	b := newTestSoftwareBackendWithStore(t, store)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}

	_ = store.Close()

	err := b.SetUserPIN("sopin123", "userpin1")
	if err == nil {
		t.Fatal("expected error when storage write fails")
	}
	var persistErr *ErrStoragePersistFailed
	if !errors.As(err, &persistErr) {
		t.Errorf("expected *ErrStoragePersistFailed, got: %T %v", err, err)
	}
	if persistErr.Key != userPINStorageKey {
		t.Errorf("expected key %q, got %q", userPINStorageKey, persistErr.Key)
	}
}

func TestSoftwareBackend_StorageLoadFailure(t *testing.T) {
	store := storage.NewMemory()
	_ = store.Close()

	_, err := NewSoftwareBackend(store, testHashConfig())
	if err == nil {
		t.Fatal("expected error when storage load fails")
	}
	var loadErr *ErrStorageLoadFailed
	if !errors.As(err, &loadErr) {
		t.Errorf("expected *ErrStorageLoadFailed, got: %T %v", err, err)
	}
}

func TestSoftwareBackend_FIDO2HashLazyRecompute(t *testing.T) {
	store := storage.NewMemory()

	b1 := newTestSoftwareBackendWithStore(t, store)
	if err := b1.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b1.SetUserPIN("sopin123", "userpin1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}

	b2 := newTestSoftwareBackendWithStore(t, store)

	hash := ComputeFIDO2PINHash("userpin1")
	if b2.VerifyFIDO2Hash(hash) {
		t.Error("FIDO2 hash should not verify before first VerifyUserPIN after restart")
	}

	if err := b2.VerifyUserPIN("userpin1"); err != nil {
		t.Fatalf("VerifyUserPIN failed: %v", err)
	}

	if !b2.VerifyFIDO2Hash(hash) {
		t.Error("FIDO2 hash should verify after VerifyUserPIN triggered lazy recompute")
	}
}

func TestSoftwareBackend_PersistsUserPINOnChange(t *testing.T) {
	store := storage.NewMemory()

	b1 := newTestSoftwareBackendWithStore(t, store)
	if err := b1.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b1.SetUserPIN("sopin123", "userpin1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}
	if err := b1.ChangeUserPIN("userpin1", "newuser1"); err != nil {
		t.Fatalf("ChangeUserPIN failed: %v", err)
	}

	b2 := newTestSoftwareBackendWithStore(t, store)

	if err := b2.VerifyUserPIN("userpin1"); !errors.Is(err, ErrPINInvalid) {
		t.Errorf("expected ErrPINInvalid for old PIN after restart, got: %v", err)
	}
	if err := b2.VerifyUserPIN("newuser1"); err != nil {
		t.Errorf("VerifyUserPIN failed for changed PIN after restart: %v", err)
	}
}

func TestSoftwareBackend_PersistsSOPINOnChange(t *testing.T) {
	store := storage.NewMemory()

	b1 := newTestSoftwareBackendWithStore(t, store)
	if err := b1.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b1.ChangeSOPIN("sopin123", "newso456"); err != nil {
		t.Fatalf("ChangeSOPIN failed: %v", err)
	}

	b2 := newTestSoftwareBackendWithStore(t, store)

	if err := b2.VerifySOPIN("sopin123"); !errors.Is(err, ErrPINInvalid) {
		t.Errorf("expected ErrPINInvalid for old SO PIN after restart, got: %v", err)
	}
	if err := b2.VerifySOPIN("newso456"); err != nil {
		t.Errorf("VerifySOPIN failed for changed SO PIN after restart: %v", err)
	}
}

// --- Secure memory tests ---

func TestSoftwareBackend_Close_FreesGuardedBuffer(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b.SetUserPIN("sopin123", "userpin1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}

	guard := b.fido2Guard.Load()
	if guard == nil {
		t.Fatal("expected fido2Guard to be set after SetUserPIN")
	}
	if guard.IsFreed() {
		t.Fatal("fido2Guard should not be freed yet")
	}

	b.Close()

	if !guard.IsFreed() {
		t.Error("fido2Guard should be freed after Close")
	}

	hash := ComputeFIDO2PINHash("userpin1")
	if b.VerifyFIDO2Hash(hash) {
		t.Error("VerifyFIDO2Hash should return false after Close")
	}
}

func TestSoftwareBackend_Close_Idempotent(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b.SetUserPIN("sopin123", "userpin1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}
	b.Close()
	b.Close()
}

func TestSoftwareBackend_Close_NilGuard(t *testing.T) {
	b := newTestSoftwareBackend(t)
	b.Close()
}

func TestSoftwareBackend_VerifyFIDO2Hash_GuardedBuffer(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b.SetUserPIN("sopin123", "userpin1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}

	guard := b.fido2Guard.Load()
	if guard == nil {
		t.Fatal("expected fido2Guard to be allocated")
	}
	if guard.IsFreed() {
		t.Fatal("fido2Guard should not be freed")
	}
	if guard.Size() != FIDO2PINHashSize {
		t.Errorf("expected guard size %d, got %d", FIDO2PINHashSize, guard.Size())
	}

	hash := ComputeFIDO2PINHash("userpin1")
	if !b.VerifyFIDO2Hash(hash) {
		t.Error("FIDO2 hash verification failed with guarded buffer")
	}

	if err := b.ChangeUserPIN("userpin1", "newpin12"); err != nil {
		t.Fatalf("ChangeUserPIN failed: %v", err)
	}

	if !guard.IsFreed() {
		t.Error("old fido2Guard should be freed after PIN change")
	}

	newHash := ComputeFIDO2PINHash("newpin12")
	if !b.VerifyFIDO2Hash(newHash) {
		t.Error("FIDO2 hash verification failed after PIN change")
	}
}

// --- PBKDF2 algorithm tests ---

func TestSoftwareBackend_PBKDF2_FullWorkflow(t *testing.T) {
	b, err := NewSoftwareBackend(nil, testPBKDF2HashConfig())
	if err != nil {
		t.Fatalf("NewSoftwareBackend with PBKDF2 failed: %v", err)
	}

	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b.VerifySOPIN("sopin123"); err != nil {
		t.Fatalf("VerifySOPIN failed: %v", err)
	}
	if err := b.SetUserPIN("sopin123", "userpin1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}
	if err := b.VerifyUserPIN("userpin1"); err != nil {
		t.Fatalf("VerifyUserPIN failed: %v", err)
	}

	hash := ComputeFIDO2PINHash("userpin1")
	if !b.VerifyFIDO2Hash(hash) {
		t.Error("FIDO2 hash should verify with PBKDF2 backend")
	}
}

func TestSoftwareBackend_PBKDF2_Persistence(t *testing.T) {
	store := storage.NewMemory()
	cfg := testPBKDF2HashConfig()

	b1, err := NewSoftwareBackend(store, cfg)
	if err != nil {
		t.Fatalf("NewSoftwareBackend failed: %v", err)
	}
	if err := b1.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b1.SetUserPIN("sopin123", "userpin1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}

	b2, err := NewSoftwareBackend(store, cfg)
	if err != nil {
		t.Fatalf("NewSoftwareBackend restart failed: %v", err)
	}
	if err := b2.VerifySOPIN("sopin123"); err != nil {
		t.Errorf("VerifySOPIN after restart: %v", err)
	}
	if err := b2.VerifyUserPIN("userpin1"); err != nil {
		t.Errorf("VerifyUserPIN after restart: %v", err)
	}
}

func TestSoftwareBackend_UnsupportedHashAlgorithm(t *testing.T) {
	b, err := NewSoftwareBackend(nil, HashConfig{
		Algorithm: "invalid-algo",
		SaltLen:   16,
	})
	if err != nil {
		t.Fatalf("NewSoftwareBackend failed: %v", err)
	}

	hashErr := b.SetSOPIN("", "sopin123")
	if !errors.Is(hashErr, ErrUnsupportedHashAlgorithm) {
		t.Errorf("expected ErrUnsupportedHashAlgorithm, got: %v", hashErr)
	}
}

// --- Storage edge cases ---

func TestSoftwareBackend_StoragePersistSOPINFailure(t *testing.T) {
	store := storage.NewMemory()
	b := newTestSoftwareBackendWithStore(t, store)

	_ = store.Close()

	err := b.SetSOPIN("", "sopin123")
	if err == nil {
		t.Fatal("expected error when SO PIN storage write fails")
	}
	var persistErr *ErrStoragePersistFailed
	if !errors.As(err, &persistErr) {
		t.Errorf("expected *ErrStoragePersistFailed, got: %T %v", err, err)
	}
	if persistErr.Key != soPINStorageKey {
		t.Errorf("expected key %q, got %q", soPINStorageKey, persistErr.Key)
	}
}

func TestSoftwareBackend_NoStoreNoPersistence(t *testing.T) {
	b := newTestSoftwareBackend(t)
	if err := b.SetSOPIN("", "sopin123"); err != nil {
		t.Fatalf("SetSOPIN failed: %v", err)
	}
	if err := b.SetUserPIN("sopin123", "userpin1"); err != nil {
		t.Fatalf("SetUserPIN failed: %v", err)
	}
	if err := b.VerifySOPIN("sopin123"); err != nil {
		t.Errorf("VerifySOPIN failed: %v", err)
	}
	if err := b.VerifyUserPIN("userpin1"); err != nil {
		t.Errorf("VerifyUserPIN failed: %v", err)
	}
}
