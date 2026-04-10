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
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func TestErrStoragePersistFailed_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("disk full")
	err := &ErrStoragePersistFailed{Key: "so-pin", Cause: cause}

	msg := err.Error()
	if !strings.Contains(msg, "so-pin") {
		t.Errorf("Error() missing key, got %q", msg)
	}
	if !strings.Contains(msg, "disk full") {
		t.Errorf("Error() missing cause, got %q", msg)
	}

	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}

	// Verify errors.Is works through Unwrap chain.
	if !errors.Is(err, cause) {
		t.Error("errors.Is should find cause through Unwrap")
	}
}

func TestErrStoragePersistFailed_ErrorsAs(t *testing.T) {
	cause := fmt.Errorf("write failed")
	err := &ErrStoragePersistFailed{Key: "user-pin", Cause: cause}

	var target *ErrStoragePersistFailed
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match ErrStoragePersistFailed")
	}
	if target.Key != "user-pin" {
		t.Errorf("Key = %q, want %q", target.Key, "user-pin")
	}
}

func TestErrStorageLoadFailed_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("permission denied")
	err := &ErrStorageLoadFailed{Key: "user-pin", Cause: cause}

	msg := err.Error()
	if !strings.Contains(msg, "user-pin") {
		t.Errorf("Error() missing key, got %q", msg)
	}
	if !strings.Contains(msg, "permission denied") {
		t.Errorf("Error() missing cause, got %q", msg)
	}

	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}

	if !errors.Is(err, cause) {
		t.Error("errors.Is should find cause through Unwrap")
	}
}

func TestErrStorageLoadFailed_ErrorsAs(t *testing.T) {
	cause := fmt.Errorf("corrupt data")
	err := &ErrStorageLoadFailed{Key: "so-pin", Cause: cause}

	var target *ErrStorageLoadFailed
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match ErrStorageLoadFailed")
	}
	if target.Key != "so-pin" {
		t.Errorf("Key = %q, want %q", target.Key, "so-pin")
	}
}

func TestErrUnsupportedPBKDF2Hash_Error(t *testing.T) {
	err := &ErrUnsupportedPBKDF2Hash{Hash: types.HashName("BLAKE2b")}
	msg := err.Error()
	if !strings.Contains(msg, "BLAKE2b") {
		t.Errorf("Error() missing hash name, got %q", msg)
	}
	if !strings.Contains(msg, "unsupported") {
		t.Errorf("Error() missing 'unsupported', got %q", msg)
	}
}

func TestErrUnsupportedPBKDF2Hash_ErrorsAs(t *testing.T) {
	err := &ErrUnsupportedPBKDF2Hash{Hash: types.HashName("MD5")}

	var target *ErrUnsupportedPBKDF2Hash
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match ErrUnsupportedPBKDF2Hash")
	}
	if target.Hash != "MD5" {
		t.Errorf("Hash = %q, want %q", target.Hash, "MD5")
	}
}

func TestErrTPMLocked_Error(t *testing.T) {
	err := &ErrTPMLocked{
		Status: &LockoutStatus{
			RecoverySeconds: 300,
		},
	}
	msg := err.Error()
	if !strings.Contains(msg, "300") {
		t.Errorf("Error() missing recovery seconds, got %q", msg)
	}
	if !strings.Contains(msg, "locked") {
		t.Errorf("Error() missing 'locked', got %q", msg)
	}
}

func TestErrTPMLocked_ZeroRecovery(t *testing.T) {
	err := &ErrTPMLocked{
		Status: &LockoutStatus{
			RecoverySeconds: 0,
		},
	}
	msg := err.Error()
	if !strings.Contains(msg, "0 seconds") {
		t.Errorf("Error() should show 0 seconds, got %q", msg)
	}
}

func TestErrPINInvalidWithStatus_Error(t *testing.T) {
	err := &ErrPINInvalidWithStatus{
		Status: &LockoutStatus{
			FailedAttempts: 3,
			MaxAttempts:    5,
		},
	}
	msg := err.Error()
	// remaining = 5 - 3 = 2
	if !strings.Contains(msg, "2 of 5") {
		t.Errorf("Error() should contain '2 of 5', got %q", msg)
	}
	if !strings.Contains(msg, "invalid PIN") {
		t.Errorf("Error() should contain 'invalid PIN', got %q", msg)
	}
}

func TestErrPINInvalidWithStatus_AllAttemptsUsed(t *testing.T) {
	err := &ErrPINInvalidWithStatus{
		Status: &LockoutStatus{
			FailedAttempts: 5,
			MaxAttempts:    5,
		},
	}
	msg := err.Error()
	// remaining = 5 - 5 = 0
	if !strings.Contains(msg, "0 of 5") {
		t.Errorf("Error() should contain '0 of 5', got %q", msg)
	}
}

func TestSentinelErrors_AreDistinct(t *testing.T) {
	sentinels := []error{
		ErrPINNotSet,
		ErrPINLocked,
		ErrPINInvalid,
		ErrSOPINRequired,
		ErrPINTooShort,
		ErrPINAlreadySet,
		ErrInvalidCurrentPIN,
		ErrStateCorrupted,
		ErrStrategyNotSet,
		ErrHierarchyAuthMismatch,
		ErrUnsupportedHashAlgorithm,
	}
	for i := 0; i < len(sentinels); i++ {
		for j := i + 1; j < len(sentinels); j++ {
			if errors.Is(sentinels[i], sentinels[j]) {
				t.Errorf("sentinel errors %d and %d should be distinct", i, j)
			}
		}
	}
}
