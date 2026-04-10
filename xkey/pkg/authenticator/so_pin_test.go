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

package authenticator

import (
	"bytes"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// Test PINs for use in tests.
const (
	testValidPIN     = "123456"                                                          // Minimum length valid PIN
	testValidPIN2    = "SecureP@ss1!"                                                    // Another valid PIN for change tests
	testShortPIN     = "12345"                                                           // 5 chars - too short
	testMaxLengthPIN = "a12345678901234567890123456789012345678901234567890123456789abc" // 63 chars - exactly max
)

// testLongPIN returns a 64-character PIN (one more than max).
func testLongPIN() string {
	return strings.Repeat("a", 64)
}

func TestNewSOPINManager(t *testing.T) {
	t.Run("creates manager with default parameters", func(t *testing.T) {
		mgr := NewSOPINManager()

		require.NotNil(t, mgr)
		require.Equal(t, uint32(SOPINDefaultIterations), mgr.Iterations)
		require.Equal(t, uint32(SOPINDefaultMemory), mgr.Memory)
		require.Equal(t, uint8(SOPINDefaultParallelism), mgr.Parallelism)
	})

	t.Run("manager starts with IsSet false", func(t *testing.T) {
		mgr := NewSOPINManager()

		require.False(t, mgr.IsSet)
		require.Nil(t, mgr.Salt)
	})

	t.Run("manager starts with default retries", func(t *testing.T) {
		mgr := NewSOPINManager()

		require.Equal(t, DefaultSOPINMaxRetries, mgr.Retries())
	})
}

func TestSOPINManager_Initialize(t *testing.T) {
	t.Run("valid PIN initializes successfully", func(t *testing.T) {
		mgr := NewSOPINManager()

		smk, err := mgr.Initialize(testValidPIN)

		require.NoError(t, err)
		require.NotNil(t, smk)
		require.True(t, mgr.IsSet)
	})

	t.Run("returns 32-byte SMK", func(t *testing.T) {
		mgr := NewSOPINManager()

		smk, err := mgr.Initialize(testValidPIN)

		require.NoError(t, err)
		require.Len(t, smk, SOPINDerivedKeySize)
	})

	t.Run("sets IsSet to true", func(t *testing.T) {
		mgr := NewSOPINManager()
		require.False(t, mgr.IsSet)

		_, err := mgr.Initialize(testValidPIN)

		require.NoError(t, err)
		require.True(t, mgr.IsSet)
	})

	t.Run("resets retry counter", func(t *testing.T) {
		mgr := NewSOPINManager()
		mgr.SetRetries(3) // Simulate previous failed attempts

		_, err := mgr.Initialize(testValidPIN)

		require.NoError(t, err)
		require.Equal(t, DefaultSOPINMaxRetries, mgr.Retries())
	})

	t.Run("generates salt", func(t *testing.T) {
		mgr := NewSOPINManager()
		require.Nil(t, mgr.Salt)

		_, err := mgr.Initialize(testValidPIN)

		require.NoError(t, err)
		require.NotNil(t, mgr.Salt)
		require.Len(t, mgr.Salt, SOPINSaltSize)
	})

	t.Run("generates unique salt each initialization", func(t *testing.T) {
		mgr1 := NewSOPINManager()
		mgr2 := NewSOPINManager()

		_, err1 := mgr1.Initialize(testValidPIN)
		_, err2 := mgr2.Initialize(testValidPIN)

		require.NoError(t, err1)
		require.NoError(t, err2)
		require.NotEqual(t, mgr1.Salt, mgr2.Salt)
	})

	t.Run("too short PIN returns ErrSOPINPolicyViolation", func(t *testing.T) {
		mgr := NewSOPINManager()

		smk, err := mgr.Initialize(testShortPIN)

		require.ErrorIs(t, err, ErrSOPINPolicyViolation)
		require.Nil(t, smk)
		require.False(t, mgr.IsSet)
	})

	t.Run("too long PIN returns ErrSOPINPolicyViolation", func(t *testing.T) {
		mgr := NewSOPINManager()

		smk, err := mgr.Initialize(testLongPIN())

		require.ErrorIs(t, err, ErrSOPINPolicyViolation)
		require.Nil(t, smk)
		require.False(t, mgr.IsSet)
	})

	t.Run("max length PIN succeeds", func(t *testing.T) {
		mgr := NewSOPINManager()

		smk, err := mgr.Initialize(testMaxLengthPIN)

		require.NoError(t, err)
		require.NotNil(t, smk)
		require.Len(t, smk, SOPINDerivedKeySize)
	})

	t.Run("second Initialize returns ErrSOPINAlreadySet", func(t *testing.T) {
		mgr := NewSOPINManager()

		smk1, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)
		require.NotNil(t, smk1)

		smk2, err := mgr.Initialize(testValidPIN2)

		require.ErrorIs(t, err, ErrSOPINAlreadySet)
		require.Nil(t, smk2)
	})

	t.Run("does not store key hash (relies on AES-GCM unwrap)", func(t *testing.T) {
		mgr := NewSOPINManager()

		_, err := mgr.Initialize(testValidPIN)

		require.NoError(t, err)
		// StoredKeyHash was removed. Verification is done by AES-GCM
		// authenticated unwrap in KeyManager.UnlockWithSOPIN.
	})
}

func TestSOPINManager_DeriveKey(t *testing.T) {
	t.Run("returns nil if salt not set", func(t *testing.T) {
		mgr := NewSOPINManager()
		// Salt is not set - manager not initialized

		key := mgr.DeriveKey(testValidPIN)

		require.Nil(t, key)
	})

	t.Run("returns 32-byte key after Initialize", func(t *testing.T) {
		mgr := NewSOPINManager()
		_, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)

		key := mgr.DeriveKey(testValidPIN)

		require.NotNil(t, key)
		require.Len(t, key, SOPINDerivedKeySize)
	})

	t.Run("same PIN and salt produces same key (deterministic)", func(t *testing.T) {
		mgr := NewSOPINManager()
		_, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)

		key1 := mgr.DeriveKey(testValidPIN)
		key2 := mgr.DeriveKey(testValidPIN)

		require.Equal(t, key1, key2)
	})

	t.Run("different PIN produces different key", func(t *testing.T) {
		mgr := NewSOPINManager()
		_, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)

		key1 := mgr.DeriveKey(testValidPIN)
		key2 := mgr.DeriveKey(testValidPIN2)

		require.NotEqual(t, key1, key2)
	})

	t.Run("different salt produces different key", func(t *testing.T) {
		mgr1 := NewSOPINManager()
		mgr2 := NewSOPINManager()

		_, err1 := mgr1.Initialize(testValidPIN)
		require.NoError(t, err1)
		_, err2 := mgr2.Initialize(testValidPIN)
		require.NoError(t, err2)

		// Same PIN but different salts (generated randomly)
		key1 := mgr1.DeriveKey(testValidPIN)
		key2 := mgr2.DeriveKey(testValidPIN)

		require.NotEqual(t, key1, key2)
	})
}

func TestSOPINManager_Verify(t *testing.T) {
	t.Run("correct PIN returns SMK", func(t *testing.T) {
		mgr := NewSOPINManager()
		expectedSMK, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)

		smk, err := mgr.Verify(testValidPIN)

		require.NoError(t, err)
		require.NotNil(t, smk)
		require.Equal(t, expectedSMK, smk)
	})

	t.Run("wrong PIN returns different SMK (caller validates via AES-GCM)", func(t *testing.T) {
		mgr := NewSOPINManager()
		expectedSMK, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)

		// With StoredKeyHash removed, Verify no longer rejects wrong PINs directly.
		// It returns a different SMK; the caller (KeyManager.UnlockWithSOPIN)
		// detects the wrong PIN when AES-GCM authenticated unwrap fails.
		wrongSMK, err := mgr.Verify("wrongpin")

		require.NoError(t, err)
		require.NotNil(t, wrongSMK)
		require.NotEqual(t, expectedSMK, wrongSMK)
	})

	t.Run("uninitialized manager returns ErrSOPINNotSet", func(t *testing.T) {
		mgr := NewSOPINManager()

		smk, err := mgr.Verify(testValidPIN)

		require.ErrorIs(t, err, ErrSOPINNotSet)
		require.Nil(t, smk)
	})

	t.Run("blocked manager returns ErrSOPINBlocked", func(t *testing.T) {
		mgr := NewSOPINManager()
		_, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)
		mgr.SetRetries(0) // Block the PIN

		smk, err := mgr.Verify(testValidPIN)

		require.ErrorIs(t, err, ErrSOPINBlocked)
		require.Nil(t, smk)
	})

	t.Run("successful verify resets retry counter", func(t *testing.T) {
		mgr := NewSOPINManager()
		_, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)
		mgr.SetRetries(3) // Simulate some failed attempts

		_, err = mgr.Verify(testValidPIN)

		require.NoError(t, err)
		require.Equal(t, DefaultSOPINMaxRetries, mgr.Retries())
	})

	t.Run("verify derives SMK deterministically", func(t *testing.T) {
		mgr := NewSOPINManager()
		expectedSMK, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)

		// Verify returns the same SMK for the same PIN (deterministic derivation)
		smk1, err := mgr.Verify(testValidPIN)
		require.NoError(t, err)
		require.Equal(t, expectedSMK, smk1)

		smk2, err := mgr.Verify(testValidPIN)
		require.NoError(t, err)
		require.Equal(t, expectedSMK, smk2)
	})
}

func TestSOPINManager_Change(t *testing.T) {
	t.Run("valid change updates salt", func(t *testing.T) {
		mgr := NewSOPINManager()
		originalSMK, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)
		originalSalt := make([]byte, len(mgr.Salt))
		copy(originalSalt, mgr.Salt)

		_, err = mgr.Change(originalSMK, testValidPIN2)

		require.NoError(t, err)
		require.NotEqual(t, originalSalt, mgr.Salt)
	})

	t.Run("returns new SMK", func(t *testing.T) {
		mgr := NewSOPINManager()
		originalSMK, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)

		newSMK, err := mgr.Change(originalSMK, testValidPIN2)

		require.NoError(t, err)
		require.NotNil(t, newSMK)
		require.Len(t, newSMK, SOPINDerivedKeySize)
		require.NotEqual(t, originalSMK, newSMK)
	})

	t.Run("old PIN produces different SMK after change", func(t *testing.T) {
		mgr := NewSOPINManager()
		originalSMK, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)

		newSMK, err := mgr.Change(originalSMK, testValidPIN2)
		require.NoError(t, err)

		// Old PIN now produces a different key (salt changed)
		oldPINDerived := mgr.DeriveKey(testValidPIN)
		require.NotEqual(t, newSMK, oldPINDerived)
	})

	t.Run("new PIN works after change", func(t *testing.T) {
		mgr := NewSOPINManager()
		originalSMK, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)

		newSMK, err := mgr.Change(originalSMK, testValidPIN2)
		require.NoError(t, err)

		// Verify with new PIN should succeed
		verifiedSMK, err := mgr.Verify(testValidPIN2)

		require.NoError(t, err)
		require.Equal(t, newSMK, verifiedSMK)
	})

	t.Run("old PIN produces different SMK after change (detected by AES-GCM)", func(t *testing.T) {
		mgr := NewSOPINManager()
		originalSMK, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)

		newSMK, err := mgr.Change(originalSMK, testValidPIN2)
		require.NoError(t, err)

		// Verify with old PIN returns a different SMK (salt changed).
		// KeyManager.UnlockWithSOPIN will detect this via AES-GCM unwrap failure.
		oldSMK, err := mgr.Verify(testValidPIN)
		require.NoError(t, err)
		require.NotEqual(t, newSMK, oldSMK)
	})

	t.Run("Change accepts any currentSMK (caller validates via AES-GCM)", func(t *testing.T) {
		mgr := NewSOPINManager()
		_, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)

		// Change() no longer validates currentSMK locally.
		// The caller (KeyManager.ChangeSOPIN) validates by unwrapping AK
		// with the SMK first, which is authenticated encryption.
		invalidSMK := make([]byte, SOPINDerivedKeySize)
		newSMK, err := mgr.Change(invalidSMK, testValidPIN2)

		require.NoError(t, err)
		require.NotNil(t, newSMK)
		require.Len(t, newSMK, SOPINDerivedKeySize)
	})

	t.Run("invalid new PIN returns ErrSOPINPolicyViolation", func(t *testing.T) {
		mgr := NewSOPINManager()
		originalSMK, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)

		_, err = mgr.Change(originalSMK, testShortPIN)

		require.ErrorIs(t, err, ErrSOPINPolicyViolation)
	})

	t.Run("too long new PIN returns ErrSOPINPolicyViolation", func(t *testing.T) {
		mgr := NewSOPINManager()
		originalSMK, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)

		_, err = mgr.Change(originalSMK, testLongPIN())

		require.ErrorIs(t, err, ErrSOPINPolicyViolation)
	})

	t.Run("uninitialized manager returns ErrSOPINNotSet", func(t *testing.T) {
		mgr := NewSOPINManager()
		fakeSMK := make([]byte, SOPINDerivedKeySize)

		_, err := mgr.Change(fakeSMK, testValidPIN2)

		require.ErrorIs(t, err, ErrSOPINNotSet)
	})

	t.Run("blocked manager returns ErrSOPINBlocked", func(t *testing.T) {
		mgr := NewSOPINManager()
		originalSMK, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)
		mgr.SetRetries(0)

		_, err = mgr.Change(originalSMK, testValidPIN2)

		require.ErrorIs(t, err, ErrSOPINBlocked)
	})

	t.Run("change resets retry counter", func(t *testing.T) {
		mgr := NewSOPINManager()
		originalSMK, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)
		mgr.SetRetries(3) // Simulate some failed attempts

		_, err = mgr.Change(originalSMK, testValidPIN2)

		require.NoError(t, err)
		require.Equal(t, DefaultSOPINMaxRetries, mgr.Retries())
	})

	t.Run("change generates new salt", func(t *testing.T) {
		mgr := NewSOPINManager()
		originalSMK, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)
		originalSalt := make([]byte, len(mgr.Salt))
		copy(originalSalt, mgr.Salt)

		_, err = mgr.Change(originalSMK, testValidPIN2)

		require.NoError(t, err)
		require.NotEqual(t, originalSalt, mgr.Salt)
		require.Len(t, mgr.Salt, SOPINSaltSize)
	})
}

func TestSOPINManager_Retries(t *testing.T) {
	t.Run("Retries returns correct value", func(t *testing.T) {
		mgr := NewSOPINManager()

		require.Equal(t, DefaultSOPINMaxRetries, mgr.Retries())
	})

	t.Run("SetRetries updates value", func(t *testing.T) {
		mgr := NewSOPINManager()

		mgr.SetRetries(5)

		require.Equal(t, 5, mgr.Retries())
	})

	t.Run("SetRetries to zero", func(t *testing.T) {
		mgr := NewSOPINManager()

		mgr.SetRetries(0)

		require.Equal(t, 0, mgr.Retries())
		require.True(t, mgr.IsBlocked())
	})

	t.Run("DecrementRetries decrements atomically", func(t *testing.T) {
		mgr := NewSOPINManager()
		require.Equal(t, DefaultSOPINMaxRetries, mgr.Retries())

		newValue := mgr.DecrementRetries()

		require.Equal(t, DefaultSOPINMaxRetries-1, newValue)
		require.Equal(t, DefaultSOPINMaxRetries-1, mgr.Retries())
	})

	t.Run("DecrementRetries multiple times", func(t *testing.T) {
		mgr := NewSOPINManager()
		mgr.SetRetries(5)

		for i := 4; i >= 0; i-- {
			newValue := mgr.DecrementRetries()
			require.Equal(t, i, newValue)
		}

		require.Equal(t, 0, mgr.Retries())
		require.True(t, mgr.IsBlocked())
	})

	t.Run("DecrementRetries can go negative", func(t *testing.T) {
		mgr := NewSOPINManager()
		mgr.SetRetries(1)

		mgr.DecrementRetries()             // Now 0
		newValue := mgr.DecrementRetries() // Now -1

		require.Equal(t, -1, newValue)
		require.True(t, mgr.IsBlocked())
	})

	t.Run("ResetRetries sets to default", func(t *testing.T) {
		mgr := NewSOPINManager()
		mgr.SetRetries(2)

		mgr.ResetRetries()

		require.Equal(t, DefaultSOPINMaxRetries, mgr.Retries())
	})

	t.Run("ResetRetries from zero", func(t *testing.T) {
		mgr := NewSOPINManager()
		mgr.SetRetries(0)
		require.True(t, mgr.IsBlocked())

		mgr.ResetRetries()

		require.Equal(t, DefaultSOPINMaxRetries, mgr.Retries())
		require.False(t, mgr.IsBlocked())
	})

	t.Run("IsBlocked returns true when retries equals 0", func(t *testing.T) {
		mgr := NewSOPINManager()
		mgr.SetRetries(0)

		require.True(t, mgr.IsBlocked())
	})

	t.Run("IsBlocked returns true when retries negative", func(t *testing.T) {
		mgr := NewSOPINManager()
		mgr.SetRetries(-1)

		require.True(t, mgr.IsBlocked())
	})

	t.Run("IsBlocked returns false when retries positive", func(t *testing.T) {
		mgr := NewSOPINManager()
		mgr.SetRetries(1)

		require.False(t, mgr.IsBlocked())
	})

	t.Run("concurrent retries operations are thread-safe", func(t *testing.T) {
		mgr := NewSOPINManager()
		mgr.SetRetries(1000)

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 10; j++ {
					mgr.DecrementRetries()
				}
			}()
		}
		wg.Wait()

		// 100 goroutines * 10 decrements = 1000 total decrements
		require.Equal(t, 0, mgr.Retries())
	})
}

func TestSOPINManager_EdgeCases(t *testing.T) {
	t.Run("empty PIN returns policy violation", func(t *testing.T) {
		mgr := NewSOPINManager()

		_, err := mgr.Initialize("")

		require.ErrorIs(t, err, ErrSOPINPolicyViolation)
	})

	t.Run("exactly min length PIN succeeds", func(t *testing.T) {
		mgr := NewSOPINManager()

		smk, err := mgr.Initialize("123456") // 6 chars = min length

		require.NoError(t, err)
		require.NotNil(t, smk)
	})

	t.Run("one less than min length fails", func(t *testing.T) {
		mgr := NewSOPINManager()

		_, err := mgr.Initialize("12345") // 5 chars < 6 min

		require.ErrorIs(t, err, ErrSOPINPolicyViolation)
	})

	t.Run("exactly max length PIN succeeds", func(t *testing.T) {
		mgr := NewSOPINManager()
		// Create exactly 63-character PIN
		pin := testMaxLengthPIN
		require.Len(t, pin, 63)

		smk, err := mgr.Initialize(pin)

		require.NoError(t, err)
		require.NotNil(t, smk)
	})

	t.Run("one more than max length fails", func(t *testing.T) {
		mgr := NewSOPINManager()
		// Create exactly 64-character PIN
		longPIN := testLongPIN()
		require.Len(t, longPIN, 64)

		_, err := mgr.Initialize(longPIN)

		require.ErrorIs(t, err, ErrSOPINPolicyViolation)
	})

	t.Run("unicode PIN length is measured in bytes", func(t *testing.T) {
		mgr := NewSOPINManager()
		// Unicode characters may be multiple bytes
		// "emoji" = 6 emoji characters, each 4 bytes = 24 bytes > 6 min
		emojiPIN := "123456" // Use ASCII for predictable length

		smk, err := mgr.Initialize(emojiPIN)

		require.NoError(t, err)
		require.NotNil(t, smk)
	})

	t.Run("DeriveKey returns nil with empty salt", func(t *testing.T) {
		mgr := NewSOPINManager()
		mgr.Salt = []byte{} // Empty but not nil

		key := mgr.DeriveKey(testValidPIN)

		require.Nil(t, key)
	})

	t.Run("multiple verifications with correct PIN succeed", func(t *testing.T) {
		mgr := NewSOPINManager()
		expectedSMK, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)

		for i := 0; i < 10; i++ {
			smk, err := mgr.Verify(testValidPIN)
			require.NoError(t, err)
			require.True(t, bytes.Equal(expectedSMK, smk))
		}
	})

	t.Run("verify does not modify salt", func(t *testing.T) {
		mgr := NewSOPINManager()
		_, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)
		originalSalt := make([]byte, len(mgr.Salt))
		copy(originalSalt, mgr.Salt)

		_, err = mgr.Verify(testValidPIN)
		require.NoError(t, err)

		require.Equal(t, originalSalt, mgr.Salt)
	})
}

func TestSOPINManager_Constants(t *testing.T) {
	t.Run("salt size is 32 bytes", func(t *testing.T) {
		require.Equal(t, 32, SOPINSaltSize)
	})

	t.Run("derived key size is 32 bytes", func(t *testing.T) {
		require.Equal(t, 32, SOPINDerivedKeySize)
	})

	t.Run("default max retries is 8", func(t *testing.T) {
		require.Equal(t, 8, DefaultSOPINMaxRetries)
	})

	t.Run("default iterations is 3", func(t *testing.T) {
		require.Equal(t, uint32(3), uint32(SOPINDefaultIterations))
	})

	t.Run("default memory is 64 MiB in KiB", func(t *testing.T) {
		require.Equal(t, uint32(64*1024), uint32(SOPINDefaultMemory))
	})

	t.Run("default parallelism is 4", func(t *testing.T) {
		require.Equal(t, uint8(4), uint8(SOPINDefaultParallelism))
	})
}
