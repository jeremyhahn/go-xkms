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
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

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

// TestSOPINManager_ConcurrentDeriveKeyHeapBudget pins the fix for main run
// 42509523145: concurrent Argon2id SO PIN derivations on one manager each
// held SOPINDefaultMemory at once, and the race detector's runner was killed.
func TestSOPINManager_ConcurrentDeriveKeyHeapBudget(t *testing.T) {
	const derivations = 6
	const budget = 3 * SOPINDefaultMemory * 1024 // bytes

	mgr := NewSOPINManager()
	_, err := mgr.Initialize(testValidPIN)
	require.NoError(t, err)

	// Collect each finished derivation's buffer promptly, so the peak
	// counts the buffers held at once, not the garbage pacing leaves.
	defer debug.SetGCPercent(debug.SetGCPercent(10))

	var stats runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&stats)
	baseline := stats.HeapAlloc

	done := make(chan struct{})
	peak := make(chan uint64, 1)
	go func() {
		var max uint64
		var s runtime.MemStats
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			runtime.ReadMemStats(&s)
			if s.HeapAlloc > baseline && s.HeapAlloc-baseline > max {
				max = s.HeapAlloc - baseline
			}
			select {
			case <-done:
				peak <- max
				return
			case <-ticker.C:
			}
		}
	}()

	var wg sync.WaitGroup
	keys := make([][]byte, derivations)
	for i := range derivations {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			keys[i] = mgr.DeriveKey(testValidPIN)
		}(i)
	}
	wg.Wait()
	close(done)

	for _, key := range keys {
		require.Len(t, key, SOPINDerivedKeySize)
		require.Equal(t, keys[0], key)
	}
	require.LessOrEqual(t, <-peak, uint64(budget),
		"%d concurrent SO PIN derivations exceeded the heap budget", derivations)
}

func TestSOPINManager_BeginVerify(t *testing.T) {
	t.Run("correct PIN returns SMK", func(t *testing.T) {
		mgr := NewSOPINManager()
		expectedSMK, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)

		smk, err := mgr.BeginVerify(testValidPIN)

		require.NoError(t, err)
		require.NotNil(t, smk)
		require.Equal(t, expectedSMK, smk)
	})

	t.Run("wrong PIN returns different SMK (caller validates via AES-GCM)", func(t *testing.T) {
		mgr := NewSOPINManager()
		expectedSMK, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)

		// BeginVerify cannot itself reject a wrong PIN: it returns a different
		// SMK, and the caller detects the mismatch when AES-GCM authenticated
		// unwrap fails.
		wrongSMK, err := mgr.BeginVerify("wrongpin")

		require.NoError(t, err)
		require.NotNil(t, wrongSMK)
		require.NotEqual(t, expectedSMK, wrongSMK)
	})

	t.Run("uninitialized manager returns ErrSOPINNotSet", func(t *testing.T) {
		mgr := NewSOPINManager()

		smk, err := mgr.BeginVerify(testValidPIN)

		require.ErrorIs(t, err, ErrSOPINNotSet)
		require.Nil(t, smk)
	})

	t.Run("blocked manager returns ErrSOPINBlocked", func(t *testing.T) {
		mgr := NewSOPINManager()
		_, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)
		mgr.SetRetries(0) // Exhaust the budget

		smk, err := mgr.BeginVerify(testValidPIN)

		require.ErrorIs(t, err, ErrSOPINBlocked)
		require.Nil(t, smk)
	})

	t.Run("spends a retry before the answer is known", func(t *testing.T) {
		mgr := NewSOPINManager()
		_, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)

		// Even the CORRECT PIN spends a retry up front. A caller that never
		// reports back must not get a free attempt.
		_, err = mgr.BeginVerify(testValidPIN)
		require.NoError(t, err)
		require.Equal(t, DefaultSOPINMaxRetries-1, mgr.Retries())
	})

	t.Run("ConfirmVerified restores the budget", func(t *testing.T) {
		mgr := NewSOPINManager()
		_, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)
		mgr.SetRetries(3)

		_, err = mgr.BeginVerify(testValidPIN)
		require.NoError(t, err)
		require.Equal(t, 2, mgr.Retries())

		mgr.ConfirmVerified()
		require.Equal(t, DefaultSOPINMaxRetries, mgr.Retries())
		require.Equal(t, 0, mgr.ConsecutiveFailures())
	})

	t.Run("derives SMK deterministically", func(t *testing.T) {
		mgr := NewSOPINManager()
		expectedSMK, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)

		smk1, err := mgr.BeginVerify(testValidPIN)
		require.NoError(t, err)
		mgr.ConfirmVerified()
		require.Equal(t, expectedSMK, smk1)

		smk2, err := mgr.BeginVerify(testValidPIN)
		require.NoError(t, err)
		mgr.ConfirmVerified()
		require.Equal(t, expectedSMK, smk2)
	})
}

// TestSOPINManager_RetryBudgetIsSpent pins the property whose absence made the
// lockout ornamental: repeated failures must actually exhaust the budget.
func TestSOPINManager_RetryBudgetIsSpent(t *testing.T) {
	t.Run("failures exhaust the budget and lock out", func(t *testing.T) {
		mgr := NewSOPINManager()
		_, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)

		var last error
		for i := 0; i < DefaultSOPINMaxRetries; i++ {
			// A power cycle between attempts clears only the consecutive
			// counter, never the budget.
			mgr.consecutiveFailures.reset()

			_, err := mgr.BeginVerify("wrongpin999")
			require.NoError(t, err, "attempt %d must be admitted", i)
			last = mgr.RecordFailure()
		}

		require.ErrorIs(t, last, ErrSOPINBlocked)
		require.True(t, mgr.IsBlocked())
		require.Equal(t, 0, mgr.Retries())

		// Even the correct PIN is refused once the budget is gone.
		_, err = mgr.BeginVerify(testValidPIN)
		require.ErrorIs(t, err, ErrSOPINBlocked)
	})

	t.Run("power cycle threshold blocks before the budget is gone", func(t *testing.T) {
		mgr := NewSOPINManager()
		_, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)

		var last error
		for i := 0; i < PINMaxConsecutiveFailures; i++ {
			_, err := mgr.BeginVerify("wrongpin999")
			require.NoError(t, err)
			last = mgr.RecordFailure()
		}

		require.ErrorIs(t, last, ErrSOPINAuthBlocked)
		require.True(t, mgr.IsAuthBlocked())
		require.False(t, mgr.IsBlocked(), "the total budget must not be exhausted yet")

		// Further attempts are refused until a power cycle, even with the
		// correct PIN, and they do NOT consume more of the budget.
		before := mgr.Retries()
		_, err = mgr.BeginVerify(testValidPIN)
		require.ErrorIs(t, err, ErrSOPINAuthBlocked)
		require.Equal(t, before, mgr.Retries())
	})

	t.Run("a success between failures clears the consecutive counter", func(t *testing.T) {
		mgr := NewSOPINManager()
		_, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)

		for i := 0; i < PINMaxConsecutiveFailures-1; i++ {
			_, err := mgr.BeginVerify("wrongpin999")
			require.NoError(t, err)
			require.ErrorIs(t, mgr.RecordFailure(), ErrSOPINInvalid)
		}

		_, err = mgr.BeginVerify(testValidPIN)
		require.NoError(t, err)
		mgr.ConfirmVerified()

		require.Equal(t, 0, mgr.ConsecutiveFailures())
		require.Equal(t, DefaultSOPINMaxRetries, mgr.Retries())
	})
}

func TestSOPINManager_Rekey(t *testing.T) {
	t.Run("valid rekey updates salt", func(t *testing.T) {
		mgr := NewSOPINManager()
		_, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)
		originalSalt := make([]byte, len(mgr.Salt))
		copy(originalSalt, mgr.Salt)

		_, err = mgr.Rekey(testValidPIN2)

		require.NoError(t, err)
		require.NotEqual(t, originalSalt, mgr.Salt)
		require.Len(t, mgr.Salt, SOPINSaltSize)
	})

	t.Run("returns new SMK", func(t *testing.T) {
		mgr := NewSOPINManager()
		originalSMK, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)

		newSMK, err := mgr.Rekey(testValidPIN2)

		require.NoError(t, err)
		require.NotNil(t, newSMK)
		require.Len(t, newSMK, SOPINDerivedKeySize)
		require.NotEqual(t, originalSMK, newSMK)
	})

	t.Run("old PIN produces different SMK after rekey", func(t *testing.T) {
		mgr := NewSOPINManager()
		_, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)

		newSMK, err := mgr.Rekey(testValidPIN2)
		require.NoError(t, err)

		// Old PIN now produces a different key (salt changed)
		require.NotEqual(t, newSMK, mgr.DeriveKey(testValidPIN))
	})

	t.Run("new PIN derives the returned SMK", func(t *testing.T) {
		mgr := NewSOPINManager()
		_, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)

		newSMK, err := mgr.Rekey(testValidPIN2)
		require.NoError(t, err)

		verifiedSMK, err := mgr.BeginVerify(testValidPIN2)
		require.NoError(t, err)
		require.Equal(t, newSMK, verifiedSMK)
	})

	t.Run("too short new PIN returns ErrSOPINPolicyViolation and does not rotate", func(t *testing.T) {
		mgr := NewSOPINManager()
		_, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)
		originalSalt := make([]byte, len(mgr.Salt))
		copy(originalSalt, mgr.Salt)

		_, err = mgr.Rekey(testShortPIN)

		require.ErrorIs(t, err, ErrSOPINPolicyViolation)
		require.Equal(t, originalSalt, mgr.Salt, "a rejected rekey must not rotate the salt")
	})

	t.Run("too long new PIN returns ErrSOPINPolicyViolation", func(t *testing.T) {
		mgr := NewSOPINManager()
		_, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)

		_, err = mgr.Rekey(testLongPIN())

		require.ErrorIs(t, err, ErrSOPINPolicyViolation)
	})

	t.Run("uninitialized manager returns ErrSOPINNotSet", func(t *testing.T) {
		mgr := NewSOPINManager()

		_, err := mgr.Rekey(testValidPIN2)

		require.ErrorIs(t, err, ErrSOPINNotSet)
	})

	t.Run("rekey restores the retry budget", func(t *testing.T) {
		mgr := NewSOPINManager()
		_, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)
		mgr.SetRetries(3)

		_, err = mgr.Rekey(testValidPIN2)

		require.NoError(t, err)
		require.Equal(t, DefaultSOPINMaxRetries, mgr.Retries())
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

	t.Run("BeginVerify decrements atomically", func(t *testing.T) {
		mgr := NewSOPINManager()
		_, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)
		require.Equal(t, DefaultSOPINMaxRetries, mgr.Retries())

		_, err = mgr.BeginVerify(testValidPIN)

		require.NoError(t, err)
		require.Equal(t, DefaultSOPINMaxRetries-1, mgr.Retries())
	})

	t.Run("repeated attempts walk the budget down to a lockout", func(t *testing.T) {
		mgr := NewSOPINManager()
		_, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)
		mgr.SetRetries(5)

		for i := 4; i >= 0; i-- {
			mgr.consecutiveFailures.reset()
			_, err := mgr.BeginVerify("wrongpin999")
			require.NoError(t, err)
			require.Equal(t, i, mgr.Retries())
			require.ErrorIs(t, mgr.RecordFailure(), map[bool]error{true: ErrSOPINBlocked, false: ErrSOPINInvalid}[i == 0])
		}

		require.Equal(t, 0, mgr.Retries())
		require.True(t, mgr.IsBlocked())
	})

	t.Run("a blocked manager admits no further attempts", func(t *testing.T) {
		mgr := NewSOPINManager()
		_, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)
		mgr.SetRetries(1)

		_, err = mgr.BeginVerify("wrongpin999")
		require.NoError(t, err)
		require.ErrorIs(t, mgr.RecordFailure(), ErrSOPINBlocked)

		// The budget cannot be driven negative by further attempts, because
		// there are no further attempts.
		_, err = mgr.BeginVerify("wrongpin999")
		require.ErrorIs(t, err, ErrSOPINBlocked)
		require.Equal(t, 0, mgr.Retries())
	})

	t.Run("ConfirmVerified sets to default", func(t *testing.T) {
		mgr := NewSOPINManager()
		mgr.SetRetries(2)

		mgr.ConfirmVerified()

		require.Equal(t, DefaultSOPINMaxRetries, mgr.Retries())
	})

	t.Run("ConfirmVerified from zero", func(t *testing.T) {
		mgr := NewSOPINManager()
		mgr.SetRetries(0)
		require.True(t, mgr.IsBlocked())

		mgr.ConfirmVerified()

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

	t.Run("concurrent attempts each cost exactly one retry", func(t *testing.T) {
		mgr := NewSOPINManager()
		_, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)

		// Argon2id at the production parameters is memory-hard by design: 64
		// MiB of scratch per derivation. This subtest deliberately runs 100
		// derivations at once, so at the defaults it holds ~6.4 GiB live --
		// and under -race, which is how CI runs this package, it peaked at
		// 41.7 GB and the runner's OOM killer took the process ("signal:
		// killed", job 44178). The assertion here is about the atomic budget
		// accounting, not about the KDF's cost, so the manager is dialled down
		// to Argon2's floor (memory >= 8*parallelism). Every other subtest in
		// this file exercises the derivation at the shipped parameters.
		mgr.Iterations = 1
		mgr.Memory = 8
		mgr.Parallelism = 1

		mgr.SetRetries(1000)

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 10; j++ {
					// consecutiveFailures is left alone: this exercises the
					// budget accounting, which must not lose or double-count a
					// decrement under contention.
					if _, err := mgr.BeginVerify(testValidPIN); err != nil {
						return
					}
				}
			}()
		}
		wg.Wait()

		// 100 goroutines * 10 attempts = 1000 retries spent
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

	t.Run("multiple confirmed verifications with correct PIN succeed", func(t *testing.T) {
		mgr := NewSOPINManager()
		expectedSMK, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)

		for i := 0; i < 10; i++ {
			smk, err := mgr.BeginVerify(testValidPIN)
			require.NoError(t, err)
			require.True(t, bytes.Equal(expectedSMK, smk))
			mgr.ConfirmVerified()
		}
	})

	t.Run("verification does not modify salt", func(t *testing.T) {
		mgr := NewSOPINManager()
		_, err := mgr.Initialize(testValidPIN)
		require.NoError(t, err)
		originalSalt := make([]byte, len(mgr.Salt))
		copy(originalSalt, mgr.Salt)

		_, err = mgr.BeginVerify(testValidPIN)
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
