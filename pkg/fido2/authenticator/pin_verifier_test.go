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
	"crypto/sha256"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// testPINVerifier implements PINVerifier for testing.
type testPINVerifier struct {
	pinSet    bool
	fido2Hash []byte
}

func (v *testPINVerifier) IsPINSet() bool {
	return v.pinSet
}

func (v *testPINVerifier) VerifyFIDO2Hash(hash []byte) bool {
	if len(hash) != len(v.fido2Hash) {
		return false
	}
	for i := range hash {
		if hash[i] != v.fido2Hash[i] {
			return false
		}
	}
	return true
}

func TestAuthenticator_SetPINVerifier(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	verifier := &testPINVerifier{pinSet: true}
	auth.SetPINVerifier(verifier)

	// IsPINSet should delegate to verifier.
	require.True(t, auth.IsPINSet())

	// Change verifier state.
	verifier.pinSet = false
	require.False(t, auth.IsPINSet())
}

func TestAuthenticator_IsPINSet_FallsBackToState(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	// No verifier set — should fall back to state.PINSet.
	require.False(t, auth.IsPINSet())

	// Set PIN via internal state.
	pinHash := sha256.Sum256([]byte("testpin123"))
	auth.SyncPINHash(pinHash[:PINHashSize])
	require.True(t, auth.IsPINSet())
}

func TestAuthenticator_SetPINVerifier_OverridesInternalState(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	// Set internal PIN state.
	pinHash := sha256.Sum256([]byte("testpin123"))
	auth.SyncPINHash(pinHash[:PINHashSize])
	require.True(t, auth.IsPINSet())

	// Set verifier that says PIN is NOT set — verifier wins.
	verifier := &testPINVerifier{pinSet: false}
	auth.SetPINVerifier(verifier)
	require.False(t, auth.IsPINSet())
}

func TestAuthenticator_SetFIDO2PINHash(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	pinHash := sha256.Sum256([]byte("testpin123"))
	hash := pinHash[:PINHashSize]

	auth.SetFIDO2PINHash(hash)

	require.True(t, auth.state.PINSet)
	require.Equal(t, hash, auth.state.PINHash)
}

func TestAuthenticator_SetFIDO2PINHash_ResetsRetries(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	// Simulate failed attempts.
	auth.state.DecrementPINRetries()
	auth.state.DecrementPINRetries()
	retries := auth.state.PINRetries()
	require.Less(t, retries, DefaultPINMaxRetries)

	// SetFIDO2PINHash should reset retries.
	pinHash := sha256.Sum256([]byte("testpin123"))
	auth.SetFIDO2PINHash(pinHash[:PINHashSize])
	require.Equal(t, DefaultPINMaxRetries, auth.state.PINRetries())
}

func TestAuthenticator_SetPINVerifier_NilVerifier(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	verifier := &testPINVerifier{pinSet: true}
	auth.SetPINVerifier(verifier)
	require.True(t, auth.IsPINSet())

	// Clear verifier — falls back to state.
	auth.SetPINVerifier(nil)
	require.False(t, auth.IsPINSet())
}

// ---------------------------------------------------------------------------
// isPINSetLocked tests
// ---------------------------------------------------------------------------

func TestIsPINSetLocked_DelegatesToVerifier(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	verifier := &testPINVerifier{pinSet: true}
	auth.SetPINVerifier(verifier)

	auth.mu.RLock()
	result := auth.isPINSetLocked()
	auth.mu.RUnlock()

	require.True(t, result)

	// Verifier says false.
	verifier.pinSet = false
	auth.mu.RLock()
	result = auth.isPINSetLocked()
	auth.mu.RUnlock()

	require.False(t, result)
}

func TestIsPINSetLocked_FallsBackToState(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	// No verifier — should use state.
	auth.mu.RLock()
	result := auth.isPINSetLocked()
	auth.mu.RUnlock()
	require.False(t, result)

	// Set PIN via state.
	pinHash := sha256.Sum256([]byte("testpin123"))
	auth.SyncPINHash(pinHash[:PINHashSize])

	auth.mu.RLock()
	result = auth.isPINSetLocked()
	auth.mu.RUnlock()
	require.True(t, result)
}

// ---------------------------------------------------------------------------
// verifyPINHashLocked tests
// ---------------------------------------------------------------------------

func TestVerifyPINHashLocked_DelegatesToVerifier(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	pinHash := sha256.Sum256([]byte("testpin123"))
	hash := pinHash[:PINHashSize]

	verifier := &testPINVerifier{pinSet: true, fido2Hash: hash}
	auth.SetPINVerifier(verifier)

	auth.mu.RLock()
	result := auth.verifyPINHashLocked(hash)
	auth.mu.RUnlock()

	require.True(t, result)
}

func TestVerifyPINHashLocked_FallsBackToState(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	// No verifier — set PIN in state directly.
	pinHash := sha256.Sum256([]byte("testpin123"))
	hash := pinHash[:PINHashSize]
	auth.SetFIDO2PINHash(hash)

	auth.mu.RLock()
	result := auth.verifyPINHashLocked(hash)
	auth.mu.RUnlock()

	require.True(t, result)
}

func TestVerifyPINHashLocked_WrongHash(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	pinHash := sha256.Sum256([]byte("testpin123"))
	hash := pinHash[:PINHashSize]
	auth.SetFIDO2PINHash(hash)

	wrongHash := sha256.Sum256([]byte("wrongpin"))

	auth.mu.RLock()
	result := auth.verifyPINHashLocked(wrongHash[:PINHashSize])
	auth.mu.RUnlock()

	require.False(t, result)
}

// TestVerifyPINHashLocked_VerifierRejectionIsNotOverridden proves a
// configured verifier's negative result stands even though a.state.PINHash
// carries a hash that would itself match — there is no fallback to local
// state once a verifier is configured. See also
// TestAuthenticator_VerifyPINHash_VerifierRejectionIsFinal for the
// restart/lazy-init scenario this compat path used to paper over.
func TestVerifyPINHashLocked_VerifierRejectionIsNotOverridden(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	pinHash := sha256.Sum256([]byte("testpin123"))
	hash := pinHash[:PINHashSize]

	// Set the PIN hash in state directly.
	auth.SetFIDO2PINHash(hash)

	// Set a verifier that does NOT know the hash (e.g. lazy-init race).
	verifier := &testPINVerifier{pinSet: true, fido2Hash: nil}
	auth.SetPINVerifier(verifier)

	// The verifier is authoritative once configured: its rejection is final.
	auth.mu.RLock()
	result := auth.verifyPINHashLocked(hash)
	auth.mu.RUnlock()

	require.False(t, result)
}

func TestVerifyPINHashLocked_NoPINHashStored(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	// No PIN hash stored, no verifier.
	someHash := sha256.Sum256([]byte("testpin123"))

	auth.mu.RLock()
	result := auth.verifyPINHashLocked(someHash[:PINHashSize])
	auth.mu.RUnlock()

	require.False(t, result)
}

// ---------------------------------------------------------------------------
// PINVerifier is authoritative: no local-hash fallback
// ---------------------------------------------------------------------------

// TestAuthenticator_VerifyPINHash_VerifierRejectionIsFinal proves a
// configured PINVerifier's negative result is final: verifyPINHashLocked no
// longer re-checks a.state.PINHash after the verifier rejects a hash, even
// when the persisted hash would itself have matched. The previous fallback
// (kept for "restart / lazy-init" scenarios where the verifier's backend
// guard was still nil) re-checked a second, potentially-stale source of
// truth after an explicit negative result; that compat path is deleted, so
// a caller with a configured PINVerifier that is not yet ready to answer
// must report itself unready (or initialize synchronously) rather than
// relying on the authenticator to paper over it.
func TestAuthenticator_VerifyPINHash_VerifierRejectionIsFinal(t *testing.T) {
	storage := NewMemoryStorage()

	config := DefaultConfig()
	config.UserPresenceHandler = NewAutoGrantHandler()
	config.Storage = storage

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	pinHash := sha256.Sum256([]byte("restart-pin-test"))
	hash := pinHash[:PINHashSize]

	// Persist a PIN hash directly on the authenticator's internal state, so
	// a local hmac.Equal comparison (if one ran) would succeed.
	auth.SetFIDO2PINHash(hash)
	require.True(t, auth.state.PINSet)
	require.Equal(t, hash, auth.state.PINHash)

	// A PINVerifier that rejects every hash (e.g. its own backend not yet
	// initialized) must be trusted as-is — not overridden by the matching
	// local state.
	verifier := &testPINVerifier{pinSet: true, fido2Hash: nil}
	auth.SetPINVerifier(verifier)

	auth.mu.RLock()
	result := auth.verifyPINHashLocked(hash)
	auth.mu.RUnlock()

	require.False(t, result,
		"verifyPINHashLocked must honor the PINVerifier's rejection even though "+
			"a.state.PINHash matches — there is no local-hash fallback")
}

// ---------------------------------------------------------------------------
// Concurrent verifier publish vs. verify (go-xkms#640)
// ---------------------------------------------------------------------------

// raceTestPINVerifier is a concurrency-safe PINVerifier double that models a
// PINService published to the authenticator (SetPINVerifier) before it is
// populated: ready is false and every query fails closed until publish is
// called, at which point it becomes the authoritative, correct answer.
type raceTestPINVerifier struct {
	ready atomic.Bool
	hash  atomic.Pointer[[]byte]
}

func (v *raceTestPINVerifier) IsPINSet() bool {
	return v.ready.Load()
}

func (v *raceTestPINVerifier) VerifyFIDO2Hash(hash []byte) bool {
	if !v.ready.Load() {
		return false
	}
	want := v.hash.Load()
	if want == nil || len(*want) != len(hash) {
		return false
	}
	for i := range hash {
		if hash[i] != (*want)[i] {
			return false
		}
	}
	return true
}

func (v *raceTestPINVerifier) publish(hash []byte) {
	stored := append([]byte(nil), hash...)
	v.hash.Store(&stored)
	v.ready.Store(true)
}

// TestAuthenticator_PINVerifier_ConcurrentPublishNeverReturnsWrongResult
// drives IsPINSet/verifyPINHashLocked concurrently with the verifier being
// populated, under -race (go-xkms#640). The verifier is published to the
// authenticator via SetPINVerifier before it is populated — the exact
// start-up ordering this issue is about. Readers hammer both the correct
// and an incorrect hash throughout the transition; the wrong hash must
// never verify (a false positive would be a security bug, not just a
// start-up glitch), and once verification of the correct hash succeeds it
// must never regress.
func TestAuthenticator_PINVerifier_ConcurrentPublishNeverReturnsWrongResult(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	pinHash := sha256.Sum256([]byte("race-pin-test"))
	hash := pinHash[:PINHashSize]

	wrongPINHash := sha256.Sum256([]byte("not-the-pin"))
	wrongHash := wrongPINHash[:PINHashSize]

	verifier := &raceTestPINVerifier{}
	auth.SetPINVerifier(verifier)

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
				auth.mu.RLock()
				wrongVerified := auth.verifyPINHashLocked(wrongHash)
				verified := auth.verifyPINHashLocked(hash)
				auth.mu.RUnlock()
				if wrongVerified {
					falsePositive.Store(true)
				}
				if verified {
					verifiedBefore = true
				} else if verifiedBefore {
					regressed.Store(true)
				}
			}
		}()
	}

	// Populate the verifier once, simulating initPINService() completing
	// after SetPINVerifier already published the not-yet-ready verifier.
	time.Sleep(time.Millisecond)
	verifier.publish(hash)

	// Wait for the readers to observe the now-populated verifier before
	// tearing them down, and confirm verification succeeds reliably.
	deadline := time.Now().Add(50 * time.Millisecond)
	for time.Now().Before(deadline) {
		auth.mu.RLock()
		verified := auth.verifyPINHashLocked(hash)
		auth.mu.RUnlock()
		if verified {
			break
		}
	}
	auth.mu.RLock()
	finalVerified := auth.verifyPINHashLocked(hash)
	auth.mu.RUnlock()
	require.True(t, finalVerified, "verification must succeed once the verifier is populated")

	close(done)
	readers.Wait()

	require.False(t, falsePositive.Load(), "an incorrect hash must never verify")
	require.False(t, regressed.Load(), "verification must never regress once it has succeeded")
}

// TestAuthenticator_VerifyPINHash_NoVerifierUsesLocalState proves the local
// hmac.Equal comparison against a.state.PINHash remains the verification
// mechanism for standalone mode — no PINVerifier configured at all — which
// is a distinct, still-supported case from a configured verifier's negative
// result.
func TestAuthenticator_VerifyPINHash_NoVerifierUsesLocalState(t *testing.T) {
	storage := NewMemoryStorage()

	config := DefaultConfig()
	config.UserPresenceHandler = NewAutoGrantHandler()
	config.Storage = storage

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	pinHash := sha256.Sum256([]byte("standalone-pin-test"))
	hash := pinHash[:PINHashSize]
	auth.SetFIDO2PINHash(hash)

	auth.mu.RLock()
	result := auth.verifyPINHashLocked(hash)
	auth.mu.RUnlock()
	require.True(t, result, "no PINVerifier configured: local state.PINHash must verify")

	wrongHash := sha256.Sum256([]byte("wrong-pin"))
	auth.mu.RLock()
	wrongResult := auth.verifyPINHashLocked(wrongHash[:PINHashSize])
	auth.mu.RUnlock()
	require.False(t, wrongResult, "no PINVerifier configured: an incorrect hash must still fail")
}
