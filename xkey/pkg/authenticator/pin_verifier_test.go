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
	"testing"

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

func TestVerifyPINHashLocked_VerifierFailsFallsBackToState(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	pinHash := sha256.Sum256([]byte("testpin123"))
	hash := pinHash[:PINHashSize]

	// Set the PIN hash in state directly.
	auth.SetFIDO2PINHash(hash)

	// Set verifier that does NOT know the hash (simulates lazy-init race).
	verifier := &testPINVerifier{pinSet: true, fido2Hash: nil}
	auth.SetPINVerifier(verifier)

	// Verifier fails, but state has the hash — should fall back.
	auth.mu.RLock()
	result := auth.verifyPINHashLocked(hash)
	auth.mu.RUnlock()

	require.True(t, result)
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
// Regression: restart fallback
// ---------------------------------------------------------------------------

// TestAuthenticator_VerifyPINHash_FallbackAfterRestart is a regression test for
// a bug where PINVerifier.VerifyFIDO2Hash returned false after an application
// restart because the SoftwareBackend's fido2Guard was nil (not yet
// re-initialized). The authenticator must fall back to hmac.Equal against
// the persisted state.PINHash in that scenario so that PIN verification
// continues to work immediately after restart, before the PINService has
// fully re-initialized the backend guard.
func TestAuthenticator_VerifyPINHash_FallbackAfterRestart(t *testing.T) {
	// Step 1: Create shared storage and an authenticator, set a PIN hash.
	storage := NewMemoryStorage()

	config := DefaultConfig()
	config.Storage = storage

	auth1, err := NewAuthenticator(config)
	require.NoError(t, err)

	pinHash := sha256.Sum256([]byte("restart-pin-test"))
	hash := pinHash[:PINHashSize]

	// Persist the PIN hash to storage via the authenticator.
	auth1.SetFIDO2PINHash(hash)

	// Confirm state was persisted correctly.
	require.True(t, auth1.state.PINSet)
	require.Equal(t, hash, auth1.state.PINHash)

	// Close the first authenticator (simulates app shutdown).
	// Note: Close does NOT close the storage — the caller owns the storage
	// lifecycle, which mirrors real production behavior.
	require.NoError(t, auth1.Close())

	// Step 2: Create a NEW authenticator from the same storage (simulates
	// restart). NewAuthenticator calls storage.LoadState(), which should
	// restore the persisted PINHash.
	config2 := DefaultConfig()
	config2.Storage = storage

	auth2, err := NewAuthenticator(config2)
	require.NoError(t, err)
	defer func() { _ = auth2.Close() }()

	// Verify the PIN hash was loaded from storage.
	require.True(t, auth2.state.PINSet,
		"PINSet must be true after restart — state was loaded from storage")
	require.Equal(t, hash, auth2.state.PINHash,
		"PINHash must match the original — state was loaded from storage")

	// Step 3: Set a PINVerifier that always returns false for VerifyFIDO2Hash.
	// This simulates the SoftwareBackend after restart when fido2Guard is nil.
	verifier := &testPINVerifier{pinSet: true, fido2Hash: nil}
	auth2.SetPINVerifier(verifier)

	// Step 4: Verify the fallback path. The verifier rejects the hash, but
	// the authenticator should fall back to hmac.Equal against the persisted
	// state.PINHash and succeed.
	auth2.mu.RLock()
	result := auth2.verifyPINHashLocked(hash)
	auth2.mu.RUnlock()

	require.True(t, result,
		"verifyPINHashLocked must succeed via hmac.Equal fallback when "+
			"PINVerifier.VerifyFIDO2Hash returns false (restart scenario)")

	// Step 5: Verify that a wrong hash still fails — the fallback does not
	// blindly accept everything.
	wrongHash := sha256.Sum256([]byte("wrong-pin"))

	auth2.mu.RLock()
	wrongResult := auth2.verifyPINHashLocked(wrongHash[:PINHashSize])
	auth2.mu.RUnlock()

	require.False(t, wrongResult,
		"verifyPINHashLocked must reject incorrect hash even in fallback path")
}
