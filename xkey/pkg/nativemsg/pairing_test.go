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

package nativemsg

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testOrigin = "chrome-extension://abcdefghijklmnopqrstuvwxyz123456/"

// generateTestIdentity creates a fresh Ed25519 keypair for testing.
func generateTestIdentity(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

// signEphemeral produces the identity signature over an ephemeral X25519 key
// and origin using the protocol's sign data format.
func signEphemeral(t *testing.T, privKey ed25519.PrivateKey, ephemeralPubKey []byte, origin string) []byte {
	t.Helper()
	signData := computeSignData(ephemeralPubKey, origin)
	return ed25519.Sign(privKey, signData)
}

// completePairingCeremony is a test helper that runs the full pairing flow:
// start pairing, then complete with the returned code.
func completePairingCeremony(t *testing.T, v *PairingVerifier, identityKey []byte, origin string) {
	t.Helper()
	code, err := v.StartPairing(identityKey, origin)
	require.NoError(t, err)
	require.Len(t, code, pairingCodeLength)

	err = v.CompletePairing(identityKey, origin, code)
	require.NoError(t, err)
	require.True(t, v.IsPaired())
}

func TestPairingVerifier_FullCeremony(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)
	assert.False(t, v.IsPaired())
	assert.Nil(t, v.GetState())

	pubKey, privKey := generateTestIdentity(t)

	// Start pairing ceremony.
	code, err := v.StartPairing(pubKey, testOrigin)
	require.NoError(t, err)
	require.Len(t, code, pairingCodeLength)

	// Complete pairing with correct code.
	err = v.CompletePairing(pubKey, testOrigin, code)
	require.NoError(t, err)
	assert.True(t, v.IsPaired())
	// Verify state via multi-browser API.
	state := v.GetStateForOrigin(testOrigin)
	require.NotNil(t, state, "expected state for origin %s", testOrigin)
	assert.Equal(t, []byte(pubKey), state.IdentityKey)
	assert.False(t, state.PairedAt.IsZero())

	// Also verify GetStates returns it.
	allStates := v.GetStates()
	assert.Len(t, allStates, 1)
	assert.Contains(t, allStates, testOrigin)

	// Verify identity with a valid signature.
	ephemeralKey := make([]byte, X25519KeySize)
	_, err = rand.Read(ephemeralKey)
	require.NoError(t, err)

	sig := signEphemeral(t, privKey, ephemeralKey, testOrigin)
	err = v.VerifyIdentity(pubKey, sig, ephemeralKey, testOrigin)
	require.NoError(t, err)
}

func TestPairingVerifier_FullCeremony_NoPairingState(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	// Without pairing, VerifyIdentity should return ErrPairingRequired.
	ephemeralKey := make([]byte, X25519KeySize)
	_, err = rand.Read(ephemeralKey)
	require.NoError(t, err)

	pubKey, _ := generateTestIdentity(t)
	err = v.VerifyIdentity(pubKey, []byte("sig"), ephemeralKey, testOrigin)
	assert.ErrorIs(t, err, ErrPairingRequired)
}

func TestPairingVerifier_WrongCode(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	pubKey, _ := generateTestIdentity(t)

	_, err = v.StartPairing(pubKey, testOrigin)
	require.NoError(t, err)

	// Complete with wrong code.
	err = v.CompletePairing(pubKey, testOrigin, "000000")
	assert.ErrorIs(t, err, ErrPairingInvalidCode)
	assert.False(t, v.IsPaired())
}

func TestPairingVerifier_ExpiredCode(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	pubKey, _ := generateTestIdentity(t)

	code, err := v.StartPairing(pubKey, testOrigin)
	require.NoError(t, err)

	// Manipulate the pending pairing's expiry to the past.
	v.pending.expiresAt = time.Now().Add(-1 * time.Second)

	err = v.CompletePairing(pubKey, testOrigin, code)
	assert.ErrorIs(t, err, ErrPairingExpired)
	assert.False(t, v.IsPaired())
	// Pending should be cleared after expiry.
	assert.Nil(t, v.pending)
}

func TestPairingVerifier_IdentityMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	pubKey, _ := generateTestIdentity(t)
	completePairingCeremony(t, v, pubKey, testOrigin)

	// Create a different identity key.
	wrongPubKey, _ := generateTestIdentity(t)

	ephemeralKey := make([]byte, X25519KeySize)
	_, err = rand.Read(ephemeralKey)
	require.NoError(t, err)

	err = v.VerifyIdentity(wrongPubKey, []byte("sig"), ephemeralKey, testOrigin)
	assert.ErrorIs(t, err, ErrIdentityMismatch)
}

func TestPairingVerifier_OriginMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	pubKey, _ := generateTestIdentity(t)
	completePairingCeremony(t, v, pubKey, testOrigin)

	ephemeralKey := make([]byte, X25519KeySize)
	_, err = rand.Read(ephemeralKey)
	require.NoError(t, err)

	wrongOrigin := "chrome-extension://different_extension_id/"
	err = v.VerifyIdentity(pubKey, []byte("sig"), ephemeralKey, wrongOrigin)
	assert.ErrorIs(t, err, ErrIdentityOriginMismatch)
}

func TestPairingVerifier_ReplayProtection(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	pubKey, privKey := generateTestIdentity(t)
	completePairingCeremony(t, v, pubKey, testOrigin)

	// Create a valid ephemeral key and signature.
	ephemeralKey1 := make([]byte, X25519KeySize)
	_, err = rand.Read(ephemeralKey1)
	require.NoError(t, err)

	sig1 := signEphemeral(t, privKey, ephemeralKey1, testOrigin)

	// Verify succeeds with correct ephemeral key.
	err = v.VerifyIdentity(pubKey, sig1, ephemeralKey1, testOrigin)
	require.NoError(t, err)

	// Replay: use sig1 but with a different ephemeral key.
	ephemeralKey2 := make([]byte, X25519KeySize)
	_, err = rand.Read(ephemeralKey2)
	require.NoError(t, err)

	err = v.VerifyIdentity(pubKey, sig1, ephemeralKey2, testOrigin)
	assert.ErrorIs(t, err, ErrIdentitySignature)
}

func TestPairingVerifier_Unpair(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	pubKey, _ := generateTestIdentity(t)
	completePairingCeremony(t, v, pubKey, testOrigin)
	assert.True(t, v.IsPaired())

	// Unpair.
	err = v.Unpair()
	require.NoError(t, err)
	assert.False(t, v.IsPaired())
	assert.Nil(t, v.GetState())
	assert.Empty(t, v.GetStates())

	// Verify should now return pairing required.
	ephemeralKey := make([]byte, X25519KeySize)
	_, err = rand.Read(ephemeralKey)
	require.NoError(t, err)

	err = v.VerifyIdentity(pubKey, []byte("sig"), ephemeralKey, testOrigin)
	assert.ErrorIs(t, err, ErrPairingRequired)
}

func TestPairingVerifier_Unpair_NoPairingState(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "nonexistent-pairing.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	// Unpair when no state exists should succeed.
	err = v.Unpair()
	require.NoError(t, err)
	assert.False(t, v.IsPaired())
}

func TestPairingVerifier_PersistReload(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	// Create and pair the first verifier.
	v1, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	pubKey, privKey := generateTestIdentity(t)
	completePairingCeremony(t, v1, pubKey, testOrigin)
	assert.True(t, v1.IsPaired())

	// Create a second verifier from the same path - should load existing state.
	v2, err := NewPairingVerifier(statePath)
	require.NoError(t, err)
	assert.True(t, v2.IsPaired())

	// Verify via multi-browser API.
	states := v2.GetStates()
	require.Len(t, states, 1)
	require.Contains(t, states, testOrigin)
	state := states[testOrigin]
	assert.Equal(t, []byte(pubKey), state.IdentityKey)

	// Verify identity with the reloaded verifier.
	ephemeralKey := make([]byte, X25519KeySize)
	_, err = rand.Read(ephemeralKey)
	require.NoError(t, err)

	sig := signEphemeral(t, privKey, ephemeralKey, testOrigin)
	err = v2.VerifyIdentity(pubKey, sig, ephemeralKey, testOrigin)
	require.NoError(t, err)
}

func TestPairingVerifier_PersistReload_CorruptFile(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	// Write corrupt JSON to the state file.
	err := os.WriteFile(statePath, []byte("not valid json{"), 0600)
	require.NoError(t, err)

	_, err = NewPairingVerifier(statePath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load pairing state")
}

func TestPairingVerifier_PairingLockout(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	pubKey, _ := generateTestIdentity(t)

	// Fail maxPairingFailures times.
	for i := 0; i < maxPairingFailures; i++ {
		code, startErr := v.StartPairing(pubKey, testOrigin)
		require.NoError(t, startErr)
		require.NotEmpty(t, code)

		completeErr := v.CompletePairing(pubKey, testOrigin, "999999")
		assert.ErrorIs(t, completeErr, ErrPairingInvalidCode)
	}

	// Next attempt should be locked out.
	_, err = v.StartPairing(pubKey, testOrigin)
	assert.ErrorIs(t, err, ErrPairingLocked)

	// CompletePairing should also be locked.
	err = v.CompletePairing(pubKey, testOrigin, "123456")
	assert.ErrorIs(t, err, ErrPairingLocked)
}

func TestPairingVerifier_PairingLockout_ExpiresAfterDuration(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	pubKey, _ := generateTestIdentity(t)

	// Trigger lockout.
	for i := 0; i < maxPairingFailures; i++ {
		_, startErr := v.StartPairing(pubKey, testOrigin)
		require.NoError(t, startErr)
		completeErr := v.CompletePairing(pubKey, testOrigin, "999999")
		assert.ErrorIs(t, completeErr, ErrPairingInvalidCode)
	}

	_, err = v.StartPairing(pubKey, testOrigin)
	assert.ErrorIs(t, err, ErrPairingLocked)

	// Simulate lockout expiry by setting lockUntil to the past.
	v.pairingLockUntil.Store(time.Now().Add(-1 * time.Second).Unix())

	// Should be able to start pairing again.
	code, err := v.StartPairing(pubKey, testOrigin)
	require.NoError(t, err)
	assert.Len(t, code, pairingCodeLength)
}

func TestPairingVerifier_VerifyLockout(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	pubKey, _ := generateTestIdentity(t)
	completePairingCeremony(t, v, pubKey, testOrigin)

	wrongPubKey, _ := generateTestIdentity(t)

	ephemeralKey := make([]byte, X25519KeySize)
	_, err = rand.Read(ephemeralKey)
	require.NoError(t, err)

	// Fail maxVerifyFailures times with wrong identity key.
	for i := 0; i < maxVerifyFailures; i++ {
		verifyErr := v.VerifyIdentity(wrongPubKey, []byte("bad-sig"), ephemeralKey, testOrigin)
		assert.ErrorIs(t, verifyErr, ErrIdentityMismatch)
	}

	// Next attempt should be locked.
	err = v.VerifyIdentity(pubKey, []byte("sig"), ephemeralKey, testOrigin)
	assert.ErrorIs(t, err, ErrIdentityLocked)
}

func TestPairingVerifier_VerifyLockout_ExpiresAfterDuration(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	pubKey, privKey := generateTestIdentity(t)
	completePairingCeremony(t, v, pubKey, testOrigin)

	wrongPubKey, _ := generateTestIdentity(t)

	ephemeralKey := make([]byte, X25519KeySize)
	_, err = rand.Read(ephemeralKey)
	require.NoError(t, err)

	// Trigger lockout.
	for i := 0; i < maxVerifyFailures; i++ {
		verifyErr := v.VerifyIdentity(wrongPubKey, []byte("bad-sig"), ephemeralKey, testOrigin)
		assert.ErrorIs(t, verifyErr, ErrIdentityMismatch)
	}
	err = v.VerifyIdentity(pubKey, []byte("sig"), ephemeralKey, testOrigin)
	assert.ErrorIs(t, err, ErrIdentityLocked)

	// Simulate lockout expiry.
	v.verifyLockUntil.Store(time.Now().Add(-1 * time.Second).Unix())

	// Should be able to verify again with correct credentials.
	sig := signEphemeral(t, privKey, ephemeralKey, testOrigin)
	err = v.VerifyIdentity(pubKey, sig, ephemeralKey, testOrigin)
	require.NoError(t, err)
}

func TestPairingVerifier_CompletePairing_NoPending(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	pubKey, _ := generateTestIdentity(t)

	// Complete without starting.
	err = v.CompletePairing(pubKey, testOrigin, "123456")
	assert.ErrorIs(t, err, ErrPairingRejected)
}

func TestPairingVerifier_CompletePairing_IdentityKeyMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	pubKey, _ := generateTestIdentity(t)
	differentPubKey, _ := generateTestIdentity(t)

	code, err := v.StartPairing(pubKey, testOrigin)
	require.NoError(t, err)

	// Try to complete with a different identity key.
	err = v.CompletePairing(differentPubKey, testOrigin, code)
	assert.ErrorIs(t, err, ErrPairingRejected)
}

func TestPairingVerifier_CompletePairing_OriginMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	pubKey, _ := generateTestIdentity(t)

	code, err := v.StartPairing(pubKey, testOrigin)
	require.NoError(t, err)

	// Try to complete with a different origin.
	err = v.CompletePairing(pubKey, "chrome-extension://other/", code)
	assert.ErrorIs(t, err, ErrPairingRejected)
}

func TestPairingVerifier_VerifyIdentity_InvalidSignature(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	pubKey, _ := generateTestIdentity(t)
	completePairingCeremony(t, v, pubKey, testOrigin)

	ephemeralKey := make([]byte, X25519KeySize)
	_, err = rand.Read(ephemeralKey)
	require.NoError(t, err)

	// Use a garbage signature.
	badSig := make([]byte, ed25519.SignatureSize)
	_, err = rand.Read(badSig)
	require.NoError(t, err)

	err = v.VerifyIdentity(pubKey, badSig, ephemeralKey, testOrigin)
	assert.ErrorIs(t, err, ErrIdentitySignature)
}

func TestPairingVerifier_VerifyIdentity_SuccessResetsCounter(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	pubKey, privKey := generateTestIdentity(t)
	completePairingCeremony(t, v, pubKey, testOrigin)

	ephemeralKey := make([]byte, X25519KeySize)
	_, err = rand.Read(ephemeralKey)
	require.NoError(t, err)

	// Accumulate some verify failures (but not enough to lock out).
	badSig := make([]byte, ed25519.SignatureSize)
	for i := 0; i < maxVerifyFailures-1; i++ {
		_, err = rand.Read(badSig)
		require.NoError(t, err)
		verifyErr := v.VerifyIdentity(pubKey, badSig, ephemeralKey, testOrigin)
		assert.ErrorIs(t, verifyErr, ErrIdentitySignature)
	}
	assert.Equal(t, int32(maxVerifyFailures-1), v.verifyFailures.Load())

	// A successful verify should reset the counter.
	sig := signEphemeral(t, privKey, ephemeralKey, testOrigin)
	err = v.VerifyIdentity(pubKey, sig, ephemeralKey, testOrigin)
	require.NoError(t, err)
	assert.Equal(t, int32(0), v.verifyFailures.Load())
}

func TestPairingVerifier_VerifyParentProcess(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	// In a test environment the parent process is "go" (the test runner),
	// which is not a browser. This should return ErrParentProcessInvalid
	// on Linux (where /proc is available).
	err = v.VerifyParentProcess()
	// On Linux, this will fail because the parent is go/test binary.
	// On non-Linux, this returns nil (defense in depth, not sole control).
	if err != nil {
		assert.ErrorIs(t, err, ErrParentProcessInvalid)
	}
}

func TestGeneratePairingCode(t *testing.T) {
	// Generate many codes and verify format.
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		code, err := generatePairingCode()
		require.NoError(t, err)
		assert.Len(t, code, pairingCodeLength)

		// Verify it is numeric.
		_, err = strconv.Atoi(code)
		require.NoError(t, err, "code %q is not numeric", code)

		seen[code] = true
	}

	// With 100 random 6-digit codes, we should see significant diversity.
	assert.Greater(t, len(seen), 10, "expected diverse pairing codes")
}

func TestGeneratePairingCode_Format(t *testing.T) {
	// Verify that codes with leading zeros are properly zero-padded.
	for i := 0; i < 50; i++ {
		code, err := generatePairingCode()
		require.NoError(t, err)
		assert.Len(t, code, 6)
		// Ensure all characters are digits.
		for _, c := range code {
			assert.True(t, c >= '0' && c <= '9', "non-digit character %c in code %s", c, code)
		}
	}
}

func TestMultiBrowserPairing(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	chromeOrigin := "chrome-extension://abcdefghijklmnopqrstuvwxyz123456/"
	firefoxOrigin := "moz-extension://12345678-1234-1234-1234-123456789abc/"

	chromePubKey, chromePrivKey := generateTestIdentity(t)
	firefoxPubKey, firefoxPrivKey := generateTestIdentity(t)

	// Pair Chrome.
	completePairingCeremony(t, v, chromePubKey, chromeOrigin)
	assert.True(t, v.IsPaired())
	assert.True(t, v.IsPairedForOrigin(chromeOrigin))
	assert.False(t, v.IsPairedForOrigin(firefoxOrigin))

	// Pair Firefox.
	completePairingCeremony(t, v, firefoxPubKey, firefoxOrigin)
	assert.True(t, v.IsPaired())
	assert.True(t, v.IsPairedForOrigin(chromeOrigin))
	assert.True(t, v.IsPairedForOrigin(firefoxOrigin))

	// Verify both states exist.
	allStates := v.GetStates()
	assert.Len(t, allStates, 2)
	assert.Contains(t, allStates, chromeOrigin)
	assert.Contains(t, allStates, firefoxOrigin)
	assert.Equal(t, []byte(chromePubKey), allStates[chromeOrigin].IdentityKey)
	assert.Equal(t, []byte(firefoxPubKey), allStates[firefoxOrigin].IdentityKey)

	// Verify identity works for both origins independently.
	ephemeralKey := make([]byte, X25519KeySize)
	_, err = rand.Read(ephemeralKey)
	require.NoError(t, err)

	chromeSig := signEphemeral(t, chromePrivKey, ephemeralKey, chromeOrigin)
	err = v.VerifyIdentity(chromePubKey, chromeSig, ephemeralKey, chromeOrigin)
	require.NoError(t, err)

	firefoxSig := signEphemeral(t, firefoxPrivKey, ephemeralKey, firefoxOrigin)
	err = v.VerifyIdentity(firefoxPubKey, firefoxSig, ephemeralKey, firefoxOrigin)
	require.NoError(t, err)
}

func TestUnpairSpecificOrigin(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	chromeOrigin := "chrome-extension://abcdefghijklmnopqrstuvwxyz123456/"
	firefoxOrigin := "moz-extension://12345678-1234-1234-1234-123456789abc/"

	chromePubKey, _ := generateTestIdentity(t)
	firefoxPubKey, _ := generateTestIdentity(t)

	// Pair both browsers.
	completePairingCeremony(t, v, chromePubKey, chromeOrigin)
	completePairingCeremony(t, v, firefoxPubKey, firefoxOrigin)
	assert.Len(t, v.GetStates(), 2)

	// Unpair Chrome specifically.
	err = v.UnpairOrigin(chromeOrigin)
	require.NoError(t, err)

	assert.True(t, v.IsPaired(), "Firefox should still be paired")
	assert.False(t, v.IsPairedForOrigin(chromeOrigin))
	assert.True(t, v.IsPairedForOrigin(firefoxOrigin))
	assert.Len(t, v.GetStates(), 1)

	// Verify Chrome is gone from the state file — reload from disk.
	v2, err := NewPairingVerifier(statePath)
	require.NoError(t, err)
	assert.True(t, v2.IsPairedForOrigin(firefoxOrigin))
	assert.False(t, v2.IsPairedForOrigin(chromeOrigin))
}

func TestUnpairSpecificOrigin_LastOriginDeletesFile(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	pubKey, _ := generateTestIdentity(t)
	completePairingCeremony(t, v, pubKey, testOrigin)

	// Unpair the only origin — should delete the state file.
	err = v.UnpairOrigin(testOrigin)
	require.NoError(t, err)
	assert.False(t, v.IsPaired())

	_, statErr := os.Stat(statePath)
	assert.True(t, os.IsNotExist(statErr), "state file should be deleted when last origin is unpaired")
}

func TestReload(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	// Create first verifier and pair an extension.
	v1, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	pubKey, _ := generateTestIdentity(t)
	completePairingCeremony(t, v1, pubKey, testOrigin)
	assert.True(t, v1.IsPaired())

	// Create a second verifier that loads state from disk.
	v2, err := NewPairingVerifier(statePath)
	require.NoError(t, err)
	assert.True(t, v2.IsPaired())

	// Unpair via v2 — this writes to disk.
	err = v2.Unpair()
	require.NoError(t, err)
	assert.False(t, v2.IsPaired())

	// v1 still sees the old in-memory state.
	assert.True(t, v1.IsPaired())

	// Reload v1 from disk — file was deleted by Unpair, so Reload returns
	// os.ErrNotExist but correctly resets in-memory state to empty.
	err = v1.Reload()
	if err != nil {
		require.ErrorIs(t, err, os.ErrNotExist)
	}
	assert.False(t, v1.IsPaired())
	assert.Empty(t, v1.GetStates())
}

func TestReload_NewPairingsAppear(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	// Create first verifier — no pairings.
	v1, err := NewPairingVerifier(statePath)
	require.NoError(t, err)
	assert.False(t, v1.IsPaired())

	// Create second verifier and pair.
	v2, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	pubKey, _ := generateTestIdentity(t)
	completePairingCeremony(t, v2, pubKey, testOrigin)

	// v1 does not see the pairing yet.
	assert.False(t, v1.IsPaired())

	// Reload v1 — now it should see the pairing.
	err = v1.Reload()
	require.NoError(t, err)
	assert.True(t, v1.IsPaired())
	assert.True(t, v1.IsPairedForOrigin(testOrigin))
}

func TestMigrationOldFormat(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	legacyOrigin := "chrome-extension://legacyabcdefghijklmnop123456/"

	// Generate a real identity key so the migrated state is verifiable.
	pubKey, _ := generateTestIdentity(t)

	// Write legacy single-object format file.
	legacy := map[string]interface{}{
		"extension_origin": legacyOrigin,
		"identity_key":     pubKey,
		"paired_at":        "2024-01-01T00:00:00Z",
	}
	data, err := json.Marshal(legacy)
	require.NoError(t, err)
	err = os.WriteFile(statePath, data, 0600)
	require.NoError(t, err)

	// Create verifier — should auto-migrate.
	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	assert.True(t, v.IsPaired())
	assert.True(t, v.IsPairedForOrigin(legacyOrigin))

	state := v.GetStateForOrigin(legacyOrigin)
	require.NotNil(t, state)
	assert.Equal(t, []byte(pubKey), state.IdentityKey)
	assert.False(t, state.PairedAt.IsZero())

	// Verify the file was re-saved in the new map format.
	reloaded, err := os.ReadFile(statePath)
	require.NoError(t, err)
	newStates := make(map[string]*PairingState)
	err = json.Unmarshal(reloaded, &newStates)
	require.NoError(t, err, "migrated file should be in map format")
	assert.Contains(t, newStates, legacyOrigin)
}

func TestMigrationOldFormat_EmptyLegacy(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	// Write an empty legacy object with no extension_origin.
	err := os.WriteFile(statePath, []byte(`{"extension_origin":"","identity_key":null}`), 0600)
	require.NoError(t, err)

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)
	assert.False(t, v.IsPaired())
	assert.Empty(t, v.GetStates())
}

func TestAtomicWrite(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")
	tmpPath := statePath + ".tmp"

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	pubKey, _ := generateTestIdentity(t)
	completePairingCeremony(t, v, pubKey, testOrigin)

	// After a successful save, the .tmp file should not remain.
	_, statErr := os.Stat(tmpPath)
	assert.True(t, os.IsNotExist(statErr),
		"temp file %s should not exist after successful atomic write", tmpPath)

	// The final state file should exist and be valid JSON.
	data, err := os.ReadFile(statePath)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	var parsed map[string]*PairingState
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)
	assert.Contains(t, parsed, testOrigin)
}

func TestMultiBrowserPairing_RepairSameOrigin(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	pubKey1, _ := generateTestIdentity(t)
	pubKey2, _ := generateTestIdentity(t)

	// Pair with first identity.
	completePairingCeremony(t, v, pubKey1, testOrigin)
	state := v.GetStateForOrigin(testOrigin)
	require.NotNil(t, state)
	assert.Equal(t, []byte(pubKey1), state.IdentityKey)

	// Re-pair same origin with different identity (extension reinstall).
	completePairingCeremony(t, v, pubKey2, testOrigin)
	state = v.GetStateForOrigin(testOrigin)
	require.NotNil(t, state)
	assert.Equal(t, []byte(pubKey2), state.IdentityKey)

	// Should still be only 1 entry.
	assert.Len(t, v.GetStates(), 1)
}

func TestGetStateForOrigin_NotPaired(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	state := v.GetStateForOrigin("chrome-extension://nonexistent/")
	assert.Nil(t, state)
}

func TestIsPairedForOrigin_NotPaired(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	assert.False(t, v.IsPairedForOrigin("chrome-extension://nonexistent/"))
}

func TestUnpairOrigin_NonExistentOrigin(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	pubKey, _ := generateTestIdentity(t)
	completePairingCeremony(t, v, pubKey, testOrigin)

	// Unpair a non-existent origin — should not affect the existing pairing.
	err = v.UnpairOrigin("chrome-extension://nonexistent/")
	require.NoError(t, err)
	assert.True(t, v.IsPairedForOrigin(testOrigin))
	assert.Len(t, v.GetStates(), 1)
}

func TestVerifyIdentity_UnknownOriginWithOtherPairings(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	pubKey, _ := generateTestIdentity(t)
	completePairingCeremony(t, v, pubKey, testOrigin)

	// Verify with a different origin that is not paired.
	ephemeralKey := make([]byte, X25519KeySize)
	_, err = rand.Read(ephemeralKey)
	require.NoError(t, err)

	unknownOrigin := "chrome-extension://unknownextension/"
	err = v.VerifyIdentity(pubKey, []byte("sig"), ephemeralKey, unknownOrigin)
	assert.ErrorIs(t, err, ErrIdentityOriginMismatch,
		fmt.Sprintf("verifying with unpaired origin %s should return origin mismatch", unknownOrigin))
}
