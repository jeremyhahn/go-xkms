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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// expireLockout moves sel's lockout deadline into the past, as if the lockout
// period had elapsed.
func expireLockout(t *testing.T, v *PairingVerifier, sel limitSelector) {
	t.Helper()
	require.NoError(t, v.updateLimits(func(l *pairingLimits) bool {
		sel(l).LockUntil = time.Now().Add(-time.Second).Unix()
		return true
	}))
}

// limitFailures returns sel's durable failure count.
func limitFailures(t *testing.T, v *PairingVerifier, sel limitSelector) int32 {
	t.Helper()
	var failures int32
	require.NoError(t, v.updateLimits(func(l *pairingLimits) bool {
		failures = sel(l).Failures
		return false
	}))
	return failures
}

// newHostInstance builds a fresh PairingVerifier over statePath, as each
// browser-launched native host does.
func newHostInstance(t *testing.T, statePath string) *PairingVerifier {
	t.Helper()
	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)
	return v
}

func TestLimitsPathFor(t *testing.T) {
	assert.Equal(t, filepath.Join("dir", "pairing-limits.json"), limitsPathFor(filepath.Join("dir", "pairing.json")))
	assert.Equal(t, filepath.Join("dir", "state-limits.json"), limitsPathFor(filepath.Join("dir", "state")))
}

// TestPairingFailures_SurviveHostRelaunch proves the pairing-code failure
// count and the lockout it earns are durable: each wrong code is sent through
// a new host instance over the same state directory, as a browser relaunching
// the native host would, and the lockout still engages and still holds for
// yet another instance.
func TestPairingFailures_SurviveHostRelaunch(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "pairing.json")
	pubKey, _ := generateTestIdentity(t)

	for i := 0; i < maxPairingFailures; i++ {
		v := newHostInstance(t, statePath)
		_, err := v.StartPairing(pubKey, testOrigin)
		require.NoError(t, err, "attempt %d must not be locked out yet", i+1)
		require.ErrorIs(t, v.CompletePairing(pubKey, testOrigin, "not-a-code"), ErrPairingInvalidCode)
	}

	relaunched := newHostInstance(t, statePath)
	_, err := relaunched.StartPairing(pubKey, testOrigin)
	require.ErrorIs(t, err, ErrPairingLocked, "a relaunched host must inherit the lockout")
	require.ErrorIs(t, relaunched.CompletePairing(pubKey, testOrigin, "000000"), ErrPairingLocked)

	info, err := os.Stat(limitsPathFor(statePath))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "rate-limit state must be owner-only")
}

// TestVerifyFailures_SurviveHostRelaunch is the identity-verification
// counterpart: failures spread over relaunched hosts accumulate into a
// lockout that a further relaunch still honours.
func TestVerifyFailures_SurviveHostRelaunch(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "pairing.json")
	pubKey, _ := generateTestIdentity(t)
	completePairingCeremony(t, newHostInstance(t, statePath), pubKey, testOrigin)

	ephemeralKey := make([]byte, X25519KeySize)
	_, err := rand.Read(ephemeralKey)
	require.NoError(t, err)
	badSig := make([]byte, ed25519.SignatureSize)

	for i := 0; i < maxVerifyFailures; i++ {
		v := newHostInstance(t, statePath)
		require.ErrorIs(t, v.VerifyIdentity(pubKey, badSig, ephemeralKey, testOrigin), ErrIdentitySignature)
	}

	relaunched := newHostInstance(t, statePath)
	require.ErrorIs(t, relaunched.VerifyIdentity(pubKey, badSig, ephemeralKey, testOrigin), ErrIdentityLocked)
}

// TestUnpairDoesNotClearLockout proves the lockout is not part of the pairing
// state that unpairing deletes.
func TestUnpairDoesNotClearLockout(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "pairing.json")
	pubKey, _ := generateTestIdentity(t)
	v := newHostInstance(t, statePath)
	completePairingCeremony(t, v, pubKey, testOrigin)

	for i := 0; i < maxPairingFailures; i++ {
		_, err := v.StartPairing(pubKey, testOrigin)
		require.NoError(t, err)
		require.ErrorIs(t, v.CompletePairing(pubKey, testOrigin, "not-a-code"), ErrPairingInvalidCode)
	}
	require.NoError(t, v.UnpairAll())

	_, err := newHostInstance(t, statePath).StartPairing(pubKey, testOrigin)
	require.ErrorIs(t, err, ErrPairingLocked)
}

// TestPairingLimits_CorruptStateFailsClosed proves an unparsable rate-limit
// file refuses pairing rather than granting a fresh failure budget.
func TestPairingLimits_CorruptStateFailsClosed(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "pairing.json")
	require.NoError(t, os.WriteFile(limitsPathFor(statePath), []byte("{not json"), 0600))
	pubKey, _ := generateTestIdentity(t)

	_, err := newHostInstance(t, statePath).StartPairing(pubKey, testOrigin)
	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
	assert.Equal(t, "nativemsg: invalid pairing rate-limit state", wrapped.Msg)
}

// TestPairingLimits_UnwritableStateFailsClosed proves a wrong code whose
// failure cannot be persisted is reported as an error, not as a free
// ErrPairingInvalidCode the caller could retry without it counting.
func TestPairingLimits_UnwritableStateFailsClosed(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "pairing.json")
	pubKey, _ := generateTestIdentity(t)
	v := newHostInstance(t, statePath)
	_, err := v.StartPairing(pubKey, testOrigin)
	require.NoError(t, err)

	// A directory where the rate-limit file belongs can be neither written
	// through the temp file's rename nor read.
	require.NoError(t, os.Mkdir(limitsPathFor(statePath), 0700))

	err = v.CompletePairing(pubKey, testOrigin, "not-a-code")
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrPairingInvalidCode)
}
