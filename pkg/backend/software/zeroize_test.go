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

package software

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// capturedMagnitude returns the backing word array of v, aliased rather than
// copied, so a test can read the SAME memory after the value has been wiped.
//
// Reading v.Bits() after the wipe would prove nothing: a zeroization that only
// called SetInt64(0) leaves the secret words intact and merely reslices the
// magnitude to length zero, so the post-wipe Bits() is an empty slice and every
// assertion over it passes vacuously. Capturing the slice header first pins
// both the array and its original length, which is what makes these assertions
// able to fail.
func capturedMagnitude(t *testing.T, v *big.Int) []big.Word {
	t.Helper()
	words := v.Bits()
	require.NotEmpty(t, words, "the value under test has no magnitude to wipe")
	nonZero := false
	for _, w := range words {
		if w != 0 {
			nonZero = true
			break
		}
	}
	require.True(t, nonZero, "the value under test is already zero, so wiping it proves nothing")
	return words
}

func requireAllWordsZero(t *testing.T, words []big.Word, what string) {
	t.Helper()
	for i, w := range words {
		require.Zerof(t, w, "%s: word %d still holds secret material after zeroization", what, i)
	}
}

// An ECDSA private key is one secret scalar, and after zeroization that
// scalar's storage must be erased -- not merely renormalized to zero.
func TestZeroizeParsedPrivateKey_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	d := capturedMagnitude(t, key.D) //nolint:staticcheck // SA1019: D is the storage under test

	zeroizeParsedPrivateKey(key)

	requireAllWordsZero(t, d, "ECDSA D")
	assert.Zero(t, key.D.Sign(), "D must also normalize to zero") //nolint:staticcheck // SA1019: D is the storage under test
}

// RSA carries the secret in more places than D: every prime factor and the
// exported CRT precomputations reconstruct the key on their own, so a wipe that
// clears only D leaves the key recoverable.
func TestZeroizeParsedPrivateKey_RSACoversEveryExportedSecret(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	key.Precompute()

	require.Len(t, key.Primes, 2, "expected a two-prime RSA key")

	captured := map[string][]big.Word{
		"D":                capturedMagnitude(t, key.D),
		"Primes[0]":        capturedMagnitude(t, key.Primes[0]),
		"Primes[1]":        capturedMagnitude(t, key.Primes[1]),
		"Precomputed.Dp":   capturedMagnitude(t, key.Precomputed.Dp),
		"Precomputed.Dq":   capturedMagnitude(t, key.Precomputed.Dq),
		"Precomputed.Qinv": capturedMagnitude(t, key.Precomputed.Qinv),
	}

	zeroizeParsedPrivateKey(key)

	for name, words := range captured {
		requireAllWordsZero(t, words, "RSA "+name)
	}
}

// An ed25519.PrivateKey IS its bytes, so the wipe has to reach the slice the
// caller holds rather than a copy of it.
func TestZeroizeParsedPrivateKey_Ed25519(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	seed := key.Seed()
	require.NotEmpty(t, seed)

	zeroizeParsedPrivateKey(key)

	for i, b := range key {
		require.Zerof(t, b, "ed25519 key byte %d survived zeroization", i)
	}
}

// The documented residue, asserted rather than described: crypto/ecdh keeps its
// scalar in an unexported field, so this key type is passed over. The test
// exists so that the day a zeroization route appears, the expectation recorded
// here is the thing that has to change -- and so that passing one never panics.
func TestZeroizeParsedPrivateKey_ECDHIsNotWipeable(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	before := key.Bytes()

	require.NotPanics(t, func() { zeroizeParsedPrivateKey(key) })

	assert.Equal(t, before, key.Bytes(),
		"crypto/ecdh exposes no zeroization route; if this now fails, the wipe "+
			"gained one and zeroizeParsedPrivateKey's documented residue is stale")
}

// Everything this function may be handed that it cannot wipe must be survivable:
// it runs on a deferred path, where a panic would replace a returned error with
// a crash.
func TestZeroizeParsedPrivateKey_UnwipeableInputsAreSafe(t *testing.T) {
	tests := []struct {
		name string
		key  any
	}{
		{"nil interface", nil},
		{"typed nil RSA", (*rsa.PrivateKey)(nil)},
		{"typed nil ECDSA", (*ecdsa.PrivateKey)(nil)},
		{"unsupported type", struct{ secret string }{secret: "not a key"}},
		{"empty ed25519", ed25519.PrivateKey(nil)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.NotPanics(t, func() { zeroizeParsedPrivateKey(tc.key) })
		})
	}
}

// zeroizeBigInt's whole reason to exist: SetInt64(0) alone does not erase the
// magnitude. This pins that fact about math/big, so the day it stops being true
// the helper can be simplified deliberately rather than by guess.
func TestZeroizeBigInt_SetInt64AloneWouldNotErase(t *testing.T) {
	secret := new(big.Int).SetBytes([]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe})
	words := capturedMagnitude(t, secret)

	// The naive implementation, for contrast.
	naive := new(big.Int).Set(secret)
	naiveWords := capturedMagnitude(t, naive)
	naive.SetInt64(0)
	stillThere := false
	for _, w := range naiveWords {
		if w != 0 {
			stillThere = true
			break
		}
	}
	require.True(t, stillThere,
		"SetInt64(0) erased the magnitude, so zeroizeBigInt's word loop is no longer load-bearing")

	zeroizeBigInt(secret)

	requireAllWordsZero(t, words, "zeroizeBigInt")
	assert.Zero(t, secret.Sign())
}

func TestZeroizeBigInt_NilIsSafe(t *testing.T) {
	require.NotPanics(t, func() { zeroizeBigInt(nil) })
}
