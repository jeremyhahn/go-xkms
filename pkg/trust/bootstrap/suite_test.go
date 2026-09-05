// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package bootstrap

import (
	"errors"
	"testing"

	"github.com/awnumar/memguard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The approved suite must be available in EVERY build. If this ever fails, a
// FIPS deployment has no bootstrap handshake at all, which is the state
// go-xkms#269 exists to end.
func TestEnsureSuiteAvailable_P256IsAvailableInEveryBuild(t *testing.T) {
	require.NoError(t, EnsureSuiteAvailable(SuiteP256AESGCM))
}

func TestEnsureSuiteAvailable_RejectsAnUnknownSuite(t *testing.T) {
	err := EnsureSuiteAvailable(0x7f)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSuiteUnavailable)
	assert.Contains(t, err.Error(), "0x7f", "the error must name the suite the caller asked for")
}

// The two suite identifiers must never collide: they share one wire byte, and
// a collision would make the server dispatch the wrong handshake.
func TestSuiteIdentifiers_AreDistinct(t *testing.T) {
	assert.NotEqual(t, SuiteNoiseNK, SuiteP256AESGCM)
}

// EnsureSuiteAvailable is called at construction and may be called repeatedly;
// it must be stable and must not leak the probe key.
func TestEnsureSuiteAvailable_IsRepeatable(t *testing.T) {
	first := EnsureSuiteAvailable(SuiteNoiseNK)
	for range 5 {
		assert.Equal(t, first == nil, EnsureSuiteAvailable(SuiteNoiseNK) == nil,
			"availability must not change between calls")
	}
}

// The P-256 re-exports must compose: generate, encode, decode, and recover the
// same public key. This is the pairing noise_server.go documents for the Noise
// set, checked for the approved suite.
func TestP256StaticKey_EncodeDecodeRoundTrip(t *testing.T) {
	key, err := GenerateP256StaticKey()
	require.NoError(t, err)
	defer key.Destroy()

	require.Len(t, key.PublicBytes(), P256PublicKeySize)

	encoded := memguard.NewBuffer(P256HexKeySize)
	defer encoded.Destroy()
	require.NoError(t, EncodeP256StaticKey(encoded, key))

	decoded, err := DecodeP256StaticKey(encoded)
	require.NoError(t, err)
	defer decoded.Destroy()

	assert.Equal(t, key.PublicBytes(), decoded.PublicBytes(),
		"a decoded key must recover the same public point")
}

// A decode failure must not be mistaken for a suite problem.
func TestDecodeP256StaticKey_RejectsGarbage(t *testing.T) {
	buf := memguard.NewBuffer(P256HexKeySize)
	defer buf.Destroy()
	for i := range buf.Bytes() {
		buf.Bytes()[i] = 'z' // not hex
	}

	_, err := DecodeP256StaticKey(buf)
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrSuiteUnavailable))
}
