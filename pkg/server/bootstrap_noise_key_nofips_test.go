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

//go:build !fips

// bootstrap_noise_key_nofips_test.go holds the tests that generate a Noise_NK
// (X25519) static key. A FIPS build compiles X25519 out, so no such key can
// exist there; its loader refusal is asserted by requireNoiseRefused instead.
package server

import (
	"testing"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
)

// TestEncodeNoiseStaticKeyHex_RoundTrips proves the hex form decodes back to
// the same key and has the length the barrier expects.
func TestEncodeNoiseStaticKeyHex_RoundTrips(t *testing.T) {
	key, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)
	defer key.Destroy()

	hexKey, err := encodeNoiseStaticKeyHex(key)
	require.NoError(t, err)
	require.Len(t, hexKey, noiseproto.HexKeySize)

	decoded, err := noiseproto.DecodeStaticKey(hexKey)
	require.NoError(t, err)
	defer decoded.Destroy()
	assert.Equal(t, key.PublicBytes(), decoded.PublicBytes())
}

// TestRetainNoiseKey_AppendsKey proves a non-nil key is parked on the
// retention set.
func TestRetainNoiseKey_AppendsKey(t *testing.T) {
	s := &Server{}
	key, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)

	s.retainNoiseKey(key)
	require.Len(t, s.retainedNoiseKeys, 1)
	assert.Same(t, key, s.retainedNoiseKeys[0])
}

// TestRetainBootstrapKeys_RetainsBothSuites proves both keys of a listener
// that offered both handshake suites are retained.
func TestRetainBootstrapKeys_RetainsBothSuites(t *testing.T) {
	s := &Server{}
	noiseKey, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)
	p256Key, err := bootstrap.GenerateP256StaticKey()
	require.NoError(t, err)

	s.retainBootstrapKeys(&bootstrapKeys{noise: noiseKey, p256: p256Key})
	assert.Len(t, s.retainedNoiseKeys, 1)
	assert.Len(t, s.retainedP256Keys, 1)
}

// TestRetainBootstrapKeys_NilP256SkipsP256Retention proves a listener that
// offered only the Noise_NK suite (nil p256) retains only that suite's key,
// matching the doc comment's "a build that offered only one suite retains
// only that suite's key".
func TestRetainBootstrapKeys_NilP256SkipsP256Retention(t *testing.T) {
	s := &Server{}
	noiseKey, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)

	s.retainBootstrapKeys(&bootstrapKeys{noise: noiseKey, p256: nil})
	assert.Len(t, s.retainedNoiseKeys, 1)
	assert.Empty(t, s.retainedP256Keys)
}
