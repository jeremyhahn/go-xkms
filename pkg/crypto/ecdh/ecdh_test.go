// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package ecdh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDeriveSharedSecret_P256 tests ECDH with P-256 curve
func TestDeriveSharedSecret_P256(t *testing.T) {
	// Generate two key pairs
	alicePriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bobPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Alice derives shared secret using Bob's public key
	aliceShared, err := DeriveSharedSecret(alicePriv, &bobPriv.PublicKey)
	require.NoError(t, err)
	require.NotNil(t, aliceShared)

	// Bob derives shared secret using Alice's public key
	bobShared, err := DeriveSharedSecret(bobPriv, &alicePriv.PublicKey)
	require.NoError(t, err)
	require.NotNil(t, bobShared)

	// Both should derive the same shared secret
	assert.Equal(t, aliceShared, bobShared)
	assert.NotEmpty(t, aliceShared)
}

// TestDeriveSharedSecret_P384 tests ECDH with P-384 curve
func TestDeriveSharedSecret_P384(t *testing.T) {
	// Generate two key pairs
	alicePriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	bobPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	// Derive shared secrets
	aliceShared, err := DeriveSharedSecret(alicePriv, &bobPriv.PublicKey)
	require.NoError(t, err)

	bobShared, err := DeriveSharedSecret(bobPriv, &alicePriv.PublicKey)
	require.NoError(t, err)

	// Both should derive the same shared secret
	assert.Equal(t, aliceShared, bobShared)
	assert.NotEmpty(t, aliceShared)
}

// TestDeriveSharedSecret_P521 tests ECDH with P-521 curve
func TestDeriveSharedSecret_P521(t *testing.T) {
	// Generate two key pairs
	alicePriv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	bobPriv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	// Derive shared secrets
	aliceShared, err := DeriveSharedSecret(alicePriv, &bobPriv.PublicKey)
	require.NoError(t, err)

	bobShared, err := DeriveSharedSecret(bobPriv, &alicePriv.PublicKey)
	require.NoError(t, err)

	// Both should derive the same shared secret
	assert.Equal(t, aliceShared, bobShared)
	assert.NotEmpty(t, aliceShared)
}

// TestDeriveSharedSecret_MismatchedCurves tests error when curves don't match
func TestDeriveSharedSecret_MismatchedCurves(t *testing.T) {
	alicePriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bobPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	// Should fail with mismatched curves
	_, err = DeriveSharedSecret(alicePriv, &bobPriv.PublicKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "curve mismatch")
}

// TestDeriveSharedSecret_NilInputs tests error handling with nil inputs
func TestDeriveSharedSecret_NilInputs(t *testing.T) {
	alicePriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Nil private key
	_, err = DeriveSharedSecret(nil, &alicePriv.PublicKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "private key cannot be nil")

	// Nil public key
	_, err = DeriveSharedSecret(alicePriv, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "public key cannot be nil")
}

// TestDeriveKey tests KDF with different info strings
func TestDeriveKey(t *testing.T) {
	// Generate shared secret
	alicePriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bobPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	sharedSecret, err := DeriveSharedSecret(alicePriv, &bobPriv.PublicKey)
	require.NoError(t, err)

	// Derive keys with same info - should be identical
	key1, err := DeriveKey(sharedSecret, nil, []byte("test-context"), 32)
	require.NoError(t, err)
	assert.Len(t, key1, 32)

	key2, err := DeriveKey(sharedSecret, nil, []byte("test-context"), 32)
	require.NoError(t, err)
	assert.Equal(t, key1, key2)

	// Derive keys with different info - should be different
	key3, err := DeriveKey(sharedSecret, nil, []byte("different-context"), 32)
	require.NoError(t, err)
	assert.NotEqual(t, key1, key3)

	// Different key lengths
	key16, err := DeriveKey(sharedSecret, nil, []byte("test"), 16)
	require.NoError(t, err)
	assert.Len(t, key16, 16)

	key64, err := DeriveKey(sharedSecret, nil, []byte("test"), 64)
	require.NoError(t, err)
	assert.Len(t, key64, 64)
}

// TestDeriveKey_WithSalt tests KDF with custom salt
func TestDeriveKey_WithSalt(t *testing.T) {
	alicePriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bobPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	sharedSecret, err := DeriveSharedSecret(alicePriv, &bobPriv.PublicKey)
	require.NoError(t, err)

	// Same salt produces same key
	salt := []byte("my-salt")
	key1, err := DeriveKey(sharedSecret, salt, []byte("info"), 32)
	require.NoError(t, err)

	key2, err := DeriveKey(sharedSecret, salt, []byte("info"), 32)
	require.NoError(t, err)
	assert.Equal(t, key1, key2)

	// Different salt produces different key
	key3, err := DeriveKey(sharedSecret, []byte("other-salt"), []byte("info"), 32)
	require.NoError(t, err)
	assert.NotEqual(t, key1, key3)
}

// TestDeriveKey_InvalidInputs tests error handling
func TestDeriveKey_InvalidInputs(t *testing.T) {
	sharedSecret := []byte("test-secret")

	// Zero length
	_, err := DeriveKey(sharedSecret, nil, []byte("info"), 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key length must be positive")

	// Negative length
	_, err = DeriveKey(sharedSecret, nil, []byte("info"), -1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key length must be positive")

	// Nil shared secret
	_, err = DeriveKey(nil, nil, []byte("info"), 32)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "shared secret cannot be nil")
}

// TestCurveSupport tests all supported curves
func TestCurveSupport(t *testing.T) {
	curves := []elliptic.Curve{
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}

	for _, curve := range curves {
		t.Run(curve.Params().Name, func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(curve, rand.Reader)
			require.NoError(t, err)

			// Test that the curve is supported
			assert.NotNil(t, priv)
			assert.Equal(t, curve, priv.Curve)
		})
	}
}

// TestDeriveSharedSecret_ShortPrivateKey tests handling of short private key D values
func TestDeriveSharedSecret_ShortPrivateKey(t *testing.T) {
	// Generate two key pairs
	alicePriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bobPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Derive shared secret (should work even with various D byte lengths)
	aliceShared, err := DeriveSharedSecret(alicePriv, &bobPriv.PublicKey)
	require.NoError(t, err)
	require.NotNil(t, aliceShared)

	bobShared, err := DeriveSharedSecret(bobPriv, &alicePriv.PublicKey)
	require.NoError(t, err)
	require.NotNil(t, bobShared)

	// Both should derive the same shared secret
	assert.Equal(t, aliceShared, bobShared)
}

// TestDeriveKey_EmptyInfo tests KDF with empty info
func TestDeriveKey_EmptyInfo(t *testing.T) {
	alicePriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bobPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	sharedSecret, err := DeriveSharedSecret(alicePriv, &bobPriv.PublicKey)
	require.NoError(t, err)

	// Derive key with empty info
	key1, err := DeriveKey(sharedSecret, nil, []byte{}, 32)
	require.NoError(t, err)
	assert.Len(t, key1, 32)

	// Should be reproducible
	key2, err := DeriveKey(sharedSecret, nil, []byte{}, 32)
	require.NoError(t, err)
	assert.Equal(t, key1, key2)

	// nil info should give same result as empty info
	key3, err := DeriveKey(sharedSecret, nil, nil, 32)
	require.NoError(t, err)
	assert.Equal(t, key1, key3)
}

// TestConversionErrors tests error paths in key conversion functions
func TestConversionErrors(t *testing.T) {
	// Create keys with an unsupported curve (P-224 is not supported)
	priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	pub, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	// Try to derive shared secret with unsupported curve
	_, err = DeriveSharedSecret(priv, &pub.PublicKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported curve")
}

// TestDeriveSharedSecret_AllCurvesRoundTrip tests all curves produce matching secrets
func TestDeriveSharedSecret_AllCurvesRoundTrip(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			// Generate key pairs
			alicePriv, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			bobPriv, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			// Derive shared secrets
			aliceShared, err := DeriveSharedSecret(alicePriv, &bobPriv.PublicKey)
			require.NoError(t, err)
			require.NotEmpty(t, aliceShared)

			bobShared, err := DeriveSharedSecret(bobPriv, &alicePriv.PublicKey)
			require.NoError(t, err)
			require.NotEmpty(t, bobShared)

			// Both should match
			assert.Equal(t, aliceShared, bobShared)

			// Derive encryption keys from shared secret
			aliceKey, err := DeriveKey(aliceShared, nil, []byte("test"), 32)
			require.NoError(t, err)

			bobKey, err := DeriveKey(bobShared, nil, []byte("test"), 32)
			require.NoError(t, err)

			// Encryption keys should also match
			assert.Equal(t, aliceKey, bobKey)
		})
	}
}

// TestDeriveKey_ExcessiveLength tests HKDF with excessive key length request
// HKDF-SHA256 can output at most 255 * 32 = 8160 bytes
func TestDeriveKey_ExcessiveLength(t *testing.T) {
	sharedSecret := []byte("test-secret")

	// Request more than HKDF can produce (255 * 32 bytes for SHA-256)
	_, err := DeriveKey(sharedSecret, nil, []byte("info"), 8161)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HKDF derivation failed")
}

// TestDeriveKey_LargeButValidLength tests HKDF with large but valid key length
func TestDeriveKey_LargeButValidLength(t *testing.T) {
	sharedSecret := []byte("test-secret")

	// Request exactly the maximum HKDF output
	key, err := DeriveKey(sharedSecret, nil, []byte("info"), 8160)
	require.NoError(t, err)
	assert.Len(t, key, 8160)
}

// TestDeriveKey_VariousLengths tests key derivation with various lengths
func TestDeriveKey_VariousLengths(t *testing.T) {
	alicePriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bobPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	sharedSecret, err := DeriveSharedSecret(alicePriv, &bobPriv.PublicKey)
	require.NoError(t, err)

	// Test various key lengths
	lengths := []int{1, 8, 16, 24, 32, 48, 64, 128, 256, 512, 1024, 2048, 4096}
	for _, length := range lengths {
		t.Run(string(rune(length)), func(t *testing.T) {
			key, err := DeriveKey(sharedSecret, nil, []byte("test"), length)
			require.NoError(t, err)
			assert.Len(t, key, length)
		})
	}
}

// TestDeriveKey_SameInputsSameOutput tests that same inputs produce same output
func TestDeriveKey_SameInputsSameOutput(t *testing.T) {
	sharedSecret := []byte("consistent-secret")
	salt := []byte("consistent-salt")
	info := []byte("consistent-info")

	key1, err := DeriveKey(sharedSecret, salt, info, 32)
	require.NoError(t, err)

	key2, err := DeriveKey(sharedSecret, salt, info, 32)
	require.NoError(t, err)

	assert.Equal(t, key1, key2)
}

// TestDeriveKey_DifferentSecretsProduceDifferentKeys tests that different secrets produce different keys
func TestDeriveKey_DifferentSecretsProduceDifferentKeys(t *testing.T) {
	key1, err := DeriveKey([]byte("secret1"), nil, []byte("info"), 32)
	require.NoError(t, err)

	key2, err := DeriveKey([]byte("secret2"), nil, []byte("info"), 32)
	require.NoError(t, err)

	assert.NotEqual(t, key1, key2)
}

// TestDeriveSharedSecret_StressTest performs stress testing with many iterations
func TestDeriveSharedSecret_StressTest(t *testing.T) {
	for i := 0; i < 50; i++ {
		alicePriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		bobPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		aliceShared, err := DeriveSharedSecret(alicePriv, &bobPriv.PublicKey)
		require.NoError(t, err)

		bobShared, err := DeriveSharedSecret(bobPriv, &alicePriv.PublicKey)
		require.NoError(t, err)

		assert.Equal(t, aliceShared, bobShared)
	}
}

// TestEcdsaPublicToECDH_UnsupportedCurve tests public key conversion with unsupported curve
func TestEcdsaPublicToECDH_UnsupportedCurve(t *testing.T) {
	// Create a P-224 key (not supported)
	priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	// Also create another P-224 key to test both conversion paths
	priv2, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	// Try to derive shared secret - should fail at private key conversion
	_, err = DeriveSharedSecret(priv, &priv2.PublicKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported curve")
}
