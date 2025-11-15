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

package x25519

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	ka := New()
	require.NotNil(t, ka)

	// Verify it's the correct type
	impl, ok := ka.(*x25519KeyAgreement)
	require.True(t, ok)
	assert.Equal(t, ecdh.X25519(), impl.curve)
}

func TestGenerateKey(t *testing.T) {
	ka := New()

	t.Run("successful generation", func(t *testing.T) {
		keyPair, err := ka.GenerateKey()
		require.NoError(t, err)
		require.NotNil(t, keyPair)
		require.NotNil(t, keyPair.PrivateKey)
		require.NotNil(t, keyPair.PublicKey)

		// Verify key lengths (X25519 uses 32-byte keys)
		assert.Len(t, keyPair.PrivateKey.Bytes(), 32)
		assert.Len(t, keyPair.PublicKey.Bytes(), 32)

		// Verify the public key matches the private key
		derivedPublicKey := keyPair.PrivateKey.PublicKey()
		assert.Equal(t, keyPair.PublicKey.Bytes(), derivedPublicKey.Bytes())

		// Verify curve type
		assert.Equal(t, ecdh.X25519(), keyPair.PrivateKey.Curve())
		assert.Equal(t, ecdh.X25519(), keyPair.PublicKey.Curve())
	})

	t.Run("generates unique keys", func(t *testing.T) {
		keyPair1, err := ka.GenerateKey()
		require.NoError(t, err)

		keyPair2, err := ka.GenerateKey()
		require.NoError(t, err)

		// Keys should be different
		assert.NotEqual(t, keyPair1.PrivateKey.Bytes(), keyPair2.PrivateKey.Bytes())
		assert.NotEqual(t, keyPair1.PublicKey.Bytes(), keyPair2.PublicKey.Bytes())
	})

	t.Run("multiple generations", func(t *testing.T) {
		// Generate multiple keys to ensure consistency
		for i := 0; i < 10; i++ {
			keyPair, err := ka.GenerateKey()
			require.NoError(t, err)
			require.NotNil(t, keyPair)
			assert.Len(t, keyPair.PrivateKey.Bytes(), 32)
			assert.Len(t, keyPair.PublicKey.Bytes(), 32)
		}
	})
}

func TestDeriveSharedSecret(t *testing.T) {
	ka := New()

	t.Run("successful key agreement", func(t *testing.T) {
		// Generate two key pairs (Alice and Bob)
		aliceKeyPair, err := ka.GenerateKey()
		require.NoError(t, err)

		bobKeyPair, err := ka.GenerateKey()
		require.NoError(t, err)

		// Alice computes shared secret using her private key and Bob's public key
		aliceSharedSecret, err := ka.DeriveSharedSecret(aliceKeyPair.PrivateKey, bobKeyPair.PublicKey)
		require.NoError(t, err)
		require.NotNil(t, aliceSharedSecret)
		assert.Len(t, aliceSharedSecret, 32) // X25519 produces 32-byte shared secrets

		// Bob computes shared secret using his private key and Alice's public key
		bobSharedSecret, err := ka.DeriveSharedSecret(bobKeyPair.PrivateKey, aliceKeyPair.PublicKey)
		require.NoError(t, err)
		require.NotNil(t, bobSharedSecret)

		// Both should derive the same shared secret
		assert.Equal(t, aliceSharedSecret, bobSharedSecret)
	})

	t.Run("nil private key", func(t *testing.T) {
		keyPair, err := ka.GenerateKey()
		require.NoError(t, err)

		_, err = ka.DeriveSharedSecret(nil, keyPair.PublicKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "private key cannot be nil")
	})

	t.Run("nil peer public key", func(t *testing.T) {
		keyPair, err := ka.GenerateKey()
		require.NoError(t, err)

		_, err = ka.DeriveSharedSecret(keyPair.PrivateKey, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "peer public key cannot be nil")
	})

	t.Run("wrong curve for private key", func(t *testing.T) {
		// Create a P-256 key (wrong curve)
		p256PrivateKey, err := ecdh.P256().GenerateKey(rand.Reader)
		require.NoError(t, err)

		x25519KeyPair, err := ka.GenerateKey()
		require.NoError(t, err)

		_, err = ka.DeriveSharedSecret(p256PrivateKey, x25519KeyPair.PublicKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be X25519")
	})

	t.Run("wrong curve for public key", func(t *testing.T) {
		// Create a P-256 key (wrong curve)
		p256PrivateKey, err := ecdh.P256().GenerateKey(rand.Reader)
		require.NoError(t, err)

		x25519KeyPair, err := ka.GenerateKey()
		require.NoError(t, err)

		_, err = ka.DeriveSharedSecret(x25519KeyPair.PrivateKey, p256PrivateKey.PublicKey())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be X25519")
	})

	t.Run("same key pair derives non-zero secret", func(t *testing.T) {
		// Even with the same key pair, X25519 should derive a valid secret
		keyPair, err := ka.GenerateKey()
		require.NoError(t, err)

		sharedSecret, err := ka.DeriveSharedSecret(keyPair.PrivateKey, keyPair.PublicKey)
		require.NoError(t, err)
		assert.Len(t, sharedSecret, 32)
		// Secret should not be all zeros
		allZeros := make([]byte, 32)
		assert.NotEqual(t, allZeros, sharedSecret)
	})
}

func TestDeriveKey(t *testing.T) {
	ka := New()

	// Generate a shared secret for testing
	aliceKeyPair, err := ka.GenerateKey()
	require.NoError(t, err)
	bobKeyPair, err := ka.GenerateKey()
	require.NoError(t, err)
	sharedSecret, err := ka.DeriveSharedSecret(aliceKeyPair.PrivateKey, bobKeyPair.PublicKey)
	require.NoError(t, err)

	t.Run("successful key derivation", func(t *testing.T) {
		salt := []byte("test-salt")
		info := []byte("test-context")
		keyLength := 32

		derivedKey, err := ka.DeriveKey(sharedSecret, salt, info, keyLength)
		require.NoError(t, err)
		require.NotNil(t, derivedKey)
		assert.Len(t, derivedKey, keyLength)
	})

	t.Run("derive multiple keys with different info", func(t *testing.T) {
		salt := []byte("test-salt")
		keyLength := 32

		key1, err := ka.DeriveKey(sharedSecret, salt, []byte("context-1"), keyLength)
		require.NoError(t, err)

		key2, err := ka.DeriveKey(sharedSecret, salt, []byte("context-2"), keyLength)
		require.NoError(t, err)

		// Different context should produce different keys
		assert.NotEqual(t, key1, key2)
	})

	t.Run("derive multiple keys with different salt", func(t *testing.T) {
		info := []byte("test-context")
		keyLength := 32

		key1, err := ka.DeriveKey(sharedSecret, []byte("salt-1"), info, keyLength)
		require.NoError(t, err)

		key2, err := ka.DeriveKey(sharedSecret, []byte("salt-2"), info, keyLength)
		require.NoError(t, err)

		// Different salt should produce different keys
		assert.NotEqual(t, key1, key2)
	})

	t.Run("nil salt and info", func(t *testing.T) {
		keyLength := 32

		derivedKey, err := ka.DeriveKey(sharedSecret, nil, nil, keyLength)
		require.NoError(t, err)
		require.NotNil(t, derivedKey)
		assert.Len(t, derivedKey, keyLength)
	})

	t.Run("various key lengths", func(t *testing.T) {
		testCases := []int{16, 24, 32, 64, 128, 256}

		for _, keyLength := range testCases {
			t.Run(hex.EncodeToString([]byte{byte(keyLength)}), func(t *testing.T) {
				derivedKey, err := ka.DeriveKey(sharedSecret, nil, nil, keyLength)
				require.NoError(t, err)
				assert.Len(t, derivedKey, keyLength)
			})
		}
	})

	t.Run("empty shared secret", func(t *testing.T) {
		_, err := ka.DeriveKey([]byte{}, nil, nil, 32)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "shared secret cannot be empty")
	})

	t.Run("zero key length", func(t *testing.T) {
		_, err := ka.DeriveKey(sharedSecret, nil, nil, 0)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key length must be positive")
	})

	t.Run("negative key length", func(t *testing.T) {
		_, err := ka.DeriveKey(sharedSecret, nil, nil, -1)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key length must be positive")
	})

	t.Run("key length too large", func(t *testing.T) {
		// HKDF-SHA256 limit is 255 * 32 = 8160 bytes
		_, err := ka.DeriveKey(sharedSecret, nil, nil, 8161)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key length too large")
	})

	t.Run("maximum valid key length", func(t *testing.T) {
		// Test the maximum valid HKDF-SHA256 length (255 * 32 = 8160)
		maxLength := 255 * 32
		derivedKey, err := ka.DeriveKey(sharedSecret, nil, nil, maxLength)
		require.NoError(t, err)
		assert.Len(t, derivedKey, maxLength)
	})

	t.Run("deterministic derivation", func(t *testing.T) {
		// Same inputs should always produce same output
		salt := []byte("deterministic-salt")
		info := []byte("deterministic-info")
		keyLength := 32

		key1, err := ka.DeriveKey(sharedSecret, salt, info, keyLength)
		require.NoError(t, err)

		key2, err := ka.DeriveKey(sharedSecret, salt, info, keyLength)
		require.NoError(t, err)

		assert.Equal(t, key1, key2)
	})

	t.Run("empty salt with non-empty info", func(t *testing.T) {
		key1, err := ka.DeriveKey(sharedSecret, []byte{}, []byte("info"), 32)
		require.NoError(t, err)

		key2, err := ka.DeriveKey(sharedSecret, nil, []byte("info"), 32)
		require.NoError(t, err)

		// Empty slice and nil should produce the same result
		assert.Equal(t, key1, key2)
	})

	t.Run("empty info with non-empty salt", func(t *testing.T) {
		key1, err := ka.DeriveKey(sharedSecret, []byte("salt"), []byte{}, 32)
		require.NoError(t, err)

		key2, err := ka.DeriveKey(sharedSecret, []byte("salt"), nil, 32)
		require.NoError(t, err)

		// Empty slice and nil should produce the same result
		assert.Equal(t, key1, key2)
	})
}

func TestParsePrivateKey(t *testing.T) {
	t.Run("valid private key", func(t *testing.T) {
		// Generate a valid key
		ka := New()
		keyPair, err := ka.GenerateKey()
		require.NoError(t, err)

		// Get the raw bytes
		privateKeyBytes := keyPair.PrivateKey.Bytes()

		// Parse it back
		parsedKey, err := ParsePrivateKey(privateKeyBytes)
		require.NoError(t, err)
		require.NotNil(t, parsedKey)

		// Should produce the same bytes
		assert.Equal(t, privateKeyBytes, parsedKey.Bytes())
	})

	t.Run("invalid length - too short", func(t *testing.T) {
		shortKey := make([]byte, 16)
		_, err := ParsePrivateKey(shortKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be 32 bytes")
	})

	t.Run("invalid length - too long", func(t *testing.T) {
		longKey := make([]byte, 64)
		_, err := ParsePrivateKey(longKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be 32 bytes")
	})

	t.Run("empty key", func(t *testing.T) {
		_, err := ParsePrivateKey([]byte{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be 32 bytes")
	})
}

func TestParsePublicKey(t *testing.T) {
	t.Run("valid public key", func(t *testing.T) {
		// Generate a valid key
		ka := New()
		keyPair, err := ka.GenerateKey()
		require.NoError(t, err)

		// Get the raw bytes
		publicKeyBytes := keyPair.PublicKey.Bytes()

		// Parse it back
		parsedKey, err := ParsePublicKey(publicKeyBytes)
		require.NoError(t, err)
		require.NotNil(t, parsedKey)

		// Should produce the same bytes
		assert.Equal(t, publicKeyBytes, parsedKey.Bytes())
	})

	t.Run("invalid length - too short", func(t *testing.T) {
		shortKey := make([]byte, 16)
		_, err := ParsePublicKey(shortKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be 32 bytes")
	})

	t.Run("invalid length - too long", func(t *testing.T) {
		longKey := make([]byte, 64)
		_, err := ParsePublicKey(longKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be 32 bytes")
	})

	t.Run("empty key", func(t *testing.T) {
		_, err := ParsePublicKey([]byte{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be 32 bytes")
	})
}

func TestPrivateKeyBytes(t *testing.T) {
	ka := New()
	keyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	privateKeyBytes := PrivateKeyBytes(keyPair.PrivateKey)
	assert.Len(t, privateKeyBytes, 32)
	assert.Equal(t, keyPair.PrivateKey.Bytes(), privateKeyBytes)
}

func TestPublicKeyBytes(t *testing.T) {
	ka := New()
	keyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	publicKeyBytes := PublicKeyBytes(keyPair.PublicKey)
	assert.Len(t, publicKeyBytes, 32)
	assert.Equal(t, keyPair.PublicKey.Bytes(), publicKeyBytes)
}

func TestRoundTripKeyAgreement(t *testing.T) {
	ka := New()

	// Generate Alice's key pair
	aliceKeyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	// Generate Bob's key pair
	bobKeyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	// Alice derives shared secret
	aliceSharedSecret, err := ka.DeriveSharedSecret(aliceKeyPair.PrivateKey, bobKeyPair.PublicKey)
	require.NoError(t, err)

	// Bob derives shared secret
	bobSharedSecret, err := ka.DeriveSharedSecret(bobKeyPair.PrivateKey, aliceKeyPair.PublicKey)
	require.NoError(t, err)

	// Both should have the same shared secret
	assert.Equal(t, aliceSharedSecret, bobSharedSecret)

	// Derive keys using HKDF
	salt := []byte("test-salt")
	info := []byte("test-info")
	keyLength := 32

	aliceDerivedKey, err := ka.DeriveKey(aliceSharedSecret, salt, info, keyLength)
	require.NoError(t, err)

	bobDerivedKey, err := ka.DeriveKey(bobSharedSecret, salt, info, keyLength)
	require.NoError(t, err)

	// Both should derive the same key
	assert.Equal(t, aliceDerivedKey, bobDerivedKey)
}

func TestKeySerializationRoundTrip(t *testing.T) {
	ka := New()

	// Generate a key pair
	original, err := ka.GenerateKey()
	require.NoError(t, err)

	// Serialize private key
	privateKeyBytes := PrivateKeyBytes(original.PrivateKey)

	// Serialize public key
	publicKeyBytes := PublicKeyBytes(original.PublicKey)

	// Deserialize private key
	parsedPrivateKey, err := ParsePrivateKey(privateKeyBytes)
	require.NoError(t, err)

	// Deserialize public key
	parsedPublicKey, err := ParsePublicKey(publicKeyBytes)
	require.NoError(t, err)

	// Verify the keys match
	assert.Equal(t, privateKeyBytes, parsedPrivateKey.Bytes())
	assert.Equal(t, publicKeyBytes, parsedPublicKey.Bytes())

	// Verify key agreement still works
	otherKeyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	// Use original keys
	secret1, err := ka.DeriveSharedSecret(original.PrivateKey, otherKeyPair.PublicKey)
	require.NoError(t, err)

	// Use parsed keys
	secret2, err := ka.DeriveSharedSecret(parsedPrivateKey, otherKeyPair.PublicKey)
	require.NoError(t, err)

	// Should derive the same secret
	assert.Equal(t, secret1, secret2)
}

// TestAgainstRFC7748TestVectors tests against the test vectors from RFC 7748
// https://tools.ietf.org/html/rfc7748#section-6.1
func TestAgainstRFC7748TestVectors(t *testing.T) {
	// Test vector from RFC 7748 Section 6.1
	alicePrivateHex := "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	alicePublicHex := "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"

	bobPrivateHex := "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
	bobPublicHex := "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"

	sharedSecretHex := "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

	// Decode hex strings
	alicePrivateBytes, err := hex.DecodeString(alicePrivateHex)
	require.NoError(t, err)
	alicePublicBytes, err := hex.DecodeString(alicePublicHex)
	require.NoError(t, err)

	bobPrivateBytes, err := hex.DecodeString(bobPrivateHex)
	require.NoError(t, err)
	bobPublicBytes, err := hex.DecodeString(bobPublicHex)
	require.NoError(t, err)

	expectedSharedSecret, err := hex.DecodeString(sharedSecretHex)
	require.NoError(t, err)

	// Parse keys
	alicePrivate, err := ParsePrivateKey(alicePrivateBytes)
	require.NoError(t, err)
	alicePublic, err := ParsePublicKey(alicePublicBytes)
	require.NoError(t, err)

	bobPrivate, err := ParsePrivateKey(bobPrivateBytes)
	require.NoError(t, err)
	bobPublic, err := ParsePublicKey(bobPublicBytes)
	require.NoError(t, err)

	// Verify public keys match
	assert.Equal(t, alicePublicBytes, alicePrivate.PublicKey().Bytes())
	assert.Equal(t, bobPublicBytes, bobPrivate.PublicKey().Bytes())

	// Perform key agreement
	ka := New()

	// Alice computes shared secret with Bob's public key
	aliceSharedSecret, err := ka.DeriveSharedSecret(alicePrivate, bobPublic)
	require.NoError(t, err)

	// Bob computes shared secret with Alice's public key
	bobSharedSecret, err := ka.DeriveSharedSecret(bobPrivate, alicePublic)
	require.NoError(t, err)

	// Verify both computed the same shared secret
	assert.True(t, bytes.Equal(aliceSharedSecret, bobSharedSecret))

	// Verify against expected shared secret from RFC
	assert.Equal(t, expectedSharedSecret, aliceSharedSecret)
	assert.Equal(t, expectedSharedSecret, bobSharedSecret)
}

func TestHKDFCompatibility(t *testing.T) {
	// Test that our HKDF implementation matches standard expectations
	ka := New()

	// Use a fixed shared secret for reproducibility
	sharedSecret := bytes.Repeat([]byte{0x42}, 32)
	salt := []byte("my-salt")
	info := []byte("my-info")

	// Derive a key
	derivedKey, err := ka.DeriveKey(sharedSecret, salt, info, 32)
	require.NoError(t, err)
	require.Len(t, derivedKey, 32)

	// Derive again with same parameters - should get same result
	derivedKey2, err := ka.DeriveKey(sharedSecret, salt, info, 32)
	require.NoError(t, err)
	assert.Equal(t, derivedKey, derivedKey2)

	// Different parameters should give different results
	derivedKey3, err := ka.DeriveKey(sharedSecret, []byte("different-salt"), info, 32)
	require.NoError(t, err)
	assert.NotEqual(t, derivedKey, derivedKey3)
}
