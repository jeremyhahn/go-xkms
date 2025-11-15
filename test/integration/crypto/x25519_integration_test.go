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

//go:build integration

package crypto_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/crypto/x25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestX25519_GenerateKey(t *testing.T) {
	ka := x25519.New()
	require.NotNil(t, ka)

	keyPair, err := ka.GenerateKey()
	require.NoError(t, err)
	require.NotNil(t, keyPair)
	require.NotNil(t, keyPair.PrivateKey)
	require.NotNil(t, keyPair.PublicKey)

	// X25519 keys are 32 bytes
	assert.Len(t, x25519.PrivateKeyBytes(keyPair.PrivateKey), 32)
	assert.Len(t, x25519.PublicKeyBytes(keyPair.PublicKey), 32)
}

func TestX25519_GenerateMultipleKeys(t *testing.T) {
	ka := x25519.New()
	const numKeys = 100

	keys := make([]*x25519.KeyPair, numKeys)
	for i := 0; i < numKeys; i++ {
		keyPair, err := ka.GenerateKey()
		require.NoError(t, err)
		keys[i] = keyPair

		// Each key should be unique
		for j := 0; j < i; j++ {
			assert.False(t, bytes.Equal(
				x25519.PrivateKeyBytes(keys[j].PrivateKey),
				x25519.PrivateKeyBytes(keyPair.PrivateKey),
			), "Private keys should be unique")

			assert.False(t, bytes.Equal(
				x25519.PublicKeyBytes(keys[j].PublicKey),
				x25519.PublicKeyBytes(keyPair.PublicKey),
			), "Public keys should be unique")
		}
	}
}

func TestX25519_DeriveSharedSecret(t *testing.T) {
	ka := x25519.New()

	// Generate Alice's key pair
	aliceKeyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	// Generate Bob's key pair
	bobKeyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	// Alice derives shared secret using Bob's public key
	aliceSecret, err := ka.DeriveSharedSecret(aliceKeyPair.PrivateKey, bobKeyPair.PublicKey)
	require.NoError(t, err)
	require.NotNil(t, aliceSecret)
	assert.Len(t, aliceSecret, 32)

	// Bob derives shared secret using Alice's public key
	bobSecret, err := ka.DeriveSharedSecret(bobKeyPair.PrivateKey, aliceKeyPair.PublicKey)
	require.NoError(t, err)
	require.NotNil(t, bobSecret)
	assert.Len(t, bobSecret, 32)

	// Both secrets should be identical
	assert.True(t, bytes.Equal(aliceSecret, bobSecret),
		"Alice and Bob should derive the same shared secret")
}

func TestX25519_DeriveSharedSecretDeterministic(t *testing.T) {
	ka := x25519.New()

	aliceKeyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	bobKeyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	// Derive shared secret multiple times
	const numIterations = 10
	secrets := make([][]byte, numIterations)

	for i := 0; i < numIterations; i++ {
		secret, err := ka.DeriveSharedSecret(aliceKeyPair.PrivateKey, bobKeyPair.PublicKey)
		require.NoError(t, err)
		secrets[i] = secret
	}

	// All secrets should be identical
	for i := 1; i < numIterations; i++ {
		assert.True(t, bytes.Equal(secrets[0], secrets[i]),
			"X25519 should be deterministic")
	}
}

func TestX25519_DeriveKey(t *testing.T) {
	ka := x25519.New()

	aliceKeyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	bobKeyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	sharedSecret, err := ka.DeriveSharedSecret(aliceKeyPair.PrivateKey, bobKeyPair.PublicKey)
	require.NoError(t, err)

	tests := []struct {
		name      string
		salt      []byte
		info      []byte
		keyLength int
	}{
		{
			name:      "128-bit key",
			salt:      nil,
			info:      []byte("encryption"),
			keyLength: 16,
		},
		{
			name:      "256-bit key",
			salt:      nil,
			info:      []byte("aes-256-gcm"),
			keyLength: 32,
		},
		{
			name:      "With salt",
			salt:      []byte("unique-salt"),
			info:      []byte("encryption"),
			keyLength: 32,
		},
		{
			name:      "512-bit key",
			salt:      nil,
			info:      []byte("hmac-sha512"),
			keyLength: 64,
		},
		{
			name:      "Large key",
			salt:      nil,
			info:      []byte("large-key"),
			keyLength: 256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ka.DeriveKey(sharedSecret, tt.salt, tt.info, tt.keyLength)
			require.NoError(t, err)
			assert.Len(t, key, tt.keyLength)
		})
	}
}

func TestX25519_DeriveKeyWithDifferentInfo(t *testing.T) {
	ka := x25519.New()

	aliceKeyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	bobKeyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	sharedSecret, err := ka.DeriveSharedSecret(aliceKeyPair.PrivateKey, bobKeyPair.PublicKey)
	require.NoError(t, err)

	// Derive different keys for different purposes
	encKey, err := ka.DeriveKey(sharedSecret, nil, []byte("encryption"), 32)
	require.NoError(t, err)

	macKey, err := ka.DeriveKey(sharedSecret, nil, []byte("mac"), 32)
	require.NoError(t, err)

	authKey, err := ka.DeriveKey(sharedSecret, nil, []byte("authentication"), 32)
	require.NoError(t, err)

	// All keys should be different
	assert.False(t, bytes.Equal(encKey, macKey))
	assert.False(t, bytes.Equal(encKey, authKey))
	assert.False(t, bytes.Equal(macKey, authKey))
}

func TestX25519_DeriveKeyWithDifferentSalts(t *testing.T) {
	ka := x25519.New()

	aliceKeyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	bobKeyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	sharedSecret, err := ka.DeriveSharedSecret(aliceKeyPair.PrivateKey, bobKeyPair.PublicKey)
	require.NoError(t, err)

	salt1 := []byte("salt-1")
	salt2 := []byte("salt-2")
	info := []byte("encryption")

	key1, err := ka.DeriveKey(sharedSecret, salt1, info, 32)
	require.NoError(t, err)

	key2, err := ka.DeriveKey(sharedSecret, salt2, info, 32)
	require.NoError(t, err)

	// Different salts should produce different keys
	assert.False(t, bytes.Equal(key1, key2))
}

func TestX25519_InvalidInputs(t *testing.T) {
	ka := x25519.New()

	validKeyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	// Test nil private key
	t.Run("Nil private key", func(t *testing.T) {
		_, err := ka.DeriveSharedSecret(nil, validKeyPair.PublicKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "private key cannot be nil")
	})

	// Test nil public key
	t.Run("Nil public key", func(t *testing.T) {
		_, err := ka.DeriveSharedSecret(validKeyPair.PrivateKey, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "peer public key cannot be nil")
	})
}

func TestX25519_DeriveKeyInvalidInputs(t *testing.T) {
	ka := x25519.New()

	validSecret := make([]byte, 32)
	rand.Read(validSecret)

	tests := []struct {
		name         string
		sharedSecret []byte
		keyLength    int
		expectErr    bool
	}{
		{
			name:         "Empty shared secret",
			sharedSecret: []byte{},
			keyLength:    32,
			expectErr:    true,
		},
		{
			name:         "Zero key length",
			sharedSecret: validSecret,
			keyLength:    0,
			expectErr:    true,
		},
		{
			name:         "Negative key length",
			sharedSecret: validSecret,
			keyLength:    -1,
			expectErr:    true,
		},
		{
			name:         "Excessive key length",
			sharedSecret: validSecret,
			keyLength:    10000,
			expectErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ka.DeriveKey(tt.sharedSecret, nil, []byte("test"), tt.keyLength)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestX25519_ParsePrivateKey(t *testing.T) {
	// Valid 32-byte key
	validKey := make([]byte, 32)
	_, err := rand.Read(validKey)
	require.NoError(t, err)

	privateKey, err := x25519.ParsePrivateKey(validKey)
	require.NoError(t, err)
	require.NotNil(t, privateKey)

	// Retrieved bytes should match input
	assert.True(t, bytes.Equal(validKey, x25519.PrivateKeyBytes(privateKey)))

	// Invalid key sizes
	invalidSizes := []int{0, 16, 31, 33, 64}
	for _, size := range invalidSizes {
		t.Run(fmt.Sprintf("Invalid_size_%d", size), func(t *testing.T) {
			invalidKey := make([]byte, size)
			_, err := x25519.ParsePrivateKey(invalidKey)
			assert.Error(t, err)
		})
	}
}

func TestX25519_ParsePublicKey(t *testing.T) {
	// Valid 32-byte key
	validKey := make([]byte, 32)
	_, err := rand.Read(validKey)
	require.NoError(t, err)

	publicKey, err := x25519.ParsePublicKey(validKey)
	require.NoError(t, err)
	require.NotNil(t, publicKey)

	// Retrieved bytes should match input
	assert.True(t, bytes.Equal(validKey, x25519.PublicKeyBytes(publicKey)))

	// Invalid key sizes
	invalidSizes := []int{0, 16, 31, 33, 64}
	for _, size := range invalidSizes {
		t.Run(fmt.Sprintf("Invalid_size_%d", size), func(t *testing.T) {
			invalidKey := make([]byte, size)
			_, err := x25519.ParsePublicKey(invalidKey)
			assert.Error(t, err)
		})
	}
}

func TestX25519_KeyBytes(t *testing.T) {
	ka := x25519.New()

	keyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	// Get bytes
	privBytes := x25519.PrivateKeyBytes(keyPair.PrivateKey)
	pubBytes := x25519.PublicKeyBytes(keyPair.PublicKey)

	assert.Len(t, privBytes, 32)
	assert.Len(t, pubBytes, 32)

	// Parse back
	parsedPriv, err := x25519.ParsePrivateKey(privBytes)
	require.NoError(t, err)

	parsedPub, err := x25519.ParsePublicKey(pubBytes)
	require.NoError(t, err)

	// Should match original
	assert.True(t, bytes.Equal(privBytes, x25519.PrivateKeyBytes(parsedPriv)))
	assert.True(t, bytes.Equal(pubBytes, x25519.PublicKeyBytes(parsedPub)))
}

func TestX25519_MultipleParties(t *testing.T) {
	ka := x25519.New()
	const numParties = 5

	// Generate key pairs for all parties
	parties := make([]*x25519.KeyPair, numParties)
	for i := 0; i < numParties; i++ {
		keyPair, err := ka.GenerateKey()
		require.NoError(t, err)
		parties[i] = keyPair
	}

	// Each party derives shared secret with every other party
	secrets := make(map[string][]byte)

	for i := 0; i < numParties; i++ {
		for j := i + 1; j < numParties; j++ {
			// Party i with party j
			secretIJ, err := ka.DeriveSharedSecret(parties[i].PrivateKey, parties[j].PublicKey)
			require.NoError(t, err)

			// Party j with party i
			secretJI, err := ka.DeriveSharedSecret(parties[j].PrivateKey, parties[i].PublicKey)
			require.NoError(t, err)

			// Secrets should match
			assert.True(t, bytes.Equal(secretIJ, secretJI))

			// Store for uniqueness check
			key := fmt.Sprintf("%d-%d", i, j)
			secrets[key] = secretIJ
		}
	}

	// All pair-wise secrets should be unique
	secretsList := make([][]byte, 0, len(secrets))
	for _, secret := range secrets {
		secretsList = append(secretsList, secret)
	}

	for i := 0; i < len(secretsList); i++ {
		for j := i + 1; j < len(secretsList); j++ {
			assert.False(t, bytes.Equal(secretsList[i], secretsList[j]),
				"Secrets should be unique for different key pairs")
		}
	}
}

func TestX25519_DeriveKeyDeterministic(t *testing.T) {
	ka := x25519.New()

	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	salt := []byte("test-salt")
	info := []byte("test-info")
	keyLength := 32

	// Derive key multiple times
	const numIterations = 10
	keys := make([][]byte, numIterations)

	for i := 0; i < numIterations; i++ {
		key, err := ka.DeriveKey(sharedSecret, salt, info, keyLength)
		require.NoError(t, err)
		keys[i] = key
	}

	// All keys should be identical
	for i := 1; i < numIterations; i++ {
		assert.True(t, bytes.Equal(keys[0], keys[i]),
			"HKDF should be deterministic")
	}
}

func TestX25519_SelfAgreement(t *testing.T) {
	ka := x25519.New()

	keyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	// Derive shared secret with self
	secret, err := ka.DeriveSharedSecret(keyPair.PrivateKey, keyPair.PublicKey)
	require.NoError(t, err)
	assert.Len(t, secret, 32)
}

func TestX25519_KeySeparation(t *testing.T) {
	ka := x25519.New()

	aliceKeyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	bobKeyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	sharedSecret, err := ka.DeriveSharedSecret(aliceKeyPair.PrivateKey, bobKeyPair.PublicKey)
	require.NoError(t, err)

	// Derive many keys with sequential info values
	const numKeys = 100
	keys := make([][]byte, numKeys)

	for i := 0; i < numKeys; i++ {
		info := []byte(fmt.Sprintf("key-%d", i))
		key, err := ka.DeriveKey(sharedSecret, nil, info, 32)
		require.NoError(t, err)
		keys[i] = key

		// Check uniqueness against all previous keys
		for j := 0; j < i; j++ {
			assert.False(t, bytes.Equal(keys[j], key),
				"Keys %d and %d should be unique", j, i)
		}
	}
}

func TestX25519_VariousKeyLengths(t *testing.T) {
	ka := x25519.New()

	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	lengths := []int{
		1,
		16,   // 128 bits
		24,   // 192 bits
		32,   // 256 bits
		48,   // 384 bits
		64,   // 512 bits
		128,  // 1024 bits
		256,  // 2048 bits
		1024, // 8192 bits
	}

	for _, length := range lengths {
		t.Run(fmt.Sprintf("Length_%d", length), func(t *testing.T) {
			key, err := ka.DeriveKey(sharedSecret, nil, []byte("test"), length)
			require.NoError(t, err)
			assert.Len(t, key, length)
		})
	}
}

func TestX25519_EmptyInfo(t *testing.T) {
	ka := x25519.New()

	aliceKeyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	bobKeyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	sharedSecret, err := ka.DeriveSharedSecret(aliceKeyPair.PrivateKey, bobKeyPair.PublicKey)
	require.NoError(t, err)

	// Derive keys with different info values including empty
	key1, err := ka.DeriveKey(sharedSecret, nil, nil, 32)
	require.NoError(t, err)

	key2, err := ka.DeriveKey(sharedSecret, nil, []byte{}, 32)
	require.NoError(t, err)

	key3, err := ka.DeriveKey(sharedSecret, nil, []byte("info"), 32)
	require.NoError(t, err)

	// nil and empty info should produce the same key
	assert.True(t, bytes.Equal(key1, key2))

	// Non-empty info should produce different key
	assert.False(t, bytes.Equal(key1, key3))
}

func BenchmarkX25519_GenerateKey(b *testing.B) {
	ka := x25519.New()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ka.GenerateKey()
	}
}

func BenchmarkX25519_DeriveSharedSecret(b *testing.B) {
	ka := x25519.New()
	aliceKeyPair, _ := ka.GenerateKey()
	bobKeyPair, _ := ka.GenerateKey()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ka.DeriveSharedSecret(aliceKeyPair.PrivateKey, bobKeyPair.PublicKey)
	}
}

func BenchmarkX25519_DeriveKey(b *testing.B) {
	ka := x25519.New()
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)
	info := []byte("encryption")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ka.DeriveKey(sharedSecret, nil, info, 32)
	}
}
