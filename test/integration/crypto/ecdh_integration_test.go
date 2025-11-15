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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/crypto/ecdh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestECDH_DeriveSharedSecret(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, c := range curves {
		t.Run(c.name, func(t *testing.T) {
			// Generate Alice's key pair
			alicePriv, err := ecdsa.GenerateKey(c.curve, rand.Reader)
			require.NoError(t, err)

			// Generate Bob's key pair
			bobPriv, err := ecdsa.GenerateKey(c.curve, rand.Reader)
			require.NoError(t, err)

			// Alice derives shared secret using Bob's public key
			aliceSecret, err := ecdh.DeriveSharedSecret(alicePriv, &bobPriv.PublicKey)
			require.NoError(t, err)
			require.NotNil(t, aliceSecret)

			// Bob derives shared secret using Alice's public key
			bobSecret, err := ecdh.DeriveSharedSecret(bobPriv, &alicePriv.PublicKey)
			require.NoError(t, err)
			require.NotNil(t, bobSecret)

			// Both secrets should be identical
			assert.Equal(t, aliceSecret, bobSecret)

			// Shared secret should have expected length based on curve
			var expectedLength int
			switch c.curve.Params().Name {
			case "P-256":
				expectedLength = 32
			case "P-384":
				expectedLength = 48
			case "P-521":
				expectedLength = 66
			}
			assert.Len(t, aliceSecret, expectedLength)
		})
	}
}

func TestECDH_DeriveKey(t *testing.T) {
	alicePriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bobPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Derive shared secret
	sharedSecret, err := ecdh.DeriveSharedSecret(alicePriv, &bobPriv.PublicKey)
	require.NoError(t, err)

	tests := []struct {
		name      string
		salt      []byte
		info      []byte
		keyLength int
	}{
		{
			name:      "128-bit encryption key",
			salt:      nil,
			info:      []byte("encryption"),
			keyLength: 16,
		},
		{
			name:      "256-bit encryption key",
			salt:      nil,
			info:      []byte("aes-256-gcm"),
			keyLength: 32,
		},
		{
			name:      "With salt",
			salt:      []byte("random-salt-value"),
			info:      []byte("encryption"),
			keyLength: 32,
		},
		{
			name:      "512-bit key",
			salt:      nil,
			info:      []byte("hmac-sha512"),
			keyLength: 64,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ecdh.DeriveKey(sharedSecret, tt.salt, tt.info, tt.keyLength)
			require.NoError(t, err)
			assert.Len(t, key, tt.keyLength)
		})
	}
}

func TestECDH_KeySeparation(t *testing.T) {
	// Generate two parties
	alicePriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bobPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Derive shared secret
	sharedSecret, err := ecdh.DeriveSharedSecret(alicePriv, &bobPriv.PublicKey)
	require.NoError(t, err)

	// Derive different keys for different purposes
	encKey, err := ecdh.DeriveKey(sharedSecret, nil, []byte("encryption"), 32)
	require.NoError(t, err)

	macKey, err := ecdh.DeriveKey(sharedSecret, nil, []byte("mac"), 32)
	require.NoError(t, err)

	authKey, err := ecdh.DeriveKey(sharedSecret, nil, []byte("authentication"), 32)
	require.NoError(t, err)

	// All keys should be different
	assert.NotEqual(t, encKey, macKey)
	assert.NotEqual(t, encKey, authKey)
	assert.NotEqual(t, macKey, authKey)
}

func TestECDH_DifferentSalts(t *testing.T) {
	alicePriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bobPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	sharedSecret, err := ecdh.DeriveSharedSecret(alicePriv, &bobPriv.PublicKey)
	require.NoError(t, err)

	// Same info, different salts should produce different keys
	salt1 := []byte("salt-1")
	salt2 := []byte("salt-2")
	info := []byte("encryption")

	key1, err := ecdh.DeriveKey(sharedSecret, salt1, info, 32)
	require.NoError(t, err)

	key2, err := ecdh.DeriveKey(sharedSecret, salt2, info, 32)
	require.NoError(t, err)

	assert.NotEqual(t, key1, key2)
}

func TestECDH_InvalidInputs(t *testing.T) {
	validPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	validPub := &validPriv.PublicKey

	tests := []struct {
		name      string
		privKey   *ecdsa.PrivateKey
		pubKey    *ecdsa.PublicKey
		expectErr bool
	}{
		{
			name:      "Nil private key",
			privKey:   nil,
			pubKey:    validPub,
			expectErr: true,
		},
		{
			name:      "Nil public key",
			privKey:   validPriv,
			pubKey:    nil,
			expectErr: true,
		},
		{
			name:      "Both nil",
			privKey:   nil,
			pubKey:    nil,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ecdh.DeriveSharedSecret(tt.privKey, tt.pubKey)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestECDH_CurveMismatch(t *testing.T) {
	// Generate keys on different curves
	privP256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privP384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	// Attempt ECDH with mismatched curves
	_, err = ecdh.DeriveSharedSecret(privP256, &privP384.PublicKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "curve mismatch")
}

func TestECDH_DeriveKeyInvalidInputs(t *testing.T) {
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	tests := []struct {
		name         string
		sharedSecret []byte
		keyLength    int
		expectErr    bool
	}{
		{
			name:         "Nil shared secret",
			sharedSecret: nil,
			keyLength:    32,
			expectErr:    true,
		},
		{
			name:         "Zero key length",
			sharedSecret: sharedSecret,
			keyLength:    0,
			expectErr:    true,
		},
		{
			name:         "Negative key length",
			sharedSecret: sharedSecret,
			keyLength:    -1,
			expectErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ecdh.DeriveKey(tt.sharedSecret, nil, []byte("test"), tt.keyLength)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestECDH_MultipleParties(t *testing.T) {
	// Test ECDH with multiple parties
	const numParties = 5
	parties := make([]*ecdsa.PrivateKey, numParties)

	// Generate key pairs for all parties
	for i := 0; i < numParties; i++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		parties[i] = key
	}

	// Each party derives shared secret with every other party
	secrets := make(map[string][]byte)

	for i := 0; i < numParties; i++ {
		for j := i + 1; j < numParties; j++ {
			// Party i with party j
			secretIJ, err := ecdh.DeriveSharedSecret(parties[i], &parties[j].PublicKey)
			require.NoError(t, err)

			// Party j with party i
			secretJI, err := ecdh.DeriveSharedSecret(parties[j], &parties[i].PublicKey)
			require.NoError(t, err)

			// Secrets should match
			assert.Equal(t, secretIJ, secretJI)

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
			assert.NotEqual(t, secretsList[i], secretsList[j],
				"Secrets should be unique for different key pairs")
		}
	}
}

func TestECDH_DeterministicDerivation(t *testing.T) {
	alicePriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bobPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Derive shared secret multiple times
	const numIterations = 10
	secrets := make([][]byte, numIterations)

	for i := 0; i < numIterations; i++ {
		secret, err := ecdh.DeriveSharedSecret(alicePriv, &bobPriv.PublicKey)
		require.NoError(t, err)
		secrets[i] = secret
	}

	// All secrets should be identical
	for i := 1; i < numIterations; i++ {
		assert.Equal(t, secrets[0], secrets[i],
			"ECDH should be deterministic")
	}
}

func TestECDH_DeriveKeyDeterministic(t *testing.T) {
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	salt := []byte("test-salt")
	info := []byte("test-info")
	keyLength := 32

	// Derive key multiple times
	const numIterations = 10
	keys := make([][]byte, numIterations)

	for i := 0; i < numIterations; i++ {
		key, err := ecdh.DeriveKey(sharedSecret, salt, info, keyLength)
		require.NoError(t, err)
		keys[i] = key
	}

	// All keys should be identical
	for i := 1; i < numIterations; i++ {
		assert.Equal(t, keys[0], keys[i],
			"HKDF should be deterministic")
	}
}

func TestECDH_VariousKeyLengths(t *testing.T) {
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	lengths := []int{
		1,
		16,  // 128 bits
		24,  // 192 bits
		32,  // 256 bits
		48,  // 384 bits
		64,  // 512 bits
		128, // 1024 bits
		256, // 2048 bits
	}

	for _, length := range lengths {
		t.Run(fmt.Sprintf("Length_%d", length), func(t *testing.T) {
			key, err := ecdh.DeriveKey(sharedSecret, nil, []byte("test"), length)
			require.NoError(t, err)
			assert.Len(t, key, length)
		})
	}
}

func TestECDH_EmptyInfo(t *testing.T) {
	alicePriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bobPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	sharedSecret, err := ecdh.DeriveSharedSecret(alicePriv, &bobPriv.PublicKey)
	require.NoError(t, err)

	// Derive keys with different info values including empty
	key1, err := ecdh.DeriveKey(sharedSecret, nil, nil, 32)
	require.NoError(t, err)

	key2, err := ecdh.DeriveKey(sharedSecret, nil, []byte{}, 32)
	require.NoError(t, err)

	key3, err := ecdh.DeriveKey(sharedSecret, nil, []byte("info"), 32)
	require.NoError(t, err)

	// nil and empty info should produce the same key
	assert.Equal(t, key1, key2)

	// Non-empty info should produce different key
	assert.NotEqual(t, key1, key3)
}

func TestECDH_SelfAgreement(t *testing.T) {
	// A party can perform ECDH with themselves (though not useful in practice)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	secret, err := ecdh.DeriveSharedSecret(privateKey, &privateKey.PublicKey)
	require.NoError(t, err)
	assert.NotNil(t, secret)
	assert.Len(t, secret, 32) // P-256 produces 32-byte secret
}

func TestECDH_KeyUniqueness(t *testing.T) {
	// Generate shared secret
	alicePriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bobPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	sharedSecret, err := ecdh.DeriveSharedSecret(alicePriv, &bobPriv.PublicKey)
	require.NoError(t, err)

	// Derive many keys with sequential info values
	const numKeys = 100
	keys := make([][]byte, numKeys)

	for i := 0; i < numKeys; i++ {
		info := []byte(fmt.Sprintf("key-%d", i))
		key, err := ecdh.DeriveKey(sharedSecret, nil, info, 32)
		require.NoError(t, err)
		keys[i] = key

		// Check uniqueness against all previous keys
		for j := 0; j < i; j++ {
			assert.NotEqual(t, keys[j], key,
				"Keys %d and %d should be unique", j, i)
		}
	}
}

func BenchmarkECDH_DeriveSharedSecret_P256(b *testing.B) {
	alicePriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bobPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ecdh.DeriveSharedSecret(alicePriv, &bobPriv.PublicKey)
	}
}

func BenchmarkECDH_DeriveSharedSecret_P384(b *testing.B) {
	alicePriv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	bobPriv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ecdh.DeriveSharedSecret(alicePriv, &bobPriv.PublicKey)
	}
}

func BenchmarkECDH_DeriveKey(b *testing.B) {
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)
	info := []byte("encryption")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ecdh.DeriveKey(sharedSecret, nil, info, 32)
	}
}
