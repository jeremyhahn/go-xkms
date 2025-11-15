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

package wrapping

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestKeyPair generates an RSA key pair for testing
func generateTestKeyPair(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

// TestWrapUnwrapRSAOAEP_SHA1 tests RSA-OAEP wrapping and unwrapping with SHA-1
func TestWrapUnwrapRSAOAEP_SHA1(t *testing.T) {
	// Generate test key pair
	privateKey, err := generateTestKeyPair(2048)
	require.NoError(t, err)

	// Test data
	keyMaterial := []byte("This is secret key material for testing")

	// Wrap the key material
	wrapped, err := WrapRSAOAEP(keyMaterial, &privateKey.PublicKey, backend.WrappingAlgorithmRSAES_OAEP_SHA_1)
	require.NoError(t, err)
	assert.NotNil(t, wrapped)
	assert.NotEqual(t, keyMaterial, wrapped, "wrapped key should be different from plaintext")

	// Unwrap the key material
	unwrapped, err := UnwrapRSAOAEP(wrapped, privateKey, backend.WrappingAlgorithmRSAES_OAEP_SHA_1)
	require.NoError(t, err)
	assert.Equal(t, keyMaterial, unwrapped, "unwrapped key should match original")
}

// TestWrapUnwrapRSAOAEP_SHA256 tests RSA-OAEP wrapping and unwrapping with SHA-256
func TestWrapUnwrapRSAOAEP_SHA256(t *testing.T) {
	// Generate test key pair
	privateKey, err := generateTestKeyPair(2048)
	require.NoError(t, err)

	// Test data
	keyMaterial := []byte("This is secret key material for SHA-256 testing")

	// Wrap the key material
	wrapped, err := WrapRSAOAEP(keyMaterial, &privateKey.PublicKey, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)
	assert.NotNil(t, wrapped)
	assert.NotEqual(t, keyMaterial, wrapped, "wrapped key should be different from plaintext")

	// Unwrap the key material
	unwrapped, err := UnwrapRSAOAEP(wrapped, privateKey, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)
	assert.Equal(t, keyMaterial, unwrapped, "unwrapped key should match original")
}

// TestWrapUnwrapRSAAES_SHA1 tests hybrid RSA+AES wrapping and unwrapping with SHA-1
func TestWrapUnwrapRSAAES_SHA1(t *testing.T) {
	// Generate test key pair
	privateKey, err := generateTestKeyPair(2048)
	require.NoError(t, err)

	// Test data
	keyMaterial := []byte("This is secret key material for hybrid RSA+AES testing with SHA-1")

	// Wrap the key material
	wrapped, err := WrapRSAAES(keyMaterial, &privateKey.PublicKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1)
	require.NoError(t, err)
	assert.NotNil(t, wrapped)
	assert.NotEqual(t, keyMaterial, wrapped, "wrapped key should be different from plaintext")

	// Unwrap the key material
	unwrapped, err := UnwrapRSAAES(wrapped, privateKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1)
	require.NoError(t, err)
	assert.Equal(t, keyMaterial, unwrapped, "unwrapped key should match original")
}

// TestWrapUnwrapRSAAES_SHA256 tests hybrid RSA+AES wrapping and unwrapping with SHA-256
func TestWrapUnwrapRSAAES_SHA256(t *testing.T) {
	// Generate test key pair
	privateKey, err := generateTestKeyPair(2048)
	require.NoError(t, err)

	// Test data
	keyMaterial := []byte("This is secret key material for hybrid RSA+AES testing with SHA-256")

	// Wrap the key material
	wrapped, err := WrapRSAAES(keyMaterial, &privateKey.PublicKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	require.NoError(t, err)
	assert.NotNil(t, wrapped)
	assert.NotEqual(t, keyMaterial, wrapped, "wrapped key should be different from plaintext")

	// Unwrap the key material
	unwrapped, err := UnwrapRSAAES(wrapped, privateKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	require.NoError(t, err)
	assert.Equal(t, keyMaterial, unwrapped, "unwrapped key should match original")
}

// TestRSAAES_LargeKeyMaterial tests hybrid wrapping with 4KB of key material
func TestRSAAES_LargeKeyMaterial(t *testing.T) {
	// Generate test key pair
	privateKey, err := generateTestKeyPair(2048)
	require.NoError(t, err)

	// Generate 4KB of random key material
	keyMaterial := make([]byte, 4096)
	_, err = rand.Read(keyMaterial)
	require.NoError(t, err)

	// Test with SHA-1
	t.Run("SHA1", func(t *testing.T) {
		wrapped, err := WrapRSAAES(keyMaterial, &privateKey.PublicKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1)
		require.NoError(t, err)
		assert.NotNil(t, wrapped)

		unwrapped, err := UnwrapRSAAES(wrapped, privateKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1)
		require.NoError(t, err)
		assert.Equal(t, keyMaterial, unwrapped, "unwrapped key should match original")
	})

	// Test with SHA-256
	t.Run("SHA256", func(t *testing.T) {
		wrapped, err := WrapRSAAES(keyMaterial, &privateKey.PublicKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
		require.NoError(t, err)
		assert.NotNil(t, wrapped)

		unwrapped, err := UnwrapRSAAES(wrapped, privateKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
		require.NoError(t, err)
		assert.Equal(t, keyMaterial, unwrapped, "unwrapped key should match original")
	})
}

// TestInvalidInputs tests error handling with invalid inputs
func TestInvalidInputs(t *testing.T) {
	privateKey, err := generateTestKeyPair(2048)
	require.NoError(t, err)

	validKeyMaterial := []byte("valid key material")

	t.Run("WrapRSAOAEP_NilKeyMaterial", func(t *testing.T) {
		_, err := WrapRSAOAEP(nil, &privateKey.PublicKey, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key material cannot be nil or empty")
	})

	t.Run("WrapRSAOAEP_EmptyKeyMaterial", func(t *testing.T) {
		_, err := WrapRSAOAEP([]byte{}, &privateKey.PublicKey, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key material cannot be nil or empty")
	})

	t.Run("WrapRSAOAEP_NilPublicKey", func(t *testing.T) {
		_, err := WrapRSAOAEP(validKeyMaterial, nil, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "public key cannot be nil")
	})

	t.Run("WrapRSAOAEP_InvalidAlgorithm", func(t *testing.T) {
		_, err := WrapRSAOAEP(validKeyMaterial, &privateKey.PublicKey, backend.WrappingAlgorithm("INVALID"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported wrapping algorithm")
	})

	t.Run("UnwrapRSAOAEP_NilWrappedKey", func(t *testing.T) {
		_, err := UnwrapRSAOAEP(nil, privateKey, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "wrapped key cannot be nil or empty")
	})

	t.Run("UnwrapRSAOAEP_EmptyWrappedKey", func(t *testing.T) {
		_, err := UnwrapRSAOAEP([]byte{}, privateKey, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "wrapped key cannot be nil or empty")
	})

	t.Run("UnwrapRSAOAEP_NilPrivateKey", func(t *testing.T) {
		wrapped, err := WrapRSAOAEP(validKeyMaterial, &privateKey.PublicKey, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		require.NoError(t, err)

		_, err = UnwrapRSAOAEP(wrapped, nil, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "private key cannot be nil")
	})

	t.Run("UnwrapRSAOAEP_InvalidAlgorithm", func(t *testing.T) {
		wrapped, err := WrapRSAOAEP(validKeyMaterial, &privateKey.PublicKey, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		require.NoError(t, err)

		_, err = UnwrapRSAOAEP(wrapped, privateKey, backend.WrappingAlgorithm("INVALID"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported wrapping algorithm")
	})

	t.Run("UnwrapRSAOAEP_CorruptedData", func(t *testing.T) {
		wrapped, err := WrapRSAOAEP(validKeyMaterial, &privateKey.PublicKey, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		require.NoError(t, err)

		// Corrupt the wrapped data
		wrapped[0] ^= 0xFF

		_, err = UnwrapRSAOAEP(wrapped, privateKey, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		assert.Error(t, err)
	})

	t.Run("WrapRSAAES_NilKeyMaterial", func(t *testing.T) {
		_, err := WrapRSAAES(nil, &privateKey.PublicKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key material cannot be nil or empty")
	})

	t.Run("WrapRSAAES_EmptyKeyMaterial", func(t *testing.T) {
		_, err := WrapRSAAES([]byte{}, &privateKey.PublicKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key material cannot be nil or empty")
	})

	t.Run("WrapRSAAES_NilPublicKey", func(t *testing.T) {
		_, err := WrapRSAAES(validKeyMaterial, nil, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "public key cannot be nil")
	})

	t.Run("WrapRSAAES_InvalidAlgorithm", func(t *testing.T) {
		_, err := WrapRSAAES(validKeyMaterial, &privateKey.PublicKey, backend.WrappingAlgorithm("INVALID"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported wrapping algorithm")
	})

	t.Run("UnwrapRSAAES_NilWrappedKey", func(t *testing.T) {
		_, err := UnwrapRSAAES(nil, privateKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "wrapped key is too short or nil")
	})

	t.Run("UnwrapRSAAES_TooShortWrappedKey", func(t *testing.T) {
		_, err := UnwrapRSAAES([]byte{1, 2, 3}, privateKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "wrapped key is too short or nil")
	})

	t.Run("UnwrapRSAAES_NilPrivateKey", func(t *testing.T) {
		wrapped, err := WrapRSAAES(validKeyMaterial, &privateKey.PublicKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
		require.NoError(t, err)

		_, err = UnwrapRSAAES(wrapped, nil, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "private key cannot be nil")
	})

	t.Run("UnwrapRSAAES_InvalidAlgorithm", func(t *testing.T) {
		wrapped, err := WrapRSAAES(validKeyMaterial, &privateKey.PublicKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
		require.NoError(t, err)

		_, err = UnwrapRSAAES(wrapped, privateKey, backend.WrappingAlgorithm("INVALID"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported wrapping algorithm")
	})

	t.Run("UnwrapRSAAES_CorruptedLength", func(t *testing.T) {
		wrapped, err := WrapRSAAES(validKeyMaterial, &privateKey.PublicKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
		require.NoError(t, err)

		// Corrupt the length prefix to indicate more data than exists
		wrapped[0] = 0xFF
		wrapped[1] = 0xFF
		wrapped[2] = 0xFF
		wrapped[3] = 0xFF

		_, err = UnwrapRSAAES(wrapped, privateKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "corrupted")
	})

	t.Run("UnwrapRSAAES_CorruptedAESKey", func(t *testing.T) {
		wrapped, err := WrapRSAAES(validKeyMaterial, &privateKey.PublicKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
		require.NoError(t, err)

		// Corrupt the wrapped AES key
		wrapped[10] ^= 0xFF

		_, err = UnwrapRSAAES(wrapped, privateKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
		assert.Error(t, err)
	})
}

// TestAESKWP_VariousSizes tests AES-KWP with various plaintext sizes
func TestAESKWP_VariousSizes(t *testing.T) {
	aesKey := make([]byte, 32)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	testCases := []struct {
		name string
		size int
	}{
		{"1 byte", 1},
		{"7 bytes", 7},
		{"8 bytes", 8},
		{"9 bytes", 9},
		{"15 bytes", 15},
		{"16 bytes", 16},
		{"32 bytes", 32},
		{"64 bytes", 64},
		{"100 bytes", 100},
		{"256 bytes", 256},
		{"1024 bytes", 1024},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			plaintext := make([]byte, tc.size)
			_, err := rand.Read(plaintext)
			require.NoError(t, err)

			wrapped, err := wrapKeyWithAESKWP(plaintext, aesKey)
			require.NoError(t, err)
			assert.NotNil(t, wrapped)
			assert.NotEqual(t, plaintext, wrapped)

			unwrapped, err := unwrapKeyWithAESKWP(wrapped, aesKey)
			require.NoError(t, err)
			assert.Equal(t, plaintext, unwrapped)
		})
	}
}

// TestAESKWP_InvalidInputs tests AES-KWP error handling
func TestAESKWP_InvalidInputs(t *testing.T) {
	validAESKey := make([]byte, 32)
	_, err := rand.Read(validAESKey)
	require.NoError(t, err)

	validPlaintext := []byte("test plaintext")

	t.Run("InvalidKeySize_15bytes", func(t *testing.T) {
		invalidKey := make([]byte, 15)
		_, err := wrapKeyWithAESKWP(validPlaintext, invalidKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "AES key must be")
	})

	t.Run("InvalidKeySize_20bytes", func(t *testing.T) {
		invalidKey := make([]byte, 20)
		_, err := wrapKeyWithAESKWP(validPlaintext, invalidKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "AES key must be")
	})

	t.Run("UnwrapInvalidCiphertextLength", func(t *testing.T) {
		shortCiphertext := make([]byte, 8) // Too short
		_, err := unwrapKeyWithAESKWP(shortCiphertext, validAESKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be at least 16 bytes")
	})

	t.Run("UnwrapInvalidCiphertextAlignment", func(t *testing.T) {
		badCiphertext := make([]byte, 17) // Not a multiple of 8
		_, err := unwrapKeyWithAESKWP(badCiphertext, validAESKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "multiple of 8")
	})

	t.Run("UnwrapCorruptedAIV", func(t *testing.T) {
		wrapped, err := wrapKeyWithAESKWP(validPlaintext, validAESKey)
		require.NoError(t, err)

		// Corrupt the AIV
		wrapped[0] ^= 0xFF

		_, err = unwrapKeyWithAESKWP(wrapped, validAESKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid AIV")
	})

	t.Run("UnwrapWrongKey", func(t *testing.T) {
		wrapped, err := wrapKeyWithAESKWP(validPlaintext, validAESKey)
		require.NoError(t, err)

		wrongKey := make([]byte, 32)
		_, err = rand.Read(wrongKey)
		require.NoError(t, err)

		_, err = unwrapKeyWithAESKWP(wrapped, wrongKey)
		assert.Error(t, err)
	})
}

// TestGetHashForAlgorithm tests the hash function retrieval
func TestGetHashForAlgorithm(t *testing.T) {
	testCases := []struct {
		algorithm    backend.WrappingAlgorithm
		expectedHash string
		expectError  bool
	}{
		{backend.WrappingAlgorithmRSAES_OAEP_SHA_1, "SHA-1", false},
		{backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "SHA-256", false},
		{backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1, "SHA-1", false},
		{backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256, "SHA-256", false},
		{backend.WrappingAlgorithm("INVALID"), "", true},
	}

	for _, tc := range testCases {
		t.Run(string(tc.algorithm), func(t *testing.T) {
			hash, err := GetHashForAlgorithm(tc.algorithm)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedHash, hash.String())
			}
		})
	}
}

// TestWrapUnwrapAlgorithmMismatch tests error handling when algorithms don't match
func TestWrapUnwrapAlgorithmMismatch(t *testing.T) {
	privateKey, err := generateTestKeyPair(2048)
	require.NoError(t, err)

	keyMaterial := []byte("test key material")

	t.Run("RSAOAEP_AlgorithmMismatch", func(t *testing.T) {
		// Wrap with SHA-1
		wrapped, err := WrapRSAOAEP(keyMaterial, &privateKey.PublicKey, backend.WrappingAlgorithmRSAES_OAEP_SHA_1)
		require.NoError(t, err)

		// Try to unwrap with SHA-256
		_, err = UnwrapRSAOAEP(wrapped, privateKey, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		assert.Error(t, err)
	})

	t.Run("RSAAES_AlgorithmMismatch", func(t *testing.T) {
		// Wrap with SHA-1
		wrapped, err := WrapRSAAES(keyMaterial, &privateKey.PublicKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1)
		require.NoError(t, err)

		// Try to unwrap with SHA-256
		_, err = UnwrapRSAAES(wrapped, privateKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
		assert.Error(t, err)
	})
}

// TestRSAOAEP_DifferentKeySizes tests RSA-OAEP with different RSA key sizes
func TestRSAOAEP_DifferentKeySizes(t *testing.T) {
	keySizes := []int{2048, 3072, 4096}

	for _, keySize := range keySizes {
		t.Run(fmt.Sprintf("KeySize_%d", keySize), func(t *testing.T) {
			privateKey, err := generateTestKeyPair(keySize)
			require.NoError(t, err)

			keyMaterial := []byte("test key material for various key sizes")

			wrapped, err := WrapRSAOAEP(keyMaterial, &privateKey.PublicKey, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
			require.NoError(t, err)

			unwrapped, err := UnwrapRSAOAEP(wrapped, privateKey, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
			require.NoError(t, err)
			assert.Equal(t, keyMaterial, unwrapped)
		})
	}
}

// TestRSAAES_DifferentKeySizes tests hybrid wrapping with different RSA key sizes
func TestRSAAES_DifferentKeySizes(t *testing.T) {
	keySizes := []int{2048, 3072, 4096}

	for _, keySize := range keySizes {
		t.Run(fmt.Sprintf("KeySize_%d", keySize), func(t *testing.T) {
			privateKey, err := generateTestKeyPair(keySize)
			require.NoError(t, err)

			// Use larger key material to demonstrate hybrid advantage
			keyMaterial := make([]byte, 1024)
			_, err = rand.Read(keyMaterial)
			require.NoError(t, err)

			wrapped, err := WrapRSAAES(keyMaterial, &privateKey.PublicKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
			require.NoError(t, err)

			unwrapped, err := UnwrapRSAAES(wrapped, privateKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
			require.NoError(t, err)
			assert.Equal(t, keyMaterial, unwrapped)
		})
	}
}

// TestConcurrentWrapping tests thread safety of wrapping operations
func TestConcurrentWrapping(t *testing.T) {
	privateKey, err := generateTestKeyPair(2048)
	require.NoError(t, err)

	const numGoroutines = 10
	const numIterations = 10

	t.Run("RSAOAEP", func(t *testing.T) {
		done := make(chan bool, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				for j := 0; j < numIterations; j++ {
					keyMaterial := []byte(fmt.Sprintf("test key %d-%d", id, j))

					wrapped, err := WrapRSAOAEP(keyMaterial, &privateKey.PublicKey, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
					assert.NoError(t, err)

					unwrapped, err := UnwrapRSAOAEP(wrapped, privateKey, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
					assert.NoError(t, err)
					assert.Equal(t, keyMaterial, unwrapped)
				}
				done <- true
			}(i)
		}

		for i := 0; i < numGoroutines; i++ {
			<-done
		}
	})

	t.Run("RSAAES", func(t *testing.T) {
		done := make(chan bool, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				for j := 0; j < numIterations; j++ {
					keyMaterial := []byte(fmt.Sprintf("test key %d-%d with more data for hybrid wrapping", id, j))

					wrapped, err := WrapRSAAES(keyMaterial, &privateKey.PublicKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
					assert.NoError(t, err)

					unwrapped, err := UnwrapRSAAES(wrapped, privateKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
					assert.NoError(t, err)
					assert.Equal(t, keyMaterial, unwrapped)
				}
				done <- true
			}(i)
		}

		for i := 0; i < numGoroutines; i++ {
			<-done
		}
	})
}

// ==============================================================================
// Benchmarks
// ==============================================================================

func BenchmarkWrapRSAOAEP(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	publicKey := &privateKey.PublicKey
	keyMaterial := make([]byte, 32) // AES-256 key
	rand.Read(keyMaterial)

	b.Run("SHA256", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := WrapRSAOAEP(keyMaterial, publicKey, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("SHA1", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := WrapRSAOAEP(keyMaterial, publicKey, backend.WrappingAlgorithmRSAES_OAEP_SHA_1)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkUnwrapRSAOAEP(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	publicKey := &privateKey.PublicKey
	keyMaterial := make([]byte, 32)
	rand.Read(keyMaterial)

	wrapped, err := WrapRSAOAEP(keyMaterial, publicKey, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := UnwrapRSAOAEP(wrapped, privateKey, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWrapRSAAES(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	publicKey := &privateKey.PublicKey

	b.Run("32B_KeyMaterial", func(b *testing.B) {
		keyMaterial := make([]byte, 32)
		rand.Read(keyMaterial)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := WrapRSAAES(keyMaterial, publicKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("1KB_KeyMaterial", func(b *testing.B) {
		keyMaterial := make([]byte, 1024)
		rand.Read(keyMaterial)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := WrapRSAAES(keyMaterial, publicKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("4KB_KeyMaterial", func(b *testing.B) {
		keyMaterial := make([]byte, 4096)
		rand.Read(keyMaterial)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := WrapRSAAES(keyMaterial, publicKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkUnwrapRSAAES(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	publicKey := &privateKey.PublicKey

	b.Run("32B_KeyMaterial", func(b *testing.B) {
		keyMaterial := make([]byte, 32)
		rand.Read(keyMaterial)
		wrapped, err := WrapRSAAES(keyMaterial, publicKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := UnwrapRSAAES(wrapped, privateKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("1KB_KeyMaterial", func(b *testing.B) {
		keyMaterial := make([]byte, 1024)
		rand.Read(keyMaterial)
		wrapped, err := WrapRSAAES(keyMaterial, publicKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := UnwrapRSAAES(wrapped, privateKey, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkAESKWP(b *testing.B) {
	kek := make([]byte, 32) // AES-256 KEK
	rand.Read(kek)

	b.Run("Wrap_32B", func(b *testing.B) {
		plaintext := make([]byte, 32)
		rand.Read(plaintext)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := wrapKeyWithAESKWP(plaintext, kek)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Unwrap_32B", func(b *testing.B) {
		plaintext := make([]byte, 32)
		rand.Read(plaintext)
		wrapped, err := wrapKeyWithAESKWP(plaintext, kek)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := unwrapKeyWithAESKWP(wrapped, kek)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Wrap_1KB", func(b *testing.B) {
		plaintext := make([]byte, 1024)
		rand.Read(plaintext)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := wrapKeyWithAESKWP(plaintext, kek)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Unwrap_1KB", func(b *testing.B) {
		plaintext := make([]byte, 1024)
		rand.Read(plaintext)
		wrapped, err := wrapKeyWithAESKWP(plaintext, kek)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := unwrapKeyWithAESKWP(wrapped, kek)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
