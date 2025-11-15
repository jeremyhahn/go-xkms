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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/crypto/wrapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWrapUnwrapRSAOAEPSHA1Integration tests RSA-OAEP with SHA-1
func TestWrapUnwrapRSAOAEPSHA1Integration(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate RSA key")

	// Original key material to wrap
	keyMaterial := []byte("This is a secret AES-256 key!!!!") // 32 bytes

	// Wrap the key material
	wrapped, err := wrapping.WrapRSAOAEP(keyMaterial, &privateKey.PublicKey,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_1)
	require.NoError(t, err, "Failed to wrap key material")
	require.NotEmpty(t, wrapped, "Wrapped key should not be empty")

	// Unwrap the key material
	unwrapped, err := wrapping.UnwrapRSAOAEP(wrapped, privateKey,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_1)
	require.NoError(t, err, "Failed to unwrap key material")

	// Verify the unwrapped material matches the original
	assert.Equal(t, keyMaterial, unwrapped, "Unwrapped key material should match original")
}

// TestWrapUnwrapRSAOAEPSHA256Integration tests RSA-OAEP with SHA-256
func TestWrapUnwrapRSAOAEPSHA256Integration(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate RSA key")

	// Original key material to wrap
	keyMaterial := make([]byte, 32)
	_, err = rand.Read(keyMaterial)
	require.NoError(t, err, "Failed to generate random key material")

	// Wrap the key material
	wrapped, err := wrapping.WrapRSAOAEP(keyMaterial, &privateKey.PublicKey,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err, "Failed to wrap key material")
	require.NotEmpty(t, wrapped, "Wrapped key should not be empty")

	// Unwrap the key material
	unwrapped, err := wrapping.UnwrapRSAOAEP(wrapped, privateKey,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err, "Failed to unwrap key material")

	// Verify the unwrapped material matches the original
	assert.Equal(t, keyMaterial, unwrapped, "Unwrapped key material should match original")
}

// TestWrapUnwrapRSAAESSHA1Integration tests hybrid RSA+AES wrapping with SHA-1
func TestWrapUnwrapRSAAESSHA1Integration(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate RSA key")

	// Large key material that requires hybrid wrapping
	keyMaterial := make([]byte, 256) // RSA 2048 can't directly wrap this much data
	_, err = rand.Read(keyMaterial)
	require.NoError(t, err, "Failed to generate random key material")

	// Wrap the key material using hybrid approach
	wrapped, err := wrapping.WrapRSAAES(keyMaterial, &privateKey.PublicKey,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1)
	require.NoError(t, err, "Failed to wrap key material")
	require.NotEmpty(t, wrapped, "Wrapped key should not be empty")

	// Verify wrapped data includes length prefix
	assert.Greater(t, len(wrapped), 256, "Wrapped data should include overhead")

	// Unwrap the key material
	unwrapped, err := wrapping.UnwrapRSAAES(wrapped, privateKey,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1)
	require.NoError(t, err, "Failed to unwrap key material")

	// Verify the unwrapped material matches the original
	assert.Equal(t, keyMaterial, unwrapped, "Unwrapped key material should match original")
}

// TestWrapUnwrapRSAAESSHA256Integration tests hybrid RSA+AES wrapping with SHA-256
func TestWrapUnwrapRSAAESSHA256Integration(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate RSA key")

	// Large key material
	keyMaterial := make([]byte, 512)
	_, err = rand.Read(keyMaterial)
	require.NoError(t, err, "Failed to generate random key material")

	// Wrap the key material using hybrid approach
	wrapped, err := wrapping.WrapRSAAES(keyMaterial, &privateKey.PublicKey,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	require.NoError(t, err, "Failed to wrap key material")
	require.NotEmpty(t, wrapped, "Wrapped key should not be empty")

	// Unwrap the key material
	unwrapped, err := wrapping.UnwrapRSAAES(wrapped, privateKey,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	require.NoError(t, err, "Failed to unwrap key material")

	// Verify the unwrapped material matches the original
	assert.Equal(t, keyMaterial, unwrapped, "Unwrapped key material should match original")
}

// TestWrapUnwrapVariousSizesIntegration tests wrapping different key sizes
func TestWrapUnwrapVariousSizesIntegration(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate RSA key")

	// Test various sizes
	sizes := []int{16, 24, 32, 64, 128, 256, 512, 1024, 2048}

	for _, size := range sizes {
		t.Run(string(rune(size))+" bytes", func(t *testing.T) {
			// Generate key material
			keyMaterial := make([]byte, size)
			_, err = rand.Read(keyMaterial)
			require.NoError(t, err, "Failed to generate key material")

			// Determine which algorithm to use based on size
			var wrapped []byte
			var unwrapped []byte

			if size <= 190 { // RSA 2048 OAEP SHA-256 can handle ~190 bytes
				// Use direct RSA-OAEP
				wrapped, err = wrapping.WrapRSAOAEP(keyMaterial, &privateKey.PublicKey,
					backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
				require.NoError(t, err, "Failed to wrap %d bytes", size)

				unwrapped, err = wrapping.UnwrapRSAOAEP(wrapped, privateKey,
					backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
				require.NoError(t, err, "Failed to unwrap %d bytes", size)
			} else {
				// Use hybrid RSA+AES
				wrapped, err = wrapping.WrapRSAAES(keyMaterial, &privateKey.PublicKey,
					backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
				require.NoError(t, err, "Failed to wrap %d bytes", size)

				unwrapped, err = wrapping.UnwrapRSAAES(wrapped, privateKey,
					backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
				require.NoError(t, err, "Failed to unwrap %d bytes", size)
			}

			assert.Equal(t, keyMaterial, unwrapped,
				"Unwrapped %d bytes should match original", size)
		})
	}
}

// TestWrapUnwrapErrorHandlingIntegration tests error handling
func TestWrapUnwrapErrorHandlingIntegration(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	t.Run("NilKeyMaterial", func(t *testing.T) {
		_, err := wrapping.WrapRSAOAEP(nil, &privateKey.PublicKey,
			backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		assert.Error(t, err, "Should error with nil key material")
	})

	t.Run("EmptyKeyMaterial", func(t *testing.T) {
		_, err := wrapping.WrapRSAOAEP([]byte{}, &privateKey.PublicKey,
			backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		assert.Error(t, err, "Should error with empty key material")
	})

	t.Run("NilPublicKey", func(t *testing.T) {
		_, err := wrapping.WrapRSAOAEP([]byte("test"), nil,
			backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		assert.Error(t, err, "Should error with nil public key")
	})

	t.Run("NilPrivateKey", func(t *testing.T) {
		wrapped := []byte("fake-wrapped-data")
		_, err := wrapping.UnwrapRSAOAEP(wrapped, nil,
			backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		assert.Error(t, err, "Should error with nil private key")
	})

	t.Run("InvalidWrappedData", func(t *testing.T) {
		wrapped := []byte("invalid-wrapped-data")
		_, err := wrapping.UnwrapRSAOAEP(wrapped, privateKey,
			backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		assert.Error(t, err, "Should error with invalid wrapped data")
	})

	t.Run("UnsupportedAlgorithm", func(t *testing.T) {
		_, err := wrapping.WrapRSAOAEP([]byte("test"), &privateKey.PublicKey,
			backend.WrappingAlgorithm("unsupported"))
		assert.Error(t, err, "Should error with unsupported algorithm")
	})

	t.Run("TooShortWrappedKey", func(t *testing.T) {
		wrapped := []byte{0, 0, 0} // Less than 4 bytes
		_, err := wrapping.UnwrapRSAAES(wrapped, privateKey,
			backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
		assert.Error(t, err, "Should error with too short wrapped key")
	})

	t.Run("CorruptedWrappedKey", func(t *testing.T) {
		// Create a wrapped key with invalid length prefix
		wrapped := make([]byte, 300)
		// Set length prefix to invalid value (larger than remaining data)
		wrapped[0] = 0xFF
		wrapped[1] = 0xFF
		wrapped[2] = 0xFF
		wrapped[3] = 0xFF

		_, err := wrapping.UnwrapRSAAES(wrapped, privateKey,
			backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
		assert.Error(t, err, "Should error with corrupted wrapped key")
	})
}

// TestWrapUnwrapDifferentRSAKeySizesIntegration tests with different RSA key sizes
func TestWrapUnwrapDifferentRSAKeySizesIntegration(t *testing.T) {
	keySizes := []int{2048, 3072, 4096}
	keyMaterial := []byte("Test key material for wrapping")

	for _, keySize := range keySizes {
		t.Run(string(rune(keySize))+" bit", func(t *testing.T) {
			// Generate RSA key pair
			privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
			require.NoError(t, err, "Failed to generate %d-bit RSA key", keySize)

			// Wrap and unwrap with SHA-256
			wrapped, err := wrapping.WrapRSAOAEP(keyMaterial, &privateKey.PublicKey,
				backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
			require.NoError(t, err, "Failed to wrap with %d-bit key", keySize)

			unwrapped, err := wrapping.UnwrapRSAOAEP(wrapped, privateKey,
				backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
			require.NoError(t, err, "Failed to unwrap with %d-bit key", keySize)

			assert.Equal(t, keyMaterial, unwrapped)
		})
	}
}

// TestWrapRSAAESFormatIntegration tests the RSA+AES wrapped format
func TestWrapRSAAESFormatIntegration(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyMaterial := make([]byte, 256)
	_, err = rand.Read(keyMaterial)
	require.NoError(t, err)

	wrapped, err := wrapping.WrapRSAAES(keyMaterial, &privateKey.PublicKey,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	require.NoError(t, err)

	// Verify format: [4-byte length][wrapped AES key][wrapped key material]
	assert.Greater(t, len(wrapped), 4, "Should have length prefix")

	// Extract length prefix
	wrappedAESKeyLen := uint32(wrapped[0])<<24 | uint32(wrapped[1])<<16 |
		uint32(wrapped[2])<<8 | uint32(wrapped[3])

	// Verify length makes sense (RSA 2048 wrapped data should be 256 bytes)
	assert.Equal(t, uint32(256), wrappedAESKeyLen, "Wrapped AES key should be 256 bytes for RSA 2048")

	// Verify total length makes sense
	assert.Greater(t, len(wrapped), int(4+wrappedAESKeyLen),
		"Should have wrapped key material after wrapped AES key")
}

// TestWrapUnwrapConcurrentIntegration tests concurrent wrapping/unwrapping
func TestWrapUnwrapConcurrentIntegration(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	numGoroutines := 50
	done := make(chan bool, numGoroutines)
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(iteration int) {
			// Generate unique key material
			keyMaterial := make([]byte, 32)
			_, err := rand.Read(keyMaterial)
			if err != nil {
				errors <- err
				done <- false
				return
			}

			// Wrap
			wrapped, err := wrapping.WrapRSAOAEP(keyMaterial, &privateKey.PublicKey,
				backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
			if err != nil {
				errors <- err
				done <- false
				return
			}

			// Unwrap
			unwrapped, err := wrapping.UnwrapRSAOAEP(wrapped, privateKey,
				backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
			if err != nil {
				errors <- err
				done <- false
				return
			}

			// Verify
			if !bytes.Equal(keyMaterial, unwrapped) {
				errors <- assert.AnError
				done <- false
				return
			}

			done <- true
		}(i)
	}

	// Wait for all goroutines
	successCount := 0
	for i := 0; i < numGoroutines; i++ {
		select {
		case success := <-done:
			if success {
				successCount++
			}
		case err := <-errors:
			t.Errorf("Concurrent operation failed: %v", err)
		}
	}

	assert.Equal(t, numGoroutines, successCount, "All concurrent operations should succeed")
}

// TestGetHashForAlgorithmIntegration tests hash retrieval helper
func TestGetHashForAlgorithmIntegration(t *testing.T) {
	testCases := []struct {
		algorithm    backend.WrappingAlgorithm
		expectedHash crypto.Hash
		shouldError  bool
	}{
		{backend.WrappingAlgorithmRSAES_OAEP_SHA_1, crypto.SHA1, false},
		{backend.WrappingAlgorithmRSAES_OAEP_SHA_256, crypto.SHA256, false},
		{backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1, crypto.SHA1, false},
		{backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256, crypto.SHA256, false},
		{backend.WrappingAlgorithm("unsupported"), crypto.Hash(0), true},
	}

	for _, tc := range testCases {
		t.Run(string(tc.algorithm), func(t *testing.T) {
			hash, err := wrapping.GetHashForAlgorithm(tc.algorithm)

			if tc.shouldError {
				assert.Error(t, err, "Should error for unsupported algorithm")
			} else {
				require.NoError(t, err, "Should not error for supported algorithm")
				assert.Equal(t, tc.expectedHash, hash, "Hash should match expected")
			}
		})
	}
}

// TestWrapUnwrapAlgorithmMismatchIntegration tests using different algorithms for wrap/unwrap
func TestWrapUnwrapAlgorithmMismatchIntegration(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyMaterial := []byte("Test key material for mismatch")

	// Wrap with SHA-1
	wrapped, err := wrapping.WrapRSAOAEP(keyMaterial, &privateKey.PublicKey,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_1)
	require.NoError(t, err)

	// Try to unwrap with SHA-256 (should fail)
	_, err = wrapping.UnwrapRSAOAEP(wrapped, privateKey,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	assert.Error(t, err, "Should error when unwrapping with different algorithm")
}

// TestWrapUnwrapRealWorldScenarioIntegration simulates real-world key wrapping
func TestWrapUnwrapRealWorldScenarioIntegration(t *testing.T) {
	// Simulate a KEK (Key Encryption Key) scenario

	// Generate KEK (master wrapping key)
	kek, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate KEK")

	// Simulate multiple DEKs (Data Encryption Keys) to wrap
	numKeys := 10
	deks := make([][]byte, numKeys)
	wrapped := make([][]byte, numKeys)

	// Generate and wrap multiple DEKs
	for i := 0; i < numKeys; i++ {
		// Generate DEK (AES-256 key)
		dek := make([]byte, 32)
		_, err := rand.Read(dek)
		require.NoError(t, err, "Failed to generate DEK %d", i)
		deks[i] = dek

		// Wrap DEK with KEK
		wrappedDEK, err := wrapping.WrapRSAOAEP(dek, &kek.PublicKey,
			backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		require.NoError(t, err, "Failed to wrap DEK %d", i)
		wrapped[i] = wrappedDEK
	}

	// Simulate storage and retrieval
	// Later, unwrap and verify all DEKs
	for i := 0; i < numKeys; i++ {
		unwrapped, err := wrapping.UnwrapRSAOAEP(wrapped[i], kek,
			backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		require.NoError(t, err, "Failed to unwrap DEK %d", i)
		assert.Equal(t, deks[i], unwrapped, "DEK %d should match after unwrapping", i)
	}

	// Verify all wrapped DEKs are different
	for i := 0; i < numKeys; i++ {
		for j := i + 1; j < numKeys; j++ {
			assert.NotEqual(t, wrapped[i], wrapped[j],
				"Wrapped DEK %d and %d should be different (due to random padding)", i, j)
		}
	}
}

// TestWrapUnwrapKeyRotationIntegration simulates key rotation scenario
func TestWrapUnwrapKeyRotationIntegration(t *testing.T) {
	// Original KEK
	oldKEK, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// New KEK for rotation
	newKEK, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// DEK to rotate
	dek := make([]byte, 32)
	_, err = rand.Read(dek)
	require.NoError(t, err)

	// Wrap with old KEK
	wrappedOld, err := wrapping.WrapRSAOAEP(dek, &oldKEK.PublicKey,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	// Unwrap with old KEK
	unwrapped, err := wrapping.UnwrapRSAOAEP(wrappedOld, oldKEK,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)
	assert.Equal(t, dek, unwrapped)

	// Re-wrap with new KEK (key rotation)
	wrappedNew, err := wrapping.WrapRSAOAEP(dek, &newKEK.PublicKey,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	// Verify new wrapped version can be unwrapped
	unwrapped2, err := wrapping.UnwrapRSAOAEP(wrappedNew, newKEK,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)
	assert.Equal(t, dek, unwrapped2)

	// Old wrapped version should still work with old KEK
	unwrapped3, err := wrapping.UnwrapRSAOAEP(wrappedOld, oldKEK,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)
	assert.Equal(t, dek, unwrapped3)
}

// TestWrapUnwrapLargePayloadIntegration tests wrapping large data with hybrid method
func TestWrapUnwrapLargePayloadIntegration(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Test progressively larger payloads
	sizes := []int{1024, 4096, 16384, 65536} // 1KB to 64KB

	for _, size := range sizes {
		t.Run(string(rune(size))+" bytes", func(t *testing.T) {
			payload := make([]byte, size)
			_, err := rand.Read(payload)
			require.NoError(t, err)

			// Wrap with hybrid method
			wrapped, err := wrapping.WrapRSAAES(payload, &privateKey.PublicKey,
				backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
			require.NoError(t, err, "Failed to wrap %d bytes", size)

			// Unwrap
			unwrapped, err := wrapping.UnwrapRSAAES(wrapped, privateKey,
				backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
			require.NoError(t, err, "Failed to unwrap %d bytes", size)

			assert.Equal(t, payload, unwrapped, "Payload should match after unwrapping")
		})
	}
}

// TestWrapUnwrapNonMultipleOf8Integration tests AES-KWP with non-8-byte-aligned data
func TestWrapUnwrapNonMultipleOf8Integration(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Test various sizes that are not multiples of 8
	sizes := []int{1, 3, 7, 15, 31, 33, 100, 255}

	for _, size := range sizes {
		t.Run(string(rune(size))+" bytes", func(t *testing.T) {
			payload := make([]byte, size)
			_, err := rand.Read(payload)
			require.NoError(t, err)

			// Wrap with hybrid method (uses AES-KWP which handles any length)
			wrapped, err := wrapping.WrapRSAAES(payload, &privateKey.PublicKey,
				backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
			require.NoError(t, err, "Failed to wrap %d bytes", size)

			// Unwrap
			unwrapped, err := wrapping.UnwrapRSAAES(wrapped, privateKey,
				backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
			require.NoError(t, err, "Failed to unwrap %d bytes", size)

			assert.Equal(t, payload, unwrapped,
				"Payload of %d bytes should match after unwrapping", size)
		})
	}
}

// TestWrapUnwrapWrongKeyIntegration tests unwrapping with wrong private key
func TestWrapUnwrapWrongKeyIntegration(t *testing.T) {
	// Generate two different RSA key pairs
	privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyMaterial := []byte("Secret key material")

	// Wrap with first public key
	wrapped, err := wrapping.WrapRSAOAEP(keyMaterial, &privateKey1.PublicKey,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	// Try to unwrap with second private key (should fail)
	_, err = wrapping.UnwrapRSAOAEP(wrapped, privateKey2,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	assert.Error(t, err, "Should error when unwrapping with wrong private key")
}
