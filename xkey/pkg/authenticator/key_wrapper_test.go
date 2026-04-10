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

package authenticator

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

// generateRandomKey generates a random key of the specified size.
func generateRandomKey(t *testing.T, size int) []byte {
	t.Helper()
	key := make([]byte, size)
	_, err := rand.Read(key)
	require.NoError(t, err, "failed to generate random key")
	return key
}

func TestNewAESGCMKeyWrapper(t *testing.T) {
	t.Run("valid 32-byte key creates wrapper successfully", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)

		wrapper, err := NewAESGCMKeyWrapper(key)

		require.NoError(t, err)
		require.NotNil(t, wrapper)
		require.NotNil(t, wrapper.aead)
	})

	t.Run("nil key returns ErrInvalidWrappingKey", func(t *testing.T) {
		wrapper, err := NewAESGCMKeyWrapper(nil)

		require.ErrorIs(t, err, ErrInvalidWrappingKey)
		require.Nil(t, wrapper)
	})

	t.Run("zero-length key returns ErrInvalidWrappingKey", func(t *testing.T) {
		key := make([]byte, 0)

		wrapper, err := NewAESGCMKeyWrapper(key)

		require.ErrorIs(t, err, ErrInvalidWrappingKey)
		require.Nil(t, wrapper)
	})

	t.Run("16-byte key returns ErrInvalidWrappingKey", func(t *testing.T) {
		key := generateRandomKey(t, 16)

		wrapper, err := NewAESGCMKeyWrapper(key)

		require.ErrorIs(t, err, ErrInvalidWrappingKey)
		require.Nil(t, wrapper)
	})

	t.Run("31-byte key returns ErrInvalidWrappingKey", func(t *testing.T) {
		key := generateRandomKey(t, 31)

		wrapper, err := NewAESGCMKeyWrapper(key)

		require.ErrorIs(t, err, ErrInvalidWrappingKey)
		require.Nil(t, wrapper)
	})

	t.Run("33-byte key returns ErrInvalidWrappingKey", func(t *testing.T) {
		key := generateRandomKey(t, 33)

		wrapper, err := NewAESGCMKeyWrapper(key)

		require.ErrorIs(t, err, ErrInvalidWrappingKey)
		require.Nil(t, wrapper)
	})

	t.Run("64-byte key returns ErrInvalidWrappingKey", func(t *testing.T) {
		key := generateRandomKey(t, 64)

		wrapper, err := NewAESGCMKeyWrapper(key)

		require.ErrorIs(t, err, ErrInvalidWrappingKey)
		require.Nil(t, wrapper)
	})
}

func TestAESGCMKeyWrapper_WrapUnwrap(t *testing.T) {
	t.Run("round-trip wrap then unwrap returns original data", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		plaintext := []byte("this is test data for wrap/unwrap round-trip")

		wrapped, err := wrapper.Wrap(plaintext)
		require.NoError(t, err)
		require.NotNil(t, wrapped)
		require.NotEqual(t, plaintext, wrapped)

		unwrapped, err := wrapper.Unwrap(wrapped)
		require.NoError(t, err)
		require.Equal(t, plaintext, unwrapped)
	})

	t.Run("empty plaintext wraps and unwraps correctly", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		plaintext := []byte{}

		wrapped, err := wrapper.Wrap(plaintext)
		require.NoError(t, err)
		require.NotNil(t, wrapped)
		// Minimum size is nonce (12) + tag (16) = 28 bytes
		require.Len(t, wrapped, AESGCMNonceSize+aesGCMTagSize)

		unwrapped, err := wrapper.Unwrap(wrapped)
		require.NoError(t, err)
		require.Empty(t, unwrapped)
	})

	t.Run("small plaintext 1 byte wraps and unwraps correctly", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		plaintext := []byte{0x42}

		wrapped, err := wrapper.Wrap(plaintext)
		require.NoError(t, err)
		require.NotNil(t, wrapped)
		// Size should be nonce (12) + ciphertext (1) + tag (16) = 29 bytes
		require.Len(t, wrapped, AESGCMNonceSize+1+aesGCMTagSize)

		unwrapped, err := wrapper.Unwrap(wrapped)
		require.NoError(t, err)
		require.Equal(t, plaintext, unwrapped)
	})

	t.Run("large plaintext 1MB wraps and unwraps correctly", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		// Generate 1MB of random data
		plaintext := make([]byte, 1024*1024)
		_, err = rand.Read(plaintext)
		require.NoError(t, err)

		wrapped, err := wrapper.Wrap(plaintext)
		require.NoError(t, err)
		require.NotNil(t, wrapped)
		// Size should be nonce (12) + ciphertext (1MB) + tag (16)
		expectedLen := AESGCMNonceSize + len(plaintext) + aesGCMTagSize
		require.Len(t, wrapped, expectedLen)

		unwrapped, err := wrapper.Unwrap(wrapped)
		require.NoError(t, err)
		require.Equal(t, plaintext, unwrapped)
	})

	t.Run("multiple wraps of same plaintext produce different ciphertexts", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		plaintext := []byte("same data wrapped multiple times")

		wrapped1, err := wrapper.Wrap(plaintext)
		require.NoError(t, err)

		wrapped2, err := wrapper.Wrap(plaintext)
		require.NoError(t, err)

		wrapped3, err := wrapper.Wrap(plaintext)
		require.NoError(t, err)

		// Due to random nonces, all wrapped outputs should be different
		require.False(t, bytes.Equal(wrapped1, wrapped2), "first and second wrap should differ")
		require.False(t, bytes.Equal(wrapped2, wrapped3), "second and third wrap should differ")
		require.False(t, bytes.Equal(wrapped1, wrapped3), "first and third wrap should differ")

		// But all should unwrap to the same plaintext
		unwrapped1, err := wrapper.Unwrap(wrapped1)
		require.NoError(t, err)
		require.Equal(t, plaintext, unwrapped1)

		unwrapped2, err := wrapper.Unwrap(wrapped2)
		require.NoError(t, err)
		require.Equal(t, plaintext, unwrapped2)

		unwrapped3, err := wrapper.Unwrap(wrapped3)
		require.NoError(t, err)
		require.Equal(t, plaintext, unwrapped3)
	})
}

func TestAESGCMKeyWrapper_Wrap(t *testing.T) {
	t.Run("nil plaintext returns ErrKeyWrapFailed", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		wrapped, err := wrapper.Wrap(nil)

		require.ErrorIs(t, err, ErrKeyWrapFailed)
		require.Nil(t, wrapped)
	})

	t.Run("output is at least nonce plus tag size for empty input", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		plaintext := []byte{}

		wrapped, err := wrapper.Wrap(plaintext)

		require.NoError(t, err)
		require.NotNil(t, wrapped)
		// Minimum size: nonce (12 bytes) + tag (16 bytes) = 28 bytes
		minSize := AESGCMNonceSize + aesGCMTagSize
		require.GreaterOrEqual(t, len(wrapped), minSize)
		require.Equal(t, minSize, len(wrapped), "empty input should produce exactly nonce + tag")
	})
}

func TestAESGCMKeyWrapper_Unwrap(t *testing.T) {
	t.Run("too short input less than 28 bytes returns ErrInvalidWrappedData", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		minSize := AESGCMNonceSize + aesGCMTagSize // 28 bytes

		// Test various sizes below minimum
		testSizes := []int{0, 1, 10, 27}
		for _, size := range testSizes {
			shortData := make([]byte, size)
			if size > 0 {
				_, err = rand.Read(shortData)
				require.NoError(t, err)
			}

			unwrapped, err := wrapper.Unwrap(shortData)

			require.ErrorIs(t, err, ErrInvalidWrappedData, "size %d should return ErrInvalidWrappedData", size)
			require.Nil(t, unwrapped)
		}

		// Exactly 28 bytes is valid (empty plaintext) but will fail auth if random
		exactMin := make([]byte, minSize)
		_, err = rand.Read(exactMin)
		require.NoError(t, err)

		unwrapped, err := wrapper.Unwrap(exactMin)
		// Random data at minimum size will fail authentication, not size check
		require.ErrorIs(t, err, ErrKeyUnwrapFailed)
		require.Nil(t, unwrapped)
	})

	t.Run("tampered ciphertext returns ErrKeyUnwrapFailed", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		plaintext := []byte("sensitive data to be wrapped")

		wrapped, err := wrapper.Wrap(plaintext)
		require.NoError(t, err)

		// Tamper with the ciphertext portion (after nonce, before tag)
		tamperedIndex := AESGCMNonceSize + 5 // Modify byte in ciphertext
		wrapped[tamperedIndex] ^= 0xFF       // Flip all bits

		unwrapped, err := wrapper.Unwrap(wrapped)

		require.ErrorIs(t, err, ErrKeyUnwrapFailed)
		require.Nil(t, unwrapped)
	})

	t.Run("wrong key returns ErrKeyUnwrapFailed", func(t *testing.T) {
		key1 := generateRandomKey(t, AESGCMKeySize)
		key2 := generateRandomKey(t, AESGCMKeySize)

		wrapper1, err := NewAESGCMKeyWrapper(key1)
		require.NoError(t, err)

		wrapper2, err := NewAESGCMKeyWrapper(key2)
		require.NoError(t, err)

		plaintext := []byte("data wrapped with key1")

		wrapped, err := wrapper1.Wrap(plaintext)
		require.NoError(t, err)

		// Try to unwrap with different key
		unwrapped, err := wrapper2.Unwrap(wrapped)

		require.ErrorIs(t, err, ErrKeyUnwrapFailed)
		require.Nil(t, unwrapped)
	})

	t.Run("valid wrapped data from another wrapper with same key unwraps correctly", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)

		wrapper1, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		wrapper2, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		plaintext := []byte("data that should be portable between wrappers")

		wrapped, err := wrapper1.Wrap(plaintext)
		require.NoError(t, err)

		// Unwrap with different wrapper instance using same key
		unwrapped, err := wrapper2.Unwrap(wrapped)

		require.NoError(t, err)
		require.Equal(t, plaintext, unwrapped)
	})
}

func TestAESGCMKeyWrapper_TamperDetection(t *testing.T) {
	t.Run("modifying any byte in wrapped data causes unwrap failure", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		plaintext := []byte("data for tamper detection test")

		originalWrapped, err := wrapper.Wrap(plaintext)
		require.NoError(t, err)

		// Test tampering with each byte position
		for i := 0; i < len(originalWrapped); i++ {
			// Create a copy of the wrapped data
			tampered := make([]byte, len(originalWrapped))
			copy(tampered, originalWrapped)

			// Modify single byte
			tampered[i] ^= 0x01

			unwrapped, err := wrapper.Unwrap(tampered)

			require.Error(t, err, "tampering byte at position %d should cause failure", i)
			require.ErrorIs(t, err, ErrKeyUnwrapFailed, "tampering byte at position %d should return ErrKeyUnwrapFailed", i)
			require.Nil(t, unwrapped, "unwrapped should be nil when tampered at position %d", i)
		}

		// Verify original still works
		unwrapped, err := wrapper.Unwrap(originalWrapped)
		require.NoError(t, err)
		require.Equal(t, plaintext, unwrapped)
	})

	t.Run("truncating wrapped data causes unwrap failure", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		plaintext := []byte("data to test truncation detection")

		wrapped, err := wrapper.Wrap(plaintext)
		require.NoError(t, err)

		minSize := AESGCMNonceSize + aesGCMTagSize

		// Test various truncation points
		truncationPoints := []int{
			len(wrapped) - 1,    // Remove last byte
			len(wrapped) - 8,    // Remove several bytes
			len(wrapped) - 16,   // Remove full tag
			minSize,             // Minimum valid size (but wrong data)
			minSize - 1,         // Just below minimum
			AESGCMNonceSize,     // Only nonce remains
			AESGCMNonceSize / 2, // Partial nonce
			1,                   // Single byte
		}

		for _, truncateAt := range truncationPoints {
			if truncateAt <= 0 || truncateAt >= len(wrapped) {
				continue
			}

			truncated := wrapped[:truncateAt]

			unwrapped, err := wrapper.Unwrap(truncated)

			if truncateAt < minSize {
				require.ErrorIs(t, err, ErrInvalidWrappedData,
					"truncation to %d bytes should return ErrInvalidWrappedData", truncateAt)
			} else {
				require.ErrorIs(t, err, ErrKeyUnwrapFailed,
					"truncation to %d bytes should return ErrKeyUnwrapFailed", truncateAt)
			}
			require.Nil(t, unwrapped, "unwrapped should be nil when truncated to %d bytes", truncateAt)
		}
	})

	t.Run("appending data to wrapped data causes unwrap failure", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		plaintext := []byte("data to test append detection")

		wrapped, err := wrapper.Wrap(plaintext)
		require.NoError(t, err)

		// Append extra bytes
		extended := make([]byte, len(wrapped)+10)
		copy(extended, wrapped)
		_, err = rand.Read(extended[len(wrapped):])
		require.NoError(t, err)

		unwrapped, err := wrapper.Unwrap(extended)

		require.ErrorIs(t, err, ErrKeyUnwrapFailed)
		require.Nil(t, unwrapped)
	})

	t.Run("swapping nonce and ciphertext portions causes failure", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		plaintext := []byte("data for swap detection test")

		wrapped, err := wrapper.Wrap(plaintext)
		require.NoError(t, err)

		// Create corrupted data by swapping nonce with part of ciphertext
		corrupted := make([]byte, len(wrapped))
		// Put ciphertext at beginning
		copy(corrupted, wrapped[AESGCMNonceSize:AESGCMNonceSize*2])
		// Put nonce where ciphertext was
		copy(corrupted[AESGCMNonceSize:], wrapped[:AESGCMNonceSize])
		// Copy rest of original
		copy(corrupted[AESGCMNonceSize*2:], wrapped[AESGCMNonceSize*2:])

		unwrapped, err := wrapper.Unwrap(corrupted)

		require.ErrorIs(t, err, ErrKeyUnwrapFailed)
		require.Nil(t, unwrapped)
	})
}

func TestAESGCMKeyWrapper_Interface(t *testing.T) {
	t.Run("AESGCMKeyWrapper implements KeyWrapper interface", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		// Verify interface compliance at compile time
		var _ KeyWrapper = wrapper

		// Verify interface methods work correctly
		var kw KeyWrapper = wrapper

		plaintext := []byte("interface test data")

		wrapped, err := kw.Wrap(plaintext)
		require.NoError(t, err)

		unwrapped, err := kw.Unwrap(wrapped)
		require.NoError(t, err)
		require.Equal(t, plaintext, unwrapped)
	})
}

func TestAESGCMKeyWrapper_Constants(t *testing.T) {
	t.Run("constants have expected values", func(t *testing.T) {
		require.Equal(t, 12, AESGCMNonceSize, "AES-GCM nonce should be 12 bytes")
		require.Equal(t, 32, AESGCMKeySize, "AES-256-GCM key should be 32 bytes")
		require.Equal(t, 16, aesGCMTagSize, "AES-GCM tag should be 16 bytes")
	})

	t.Run("wrapped output size is predictable", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		testCases := []struct {
			name          string
			plaintextSize int
		}{
			{"empty", 0},
			{"one byte", 1},
			{"small", 32},
			{"medium", 256},
			{"large", 4096},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				plaintext := make([]byte, tc.plaintextSize)
				if tc.plaintextSize > 0 {
					_, err := rand.Read(plaintext)
					require.NoError(t, err)
				}

				wrapped, err := wrapper.Wrap(plaintext)
				require.NoError(t, err)

				expectedSize := AESGCMNonceSize + tc.plaintextSize + aesGCMTagSize
				require.Len(t, wrapped, expectedSize,
					"wrapped size should be nonce(%d) + plaintext(%d) + tag(%d) = %d",
					AESGCMNonceSize, tc.plaintextSize, aesGCMTagSize, expectedSize)
			})
		}
	})
}

func TestAESGCMKeyWrapper_ConcurrentAccess(t *testing.T) {
	t.Run("wrapper is safe for concurrent use", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		const numGoroutines = 100
		const opsPerGoroutine = 50

		errChan := make(chan error, numGoroutines*opsPerGoroutine)
		doneChan := make(chan struct{})

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				for j := 0; j < opsPerGoroutine; j++ {
					plaintext := make([]byte, 64)
					_, err := rand.Read(plaintext)
					if err != nil {
						errChan <- err
						continue
					}

					wrapped, err := wrapper.Wrap(plaintext)
					if err != nil {
						errChan <- err
						continue
					}

					unwrapped, err := wrapper.Unwrap(wrapped)
					if err != nil {
						errChan <- err
						continue
					}

					if !bytes.Equal(plaintext, unwrapped) {
						errChan <- bytes.ErrTooLarge // Use as sentinel for mismatch
						continue
					}
				}
				doneChan <- struct{}{}
			}(i)
		}

		// Wait for all goroutines to complete
		for i := 0; i < numGoroutines; i++ {
			<-doneChan
		}

		close(errChan)

		// Check for any errors
		var errors []error
		for err := range errChan {
			errors = append(errors, err)
		}

		require.Empty(t, errors, "concurrent operations should not produce errors")
	})
}
