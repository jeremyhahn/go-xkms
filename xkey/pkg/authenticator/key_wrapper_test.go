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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// generateRandomKey generates a random key of the specified size.
func generateRandomKey(t *testing.T, size int) []byte {
	t.Helper()
	key := make([]byte, size)
	_, err := rand.Read(key)
	require.NoError(t, err, "failed to generate random key")
	return key
}

// protectedBytes copies b into a protected buffer the test owns, leaving b
// intact so the test can keep comparing against it. The buffer is destroyed
// at cleanup.
func protectedBytes(t *testing.T, b []byte) *secure.Buffer {
	t.Helper()
	buf, err := secure.NewBuffer(len(b))
	require.NoError(t, err)
	t.Cleanup(buf.Destroy)
	copy(buf.Bytes(), b)
	return buf
}

// wrapForTest stages heap plaintext into protected memory and wraps it
// through WrapFrom — the heap-accepting wrap the production interface
// deliberately no longer expresses (go-xkms#387). Tests own the plaintext and
// may keep comparing against it; production code must never grow an
// equivalent. An empty plaintext cannot be staged (secure.NewBuffer refuses a
// zero size) and surfaces as that allocation error.
func wrapForTest(w KeyWrapper, plaintext []byte) ([]byte, error) {
	src, err := secure.NewBuffer(len(plaintext))
	if err != nil {
		return nil, err
	}
	defer src.Destroy()
	copy(src.Bytes(), plaintext)
	return w.WrapFrom(src)
}

// sealForTest produces AES-256-GCM wrapped data in the wrapper's wire format
// (nonce || ciphertext || tag) directly through crypto/cipher, independent of
// the KeyWrapper implementation. It pins the format UnwrapInto must accept,
// and it is the only way a test can build a zero-length payload, which
// WrapFrom cannot express.
//
// It uses cipher.NewGCMWithRandomNonce, exactly as the production
// implementation does (go-xkms#23): a plain cipher.NewGCM here would itself
// be refused under GODEBUG=fips140=only ("use of GCM with arbitrary IVs is
// not allowed"), and the output framing is identical either way, so this
// stays an independent construction of the same wire format, not a
// duplicate of AESGCMKeyWrapper.WrapFrom.
func sealForTest(t *testing.T, key, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	aead, err := cipher.NewGCMWithRandomNonce(block)
	require.NoError(t, err)
	return aead.Seal(nil, nil, plaintext, nil)
}

// openForTest decrypts wrapped data in the wire format directly through
// crypto/cipher, so a test can prove WrapFrom's output is what an independent
// AES-256-GCM implementation expects rather than only what UnwrapInto accepts.
func openForTest(t *testing.T, key, wrapped []byte) ([]byte, error) {
	t.Helper()
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	aead, err := cipher.NewGCMWithRandomNonce(block)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(wrapped), AESGCMNonceSize+aesGCMTagSize)
	return aead.Open(nil, nil, wrapped, nil)
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

		wrapped, err := wrapForTest(wrapper, plaintext)
		require.NoError(t, err)
		require.NotNil(t, wrapped)
		require.NotEqual(t, plaintext, wrapped)

		unwrapped, err := unwrapForTest(wrapper, wrapped)
		require.NoError(t, err)
		require.Equal(t, plaintext, unwrapped)
	})

	t.Run("empty payload in the wire format unwraps to empty", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		// WrapFrom cannot express an empty plaintext (a protected buffer has
		// a size), so the payload is sealed independently in the wire format.
		wrapped := sealForTest(t, key, []byte{})
		require.NotNil(t, wrapped)
		// Minimum size is nonce (12) + tag (16) = 28 bytes
		require.Len(t, wrapped, AESGCMNonceSize+aesGCMTagSize)

		unwrapped, err := unwrapForTest(wrapper, wrapped)
		require.NoError(t, err)
		require.Empty(t, unwrapped)
	})

	t.Run("small plaintext 1 byte wraps and unwraps correctly", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		plaintext := []byte{0x42}

		wrapped, err := wrapForTest(wrapper, plaintext)
		require.NoError(t, err)
		require.NotNil(t, wrapped)
		// Size should be nonce (12) + ciphertext (1) + tag (16) = 29 bytes
		require.Len(t, wrapped, AESGCMNonceSize+1+aesGCMTagSize)

		unwrapped, err := unwrapForTest(wrapper, wrapped)
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

		wrapped, err := wrapForTest(wrapper, plaintext)
		require.NoError(t, err)
		require.NotNil(t, wrapped)
		// Size should be nonce (12) + ciphertext (1MB) + tag (16)
		expectedLen := AESGCMNonceSize + len(plaintext) + aesGCMTagSize
		require.Len(t, wrapped, expectedLen)

		unwrapped, err := unwrapForTest(wrapper, wrapped)
		require.NoError(t, err)
		require.Equal(t, plaintext, unwrapped)
	})

	t.Run("multiple wraps of same plaintext produce different ciphertexts", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		plaintext := []byte("same data wrapped multiple times")

		wrapped1, err := wrapForTest(wrapper, plaintext)
		require.NoError(t, err)

		wrapped2, err := wrapForTest(wrapper, plaintext)
		require.NoError(t, err)

		wrapped3, err := wrapForTest(wrapper, plaintext)
		require.NoError(t, err)

		// Due to random nonces, all wrapped outputs should be different
		require.False(t, bytes.Equal(wrapped1, wrapped2), "first and second wrap should differ")
		require.False(t, bytes.Equal(wrapped2, wrapped3), "second and third wrap should differ")
		require.False(t, bytes.Equal(wrapped1, wrapped3), "first and third wrap should differ")

		// But all should unwrap to the same plaintext
		unwrapped1, err := unwrapForTest(wrapper, wrapped1)
		require.NoError(t, err)
		require.Equal(t, plaintext, unwrapped1)

		unwrapped2, err := unwrapForTest(wrapper, wrapped2)
		require.NoError(t, err)
		require.Equal(t, plaintext, unwrapped2)

		unwrapped3, err := unwrapForTest(wrapper, wrapped3)
		require.NoError(t, err)
		require.Equal(t, plaintext, unwrapped3)
	})
}

func TestAESGCMKeyWrapper_WrapFrom(t *testing.T) {
	t.Run("reads plaintext from protected memory and round-trips through UnwrapInto", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		plaintext := []byte("plaintext that lives only in protected memory")
		src := protectedBytes(t, plaintext)

		wrapped, err := wrapper.WrapFrom(src)
		require.NoError(t, err)
		require.Len(t, wrapped, AESGCMNonceSize+len(plaintext)+aesGCMTagSize)

		dst := make([]byte, len(plaintext))
		require.NoError(t, wrapper.UnwrapInto(wrapped, dst))
		require.Equal(t, plaintext, dst)
	})

	t.Run("output is the wire format an independent AES-256-GCM opens", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		plaintext := generateRandomKey(t, 48)
		wrapped, err := wrapper.WrapFrom(protectedBytes(t, plaintext))
		require.NoError(t, err)

		opened, err := openForTest(t, key, wrapped)
		require.NoError(t, err)
		require.Equal(t, plaintext, opened)
	})

	t.Run("source is left intact: the caller keeps ownership", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		plaintext := generateRandomKey(t, 32)
		src := protectedBytes(t, plaintext)

		_, err = wrapper.WrapFrom(src)
		require.NoError(t, err)

		require.NoError(t, src.WithBytes(func(b []byte) error {
			require.Equal(t, plaintext, b)
			return nil
		}))
	})

	t.Run("nil source returns ErrInvalidWrapSource", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		wrapped, err := wrapper.WrapFrom(nil)

		require.ErrorIs(t, err, ErrInvalidWrapSource)
		require.Nil(t, wrapped)
	})

	t.Run("destroyed source returns ErrInvalidWrapSource with the cause", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		src, err := secure.NewBuffer(32)
		require.NoError(t, err)
		src.Destroy()

		wrapped, err := wrapper.WrapFrom(src)

		require.ErrorIs(t, err, ErrInvalidWrapSource)
		var nilErr *secure.NilBufferError
		require.ErrorAs(t, err, &nilErr)
		require.Nil(t, wrapped)
	})

	t.Run("an empty plaintext cannot be staged, so no empty payload is expressible", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		wrapped, err := wrapForTest(wrapper, []byte{})

		var sizeErr *secure.InvalidSizeError
		require.ErrorAs(t, err, &sizeErr)
		require.Nil(t, wrapped)
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

			unwrapped, err := unwrapForTest(wrapper, shortData)

			require.ErrorIs(t, err, ErrInvalidWrappedData, "size %d should return ErrInvalidWrappedData", size)
			require.Nil(t, unwrapped)
		}

		// Exactly 28 bytes is valid (empty plaintext) but will fail auth if random
		exactMin := make([]byte, minSize)
		_, err = rand.Read(exactMin)
		require.NoError(t, err)

		unwrapped, err := unwrapForTest(wrapper, exactMin)
		// Random data at minimum size will fail authentication, not size check
		require.ErrorIs(t, err, ErrKeyUnwrapFailed)
		require.Nil(t, unwrapped)
	})

	t.Run("tampered ciphertext returns ErrKeyUnwrapFailed", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		plaintext := []byte("sensitive data to be wrapped")

		wrapped, err := wrapForTest(wrapper, plaintext)
		require.NoError(t, err)

		// Tamper with the ciphertext portion (after nonce, before tag)
		tamperedIndex := AESGCMNonceSize + 5 // Modify byte in ciphertext
		wrapped[tamperedIndex] ^= 0xFF       // Flip all bits

		unwrapped, err := unwrapForTest(wrapper, wrapped)

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

		wrapped, err := wrapForTest(wrapper1, plaintext)
		require.NoError(t, err)

		// Try to unwrap with different key
		unwrapped, err := unwrapForTest(wrapper2, wrapped)

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

		wrapped, err := wrapForTest(wrapper1, plaintext)
		require.NoError(t, err)

		// Unwrap with different wrapper instance using same key
		unwrapped, err := unwrapForTest(wrapper2, wrapped)

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

		originalWrapped, err := wrapForTest(wrapper, plaintext)
		require.NoError(t, err)

		// Test tampering with each byte position
		for i := 0; i < len(originalWrapped); i++ {
			// Create a copy of the wrapped data
			tampered := make([]byte, len(originalWrapped))
			copy(tampered, originalWrapped)

			// Modify single byte
			tampered[i] ^= 0x01

			unwrapped, err := unwrapForTest(wrapper, tampered)

			require.Error(t, err, "tampering byte at position %d should cause failure", i)
			require.ErrorIs(t, err, ErrKeyUnwrapFailed, "tampering byte at position %d should return ErrKeyUnwrapFailed", i)
			require.Nil(t, unwrapped, "unwrapped should be nil when tampered at position %d", i)
		}

		// Verify original still works
		unwrapped, err := unwrapForTest(wrapper, originalWrapped)
		require.NoError(t, err)
		require.Equal(t, plaintext, unwrapped)
	})

	t.Run("truncating wrapped data causes unwrap failure", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		plaintext := []byte("data to test truncation detection")

		wrapped, err := wrapForTest(wrapper, plaintext)
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

			unwrapped, err := unwrapForTest(wrapper, truncated)

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

		wrapped, err := wrapForTest(wrapper, plaintext)
		require.NoError(t, err)

		// Append extra bytes
		extended := make([]byte, len(wrapped)+10)
		copy(extended, wrapped)
		_, err = rand.Read(extended[len(wrapped):])
		require.NoError(t, err)

		unwrapped, err := unwrapForTest(wrapper, extended)

		require.ErrorIs(t, err, ErrKeyUnwrapFailed)
		require.Nil(t, unwrapped)
	})

	t.Run("swapping nonce and ciphertext portions causes failure", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		plaintext := []byte("data for swap detection test")

		wrapped, err := wrapForTest(wrapper, plaintext)
		require.NoError(t, err)

		// Create corrupted data by swapping nonce with part of ciphertext
		corrupted := make([]byte, len(wrapped))
		// Put ciphertext at beginning
		copy(corrupted, wrapped[AESGCMNonceSize:AESGCMNonceSize*2])
		// Put nonce where ciphertext was
		copy(corrupted[AESGCMNonceSize:], wrapped[:AESGCMNonceSize])
		// Copy rest of original
		copy(corrupted[AESGCMNonceSize*2:], wrapped[AESGCMNonceSize*2:])

		unwrapped, err := unwrapForTest(wrapper, corrupted)

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

		wrapped, err := kw.WrapFrom(protectedBytes(t, plaintext))
		require.NoError(t, err)

		unwrapped, err := unwrapForTest(kw, wrapped)
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
			{"one byte", 1},
			{"small", 32},
			{"medium", 256},
			{"large", 4096},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				plaintext := generateRandomKey(t, tc.plaintextSize)

				wrapped, err := wrapForTest(wrapper, plaintext)
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

					wrapped, err := wrapForTest(wrapper, plaintext)
					if err != nil {
						errChan <- err
						continue
					}

					unwrapped, err := unwrapForTest(wrapper, wrapped)
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

// unwrapForTest recreates the heap-returning unwrap the production interface
// deliberately no longer expresses (go-xkms#291): it sizes and allocates the
// destination, then decrypts into it via UnwrapInto. Tests own — and may
// inspect — the returned slice; production code must never grow an equivalent.
func unwrapForTest(w KeyWrapper, wrapped []byte) ([]byte, error) {
	plainLen, err := aesGCMUnwrappedLen(wrapped)
	if err != nil {
		return nil, err
	}
	dst := make([]byte, plainLen)
	if err := w.UnwrapInto(wrapped, dst); err != nil {
		return nil, err
	}
	return dst, nil
}

func TestAESGCMUnwrappedLen(t *testing.T) {
	t.Run("returns plaintext length for valid wrapped data", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		plaintext := []byte("sized without the key")
		wrapped, err := wrapForTest(wrapper, plaintext)
		require.NoError(t, err)

		n, err := aesGCMUnwrappedLen(wrapped)
		require.NoError(t, err)
		require.Equal(t, len(plaintext), n)
	})

	t.Run("returns ErrInvalidWrappedData for input below nonce+tag overhead", func(t *testing.T) {
		n, err := aesGCMUnwrappedLen(make([]byte, AESGCMNonceSize+aesGCMTagSize-1))
		require.ErrorIs(t, err, ErrInvalidWrappedData)
		require.Zero(t, n)
	})
}

func TestAESGCMKeyWrapper_UnwrapInto(t *testing.T) {
	t.Run("decrypts in place into the caller's destination", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		plaintext := []byte("plaintext that must land only in dst")
		wrapped, err := wrapForTest(wrapper, plaintext)
		require.NoError(t, err)

		dst := make([]byte, len(plaintext))
		require.NoError(t, wrapper.UnwrapInto(wrapped, dst))
		require.Equal(t, plaintext, dst)
	})

	t.Run("destination too short returns ErrInvalidUnwrapDestination", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		wrapped, err := wrapForTest(wrapper, []byte("some plaintext"))
		require.NoError(t, err)

		dst := make([]byte, len("some plaintext")-1)
		require.ErrorIs(t, wrapper.UnwrapInto(wrapped, dst), ErrInvalidUnwrapDestination)
		require.Equal(t, make([]byte, len(dst)), dst, "rejected destination must stay untouched")
	})

	t.Run("destination too long returns ErrInvalidUnwrapDestination", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		wrapped, err := wrapForTest(wrapper, []byte("some plaintext"))
		require.NoError(t, err)

		dst := make([]byte, len("some plaintext")+1)
		require.ErrorIs(t, wrapper.UnwrapInto(wrapped, dst), ErrInvalidUnwrapDestination)
	})

	t.Run("short wrapped data returns ErrInvalidWrappedData", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		err = wrapper.UnwrapInto(make([]byte, AESGCMNonceSize), make([]byte, 0))
		require.ErrorIs(t, err, ErrInvalidWrappedData)
	})

	t.Run("authentication failure leaves no plaintext in dst", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		plaintext := bytes.Repeat([]byte{0xAB}, 48)
		wrapped, err := wrapForTest(wrapper, plaintext)
		require.NoError(t, err)
		// Flip one ciphertext bit so the tag no longer verifies.
		wrapped[AESGCMNonceSize] ^= 0x01

		dst := make([]byte, len(plaintext))
		require.ErrorIs(t, wrapper.UnwrapInto(wrapped, dst), ErrKeyUnwrapFailed)
		require.Equal(t, make([]byte, len(dst)), dst,
			"dst must hold no plaintext after a failed unwrap")
	})

	t.Run("empty payload round-trips through a zero-length destination", func(t *testing.T) {
		key := generateRandomKey(t, AESGCMKeySize)
		wrapper, err := NewAESGCMKeyWrapper(key)
		require.NoError(t, err)

		wrapped := sealForTest(t, key, []byte{})

		require.NoError(t, wrapper.UnwrapInto(wrapped, []byte{}))
	})
}
