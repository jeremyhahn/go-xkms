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

package chacha20poly1305

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestNew(t *testing.T) {
	t.Run("valid 32-byte key", func(t *testing.T) {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		require.NoError(t, err)

		cipher, err := New(key)
		require.NoError(t, err)
		require.NotNil(t, cipher)

		// Verify properties
		assert.Equal(t, 12, cipher.NonceSize())
		assert.Equal(t, 16, cipher.Overhead())
	})

	t.Run("invalid key size - too short", func(t *testing.T) {
		key := make([]byte, 16)
		_, err := New(key)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid key size")
	})

	t.Run("invalid key size - too long", func(t *testing.T) {
		key := make([]byte, 64)
		_, err := New(key)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid key size")
	})

	t.Run("empty key", func(t *testing.T) {
		_, err := New([]byte{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid key size")
	})
}

func TestNewX(t *testing.T) {
	t.Run("valid 32-byte key", func(t *testing.T) {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		require.NoError(t, err)

		cipher, err := NewX(key)
		require.NoError(t, err)
		require.NotNil(t, cipher)

		// XChaCha20-Poly1305 uses 24-byte nonces
		assert.Equal(t, 24, cipher.NonceSize())
		assert.Equal(t, 16, cipher.Overhead())
	})

	t.Run("invalid key size", func(t *testing.T) {
		key := make([]byte, 16)
		_, err := NewX(key)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid key size")
	})
}

func TestEncrypt(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)

	cipher, err := New(key)
	require.NoError(t, err)

	t.Run("successful encryption", func(t *testing.T) {
		plaintext := []byte("Hello, ChaCha20-Poly1305!")

		encrypted, err := cipher.Encrypt(plaintext, nil)
		require.NoError(t, err)
		require.NotNil(t, encrypted)

		// Verify structure
		assert.Len(t, encrypted.Nonce, 12)
		assert.Len(t, encrypted.Tag, 16)
		assert.Len(t, encrypted.Ciphertext, len(plaintext))
		assert.Equal(t, string(backend.ALG_CHACHA20_POLY1305), encrypted.Algorithm)

		// Ciphertext should be different from plaintext
		assert.NotEqual(t, plaintext, encrypted.Ciphertext)
	})

	t.Run("encryption with additional data", func(t *testing.T) {
		plaintext := []byte("Secret message")
		additionalData := []byte("context-info")

		opts := &types.EncryptOptions{
			AdditionalData: additionalData,
		}

		encrypted, err := cipher.Encrypt(plaintext, opts)
		require.NoError(t, err)
		require.NotNil(t, encrypted)

		assert.Len(t, encrypted.Nonce, 12)
		assert.Len(t, encrypted.Tag, 16)
	})

	t.Run("encryption with custom nonce", func(t *testing.T) {
		plaintext := []byte("Test message")
		nonce := make([]byte, 12)
		_, err := rand.Read(nonce)
		require.NoError(t, err)

		opts := &types.EncryptOptions{
			Nonce: nonce,
		}

		encrypted, err := cipher.Encrypt(plaintext, opts)
		require.NoError(t, err)
		require.NotNil(t, encrypted)

		// Should use the provided nonce
		assert.Equal(t, nonce, encrypted.Nonce)
	})

	t.Run("invalid nonce size", func(t *testing.T) {
		plaintext := []byte("Test")
		invalidNonce := make([]byte, 16) // Wrong size

		opts := &types.EncryptOptions{
			Nonce: invalidNonce,
		}

		_, err := cipher.Encrypt(plaintext, opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid nonce size")
	})

	t.Run("empty plaintext", func(t *testing.T) {
		encrypted, err := cipher.Encrypt([]byte{}, nil)
		require.NoError(t, err)
		require.NotNil(t, encrypted)

		// Should still produce valid output
		assert.Len(t, encrypted.Nonce, 12)
		assert.Len(t, encrypted.Tag, 16)
		assert.Len(t, encrypted.Ciphertext, 0)
	})

	t.Run("multiple encryptions produce different nonces", func(t *testing.T) {
		plaintext := []byte("Same message")

		encrypted1, err := cipher.Encrypt(plaintext, nil)
		require.NoError(t, err)

		encrypted2, err := cipher.Encrypt(plaintext, nil)
		require.NoError(t, err)

		// Different nonces
		assert.NotEqual(t, encrypted1.Nonce, encrypted2.Nonce)
		// Different ciphertexts due to different nonces
		assert.NotEqual(t, encrypted1.Ciphertext, encrypted2.Ciphertext)
	})
}

func TestDecrypt(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)

	cipher, err := New(key)
	require.NoError(t, err)

	t.Run("successful decryption", func(t *testing.T) {
		plaintext := []byte("Hello, ChaCha20-Poly1305!")

		encrypted, err := cipher.Encrypt(plaintext, nil)
		require.NoError(t, err)

		decrypted, err := cipher.Decrypt(encrypted, nil)
		require.NoError(t, err)

		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("decryption with additional data", func(t *testing.T) {
		plaintext := []byte("Secret message")
		additionalData := []byte("context-info")

		encOpts := &types.EncryptOptions{
			AdditionalData: additionalData,
		}

		encrypted, err := cipher.Encrypt(plaintext, encOpts)
		require.NoError(t, err)

		decOpts := &types.DecryptOptions{
			AdditionalData: additionalData,
		}

		decrypted, err := cipher.Decrypt(encrypted, decOpts)
		require.NoError(t, err)

		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("wrong additional data fails", func(t *testing.T) {
		plaintext := []byte("Secret message")
		additionalData := []byte("context-info")

		encOpts := &types.EncryptOptions{
			AdditionalData: additionalData,
		}

		encrypted, err := cipher.Encrypt(plaintext, encOpts)
		require.NoError(t, err)

		// Use different additional data for decryption
		decOpts := &types.DecryptOptions{
			AdditionalData: []byte("wrong-context"),
		}

		_, err = cipher.Decrypt(encrypted, decOpts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "authentication error")
	})

	t.Run("tampered ciphertext fails", func(t *testing.T) {
		plaintext := []byte("Important message")

		encrypted, err := cipher.Encrypt(plaintext, nil)
		require.NoError(t, err)

		// Tamper with ciphertext
		if len(encrypted.Ciphertext) > 0 {
			encrypted.Ciphertext[0] ^= 0xFF
		}

		_, err = cipher.Decrypt(encrypted, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "authentication error")
	})

	t.Run("tampered tag fails", func(t *testing.T) {
		plaintext := []byte("Important message")

		encrypted, err := cipher.Encrypt(plaintext, nil)
		require.NoError(t, err)

		// Tamper with tag
		encrypted.Tag[0] ^= 0xFF

		_, err = cipher.Decrypt(encrypted, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "authentication error")
	})

	t.Run("tampered nonce fails", func(t *testing.T) {
		plaintext := []byte("Important message")

		encrypted, err := cipher.Encrypt(plaintext, nil)
		require.NoError(t, err)

		// Tamper with nonce
		encrypted.Nonce[0] ^= 0xFF

		_, err = cipher.Decrypt(encrypted, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "authentication error")
	})

	t.Run("nil encrypted data", func(t *testing.T) {
		_, err := cipher.Decrypt(nil, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "encrypted data cannot be nil")
	})

	t.Run("invalid nonce size", func(t *testing.T) {
		encrypted := &types.EncryptedData{
			Ciphertext: []byte("ciphertext"),
			Nonce:      make([]byte, 8), // Wrong size
			Tag:        make([]byte, 16),
			Algorithm:  string(backend.ALG_CHACHA20_POLY1305),
		}

		_, err := cipher.Decrypt(encrypted, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid nonce size")
	})

	t.Run("invalid tag size", func(t *testing.T) {
		encrypted := &types.EncryptedData{
			Ciphertext: []byte("ciphertext"),
			Nonce:      make([]byte, 12),
			Tag:        make([]byte, 8), // Wrong size
			Algorithm:  string(backend.ALG_CHACHA20_POLY1305),
		}

		_, err := cipher.Decrypt(encrypted, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid tag size")
	})

	t.Run("empty plaintext round-trip", func(t *testing.T) {
		plaintext := []byte{}

		encrypted, err := cipher.Encrypt(plaintext, nil)
		require.NoError(t, err)

		decrypted, err := cipher.Decrypt(encrypted, nil)
		require.NoError(t, err)

		// Both nil and empty slice are valid representations of empty data
		assert.Len(t, decrypted, 0)
	})
}

func TestXChaCha20Poly1305(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)

	cipher, err := NewX(key)
	require.NoError(t, err)

	t.Run("successful encryption and decryption", func(t *testing.T) {
		plaintext := []byte("Hello, XChaCha20-Poly1305!")

		encrypted, err := cipher.Encrypt(plaintext, nil)
		require.NoError(t, err)
		require.NotNil(t, encrypted)

		// XChaCha uses 24-byte nonces
		assert.Len(t, encrypted.Nonce, 24)
		assert.Len(t, encrypted.Tag, 16)
		assert.Equal(t, string(types.SymmetricXChaCha20Poly1305), encrypted.Algorithm)

		decrypted, err := cipher.Decrypt(encrypted, nil)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("custom nonce with XChaCha", func(t *testing.T) {
		plaintext := []byte("Test message")
		nonce := make([]byte, 24) // XChaCha nonce size
		_, err := rand.Read(nonce)
		require.NoError(t, err)

		opts := &types.EncryptOptions{
			Nonce: nonce,
		}

		encrypted, err := cipher.Encrypt(plaintext, opts)
		require.NoError(t, err)
		assert.Equal(t, nonce, encrypted.Nonce)
	})
}

func TestRoundTrip(t *testing.T) {
	testCases := []struct {
		name           string
		plaintext      string
		additionalData string
	}{
		{
			name:           "simple message",
			plaintext:      "Hello, World!",
			additionalData: "",
		},
		{
			name:           "with additional data",
			plaintext:      "Secret message",
			additionalData: "context-info",
		},
		{
			name:           "short message",
			plaintext:      "x",
			additionalData: "",
		},
		{
			name:           "large message",
			plaintext:      string(bytes.Repeat([]byte("A"), 10000)),
			additionalData: "large-data",
		},
		{
			name:           "binary data",
			plaintext:      string([]byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}),
			additionalData: "",
		},
	}

	key, err := GenerateKey()
	require.NoError(t, err)

	cipher, err := New(key)
	require.NoError(t, err)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			plaintext := []byte(tc.plaintext)
			additionalData := []byte(tc.additionalData)

			encOpts := &types.EncryptOptions{
				AdditionalData: additionalData,
			}

			encrypted, err := cipher.Encrypt(plaintext, encOpts)
			require.NoError(t, err)

			decOpts := &types.DecryptOptions{
				AdditionalData: additionalData,
			}

			decrypted, err := cipher.Decrypt(encrypted, decOpts)
			require.NoError(t, err)

			assert.Equal(t, plaintext, decrypted)
		})
	}
}

func TestGenerateKey(t *testing.T) {
	t.Run("generates valid key", func(t *testing.T) {
		key, err := GenerateKey()
		require.NoError(t, err)
		assert.Len(t, key, 32)
	})

	t.Run("generates unique keys", func(t *testing.T) {
		key1, err := GenerateKey()
		require.NoError(t, err)

		key2, err := GenerateKey()
		require.NoError(t, err)

		assert.NotEqual(t, key1, key2)
	})

	t.Run("generated key works with cipher", func(t *testing.T) {
		key, err := GenerateKey()
		require.NoError(t, err)

		cipher, err := New(key)
		require.NoError(t, err)
		require.NotNil(t, cipher)

		// Test encryption/decryption
		plaintext := []byte("Test message")
		encrypted, err := cipher.Encrypt(plaintext, nil)
		require.NoError(t, err)

		decrypted, err := cipher.Decrypt(encrypted, nil)
		require.NoError(t, err)

		assert.Equal(t, plaintext, decrypted)
	})
}

func TestNonceSize(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)

	t.Run("ChaCha20-Poly1305", func(t *testing.T) {
		cipher, err := New(key)
		require.NoError(t, err)
		assert.Equal(t, chacha20poly1305.NonceSize, cipher.NonceSize())
		assert.Equal(t, 12, cipher.NonceSize())
	})

	t.Run("XChaCha20-Poly1305", func(t *testing.T) {
		cipher, err := NewX(key)
		require.NoError(t, err)
		assert.Equal(t, chacha20poly1305.NonceSizeX, cipher.NonceSize())
		assert.Equal(t, 24, cipher.NonceSize())
	})
}

func TestOverhead(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)

	cipher, err := New(key)
	require.NoError(t, err)

	assert.Equal(t, chacha20poly1305.Overhead, cipher.Overhead())
	assert.Equal(t, 16, cipher.Overhead())
}

// TestAgainstRFC8439TestVectors tests against test vectors from RFC 8439
// https://tools.ietf.org/html/rfc8439#appendix-A.5
func TestAgainstRFC8439TestVectors(t *testing.T) {
	// Test vector from RFC 8439 Section A.5
	keyHex := "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
	nonceHex := "070000004041424344454647"
	plaintextHex := "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e"
	aadHex := "50515253c0c1c2c3c4c5c6c7"

	// Expected ciphertext+tag
	expectedHex := "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691"

	// Decode hex
	key, err := hex.DecodeString(keyHex)
	require.NoError(t, err)
	nonce, err := hex.DecodeString(nonceHex)
	require.NoError(t, err)
	plaintext, err := hex.DecodeString(plaintextHex)
	require.NoError(t, err)
	aad, err := hex.DecodeString(aadHex)
	require.NoError(t, err)
	expected, err := hex.DecodeString(expectedHex)
	require.NoError(t, err)

	// Create cipher
	cipher, err := New(key)
	require.NoError(t, err)

	// Encrypt with provided nonce
	opts := &types.EncryptOptions{
		Nonce:          nonce,
		AdditionalData: aad,
	}

	encrypted, err := cipher.Encrypt(plaintext, opts)
	require.NoError(t, err)

	// Concatenate ciphertext and tag
	result := append(encrypted.Ciphertext, encrypted.Tag...)

	// Compare with expected
	assert.Equal(t, expected, result)

	// Verify decryption works
	decOpts := &types.DecryptOptions{
		AdditionalData: aad,
	}

	decrypted, err := cipher.Decrypt(encrypted, decOpts)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestCompatibilityWithStandardLibrary(t *testing.T) {
	// Ensure our implementation is compatible with the standard library's expectations
	key, err := GenerateKey()
	require.NoError(t, err)

	cipher, err := New(key)
	require.NoError(t, err)

	plaintext := []byte("Test compatibility")
	additionalData := []byte("context")

	opts := &types.EncryptOptions{
		AdditionalData: additionalData,
	}

	encrypted, err := cipher.Encrypt(plaintext, opts)
	require.NoError(t, err)

	// Verify we can decrypt using the underlying library directly
	aead, err := chacha20poly1305.New(key)
	require.NoError(t, err)

	ciphertextWithTag := append(encrypted.Ciphertext, encrypted.Tag...)
	decrypted, err := aead.Open(nil, encrypted.Nonce, ciphertextWithTag, additionalData)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func BenchmarkEncrypt(b *testing.B) {
	key, err := GenerateKey()
	require.NoError(b, err)

	cipher, err := New(key)
	require.NoError(b, err)

	plaintext := bytes.Repeat([]byte("A"), 1024) // 1KB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cipher.Encrypt(plaintext, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key, err := GenerateKey()
	require.NoError(b, err)

	cipher, err := New(key)
	require.NoError(b, err)

	plaintext := bytes.Repeat([]byte("A"), 1024) // 1KB
	encrypted, err := cipher.Encrypt(plaintext, nil)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cipher.Decrypt(encrypted, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptXChaCha(b *testing.B) {
	key, err := GenerateKey()
	require.NoError(b, err)

	cipher, err := NewX(key)
	require.NoError(b, err)

	plaintext := bytes.Repeat([]byte("A"), 1024) // 1KB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cipher.Encrypt(plaintext, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}
