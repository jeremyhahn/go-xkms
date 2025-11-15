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

	"github.com/jeremyhahn/go-keychain/pkg/crypto/chacha20poly1305"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChaCha20Poly1305_NewCipher(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
		wantErr bool
	}{
		{
			name:    "Valid 32-byte key",
			keySize: 32,
			wantErr: false,
		},
		{
			name:    "Invalid 16-byte key",
			keySize: 16,
			wantErr: true,
		},
		{
			name:    "Invalid 24-byte key",
			keySize: 24,
			wantErr: true,
		},
		{
			name:    "Invalid 0-byte key",
			keySize: 0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			if tt.keySize > 0 {
				_, err := rand.Read(key)
				require.NoError(t, err)
			}

			cipher, err := chacha20poly1305.New(key)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, cipher)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, cipher)
				assert.Equal(t, 12, cipher.NonceSize())
				assert.Equal(t, 16, cipher.Overhead())
			}
		})
	}
}

func TestChaCha20Poly1305_NewXCipher(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
		wantErr bool
	}{
		{
			name:    "Valid 32-byte key",
			keySize: 32,
			wantErr: false,
		},
		{
			name:    "Invalid 16-byte key",
			keySize: 16,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			if tt.keySize > 0 {
				_, err := rand.Read(key)
				require.NoError(t, err)
			}

			cipher, err := chacha20poly1305.NewX(key)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, cipher)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, cipher)
				assert.Equal(t, 24, cipher.NonceSize()) // XChaCha20 uses 24-byte nonce
				assert.Equal(t, 16, cipher.Overhead())
			}
		})
	}
}

func TestChaCha20Poly1305_EncryptDecrypt(t *testing.T) {
	key, err := chacha20poly1305.GenerateKey()
	require.NoError(t, err)
	require.Len(t, key, 32)

	cipher, err := chacha20poly1305.New(key)
	require.NoError(t, err)

	tests := []struct {
		name           string
		plaintext      []byte
		additionalData []byte
	}{
		{
			name:           "Small plaintext",
			plaintext:      []byte("Hello, World!"),
			additionalData: nil,
		},
		{
			name:           "Empty plaintext",
			plaintext:      nil,
			additionalData: nil,
		},
		{
			name:           "With additional data",
			plaintext:      []byte("Secret message"),
			additionalData: []byte("version:1.0"),
		},
		{
			name:           "Large plaintext",
			plaintext:      make([]byte, 64*1024), // 64 KB
			additionalData: nil,
		},
		{
			name:           "Binary data",
			plaintext:      []byte{0x00, 0xFF, 0x01, 0xFE, 0x02, 0xFD},
			additionalData: []byte{0xDE, 0xAD, 0xBE, 0xEF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			encrypted, err := cipher.Encrypt(tt.plaintext, &types.EncryptOptions{
				AdditionalData: tt.additionalData,
			})
			require.NoError(t, err)
			require.NotNil(t, encrypted)
			assert.Len(t, encrypted.Nonce, 12)
			assert.Len(t, encrypted.Tag, 16)
			assert.Equal(t, string(types.SymmetricChaCha20Poly1305), encrypted.Algorithm)

			// Ciphertext should be same length as plaintext
			assert.Len(t, encrypted.Ciphertext, len(tt.plaintext))

			// Ciphertext should be different from plaintext (unless empty)
			if len(tt.plaintext) > 0 {
				assert.NotEqual(t, tt.plaintext, encrypted.Ciphertext)
			}

			// Decrypt
			decrypted, err := cipher.Decrypt(encrypted, &types.DecryptOptions{
				AdditionalData: tt.additionalData,
			})
			require.NoError(t, err)
			assert.Equal(t, tt.plaintext, decrypted)
		})
	}
}

func TestChaCha20Poly1305_CustomNonce(t *testing.T) {
	key, err := chacha20poly1305.GenerateKey()
	require.NoError(t, err)

	cipher, err := chacha20poly1305.New(key)
	require.NoError(t, err)

	nonce := make([]byte, 12)
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	plaintext := []byte("Test with custom nonce")

	// Encrypt with custom nonce
	encrypted, err := cipher.Encrypt(plaintext, &types.EncryptOptions{
		Nonce: nonce,
	})
	require.NoError(t, err)
	assert.Equal(t, nonce, encrypted.Nonce)

	// Decrypt
	decrypted, err := cipher.Decrypt(encrypted, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestChaCha20Poly1305_InvalidNonceSize(t *testing.T) {
	key, err := chacha20poly1305.GenerateKey()
	require.NoError(t, err)

	cipher, err := chacha20poly1305.New(key)
	require.NoError(t, err)

	tests := []struct {
		name      string
		nonceSize int
	}{
		{"Too short", 8},
		{"Too long", 16},
		{"Way too short", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nonce := make([]byte, tt.nonceSize)
			_, err = rand.Read(nonce)
			require.NoError(t, err)

			_, err = cipher.Encrypt([]byte("test"), &types.EncryptOptions{
				Nonce: nonce,
			})
			assert.Error(t, err)
		})
	}
}

func TestChaCha20Poly1305_AuthenticationFailure(t *testing.T) {
	key, err := chacha20poly1305.GenerateKey()
	require.NoError(t, err)

	cipher, err := chacha20poly1305.New(key)
	require.NoError(t, err)

	plaintext := []byte("Original message")
	encrypted, err := cipher.Encrypt(plaintext, nil)
	require.NoError(t, err)

	tests := []struct {
		name   string
		mutate func(*types.EncryptedData)
	}{
		{
			name: "Tampered ciphertext",
			mutate: func(data *types.EncryptedData) {
				if len(data.Ciphertext) > 0 {
					data.Ciphertext[0] ^= 0xFF
				}
			},
		},
		{
			name: "Tampered tag",
			mutate: func(data *types.EncryptedData) {
				data.Tag[0] ^= 0xFF
			},
		},
		{
			name: "Tampered nonce",
			mutate: func(data *types.EncryptedData) {
				data.Nonce[0] ^= 0xFF
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make a copy
			tampered := &types.EncryptedData{
				Ciphertext: append([]byte{}, encrypted.Ciphertext...),
				Nonce:      append([]byte{}, encrypted.Nonce...),
				Tag:        append([]byte{}, encrypted.Tag...),
				Algorithm:  encrypted.Algorithm,
			}

			tt.mutate(tampered)

			_, err := cipher.Decrypt(tampered, nil)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "authentication error")
		})
	}
}

func TestChaCha20Poly1305_AdditionalDataMismatch(t *testing.T) {
	key, err := chacha20poly1305.GenerateKey()
	require.NoError(t, err)

	cipher, err := chacha20poly1305.New(key)
	require.NoError(t, err)

	plaintext := []byte("Message with AAD")
	aad := []byte("version:1.0")

	encrypted, err := cipher.Encrypt(plaintext, &types.EncryptOptions{
		AdditionalData: aad,
	})
	require.NoError(t, err)

	// Decrypt with different AAD should fail
	wrongAAD := []byte("version:2.0")
	_, err = cipher.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: wrongAAD,
	})
	assert.Error(t, err)

	// Decrypt with no AAD should fail
	_, err = cipher.Decrypt(encrypted, nil)
	assert.Error(t, err)

	// Decrypt with correct AAD should succeed
	decrypted, err := cipher.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: aad,
	})
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestChaCha20Poly1305_MultipleEncryptions(t *testing.T) {
	key, err := chacha20poly1305.GenerateKey()
	require.NoError(t, err)

	cipher, err := chacha20poly1305.New(key)
	require.NoError(t, err)

	plaintext := []byte("Same message")
	const numEncryptions = 100

	// Encrypt same message multiple times
	encryptions := make([]*types.EncryptedData, numEncryptions)
	for i := 0; i < numEncryptions; i++ {
		encrypted, err := cipher.Encrypt(plaintext, nil)
		require.NoError(t, err)
		encryptions[i] = encrypted

		// Each encryption should use a different nonce
		for j := 0; j < i; j++ {
			assert.NotEqual(t, encryptions[j].Nonce, encrypted.Nonce,
				"Nonces should be unique")
		}
	}

	// All encryptions should decrypt to the same plaintext
	for i, encrypted := range encryptions {
		decrypted, err := cipher.Decrypt(encrypted, nil)
		require.NoError(t, err, "Decryption %d failed", i)
		assert.Equal(t, plaintext, decrypted)
	}
}

func TestXChaCha20Poly1305_EncryptDecrypt(t *testing.T) {
	key, err := chacha20poly1305.GenerateKey()
	require.NoError(t, err)

	cipher, err := chacha20poly1305.NewX(key)
	require.NoError(t, err)

	plaintext := []byte("XChaCha20-Poly1305 test message")

	encrypted, err := cipher.Encrypt(plaintext, nil)
	require.NoError(t, err)
	require.NotNil(t, encrypted)

	// XChaCha20 uses 24-byte nonce
	assert.Len(t, encrypted.Nonce, 24)
	assert.Len(t, encrypted.Tag, 16)
	assert.Equal(t, string(types.SymmetricXChaCha20Poly1305), encrypted.Algorithm)

	decrypted, err := cipher.Decrypt(encrypted, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestXChaCha20Poly1305_CustomNonce(t *testing.T) {
	key, err := chacha20poly1305.GenerateKey()
	require.NoError(t, err)

	cipher, err := chacha20poly1305.NewX(key)
	require.NoError(t, err)

	// XChaCha20 requires 24-byte nonce
	nonce := make([]byte, 24)
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	plaintext := []byte("Test with 24-byte nonce")

	encrypted, err := cipher.Encrypt(plaintext, &types.EncryptOptions{
		Nonce: nonce,
	})
	require.NoError(t, err)
	assert.Equal(t, nonce, encrypted.Nonce)

	decrypted, err := cipher.Decrypt(encrypted, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestChaCha20Poly1305_NilInputs(t *testing.T) {
	key, err := chacha20poly1305.GenerateKey()
	require.NoError(t, err)

	cipher, err := chacha20poly1305.New(key)
	require.NoError(t, err)

	// Encrypt nil plaintext (should work, produces empty ciphertext)
	encrypted, err := cipher.Encrypt(nil, nil)
	require.NoError(t, err)
	assert.NotNil(t, encrypted)
	assert.Len(t, encrypted.Ciphertext, 0)

	// Decrypt nil data
	_, err = cipher.Decrypt(nil, nil)
	assert.Error(t, err)
}

func TestChaCha20Poly1305_InvalidTagSize(t *testing.T) {
	key, err := chacha20poly1305.GenerateKey()
	require.NoError(t, err)

	cipher, err := chacha20poly1305.New(key)
	require.NoError(t, err)

	plaintext := []byte("test")
	encrypted, err := cipher.Encrypt(plaintext, nil)
	require.NoError(t, err)

	// Tamper with tag size
	encrypted.Tag = encrypted.Tag[:8] // Truncate tag

	_, err = cipher.Decrypt(encrypted, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid tag size")
}

func TestChaCha20Poly1305_LargeData(t *testing.T) {
	key, err := chacha20poly1305.GenerateKey()
	require.NoError(t, err)

	cipher, err := chacha20poly1305.New(key)
	require.NoError(t, err)

	sizes := []int{
		1024,             // 1 KB
		64 * 1024,        // 64 KB
		1024 * 1024,      // 1 MB
		10 * 1024 * 1024, // 10 MB
	}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("Size_%d_bytes", size), func(t *testing.T) {
			plaintext := make([]byte, size)
			_, err := rand.Read(plaintext)
			require.NoError(t, err)

			encrypted, err := cipher.Encrypt(plaintext, nil)
			require.NoError(t, err)

			decrypted, err := cipher.Decrypt(encrypted, nil)
			require.NoError(t, err)
			assert.True(t, bytes.Equal(plaintext, decrypted))
		})
	}
}

func TestChaCha20Poly1305_KeyGeneration(t *testing.T) {
	// Generate multiple keys
	const numKeys = 100
	keys := make([][]byte, numKeys)

	for i := 0; i < numKeys; i++ {
		key, err := chacha20poly1305.GenerateKey()
		require.NoError(t, err)
		require.Len(t, key, 32)
		keys[i] = key

		// Each key should be different
		for j := 0; j < i; j++ {
			assert.NotEqual(t, keys[j], key, "Keys should be unique")
		}
	}
}

func BenchmarkChaCha20Poly1305_Encrypt(b *testing.B) {
	key, _ := chacha20poly1305.GenerateKey()
	cipher, _ := chacha20poly1305.New(key)
	plaintext := make([]byte, 1024) // 1 KB
	rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cipher.Encrypt(plaintext, nil)
	}
}

func BenchmarkChaCha20Poly1305_Decrypt(b *testing.B) {
	key, _ := chacha20poly1305.GenerateKey()
	cipher, _ := chacha20poly1305.New(key)
	plaintext := make([]byte, 1024)
	rand.Read(plaintext)
	encrypted, _ := cipher.Encrypt(plaintext, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cipher.Decrypt(encrypted, nil)
	}
}
