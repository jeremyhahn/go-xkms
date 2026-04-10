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

package aesgcm

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, KeySize)
	_, err := io.ReadFull(rand.Reader, key)
	require.NoError(t, err)
	return key
}

func TestEncryptDecrypt(t *testing.T) {
	key := validKey(t)
	plaintext := []byte("hello, AES-256-GCM")

	ciphertext, err := Encrypt(key, plaintext)
	require.NoError(t, err)
	require.NotNil(t, ciphertext)

	recovered, err := Decrypt(key, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, recovered)
}

func TestEncryptDecrypt_WithAAD(t *testing.T) {
	key := validKey(t)
	plaintext := []byte("authenticated payload")
	aad := []byte("context-binding-data")

	ciphertext, err := EncryptWithAAD(key, plaintext, aad)
	require.NoError(t, err)
	require.NotNil(t, ciphertext)

	recovered, err := DecryptWithAAD(key, ciphertext, aad)
	require.NoError(t, err)
	assert.Equal(t, plaintext, recovered)
}

func TestEncrypt_InvalidKeySize(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{name: "empty key", key: []byte{}},
		{name: "16 bytes", key: make([]byte, 16)},
		{name: "24 bytes", key: make([]byte, 24)},
		{name: "31 bytes", key: make([]byte, 31)},
		{name: "33 bytes", key: make([]byte, 33)},
		{name: "64 bytes", key: make([]byte, 64)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Encrypt(tc.key, []byte("plaintext"))
			assert.ErrorIs(t, err, ErrInvalidKeySize)
		})
	}
}

func TestDecrypt_InvalidKeySize(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{name: "empty key", key: []byte{}},
		{name: "16 bytes", key: make([]byte, 16)},
		{name: "24 bytes", key: make([]byte, 24)},
		{name: "31 bytes", key: make([]byte, 31)},
		{name: "33 bytes", key: make([]byte, 33)},
	}

	// Build valid-looking ciphertext.
	ciphertext := make([]byte, Overhead+10)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decrypt(tc.key, ciphertext)
			assert.ErrorIs(t, err, ErrInvalidKeySize)
		})
	}
}

func TestDecrypt_CiphertextTooShort(t *testing.T) {
	key := validKey(t)

	tests := []struct {
		name       string
		ciphertext []byte
	}{
		{name: "nil", ciphertext: nil},
		{name: "empty", ciphertext: []byte{}},
		{name: "one byte", ciphertext: []byte{0x01}},
		{name: "nonce only", ciphertext: make([]byte, NonceSize)},
		{name: "nonce plus partial tag", ciphertext: make([]byte, NonceSize+TagSize-1)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decrypt(key, tc.ciphertext)
			assert.ErrorIs(t, err, ErrCiphertextTooShort)
		})
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	key := validKey(t)
	plaintext := []byte("tamper detection test")

	ciphertext, err := Encrypt(key, plaintext)
	require.NoError(t, err)

	// Flip a byte in the ciphertext region (after nonce).
	ciphertext[len(ciphertext)-1] ^= 0xFF

	_, err = Decrypt(key, ciphertext)
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestDecrypt_WrongKey(t *testing.T) {
	key1 := validKey(t)
	key2 := validKey(t)

	ciphertext, err := Encrypt(key1, []byte("secret data"))
	require.NoError(t, err)

	_, err = Decrypt(key2, ciphertext)
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestDecrypt_TamperedAAD(t *testing.T) {
	key := validKey(t)
	plaintext := []byte("aad mismatch test")
	aad := []byte("original-aad")

	ciphertext, err := EncryptWithAAD(key, plaintext, aad)
	require.NoError(t, err)

	// Decrypt with different AAD.
	_, err = DecryptWithAAD(key, ciphertext, []byte("wrong-aad"))
	assert.ErrorIs(t, err, ErrDecryptionFailed)

	// Decrypt with nil AAD (omitted).
	_, err = DecryptWithAAD(key, ciphertext, nil)
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestEncrypt_Uniqueness(t *testing.T) {
	key := validKey(t)
	plaintext := []byte("identical plaintext")

	ct1, err := Encrypt(key, plaintext)
	require.NoError(t, err)

	ct2, err := Encrypt(key, plaintext)
	require.NoError(t, err)

	// Nonces must differ.
	nonce1 := ct1[:NonceSize]
	nonce2 := ct2[:NonceSize]
	assert.False(t, bytes.Equal(nonce1, nonce2),
		"each encryption must use a unique random nonce")

	// Full ciphertext must differ.
	assert.False(t, bytes.Equal(ct1, ct2),
		"same plaintext must produce different ciphertext")
}

func TestEncrypt_EmptyPlaintext(t *testing.T) {
	key := validKey(t)

	ciphertext, err := Encrypt(key, []byte{})
	require.NoError(t, err)
	require.NotNil(t, ciphertext)

	recovered, err := Decrypt(key, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, []byte{}, recovered)
}

func TestEncrypt_NilPlaintext(t *testing.T) {
	key := validKey(t)

	ciphertext, err := Encrypt(key, nil)
	require.NoError(t, err)
	require.NotNil(t, ciphertext)

	recovered, err := Decrypt(key, ciphertext)
	require.NoError(t, err)
	// GCM with nil plaintext returns empty slice on Open.
	assert.Empty(t, recovered)
}

func TestOutputFormat(t *testing.T) {
	key := validKey(t)

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{name: "empty", plaintext: []byte{}},
		{name: "short", plaintext: []byte("hi")},
		{name: "medium", plaintext: []byte("a medium length plaintext for testing")},
		{name: "exact block", plaintext: make([]byte, 16)},
		{name: "large", plaintext: make([]byte, 4096)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := Encrypt(key, tc.plaintext)
			require.NoError(t, err)

			expectedLen := NonceSize + len(tc.plaintext) + TagSize
			assert.Len(t, ciphertext, expectedLen,
				"output must be NonceSize + len(plaintext) + TagSize")
		})
	}
}

func TestConstants(t *testing.T) {
	assert.Equal(t, 32, KeySize)
	assert.Equal(t, 12, NonceSize)
	assert.Equal(t, 16, TagSize)
	assert.Equal(t, 28, Overhead)
	assert.Equal(t, NonceSize+TagSize, Overhead)
}

func TestEncryptWithAAD_InvalidKeySize(t *testing.T) {
	_, err := EncryptWithAAD([]byte("short"), []byte("data"), []byte("aad"))
	assert.ErrorIs(t, err, ErrInvalidKeySize)
}

func TestDecryptWithAAD_InvalidKeySize(t *testing.T) {
	ciphertext := make([]byte, Overhead+10)
	_, err := DecryptWithAAD([]byte("short"), ciphertext, []byte("aad"))
	assert.ErrorIs(t, err, ErrInvalidKeySize)
}

func TestDecryptWithAAD_CiphertextTooShort(t *testing.T) {
	key := validKey(t)
	_, err := DecryptWithAAD(key, []byte("short"), []byte("aad"))
	assert.ErrorIs(t, err, ErrCiphertextTooShort)
}

// --- Internal newGCM function: direct tests for error branches ---

func TestNewGCM_ValidKey(t *testing.T) {
	key := validKey(t)
	gcm, err := newGCM(key)
	require.NoError(t, err)
	require.NotNil(t, gcm)
	assert.Equal(t, NonceSize, gcm.NonceSize())
	assert.Equal(t, TagSize, gcm.Overhead())
}

func TestNewGCM_InvalidKeySize(t *testing.T) {
	// newGCM wraps aes.NewCipher which rejects non-16/24/32 byte keys.
	// Test with sizes that aes.NewCipher actually rejects (not 16, 24, or 32).
	invalidSizes := []int{0, 1, 7, 15, 17, 23, 25, 31, 33, 48, 64}
	for _, sz := range invalidSizes {
		key := make([]byte, sz)
		_, err := newGCM(key)
		assert.ErrorIs(t, err, ErrInvalidKeySize, "newGCM should fail for key size %d", sz)
	}
}

func TestNewGCM_AES128_256Accepted(t *testing.T) {
	// aes.NewCipher accepts 16, 24, and 32 byte keys.
	// newGCM should succeed with these (even though we only use 32 externally).
	for _, sz := range []int{16, 24, 32} {
		key := make([]byte, sz)
		gcm, err := newGCM(key)
		require.NoError(t, err, "newGCM should succeed for key size %d", sz)
		require.NotNil(t, gcm)
	}
}

// --- EncryptWithAAD with nil AAD ---

func TestEncryptDecrypt_WithNilAAD(t *testing.T) {
	key := validKey(t)
	plaintext := []byte("nil-aad test payload")

	// EncryptWithAAD with nil AAD should behave like Encrypt
	ciphertext, err := EncryptWithAAD(key, plaintext, nil)
	require.NoError(t, err)
	require.NotNil(t, ciphertext)

	recovered, err := DecryptWithAAD(key, ciphertext, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, recovered)
}

// --- EncryptWithAAD with empty AAD ---

func TestEncryptDecrypt_WithEmptyAAD(t *testing.T) {
	key := validKey(t)
	plaintext := []byte("empty-aad test payload")

	ciphertext, err := EncryptWithAAD(key, plaintext, []byte{})
	require.NoError(t, err)
	require.NotNil(t, ciphertext)

	recovered, err := DecryptWithAAD(key, ciphertext, []byte{})
	require.NoError(t, err)
	assert.Equal(t, plaintext, recovered)
}

// --- Large AAD ---

func TestEncryptDecrypt_LargeAAD(t *testing.T) {
	key := validKey(t)
	plaintext := []byte("large-aad payload")
	aad := make([]byte, 8192)
	for i := range aad {
		aad[i] = byte(i % 256)
	}

	ciphertext, err := EncryptWithAAD(key, plaintext, aad)
	require.NoError(t, err)

	recovered, err := DecryptWithAAD(key, ciphertext, aad)
	require.NoError(t, err)
	assert.Equal(t, plaintext, recovered)

	// Wrong AAD should still fail
	aad[0] ^= 0xFF
	_, err = DecryptWithAAD(key, ciphertext, aad)
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

// --- Decrypt: exact Overhead boundary ---

func TestDecrypt_ExactOverheadSize(t *testing.T) {
	key := validKey(t)
	// A ciphertext of exactly Overhead bytes contains nonce + tag but no payload.
	// It should be accepted but fail auth since it is fabricated.
	ciphertext := make([]byte, Overhead)
	_, err := Decrypt(key, ciphertext)
	assert.ErrorIs(t, err, ErrDecryptionFailed, "fabricated minimal ciphertext should fail auth")
}
