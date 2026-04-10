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

package chacha20poly1305

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockAEAD implements cipher.AEAD and returns a too-short ciphertext from Seal
// to exercise the defensive "ciphertext too short" branch in Encrypt.
type mockAEAD struct {
	nonceSize int
	overhead  int
	sealFn    func(dst, nonce, plaintext, additionalData []byte) []byte
}

func (m *mockAEAD) NonceSize() int { return m.nonceSize }
func (m *mockAEAD) Overhead() int  { return m.overhead }
func (m *mockAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if m.sealFn != nil {
		return m.sealFn(dst, nonce, plaintext, additionalData)
	}
	return nil
}
func (m *mockAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return nil, nil
}

func TestEncryptCiphertextTooShort(t *testing.T) {
	// Create a chacha20poly1305AEAD with a mock AEAD that returns
	// an empty slice from Seal, which is shorter than the overhead.
	c := &chacha20poly1305AEAD{
		aead: &mockAEAD{
			nonceSize: 12,
			overhead:  16,
			sealFn: func(dst, nonce, plaintext, additionalData []byte) []byte {
				// Return a slice shorter than the tag overhead (16 bytes)
				return []byte{0x01, 0x02}
			},
		},
		algorithm: "chacha20-poly1305",
	}

	nonce := make([]byte, 12)
	opts := &types.EncryptOptions{
		Nonce: nonce,
	}

	_, err := c.Encrypt([]byte("test"), opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext too short")
}

func TestEncryptWithXChaChaInvalidNonceSize(t *testing.T) {
	// XChaCha20-Poly1305 requires 24-byte nonces; provide a 12-byte one
	key, err := GenerateKey()
	require.NoError(t, err)

	cipher, err := NewX(key)
	require.NoError(t, err)

	opts := &types.EncryptOptions{
		Nonce: make([]byte, 12), // Wrong size for XChaCha (needs 24)
	}

	_, err = cipher.Encrypt([]byte("test message"), opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid nonce size")
}

func TestDecryptWrongKeyFails(t *testing.T) {
	key1, err := GenerateKey()
	require.NoError(t, err)
	key2, err := GenerateKey()
	require.NoError(t, err)

	cipher1, err := New(key1)
	require.NoError(t, err)
	cipher2, err := New(key2)
	require.NoError(t, err)

	plaintext := []byte("cross-key decryption must fail")
	encrypted, err := cipher1.Encrypt(plaintext, nil)
	require.NoError(t, err)

	_, err = cipher2.Decrypt(encrypted, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication error")
}
