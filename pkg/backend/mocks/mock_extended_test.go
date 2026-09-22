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

package mocks

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestMockSymmetricEncrypter_EncryptDecrypt verifies the round trip works
// and produces a nonce/tag of the expected AES-GCM sizes.
func TestMockSymmetricEncrypter_EncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	encrypter, err := NewMockSymmetricEncrypter(key, "aes256-gcm")
	if err != nil {
		t.Fatalf("NewMockSymmetricEncrypter() error = %v", err)
	}

	plaintext := []byte("mock backend plaintext")
	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if len(encrypted.Nonce) != 12 {
		t.Fatalf("Nonce length = %d, want 12", len(encrypted.Nonce))
	}

	decrypted, err := encrypter.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypted plaintext does not match original")
	}
}

// TestMockSymmetricEncrypter_Decrypt_WrongNonceLength verifies that Decrypt
// returns an error instead of panicking when the encrypted data carries a
// nonce that is not exactly the GCM nonce size. crypto/cipher.AEAD.Open
// panics on a mismatched nonce length, so a caller-controlled nonce must be
// validated before it reaches Open.
func TestMockSymmetricEncrypter_Decrypt_WrongNonceLength(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	encrypter, err := NewMockSymmetricEncrypter(key, "aes256-gcm")
	if err != nil {
		t.Fatalf("NewMockSymmetricEncrypter() error = %v", err)
	}

	tests := []struct {
		name      string
		nonceSize int
	}{
		{name: "16-byte AES-CBC-style IV", nonceSize: 16},
		{name: "empty nonce", nonceSize: 0},
		{name: "single byte nonce", nonceSize: 1},
		{name: "oversized nonce", nonceSize: 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &types.EncryptedData{
				Ciphertext: []byte("ciphertext"),
				Nonce:      make([]byte, tt.nonceSize),
				Tag:        make([]byte, 16),
			}
			if _, err := encrypter.Decrypt(data, nil); err == nil {
				t.Fatalf("Decrypt() with %d-byte nonce should return an error, not panic", tt.nonceSize)
			}
		})
	}
}

// TestMockSymmetricEncrypter_Decrypt_NilData verifies that Decrypt rejects
// nil EncryptedData with an error instead of a nil-pointer panic.
func TestMockSymmetricEncrypter_Decrypt_NilData(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	encrypter, err := NewMockSymmetricEncrypter(key, "aes256-gcm")
	if err != nil {
		t.Fatalf("NewMockSymmetricEncrypter() error = %v", err)
	}

	if _, err := encrypter.Decrypt(nil, nil); err == nil {
		t.Fatal("Decrypt(nil, ...) should return an error, not panic")
	}
}
