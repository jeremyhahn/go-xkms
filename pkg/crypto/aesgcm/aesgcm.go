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

// Package aesgcm provides AES-256-GCM authenticated encryption and decryption.
//
// This is the canonical AES-GCM implementation for go-xkms. All code needing
// AES-GCM should use this package rather than directly importing crypto/aes
// and crypto/cipher.
//
// Wire format: [nonce:12][ciphertext+GCM-tag:16]
//
// The nonce is randomly generated for each encryption operation and prepended
// to the output. Decryption splits the nonce from the front and authenticates
// the remaining ciphertext.
package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

const (
	// KeySize is the required AES-256 key size in bytes.
	KeySize = 32

	// NonceSize is the GCM standard nonce size in bytes.
	NonceSize = 12

	// TagSize is the GCM authentication tag size in bytes.
	TagSize = 16

	// Overhead is the total overhead added to plaintext (nonce + tag).
	Overhead = NonceSize + TagSize
)

// Encrypt encrypts plaintext using AES-256-GCM with a random nonce.
// The key must be exactly 32 bytes (AES-256).
// Returns [nonce:12][ciphertext+tag] on success.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	return EncryptWithAAD(key, plaintext, nil)
}

// Decrypt decrypts ciphertext produced by Encrypt.
// The key must be exactly 32 bytes (AES-256).
// Input format: [nonce:12][ciphertext+tag]
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	return DecryptWithAAD(key, ciphertext, nil)
}

// newGCM creates an AES-256-GCM cipher from a validated key.
// The key must already be validated as exactly KeySize bytes.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		// Should never happen after key length validation.
		return nil, ErrInvalidKeySize
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		// Should never happen with standard AES block cipher.
		return nil, ErrDecryptionFailed
	}
	return gcm, nil
}

// EncryptWithAAD encrypts plaintext using AES-256-GCM with additional
// authenticated data (AAD). The key must be exactly 32 bytes (AES-256).
// Returns [nonce:12][ciphertext+tag] on success.
func EncryptWithAAD(key, plaintext, aad []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	sealed := gcm.Seal(nil, nonce, plaintext, aad)

	// output: nonce || ciphertext+tag
	out := make([]byte, NonceSize+len(sealed))
	copy(out[:NonceSize], nonce)
	copy(out[NonceSize:], sealed)
	return out, nil
}

// DecryptWithAAD decrypts ciphertext produced by EncryptWithAAD with the
// same additional authenticated data. The key must be exactly 32 bytes
// (AES-256). Input format: [nonce:12][ciphertext+tag]
func DecryptWithAAD(key, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	if len(ciphertext) < Overhead {
		return nil, ErrCiphertextTooShort
	}

	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	nonce := ciphertext[:NonceSize]
	sealed := ciphertext[NonceSize:]

	plaintext, err := gcm.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	// Normalize nil to empty slice so that Encrypt(key, []byte{}) /
	// Decrypt(key, ct) round-trips correctly.
	if plaintext == nil {
		plaintext = []byte{}
	}

	return plaintext, nil
}
