// Package aesgcm provides AES-GCM encryption utilities for TPM operations
package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

var (
	// ErrCiphertextTooShort indicates the ciphertext is too short
	ErrCiphertextTooShort = errors.New("ciphertext too short")
)

// AESGCM provides AES-GCM encryption/decryption
type AESGCM struct {
	random io.Reader
}

// NewAESGCM creates a new AESGCM instance
// The parameter is ignored for compatibility but could be a TPM instance in the future
func NewAESGCM(tpm interface{}) *AESGCM {
	return &AESGCM{
		random: rand.Reader,
	}
}

// GenerateKey generates a 32-byte AES-256 key
func (a *AESGCM) GenerateKey() []byte {
	key := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(a.random, key); err != nil {
		panic(err) // Should never happen with crypto/rand
	}
	return key
}

// Encrypt encrypts plaintext using AES-GCM
func (a *AESGCM) Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(a.random, nonce); err != nil {
		return nil, err
	}

	// Prepend nonce to ciphertext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-GCM
func (a *AESGCM) Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrCiphertextTooShort
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
