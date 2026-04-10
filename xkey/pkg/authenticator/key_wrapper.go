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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

// Key wrapping constants for AES-256-GCM.
const (
	// AESGCMNonceSize is the standard nonce size for AES-GCM (96 bits).
	AESGCMNonceSize = 12

	// AESGCMKeySize is the key size for AES-256-GCM (256 bits).
	AESGCMKeySize = 32

	// aesGCMTagSize is the authentication tag size for AES-GCM (128 bits).
	// This is included in the ciphertext by crypto/cipher.
	aesGCMTagSize = 16
)

// Key wrapping errors.
var (
	// ErrKeyWrapFailed indicates the key wrapping operation failed.
	ErrKeyWrapFailed = errors.New("authenticator: key wrap failed")

	// ErrKeyUnwrapFailed indicates the key unwrapping operation failed.
	ErrKeyUnwrapFailed = errors.New("authenticator: key unwrap failed")

	// ErrInvalidWrappedData indicates the wrapped data is malformed or corrupted.
	ErrInvalidWrappedData = errors.New("authenticator: invalid wrapped data")

	// ErrInvalidWrappingKey indicates the wrapping key is invalid or has incorrect size.
	ErrInvalidWrappingKey = errors.New("authenticator: invalid wrapping key")
)

// KeyWrapper defines the interface for key wrapping operations.
// Implementations must be safe for concurrent use.
type KeyWrapper interface {
	// Wrap encrypts plaintext and returns the wrapped (encrypted) data.
	// The output format is implementation-specific but must be deterministically
	// unwrappable by the corresponding Unwrap method.
	Wrap(plaintext []byte) ([]byte, error)

	// Unwrap decrypts wrapped data and returns the original plaintext.
	// Returns ErrKeyUnwrapFailed if decryption fails due to authentication failure.
	// Returns ErrInvalidWrappedData if the wrapped data is malformed.
	Unwrap(wrapped []byte) ([]byte, error)
}

// AESGCMKeyWrapper implements KeyWrapper using AES-256-GCM.
// The wrapped format is: nonce (12 bytes) || ciphertext || tag (16 bytes).
// Note: GCM appends the tag to the ciphertext automatically.
//
// This implementation is thread-safe as it holds no mutable state after construction.
type AESGCMKeyWrapper struct {
	aead cipher.AEAD
}

// NewAESGCMKeyWrapper creates a new AESGCMKeyWrapper with the given wrapping key.
// The key must be exactly 32 bytes (256 bits) for AES-256-GCM.
// Returns ErrInvalidWrappingKey if the key size is incorrect.
func NewAESGCMKeyWrapper(key []byte) (*AESGCMKeyWrapper, error) {
	if len(key) != AESGCMKeySize {
		return nil, ErrInvalidWrappingKey
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrInvalidWrappingKey
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrKeyWrapFailed
	}

	return &AESGCMKeyWrapper{
		aead: aead,
	}, nil
}

// Wrap encrypts the plaintext using AES-256-GCM with a random nonce.
// Output format: nonce (12 bytes) || ciphertext || tag (16 bytes).
// The tag is automatically appended by the GCM Seal operation.
//
// Returns ErrKeyWrapFailed if nonce generation or encryption fails.
func (w *AESGCMKeyWrapper) Wrap(plaintext []byte) ([]byte, error) {
	if plaintext == nil {
		return nil, ErrKeyWrapFailed
	}

	// Generate random nonce
	nonce := make([]byte, AESGCMNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, ErrKeyWrapFailed
	}

	// Encrypt: Seal appends ciphertext+tag to nonce
	// Pre-allocate output buffer: nonce + ciphertext + tag
	outputLen := AESGCMNonceSize + len(plaintext) + aesGCMTagSize
	wrapped := make([]byte, AESGCMNonceSize, outputLen)
	copy(wrapped, nonce)

	// Seal appends ciphertext+tag to the destination slice
	wrapped = w.aead.Seal(wrapped, nonce, plaintext, nil)

	return wrapped, nil
}

// Unwrap decrypts the wrapped data using AES-256-GCM.
// Expected input format: nonce (12 bytes) || ciphertext || tag (16 bytes).
//
// Returns ErrInvalidWrappedData if the input is too short.
// Returns ErrKeyUnwrapFailed if decryption or authentication fails.
func (w *AESGCMKeyWrapper) Unwrap(wrapped []byte) ([]byte, error) {
	// Minimum size: nonce + tag (empty plaintext is valid)
	minSize := AESGCMNonceSize + aesGCMTagSize
	if len(wrapped) < minSize {
		return nil, ErrInvalidWrappedData
	}

	// Extract nonce and ciphertext+tag
	nonce := wrapped[:AESGCMNonceSize]
	ciphertext := wrapped[AESGCMNonceSize:]

	// Decrypt and verify
	plaintext, err := w.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrKeyUnwrapFailed
	}

	return plaintext, nil
}
