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

	// ErrInvalidUnwrapDestination indicates the destination slice passed to
	// UnwrapInto is not exactly the plaintext length of the wrapped data.
	ErrInvalidUnwrapDestination = errors.New("authenticator: unwrap destination has wrong length")

	// ErrUnwrapNotInPlace indicates the cipher wrote the plaintext somewhere
	// other than the caller's destination. The stray copy is wiped before this
	// is returned; it exists so a standard-library change that breaks the
	// in-place decrypt invariant fails closed instead of silently leaking
	// plaintext onto the heap.
	ErrUnwrapNotInPlace = errors.New("authenticator: unwrap did not decrypt in place")
)

// KeyWrapper defines the interface for key wrapping operations.
// Implementations must be safe for concurrent use.
//
// Unwrapping deliberately cannot return a plaintext slice: the caller supplies
// the destination, so decrypted key material lands only in memory the caller
// owns — typically an mlocked secure.Buffer allocated before any protected-key
// borrow is taken (go-xkms#291). An implementation must never allocate a
// plaintext copy the caller cannot wipe.
type KeyWrapper interface {
	// Wrap encrypts plaintext and returns the wrapped (encrypted) data.
	// The output format is implementation-specific but must be deterministically
	// unwrappable by the corresponding UnwrapInto method.
	Wrap(plaintext []byte) ([]byte, error)

	// UnwrapInto decrypts wrapped data into dst, which must be exactly the
	// plaintext length (aesGCMUnwrappedLen for the AES-GCM format). dst is
	// written in place and contains no plaintext when an error is returned.
	// Returns ErrKeyUnwrapFailed if decryption fails due to authentication failure.
	// Returns ErrInvalidWrappedData if the wrapped data is malformed.
	// Returns ErrInvalidUnwrapDestination if dst has the wrong length.
	UnwrapInto(wrapped, dst []byte) error
}

// aesGCMUnwrappedLen returns the plaintext length of AES-GCM wrapped data
// (nonce || ciphertext || tag) without touching any key material, so an
// UnwrapInto destination can be sized and allocated BEFORE a protected-key
// borrow is entered. Returns ErrInvalidWrappedData if wrapped is shorter than
// the nonce and tag overhead.
func aesGCMUnwrappedLen(wrapped []byte) (int, error) {
	minSize := AESGCMNonceSize + aesGCMTagSize
	if len(wrapped) < minSize {
		return 0, ErrInvalidWrappedData
	}
	return len(wrapped) - minSize, nil
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

// UnwrapInto decrypts the wrapped data using AES-256-GCM, writing the
// plaintext into dst in place. Expected input format: nonce (12 bytes) ||
// ciphertext || tag (16 bytes). dst must be exactly len(wrapped) minus that
// overhead (aesGCMUnwrappedLen); the caller allocates it, so the plaintext
// never lands in memory the caller does not own.
//
// On any error dst holds no plaintext: crypto/cipher zeroes the output on an
// authentication failure, and the in-place check below wipes a relocated copy
// before failing closed.
//
// Returns ErrInvalidWrappedData if the input is too short.
// Returns ErrInvalidUnwrapDestination if dst has the wrong length.
// Returns ErrKeyUnwrapFailed if decryption or authentication fails.
// Returns ErrUnwrapNotInPlace if the cipher did not decrypt into dst.
func (w *AESGCMKeyWrapper) UnwrapInto(wrapped, dst []byte) error {
	plainLen, err := aesGCMUnwrappedLen(wrapped)
	if err != nil {
		return err
	}
	if len(dst) != plainLen {
		return ErrInvalidUnwrapDestination
	}

	// Extract nonce and ciphertext+tag
	nonce := wrapped[:AESGCMNonceSize]
	ciphertext := wrapped[AESGCMNonceSize:]

	// Decrypt and verify. Open appends to dst[:0]; cap(dst) >= plainLen, so
	// crypto/cipher's sliceForAppend reuses dst rather than allocating —
	// the plaintext is written directly into the caller's memory.
	out, err := w.aead.Open(dst[:0], nonce, ciphertext, nil)
	if err != nil {
		// crypto/cipher clears the output buffer on authentication failure,
		// so dst carries no partial plaintext here.
		return ErrKeyUnwrapFailed
	}

	// Fail closed if the standard library ever stops decrypting in place:
	// a relocated output is a heap copy of the plaintext the caller cannot
	// see, so wipe it before reporting the broken invariant.
	if plainLen > 0 && &out[0] != &dst[0] {
		clearBytes(out)
		clearBytes(dst)
		return ErrUnwrapNotInPlace
	}

	return nil
}
