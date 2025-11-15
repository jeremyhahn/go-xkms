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
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/types"
	"golang.org/x/crypto/chacha20poly1305"
)

// AEAD provides ChaCha20-Poly1305 authenticated encryption with associated data.
// This interface provides operations compatible with the existing AES-GCM implementation
// while using the ChaCha20-Poly1305 algorithm.
//
// ChaCha20-Poly1305 is a modern AEAD cipher that provides:
// - Fast encryption on devices without AES hardware acceleration
// - 256-bit key security
// - 96-bit (12-byte) nonces (standard) or 192-bit (24-byte) XChaCha20
// - 128-bit (16-byte) authentication tags
// - Resistance to timing attacks
//
// This implementation uses the standard ChaCha20-Poly1305 variant.
// For extended nonce support, use XChaCha20-Poly1305 (future enhancement).
type AEAD interface {
	// Encrypt encrypts plaintext using ChaCha20-Poly1305 AEAD.
	// Returns EncryptedData containing ciphertext, nonce, and authentication tag.
	// If opts.Nonce is nil, a random 12-byte nonce is generated.
	Encrypt(plaintext []byte, opts *types.EncryptOptions) (*types.EncryptedData, error)

	// Decrypt decrypts ciphertext using ChaCha20-Poly1305 AEAD.
	// Verifies the authentication tag before decrypting.
	// Returns an error if authentication fails.
	Decrypt(data *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error)

	// NonceSize returns the nonce size for this cipher (12 bytes for ChaCha20-Poly1305).
	NonceSize() int

	// Overhead returns the authentication tag overhead (16 bytes for Poly1305).
	Overhead() int
}

// chacha20poly1305AEAD implements the AEAD interface using ChaCha20-Poly1305.
type chacha20poly1305AEAD struct {
	aead      cipher.AEAD
	algorithm string
}

// New creates a new ChaCha20-Poly1305 AEAD cipher with the given key.
// The key must be exactly 32 bytes (256 bits).
//
// Example:
//
//	key := make([]byte, 32)
//	if _, err := rand.Read(key); err != nil {
//	    return err
//	}
//	cipher, err := chacha20poly1305.New(key)
//	if err != nil {
//	    return err
//	}
//	encrypted, err := cipher.Encrypt(plaintext, nil)
func New(key []byte) (AEAD, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key size: %d bytes (must be 32 bytes)", len(key))
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20-Poly1305 cipher: %w", err)
	}

	return &chacha20poly1305AEAD{
		aead:      aead,
		algorithm: string(types.SymmetricChaCha20Poly1305),
	}, nil
}

// NewX creates a new XChaCha20-Poly1305 AEAD cipher with the given key.
// XChaCha20-Poly1305 uses a 24-byte (192-bit) nonce instead of 12 bytes,
// making it more resistant to nonce reuse and suitable for random nonce generation.
//
// The key must be exactly 32 bytes (256 bits).
//
// Use XChaCha20-Poly1305 when:
// - You need random nonce generation without counter management
// - You want additional safety margin against nonce reuse
// - You're implementing protocols like age or WireGuard
func NewX(key []byte) (AEAD, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key size: %d bytes (must be 32 bytes)", len(key))
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20-Poly1305 cipher: %w", err)
	}

	return &chacha20poly1305AEAD{
		aead:      aead,
		algorithm: string(types.SymmetricXChaCha20Poly1305),
	}, nil
}

// Encrypt encrypts plaintext using ChaCha20-Poly1305 AEAD.
//
// The encryption process:
// 1. Generate a random nonce if not provided in opts
// 2. Encrypt plaintext with authenticated data
// 3. Return ciphertext with appended authentication tag
//
// Security notes:
// - Never reuse a nonce with the same key
// - For ChaCha20-Poly1305 (12-byte nonce), use a counter or random generation with care
// - For XChaCha20-Poly1305 (24-byte nonce), random generation is safe
func (c *chacha20poly1305AEAD) Encrypt(plaintext []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	if opts == nil {
		opts = &types.EncryptOptions{}
	}

	// Generate or validate nonce
	nonce := opts.Nonce
	nonceSize := c.aead.NonceSize()

	if nonce == nil {
		// Generate random nonce
		nonce = make([]byte, nonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("failed to generate nonce: %w", err)
		}
	} else if len(nonce) != nonceSize {
		return nil, fmt.Errorf("invalid nonce size: %d bytes (must be %d bytes)", len(nonce), nonceSize)
	}

	// Encrypt and authenticate
	// The Seal method appends the ciphertext and tag to dst
	ciphertextWithTag := c.aead.Seal(nil, nonce, plaintext, opts.AdditionalData)

	// Split ciphertext and tag
	// ChaCha20-Poly1305 appends the 16-byte tag to the ciphertext
	tagSize := c.aead.Overhead()
	if len(ciphertextWithTag) < tagSize {
		return nil, fmt.Errorf("ciphertext too short: %d bytes", len(ciphertextWithTag))
	}

	ciphertext := ciphertextWithTag[:len(ciphertextWithTag)-tagSize]
	tag := ciphertextWithTag[len(ciphertextWithTag)-tagSize:]

	return &types.EncryptedData{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Tag:        tag,
		Algorithm:  c.algorithm,
	}, nil
}

// Decrypt decrypts ciphertext using ChaCha20-Poly1305 AEAD.
//
// The decryption process:
// 1. Concatenate ciphertext and authentication tag
// 2. Verify authentication tag with authenticated data
// 3. Decrypt if authentication succeeds
// 4. Return error if authentication fails (prevents tampering)
//
// Security notes:
// - Authentication is verified before decryption (AEAD property)
// - Timing attacks are mitigated by constant-time comparison
// - Any tampering with ciphertext, tag, or additional data will be detected
func (c *chacha20poly1305AEAD) Decrypt(data *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	if data == nil {
		return nil, fmt.Errorf("encrypted data cannot be nil")
	}

	if opts == nil {
		opts = &types.DecryptOptions{}
	}

	// Validate nonce size
	nonceSize := c.aead.NonceSize()
	if len(data.Nonce) != nonceSize {
		return nil, fmt.Errorf("invalid nonce size: %d bytes (must be %d bytes)", len(data.Nonce), nonceSize)
	}

	// Validate tag size
	tagSize := c.aead.Overhead()
	if len(data.Tag) != tagSize {
		return nil, fmt.Errorf("invalid tag size: %d bytes (must be %d bytes)", len(data.Tag), tagSize)
	}

	// Concatenate ciphertext and tag for Open
	ciphertextWithTag := make([]byte, len(data.Ciphertext)+len(data.Tag))
	copy(ciphertextWithTag, data.Ciphertext)
	copy(ciphertextWithTag[len(data.Ciphertext):], data.Tag)

	// Decrypt and verify
	plaintext, err := c.aead.Open(nil, data.Nonce, ciphertextWithTag, opts.AdditionalData)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (authentication error): %w", err)
	}

	return plaintext, nil
}

// NonceSize returns the nonce size for this cipher.
// - ChaCha20-Poly1305: 12 bytes
// - XChaCha20-Poly1305: 24 bytes
func (c *chacha20poly1305AEAD) NonceSize() int {
	return c.aead.NonceSize()
}

// Overhead returns the authentication tag size (16 bytes for Poly1305).
func (c *chacha20poly1305AEAD) Overhead() int {
	return c.aead.Overhead()
}

// GenerateKey generates a new random 256-bit (32-byte) key for ChaCha20-Poly1305.
func GenerateKey() ([]byte, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return key, nil
}
