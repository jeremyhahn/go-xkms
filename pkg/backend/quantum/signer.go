//go:build quantum

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

package quantum

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// MLDSAPublicKey represents a post-quantum ML-DSA public key
type MLDSAPublicKey struct {
	Algorithm string
	Key       []byte
}

// MLDSAPrivateKey represents a post-quantum ML-DSA private key
// that implements crypto.Signer for compatibility with Go's crypto interfaces
type MLDSAPrivateKey struct {
	Algorithm string
	PublicKey *MLDSAPublicKey
	signer    *oqs.Signature
}

// Public returns the public key corresponding to the private key.
func (k *MLDSAPrivateKey) Public() crypto.PublicKey {
	return k.PublicKey
}

// Sign signs digest with the private key.
// The signature algorithm is determined by the key type (ML-DSA-44, ML-DSA-65, ML-DSA-87).
// The opts and rand parameters are ignored as ML-DSA is deterministic.
func (k *MLDSAPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if k.signer == nil {
		return nil, ErrNotInitialized
	}

	// ML-DSA signs the full message, not just a digest
	// For compatibility with crypto.Signer, we treat the digest as the message
	signature, err := k.signer.Sign(digest)
	if err != nil {
		return nil, ErrSigningFailed
	}

	return signature, nil
}

// Verify verifies a ML-DSA signature
func (k *MLDSAPrivateKey) Verify(message, signature []byte) (bool, error) {
	if k.signer == nil {
		return false, ErrNotInitialized
	}

	return k.signer.Verify(message, signature, k.PublicKey.Key)
}

// Clean releases resources held by the signer
func (k *MLDSAPrivateKey) Clean() {
	if k.signer != nil {
		k.signer.Clean()
	}
}

// ExportSecretKey returns the secret key bytes
func (k *MLDSAPrivateKey) ExportSecretKey() []byte {
	if k.signer == nil {
		return nil
	}
	return k.signer.ExportSecretKey()
}

// MLKEMPublicKey represents a post-quantum ML-KEM public key
type MLKEMPublicKey struct {
	Algorithm string
	Key       []byte
}

// Bytes returns the raw public key bytes
func (pk *MLKEMPublicKey) Bytes() []byte {
	return pk.Key
}

// MLKEMPrivateKey represents a post-quantum ML-KEM private key
// ML-KEM is a Key Encapsulation Mechanism, not a direct encryption scheme
//
// AEAD Safety: When using Encrypt/Decrypt methods, this key uses AES-256-GCM
// internally and integrates with AEAD safety tracking to prevent nonce reuse
// and enforce byte limits per NIST SP 800-38D recommendations.
type MLKEMPrivateKey struct {
	Algorithm string
	PublicKey *MLKEMPublicKey
	kem       *oqs.KeyEncapsulation

	// AEAD tracking (optional - if nil, tracking is disabled)
	tracker types.AEADSafetyTracker
	keyID   string
}

// Public returns the public key
func (k *MLKEMPrivateKey) Public() crypto.PublicKey {
	return k.PublicKey
}

// Encapsulate generates a shared secret and ciphertext using a recipient's public key
func (k *MLKEMPrivateKey) Encapsulate(recipientPublicKey []byte) (ciphertext, sharedSecret []byte, err error) {
	if k.kem == nil {
		return nil, nil, ErrNotInitialized
	}

	ciphertext, sharedSecret, err = k.kem.EncapSecret(recipientPublicKey)
	if err != nil {
		return nil, nil, ErrEncapsulationFailed
	}

	return ciphertext, sharedSecret, nil
}

// Decapsulate recovers the shared secret from ciphertext
func (k *MLKEMPrivateKey) Decapsulate(ciphertext []byte) (sharedSecret []byte, err error) {
	if k.kem == nil {
		return nil, ErrNotInitialized
	}

	sharedSecret, err = k.kem.DecapSecret(ciphertext)
	if err != nil {
		return nil, ErrDecapsulationFailed
	}

	return sharedSecret, nil
}

// Clean releases resources held by the KEM
func (k *MLKEMPrivateKey) Clean() {
	if k.kem != nil {
		k.kem.Clean()
	}
}

// ExportSecretKey returns the secret key bytes
func (k *MLKEMPrivateKey) ExportSecretKey() []byte {
	if k.kem == nil {
		return nil
	}
	return k.kem.ExportSecretKey()
}

// Encrypt performs quantum-safe encryption using ML-KEM + AES-256-GCM.
// It encapsulates a shared secret to the recipient's public key, then uses
// that secret to encrypt the plaintext with AES-256-GCM.
//
// Returns:
//   - kemCiphertext: The encapsulated shared secret (send to recipient)
//   - encryptedData: The AES-GCM encrypted plaintext (send to recipient)
//   - error: Any error that occurred
//
// The recipient must receive both kemCiphertext and encryptedData to decrypt.
func (k *MLKEMPrivateKey) Encrypt(plaintext []byte, recipientPublicKey []byte) (kemCiphertext, encryptedData []byte, err error) {
	if k.kem == nil {
		return nil, nil, ErrNotInitialized
	}

	// Step 1: Encapsulate to establish shared secret
	kemCiphertext, sharedSecret, err := k.Encapsulate(recipientPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("encapsulation failed: %w", err)
	}
	defer func() {
		// Clear shared secret from memory
		for i := range sharedSecret {
			sharedSecret[i] = 0
		}
	}()

	// Step 2: Encrypt plaintext using shared secret as AES-256 key
	encryptedData, err = encryptWithAESGCM(plaintext, sharedSecret, nil, k.tracker, k.keyID)
	if err != nil {
		return nil, nil, fmt.Errorf("AES-GCM encryption failed: %w", err)
	}

	return kemCiphertext, encryptedData, nil
}

// Decrypt performs quantum-safe decryption using ML-KEM + AES-256-GCM.
// It decapsulates the shared secret from kemCiphertext, then uses that
// secret to decrypt the encryptedData with AES-256-GCM.
//
// Parameters:
//   - kemCiphertext: The encapsulated shared secret
//   - encryptedData: The AES-GCM encrypted plaintext
//
// Returns:
//   - plaintext: The decrypted data
//   - error: Any error that occurred
func (k *MLKEMPrivateKey) Decrypt(kemCiphertext, encryptedData []byte) (plaintext []byte, err error) {
	if k.kem == nil {
		return nil, ErrNotInitialized
	}

	// Step 1: Decapsulate to recover shared secret
	sharedSecret, err := k.Decapsulate(kemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("decapsulation failed: %w", err)
	}
	defer func() {
		// Clear shared secret from memory
		for i := range sharedSecret {
			sharedSecret[i] = 0
		}
	}()

	// Step 2: Decrypt using shared secret as AES-256 key
	plaintext, err = decryptWithAESGCM(encryptedData, sharedSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}

	return plaintext, nil
}

// EncryptWithAAD performs quantum-safe encryption with Additional Authenticated Data (AAD).
// Similar to Encrypt, but includes AAD in the authentication tag.
func (k *MLKEMPrivateKey) EncryptWithAAD(plaintext, aad []byte, recipientPublicKey []byte) (kemCiphertext, encryptedData []byte, err error) {
	if k.kem == nil {
		return nil, nil, ErrNotInitialized
	}

	// Step 1: Encapsulate to establish shared secret
	kemCiphertext, sharedSecret, err := k.Encapsulate(recipientPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("encapsulation failed: %w", err)
	}
	defer func() {
		for i := range sharedSecret {
			sharedSecret[i] = 0
		}
	}()

	// Step 2: Encrypt with AAD
	encryptedData, err = encryptWithAESGCM(plaintext, sharedSecret, aad, k.tracker, k.keyID)
	if err != nil {
		return nil, nil, fmt.Errorf("AES-GCM encryption failed: %w", err)
	}

	return kemCiphertext, encryptedData, nil
}

// DecryptWithAAD performs quantum-safe decryption with Additional Authenticated Data (AAD).
// Similar to Decrypt, but validates AAD in the authentication tag.
func (k *MLKEMPrivateKey) DecryptWithAAD(kemCiphertext, encryptedData, aad []byte) (plaintext []byte, err error) {
	if k.kem == nil {
		return nil, ErrNotInitialized
	}

	// Step 1: Decapsulate to recover shared secret
	sharedSecret, err := k.Decapsulate(kemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("decapsulation failed: %w", err)
	}
	defer func() {
		for i := range sharedSecret {
			sharedSecret[i] = 0
		}
	}()

	// Step 2: Decrypt with AAD validation
	plaintext, err = decryptWithAESGCM(encryptedData, sharedSecret, aad)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}

	return plaintext, nil
}

// encryptWithAESGCM encrypts plaintext using AES-256-GCM with the provided key.
// The nonce is randomly generated and prepended to the ciphertext.
//
// If tracker and keyID are provided, performs AEAD safety checks:
//   - Checks that the nonce hasn't been used before (prevents catastrophic nonce reuse)
//   - Records the nonce after successful encryption
//   - Tracks bytes encrypted to enforce NIST SP 800-38D limits
//
// Format: [nonce (12 bytes)][ciphertext][auth tag (16 bytes)]
func encryptWithAESGCM(plaintext, key, aad []byte, tracker types.AEADSafetyTracker, keyID string) ([]byte, error) {
	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// AEAD Safety: Check nonce hasn't been used (if tracker available)
	if tracker != nil && keyID != "" {
		if err := tracker.CheckNonce(keyID, nonce); err != nil {
			return nil, fmt.Errorf("nonce reuse detected: %w (CRITICAL SECURITY VIOLATION)", err)
		}
	}

	// AEAD Safety: Check bytes limit (if tracker available)
	if tracker != nil && keyID != "" {
		if err := tracker.IncrementBytes(keyID, int64(len(plaintext))); err != nil {
			return nil, fmt.Errorf("bytes limit exceeded: %w (key rotation required)", err)
		}
	}

	// Encrypt and authenticate
	// Format: nonce || gcm.Seal(plaintext)
	ciphertext := gcm.Seal(nonce, nonce, plaintext, aad)

	// AEAD Safety: Record nonce after successful encryption (if tracker available)
	if tracker != nil && keyID != "" {
		if err := tracker.RecordNonce(keyID, nonce); err != nil {
			// Log warning but don't fail - tracking is best-effort
			fmt.Printf("Warning: failed to record nonce for key %s: %v\n", keyID, err)
		}
	}

	return ciphertext, nil
}

// decryptWithAESGCM decrypts ciphertext using AES-256-GCM with the provided key.
// Expects the nonce to be prepended to the ciphertext (as created by encryptWithAESGCM).
func decryptWithAESGCM(ciphertext, key, aad []byte) ([]byte, error) {
	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Check minimum length: nonce + auth tag
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and actual ciphertext
	nonce := ciphertext[:nonceSize]
	actualCiphertext := ciphertext[nonceSize:]

	// Decrypt and verify
	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}
