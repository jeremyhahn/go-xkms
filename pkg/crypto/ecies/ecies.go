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

// Package ecies provides Elliptic Curve Integrated Encryption Scheme (ECIES)
// for public key encryption using ECDSA keys.
//
// ECIES combines:
//  1. ECDH for key agreement (ephemeral-static)
//  2. HKDF for key derivation
//  3. AES-256-GCM for authenticated encryption
//
// The encryption format is:
//
//	[ephemeral_public_key || nonce || tag || ciphertext]
//
// Where:
//   - ephemeral_public_key: Uncompressed EC point (65/97/133 bytes for P-256/P-384/P-521)
//   - nonce: 12 bytes (GCM standard)
//   - tag: 16 bytes (GCM authentication tag)
//   - ciphertext: variable length
//
// Example usage:
//
//	// Generate recipient key pair
//	recipientPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
//
//	// Encrypt message with recipient's public key
//	plaintext := []byte("Secret message")
//	ciphertext, _ := ecies.Encrypt(rand.Reader, &recipientPriv.PublicKey, plaintext, nil)
//
//	// Decrypt with recipient's private key
//	decrypted, _ := ecies.Decrypt(recipientPriv, ciphertext, nil)
package ecies

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"io"

	"github.com/jeremyhahn/go-keychain/pkg/crypto/ecdh"
)

const (
	// Key size for AES-256
	aesKeySize = 32

	// GCM nonce size (96 bits / 12 bytes is standard)
	nonceSize = 12

	// GCM tag size (128 bits / 16 bytes)
	tagSize = 16
)

// Encrypt encrypts plaintext using ECIES with the recipient's public key.
//
// The encryption process:
//  1. Generate ephemeral EC key pair
//  2. Perform ECDH with ephemeral private key and recipient's public key
//  3. Derive AES-256 key using HKDF from shared secret
//  4. Encrypt plaintext using AES-256-GCM
//  5. Return: ephemeral_public_key || nonce || tag || ciphertext
//
// Parameters:
//   - random: Cryptographically secure random source (typically crypto/rand.Reader)
//   - publicKey: Recipient's ECDSA public key (P-256, P-384, or P-521)
//   - plaintext: Data to encrypt
//   - aad: Optional additional authenticated data (not encrypted, but authenticated)
//
// Returns encrypted data that can be decrypted by the private key holder.
func Encrypt(random io.Reader, publicKey *ecdsa.PublicKey, plaintext, aad []byte) ([]byte, error) {
	if random == nil {
		return nil, fmt.Errorf("random source cannot be nil")
	}
	if publicKey == nil {
		return nil, fmt.Errorf("public key cannot be nil")
	}
	if plaintext == nil {
		return nil, fmt.Errorf("plaintext cannot be nil")
	}

	// Generate ephemeral key pair on the same curve
	ephemeralPriv, err := ecdsa.GenerateKey(publicKey.Curve, random)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Perform ECDH: ephemeral_private × recipient_public
	sharedSecret, err := ecdh.DeriveSharedSecret(ephemeralPriv, publicKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Derive AES-256 encryption key using HKDF
	encKey, err := ecdh.DeriveKey(sharedSecret, nil, []byte("ecies-encryption"), aesKeySize)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt plaintext (GCM appends tag to ciphertext)
	ciphertextWithTag := gcm.Seal(nil, nonce, plaintext, aad)

	// Extract tag from end
	// Note: GCM.Seal always returns at least tagSize bytes (the authentication tag)
	// so this operation is always safe
	ciphertext := ciphertextWithTag[:len(ciphertextWithTag)-tagSize]
	tag := ciphertextWithTag[len(ciphertextWithTag)-tagSize:]

	// Serialize ephemeral public key (uncompressed format)
	ephemeralPubBytes := elliptic.Marshal(ephemeralPriv.Curve, ephemeralPriv.X, ephemeralPriv.Y)

	// Build final output: ephemeral_pub || nonce || tag || ciphertext
	result := make([]byte, 0, len(ephemeralPubBytes)+nonceSize+tagSize+len(ciphertext))
	result = append(result, ephemeralPubBytes...)
	result = append(result, nonce...)
	result = append(result, tag...)
	result = append(result, ciphertext...)

	return result, nil
}

// Decrypt decrypts ECIES ciphertext using the recipient's private key.
//
// The decryption process:
//  1. Extract ephemeral public key from ciphertext
//  2. Perform ECDH with recipient's private key and ephemeral public key
//  3. Derive AES-256 key using HKDF from shared secret
//  4. Decrypt ciphertext using AES-256-GCM
//  5. Return plaintext
//
// Parameters:
//   - privateKey: Recipient's ECDSA private key
//   - ciphertext: Encrypted data from Encrypt()
//   - aad: Optional additional authenticated data (must match encryption)
//
// Returns the original plaintext or an error if decryption fails.
func Decrypt(privateKey *ecdsa.PrivateKey, ciphertext, aad []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}
	if ciphertext == nil {
		return nil, fmt.Errorf("ciphertext cannot be nil")
	}

	// Determine ephemeral public key size based on curve
	pubKeySize := getPublicKeySize(privateKey.Curve)
	minSize := pubKeySize + nonceSize + tagSize

	if len(ciphertext) < minSize {
		return nil, fmt.Errorf("ciphertext too short: got %d bytes, need at least %d",
			len(ciphertext), minSize)
	}

	// Extract components
	ephemeralPubBytes := ciphertext[:pubKeySize]
	nonce := ciphertext[pubKeySize : pubKeySize+nonceSize]
	tag := ciphertext[pubKeySize+nonceSize : pubKeySize+nonceSize+tagSize]
	encryptedData := ciphertext[pubKeySize+nonceSize+tagSize:]

	// Deserialize ephemeral public key
	ephemeralX, ephemeralY := elliptic.Unmarshal(privateKey.Curve, ephemeralPubBytes)
	if ephemeralX == nil {
		return nil, fmt.Errorf("failed to unmarshal ephemeral public key")
	}

	ephemeralPub := &ecdsa.PublicKey{
		Curve: privateKey.Curve,
		X:     ephemeralX,
		Y:     ephemeralY,
	}

	// Perform ECDH: recipient_private × ephemeral_public
	sharedSecret, err := ecdh.DeriveSharedSecret(privateKey, ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Derive AES-256 encryption key using HKDF (same as encryption)
	encKey, err := ecdh.DeriveKey(sharedSecret, nil, []byte("ecies-encryption"), aesKeySize)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Reconstruct ciphertext with tag for GCM
	fullCiphertext := append(encryptedData, tag...)

	// Decrypt and verify
	plaintext, err := gcm.Open(nil, nonce, fullCiphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (authentication error): %w", err)
	}

	return plaintext, nil
}

// getPublicKeySize returns the size of an uncompressed public key for the given curve
func getPublicKeySize(curve elliptic.Curve) int {
	switch curve.Params().Name {
	case "P-256":
		return 65 // 1 (format) + 32 (x) + 32 (y)
	case "P-384":
		return 97 // 1 (format) + 48 (x) + 48 (y)
	case "P-521":
		return 133 // 1 (format) + 66 (x) + 66 (y)
	default:
		return 0
	}
}
