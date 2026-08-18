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
	"slices"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/ecdh"
)

const (
	// Key size for AES-256
	aesKeySize = 32

	// GCM nonce size (96 bits / 12 bytes is standard)
	nonceSize = 12

	// GCM tag size (128 bits / 16 bytes)
	tagSize = 16
)

// Package-level functions that can be replaced during testing for error injection.
// These enable testing of defensive error handling paths that cannot be triggered
// with valid inputs.
var (
	// deriveKeyFunc wraps ecdh.DeriveKey for testability
	deriveKeyFunc = ecdh.DeriveKey

	// newAESCipherFunc wraps aes.NewCipher for testability
	newAESCipherFunc = aes.NewCipher

	// newGCMFunc wraps cipher.NewGCMWithRandomNonce for testability.
	//
	// NewGCMWithRandomNonce, not NewGCM: FIPS 140-3 (SP 800-38D, CMVP IG C.H)
	// requires the GCM IV be generated inside the module boundary, and
	// GODEBUG=fips140=only rejects an externally supplied one. Seal prepends
	// the nonce and Open strips it; splitting that output back into the nonce,
	// ciphertext and tag reproduces this package's existing
	// ephemeral_pub || nonce || tag || ciphertext wire format byte for byte, so
	// blobs written by earlier builds still decrypt.
	newGCMFunc = cipher.NewGCMWithRandomNonce
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
//   - random: retained for API compatibility and rejected when nil. Go 1.26's
//     ecdsa.GenerateKey draws the ephemeral key from crypto/rand regardless,
//     and the GCM nonce is generated inside the FIPS module boundary, so this
//     reader is not read from.
//   - publicKey: Recipient's ECDSA public key (P-256, P-384, or P-521)
//   - plaintext: Data to encrypt
//   - aad: Optional additional authenticated data (not encrypted, but authenticated)
//
// Returns encrypted data that can be decrypted by the private key holder.
func Encrypt(random io.Reader, publicKey *ecdsa.PublicKey, plaintext, aad []byte) ([]byte, error) {
	if random == nil {
		return nil, &errs.Message{Msg: "random source cannot be nil"}
	}
	if publicKey == nil {
		return nil, &errs.Message{Msg: "public key cannot be nil"}
	}
	if plaintext == nil {
		return nil, &errs.Message{Msg: "plaintext cannot be nil"}
	}

	// Generate ephemeral key pair on the same curve
	ephemeralPriv, err := ecdsa.GenerateKey(publicKey.Curve, random)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate ephemeral key", Err: err}
	}

	// Perform ECDH: ephemeral_private × recipient_public
	sharedSecret, err := ecdh.DeriveSharedSecret(ephemeralPriv, publicKey)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "ECDH failed", Err: err}
	}

	// Derive AES-256 encryption key using HKDF
	encKey, err := deriveKeyFunc(sharedSecret, nil, []byte("ecies-encryption"), aesKeySize)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "key derivation failed", Err: err}
	}

	// Create AES cipher
	block, err := newAESCipherFunc(encKey)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create cipher", Err: err}
	}

	// Create GCM mode
	gcm, err := newGCMFunc(block)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create GCM", Err: err}
	}

	// Encrypt plaintext. Seal emits nonce || ciphertext || tag; the nonce comes
	// from inside the module rather than from the caller-supplied random
	// source, which is still used for the ephemeral key above.
	sealed := gcm.Seal(nil, nil, plaintext, aad)

	// Split into the three pieces the wire format keeps in separate positions.
	// Note: Seal always returns at least nonceSize+tagSize bytes, so these
	// slices are always safe.
	nonce := sealed[:nonceSize]
	body := sealed[nonceSize:]
	ciphertext := body[:len(body)-tagSize]
	tag := body[len(body)-tagSize:]

	// Serialize ephemeral public key using modern crypto/ecdh (Go 1.20+)
	ecdhPub, err := ephemeralPriv.PublicKey.ECDH()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to convert ephemeral public key", Err: err}
	}
	ephemeralPubBytes := ecdhPub.Bytes()

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
		return nil, &errs.Message{Msg: "private key cannot be nil"}
	}
	if ciphertext == nil {
		return nil, &errs.Message{Msg: "ciphertext cannot be nil"}
	}

	// Determine ephemeral public key size based on curve
	pubKeySize := getPublicKeySize(privateKey.Curve)
	minSize := pubKeySize + nonceSize + tagSize

	if len(ciphertext) < minSize {
		return nil, &errs.Message{Msg: fmt.Sprintf("ciphertext too short: got %d bytes, need at least %d", len(ciphertext), minSize)}
	}

	// Extract components
	ephemeralPubBytes := ciphertext[:pubKeySize]
	nonce := ciphertext[pubKeySize : pubKeySize+nonceSize]
	tag := ciphertext[pubKeySize+nonceSize : pubKeySize+nonceSize+tagSize]
	encryptedData := ciphertext[pubKeySize+nonceSize+tagSize:]

	// Convert recipient private key to ECDH using modern Go 1.20+ API
	recipientECDH, err := privateKey.ECDH()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to convert recipient private key", Err: err}
	}

	// Parse ephemeral public key using modern crypto/ecdh API
	ephemeralPub, err := recipientECDH.Curve().NewPublicKey(ephemeralPubBytes)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse ephemeral public key", Err: err}
	}

	// Perform ECDH: recipient_private × ephemeral_public using modern API
	sharedSecret, err := recipientECDH.ECDH(ephemeralPub)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "ECDH failed", Err: err}
	}

	// Derive AES-256 encryption key using HKDF (same as encryption)
	encKey, err := deriveKeyFunc(sharedSecret, nil, []byte("ecies-encryption"), aesKeySize)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "key derivation failed", Err: err}
	}

	// Create AES cipher
	block, err := newAESCipherFunc(encKey)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create cipher", Err: err}
	}

	// Create GCM mode
	gcm, err := newGCMFunc(block)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create GCM", Err: err}
	}

	// Reconstruct the nonce || ciphertext || tag layout Open expects.
	fullCiphertext := slices.Concat(nonce, encryptedData, tag)

	// Decrypt and verify
	plaintext, err := gcm.Open(nil, nil, fullCiphertext, aad)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "decryption failed (authentication error)", Err: err}
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
