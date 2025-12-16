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

// Package ecdh provides Elliptic Curve Diffie-Hellman (ECDH) key agreement
// functionality for establishing shared secrets between parties.
//
// This package supports the NIST P-256, P-384, and P-521 curves and uses
// HKDF (HMAC-based Key Derivation Function) for deriving keys from shared secrets.
//
// Example usage:
//
//	// Generate key pairs for Alice and Bob
//	alicePriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
//	bobPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
//
//	// Alice derives shared secret using Bob's public key
//	aliceSecret, _ := ecdh.DeriveSharedSecret(alicePriv, &bobPriv.PublicKey)
//
//	// Bob derives shared secret using Alice's public key
//	bobSecret, _ := ecdh.DeriveSharedSecret(bobPriv, &alicePriv.PublicKey)
//
//	// Both secrets are identical
//	// aliceSecret == bobSecret
//
//	// Derive encryption key from shared secret
//	encKey, _ := ecdh.DeriveKey(aliceSecret, nil, []byte("encryption"), 32)
package ecdh

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DeriveSharedSecret performs ECDH key agreement between a private key and
// a public key, returning the shared secret.
//
// Both keys must use the same elliptic curve (P-256, P-384, or P-521).
// The shared secret is the raw output of the ECDH operation.
//
// For actual encryption keys, use DeriveKey() with the returned shared secret.
func DeriveSharedSecret(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}
	if publicKey == nil {
		return nil, fmt.Errorf("public key cannot be nil")
	}

	// Check that curves match
	if privateKey.Curve != publicKey.Curve {
		return nil, fmt.Errorf("curve mismatch: private key uses %s, public key uses %s",
			privateKey.Curve.Params().Name, publicKey.Curve.Params().Name)
	}

	// Convert ECDSA keys to crypto/ecdh keys
	ecdhPriv, err := ecdsaToECDH(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert private key: %w", err)
	}

	ecdhPub, err := ecdsaPublicToECDH(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key: %w", err)
	}

	// Perform ECDH
	sharedSecret, err := ecdhPriv.ECDH(ecdhPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH operation failed: %w", err)
	}

	return sharedSecret, nil
}

// DeriveKey derives a key of the specified length from a shared secret using
// HKDF-SHA256 (HMAC-based Key Derivation Function).
//
// Parameters:
//   - sharedSecret: The raw shared secret from ECDH
//   - salt: Optional salt value (can be nil)
//   - info: Context-specific information (e.g., "encryption", "mac")
//   - keyLength: Desired output key length in bytes
//
// HKDF provides key separation - different info values produce different keys
// from the same shared secret.
//
// Example:
//
//	encKey, _ := DeriveKey(secret, nil, []byte("aes-256-gcm"), 32)
//	macKey, _ := DeriveKey(secret, nil, []byte("hmac-sha256"), 32)
func DeriveKey(sharedSecret, salt, info []byte, keyLength int) ([]byte, error) {
	if sharedSecret == nil {
		return nil, fmt.Errorf("shared secret cannot be nil")
	}
	if keyLength <= 0 {
		return nil, fmt.Errorf("key length must be positive, got %d", keyLength)
	}

	// Create HKDF reader using SHA-256
	hkdfReader := hkdf.New(sha256.New, sharedSecret, salt, info)

	// Derive key
	derivedKey := make([]byte, keyLength)
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		return nil, fmt.Errorf("HKDF derivation failed: %w", err)
	}

	return derivedKey, nil
}

// ecdsaToECDH converts an ECDSA private key to crypto/ecdh private key
// Uses the native ECDH() method available in Go 1.20+
func ecdsaToECDH(key *ecdsa.PrivateKey) (*ecdh.PrivateKey, error) {
	// Use the native ECDH() method for conversion (Go 1.20+)
	ecdhKey, err := key.ECDH()
	if err != nil {
		return nil, fmt.Errorf("failed to convert ECDSA to ECDH private key: %w", err)
	}
	return ecdhKey, nil
}

// ecdsaPublicToECDH converts an ECDSA public key to crypto/ecdh public key
// Uses the native ECDH() method available in Go 1.20+
func ecdsaPublicToECDH(key *ecdsa.PublicKey) (*ecdh.PublicKey, error) {
	// Use the native ECDH() method for conversion (Go 1.20+)
	ecdhKey, err := key.ECDH()
	if err != nil {
		return nil, fmt.Errorf("failed to convert ECDSA to ECDH public key: %w", err)
	}
	return ecdhKey, nil
}
