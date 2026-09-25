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
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
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
		return nil, &errs.Message{Msg: "private key cannot be nil"}
	}
	if publicKey == nil {
		return nil, &errs.Message{Msg: "public key cannot be nil"}
	}

	// Check that curves match
	if privateKey.Curve != publicKey.Curve {
		return nil, &errs.Message{Msg: fmt.Sprintf("curve mismatch: private key uses %s, public key uses %s", privateKey.Curve.Params().Name, publicKey.Curve.Params().Name)}
	}

	// Convert ECDSA keys to crypto/ecdh keys
	ecdhPriv, err := ecdsaToECDH(privateKey)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to convert private key", Err: err}
	}

	ecdhPub, err := ecdsaPublicToECDH(publicKey)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to convert public key", Err: err}
	}

	// Perform ECDH
	sharedSecret, err := ecdhPriv.ECDH(ecdhPub)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "ECDH operation failed", Err: err}
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
		return nil, &errs.Message{Msg: "shared secret cannot be nil"}
	}
	if keyLength <= 0 {
		return nil, &errs.Message{Msg: fmt.Sprintf("key length must be positive, got %d", keyLength)}
	}

	// crypto/hkdf.Key (the stdlib RFC 5869 implementation, Go 1.24+) is used
	// instead of golang.org/x/crypto/hkdf.New: the x/crypto Reader
	// constructor converts the stdlib's own FIPS 140-only refusals (short
	// shared secret, an over-length request) into a panic, which would crash
	// this process instead of returning the error this function promises.
	derivedKey, err := hkdf.Key(sha256.New, sharedSecret, salt, string(info), keyLength)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "HKDF derivation failed", Err: err}
	}

	return derivedKey, nil
}

// ecdsaToECDH converts an ECDSA private key to crypto/ecdh private key
// Uses the native ECDH() method available in Go 1.20+
func ecdsaToECDH(key *ecdsa.PrivateKey) (*ecdh.PrivateKey, error) {
	// Use the native ECDH() method for conversion (Go 1.20+)
	ecdhKey, err := key.ECDH()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to convert ECDSA to ECDH private key", Err: err}
	}
	return ecdhKey, nil
}

// ecdsaPublicToECDH converts an ECDSA public key to crypto/ecdh public key
// Uses the native ECDH() method available in Go 1.20+
func ecdsaPublicToECDH(key *ecdsa.PublicKey) (*ecdh.PublicKey, error) {
	// Use the native ECDH() method for conversion (Go 1.20+)
	ecdhKey, err := key.ECDH()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to convert ECDSA to ECDH public key", Err: err}
	}
	return ecdhKey, nil
}
