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

package encoding

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/youmark/pkcs8"
)

// EncodePKCS8 encodes a private key to ASN.1 DER PKCS#8 format.
// If a password is provided, the key will be encrypted.
// If password is nil or empty, the key will be encoded without encryption.
//
// Supported key types: *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey
//
// Example:
//
//	der, err := encoding.EncodePKCS8(privateKey, []byte("mypassword"))
func EncodePKCS8(privateKey crypto.PrivateKey, password []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, ErrInvalidPrivateKey
	}

	// Use youmark/pkcs8 package which handles encryption
	der, err := pkcs8.MarshalPrivateKey(privateKey, password, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PKCS#8: %w", err)
	}

	return der, nil
}

// DecodePKCS8 decodes ASN.1 DER PKCS#8 encoded data to a private key.
// If the data is encrypted, a password must be provided.
// If password is nil or empty and the data is encrypted, this will return ErrPasswordRequired.
//
// Returns the private key as crypto.PrivateKey (type assert to specific type if needed).
//
// Example:
//
//	key, err := encoding.DecodePKCS8(derData, []byte("mypassword"))
//	rsaKey := key.(*rsa.PrivateKey)
func DecodePKCS8(data []byte, password []byte) (crypto.PrivateKey, error) {
	if len(data) == 0 {
		return nil, ErrInvalidData
	}

	// Parse the PKCS#8 data
	key, err := pkcs8.ParsePKCS8PrivateKey(data, password)
	if err != nil {
		// Check for common error cases
		if isPasswordError(err) {
			return nil, ErrInvalidPassword
		}
		return nil, fmt.Errorf("failed to parse PKCS#8: %w", err)
	}

	// Type assertion - pkcs8 returns interface{}
	privKey, ok := key.(crypto.PrivateKey)
	if !ok {
		return nil, ErrInvalidPrivateKey
	}

	return privKey, nil
}

// EncodePublicKeyPKIX encodes a public key to ASN.1 DER PKIX format.
// This is the standard format for public keys (SubjectPublicKeyInfo).
//
// Supported key types: *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey
//
// Example:
//
//	der, err := encoding.EncodePublicKeyPKIX(publicKey)
func EncodePublicKeyPKIX(publicKey crypto.PublicKey) ([]byte, error) {
	if publicKey == nil {
		return nil, ErrInvalidPublicKey
	}

	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PKIX public key: %w", err)
	}

	return der, nil
}

// DecodePublicKeyPKIX decodes ASN.1 DER PKIX encoded data to a public key.
//
// Returns the public key as crypto.PublicKey (type assert to specific type if needed).
//
// Example:
//
//	key, err := encoding.DecodePublicKeyPKIX(derData)
//	rsaPub := key.(*rsa.PublicKey)
func DecodePublicKeyPKIX(data []byte) (crypto.PublicKey, error) {
	if len(data) == 0 {
		return nil, ErrInvalidData
	}

	pubKey, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}

	return pubKey, nil
}

// isPasswordError checks if an error is related to incorrect password.
// The pkcs8 package returns various error messages for password issues.
func isPasswordError(err error) bool {
	if err == nil {
		return false
	}

	errMsg := err.Error()

	// Common password-related error messages from youmark/pkcs8
	passwordErrors := []string{
		"pkcs8: incorrect password",
		"incorrect password",
		"asn1: structure error",
		"tags don't match",
	}

	for _, msg := range passwordErrors {
		if contains(errMsg, msg) {
			return true
		}
	}

	return false
}

// contains checks if a string contains a substring (case-sensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr || len(s) > len(substr) &&
			indexOf(s, substr) >= 0)
}

// indexOf returns the index of substr in s, or -1 if not found
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
