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

package x25519

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// KeyPair represents an X25519 key pair.
type KeyPair struct {
	PrivateKey *ecdh.PrivateKey
	PublicKey  *ecdh.PublicKey
}

// KeyAgreement provides X25519 Diffie-Hellman key agreement operations.
// This interface allows for key generation and shared secret derivation
// using the X25519 elliptic curve (Curve25519 for ECDH).
//
// X25519 is designed for key agreement and provides:
// - Fast key agreement operations
// - Simple, constant-time implementation
// - 128-bit security level
// - Compatible with age encryption and modern protocols
//
// Note: X25519 is related to Ed25519 but serves a different purpose:
// - Ed25519: Digital signatures (signing/verification)
// - X25519: Key agreement (shared secret derivation)
type KeyAgreement interface {
	// GenerateKey generates a new X25519 key pair.
	// Returns the private and public keys, or an error if generation fails.
	GenerateKey() (*KeyPair, error)

	// DeriveSharedSecret performs X25519 key agreement between a private key
	// and a peer's public key to derive a shared secret.
	// The shared secret should be used with a KDF (like HKDF) before use.
	DeriveSharedSecret(privateKey *ecdh.PrivateKey, peerPublicKey *ecdh.PublicKey) ([]byte, error)

	// DeriveKey derives a key from a shared secret using HKDF-SHA256.
	// This is the recommended way to use the shared secret from DeriveSharedSecret.
	//
	// Parameters:
	//   - sharedSecret: The output from DeriveSharedSecret
	//   - salt: Optional salt value (can be nil)
	//   - info: Context and application specific information (can be nil)
	//   - keyLength: Desired output key length in bytes
	DeriveKey(sharedSecret, salt, info []byte, keyLength int) ([]byte, error)
}

// x25519KeyAgreement implements the KeyAgreement interface using crypto/ecdh.
type x25519KeyAgreement struct {
	curve ecdh.Curve
}

// New creates a new X25519 key agreement instance.
func New() KeyAgreement {
	return &x25519KeyAgreement{
		curve: ecdh.X25519(),
	}
}

// GenerateKey generates a new X25519 key pair using crypto/rand.
func (ka *x25519KeyAgreement) GenerateKey() (*KeyPair, error) {
	privateKey, err := ka.curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate X25519 key: %w", err)
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  privateKey.PublicKey(),
	}, nil
}

// DeriveSharedSecret performs X25519 ECDH to derive a shared secret.
// The shared secret should not be used directly - use DeriveKey instead.
func (ka *x25519KeyAgreement) DeriveSharedSecret(privateKey *ecdh.PrivateKey, peerPublicKey *ecdh.PublicKey) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}
	if peerPublicKey == nil {
		return nil, fmt.Errorf("peer public key cannot be nil")
	}

	// Verify the keys are X25519 keys
	if privateKey.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("private key must be X25519, got %v", privateKey.Curve())
	}
	if peerPublicKey.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("peer public key must be X25519, got %v", peerPublicKey.Curve())
	}

	sharedSecret, err := privateKey.ECDH(peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("X25519 key agreement failed: %w", err)
	}

	return sharedSecret, nil
}

// DeriveKey derives a key from a shared secret using HKDF-SHA256.
// This implements the HKDF-Extract-and-Expand pattern for key derivation.
//
// HKDF is recommended because:
// - The raw ECDH output is not uniformly distributed
// - HKDF produces cryptographically strong key material
// - Supports multiple derived keys from one shared secret
// - Binds the key to application context via 'info'
func (ka *x25519KeyAgreement) DeriveKey(sharedSecret, salt, info []byte, keyLength int) ([]byte, error) {
	if len(sharedSecret) == 0 {
		return nil, fmt.Errorf("shared secret cannot be empty")
	}
	if keyLength <= 0 {
		return nil, fmt.Errorf("key length must be positive, got %d", keyLength)
	}
	if keyLength > 255*32 { // HKDF-SHA256 limit
		return nil, fmt.Errorf("key length too large: %d (max 8160 bytes for HKDF-SHA256)", keyLength)
	}

	// Use HKDF-SHA256 to derive the key
	// This is the standard approach used by age and other modern protocols
	reader := hkdf.New(sha256.New, sharedSecret, salt, info)

	derivedKey := make([]byte, keyLength)
	if _, err := io.ReadFull(reader, derivedKey); err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	return derivedKey, nil
}

// ParsePrivateKey parses an X25519 private key from raw bytes.
// The input should be 32 bytes.
func ParsePrivateKey(privateKeyBytes []byte) (*ecdh.PrivateKey, error) {
	if len(privateKeyBytes) != 32 {
		return nil, fmt.Errorf("X25519 private key must be 32 bytes, got %d", len(privateKeyBytes))
	}

	return ecdh.X25519().NewPrivateKey(privateKeyBytes)
}

// ParsePublicKey parses an X25519 public key from raw bytes.
// The input should be 32 bytes.
func ParsePublicKey(publicKeyBytes []byte) (*ecdh.PublicKey, error) {
	if len(publicKeyBytes) != 32 {
		return nil, fmt.Errorf("X25519 public key must be 32 bytes, got %d", len(publicKeyBytes))
	}

	return ecdh.X25519().NewPublicKey(publicKeyBytes)
}

// PrivateKeyBytes returns the raw bytes of an X25519 private key.
func PrivateKeyBytes(privateKey *ecdh.PrivateKey) []byte {
	return privateKey.Bytes()
}

// PublicKeyBytes returns the raw bytes of an X25519 public key.
func PublicKeyBytes(publicKey *ecdh.PublicKey) []byte {
	return publicKey.Bytes()
}
