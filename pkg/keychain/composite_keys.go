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

package keychain

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/opaque"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// ========================================================================
// Key Generation Operations
// ========================================================================

// GenerateRSA generates a new RSA key pair with the specified attributes.
// The key size must be specified in attrs.RSAAttributes.KeySize.
//
// Common sizes are 2048, 3072, and 4096 bits.
// The key is stored in the backend and wrapped in an OpaqueKey for safe use.
func (ks *compositeKeyStore) GenerateRSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}

	// Set algorithm
	attrs.KeyAlgorithm = x509.RSA

	// Generate the key using the backend
	key, err := ks.backend.GenerateKey(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Wrap in OpaqueKey for safe operations
	pub := publicKey(key)
	if pub == nil {
		return nil, fmt.Errorf("failed to extract public key from generated RSA key")
	}

	// Wrap in OpaqueKey - pass backend attributes directly
	opaqueKey, err := opaque.NewOpaqueKey(ks, attrs, pub)
	if err != nil {
		return nil, fmt.Errorf("failed to create opaque key: %w", err)
	}
	return opaqueKey, nil
}

// GenerateECDSA generates a new ECDSA key pair with the specified attributes.
// The elliptic curve must be specified in attrs.ECCAttributes.Curve.
//
// Common curves include P-256, P-384, and P-521.
// The key is stored in the backend and wrapped in an OpaqueKey for safe use.
func (ks *compositeKeyStore) GenerateECDSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}

	// Set algorithm
	attrs.KeyAlgorithm = x509.ECDSA

	// Generate the key using the backend
	key, err := ks.backend.GenerateKey(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	// Wrap in OpaqueKey for safe operations
	pub := publicKey(key)
	if pub == nil {
		return nil, fmt.Errorf("failed to extract public key from generated ECDSA key")
	}

	// Wrap in OpaqueKey - pass backend attributes directly
	opaqueKey, err := opaque.NewOpaqueKey(ks, attrs, pub)
	if err != nil {
		return nil, fmt.Errorf("failed to create opaque key: %w", err)
	}
	return opaqueKey, nil
}

// GenerateEd25519 generates a new Ed25519 key pair with the specified attributes.
// Ed25519 keys have a fixed size and do not require additional parameters.
//
// The key is stored in the backend and wrapped in an OpaqueKey for safe use.
func (ks *compositeKeyStore) GenerateEd25519(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}

	// Set algorithm
	attrs.KeyAlgorithm = x509.Ed25519

	// Generate the key using the backend
	key, err := ks.backend.GenerateKey(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}

	// Wrap in OpaqueKey for safe operations
	pub := publicKey(key)
	if pub == nil {
		return nil, fmt.Errorf("failed to extract public key from generated Ed25519 key")
	}

	// Wrap in OpaqueKey - pass backend attributes directly
	opaqueKey, err := opaque.NewOpaqueKey(ks, attrs, pub)
	if err != nil {
		return nil, fmt.Errorf("failed to create opaque key: %w", err)
	}
	return opaqueKey, nil
}

// ========================================================================
// Key Retrieval and Management Operations
// ========================================================================

// GetKey retrieves an existing private key by its attributes.
// Returns an error if the key does not exist.
//
// The key is wrapped in an OpaqueKey for safe operations.
func (ks *compositeKeyStore) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}

	// Get the key from the backend
	key, err := ks.backend.GetKey(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	// Wrap in OpaqueKey for safe operations
	pub := publicKey(key)
	if pub == nil {
		return nil, fmt.Errorf("failed to extract public key from retrieved key")
	}

	// Wrap in OpaqueKey - pass backend attributes directly
	opaqueKey, err := opaque.NewOpaqueKey(ks, attrs, pub)
	if err != nil {
		return nil, fmt.Errorf("failed to create opaque key: %w", err)
	}
	return opaqueKey, nil
}

// DeleteKey removes a key identified by its attributes.
// Returns an error if the key does not exist.
func (ks *compositeKeyStore) DeleteKey(attrs *types.KeyAttributes) error {
	if attrs == nil {
		return ErrInvalidKeyAttributes
	}

	// Delete the key from the backend
	if err := ks.backend.DeleteKey(attrs); err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}

	return nil
}

// ListKeys returns attributes for all keys managed by this keychain.
// Returns an empty slice if no keys exist.
func (ks *compositeKeyStore) ListKeys() ([]*types.KeyAttributes, error) {
	// Get keys from backend
	keys, err := ks.backend.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	return keys, nil
}

// RotateKey replaces an existing key with a newly generated key.
// This operation atomically deletes the old key and generates a new one
// with the same attributes.
//
// Returns the newly generated key wrapped in an OpaqueKey.
func (ks *compositeKeyStore) RotateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}

	// Delete the old key
	if err := ks.DeleteKey(attrs); err != nil {
		return nil, fmt.Errorf("failed to delete old key during rotation: %w", err)
	}

	// Generate a new key based on the algorithm
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		return ks.GenerateRSA(attrs)
	case x509.ECDSA:
		return ks.GenerateECDSA(attrs)
	case x509.Ed25519:
		return ks.GenerateEd25519(attrs)
	default:
		return nil, ErrUnsupportedKeyAlgorithm
	}
}

// ========================================================================
// Helper Functions
// ========================================================================

// publicKey extracts the public key from a private key
func publicKey(priv crypto.PrivateKey) crypto.PublicKey {
	if priv == nil {
		return nil
	}

	type publicKeyer interface {
		Public() crypto.PublicKey
	}

	if pk, ok := priv.(publicKeyer); ok {
		return pk.Public()
	}

	return nil
}
