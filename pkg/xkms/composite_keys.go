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

package xkms

import (
	"crypto"
	"crypto/x509"

	"github.com/jeremyhahn/go-xkms/pkg/opaque"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// ========================================================================
// Key Generation Operations
// ========================================================================

// GenerateRSA generates a new RSA key pair with the specified attributes.
// The key size must be specified in attrs.RSAAttributes.KeySize.
//
// Common sizes are 2048, 3072, and 4096 bits.
// The key is stored in the key provider and wrapped in an OpaqueKey for safe use.
func (c *compositeBackend) GenerateRSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}

	// Set algorithm
	attrs.KeyAlgorithm = x509.RSA

	// Generate the key using the key provider
	key, err := c.backend.GenerateKey(attrs)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "generate RSA key", Err: err}
	}

	// Wrap in OpaqueKey for safe operations
	pub := publicKey(key)
	if pub == nil {
		return nil, &ErrPublicKeyExtraction{Algorithm: "RSA"}
	}

	// Wrap in OpaqueKey - pass key provider attributes directly
	opaqueKey, err := opaque.NewOpaqueKey(c, attrs, pub)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "create opaque key", Err: err}
	}
	return opaqueKey, nil
}

// GenerateECDSA generates a new ECDSA key pair with the specified attributes.
// The elliptic curve must be specified in attrs.ECCAttributes.Curve.
//
// Common curves include P-256, P-384, and P-521.
// The key is stored in the key provider and wrapped in an OpaqueKey for safe use.
func (c *compositeBackend) GenerateECDSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}

	// Set algorithm
	attrs.KeyAlgorithm = x509.ECDSA

	// Generate the key using the key provider
	key, err := c.backend.GenerateKey(attrs)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "generate ECDSA key", Err: err}
	}

	// Wrap in OpaqueKey for safe operations
	pub := publicKey(key)
	if pub == nil {
		return nil, &ErrPublicKeyExtraction{Algorithm: "ECDSA"}
	}

	// Wrap in OpaqueKey - pass key provider attributes directly
	opaqueKey, err := opaque.NewOpaqueKey(c, attrs, pub)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "create opaque key", Err: err}
	}
	return opaqueKey, nil
}

// GenerateEd25519 generates a new Ed25519 key pair with the specified attributes.
// Ed25519 keys have a fixed size and do not require additional parameters.
//
// The key is stored in the key provider and wrapped in an OpaqueKey for safe use.
func (c *compositeBackend) GenerateEd25519(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}

	// Set algorithm
	attrs.KeyAlgorithm = x509.Ed25519

	// Generate the key using the key provider
	key, err := c.backend.GenerateKey(attrs)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "generate Ed25519 key", Err: err}
	}

	// Wrap in OpaqueKey for safe operations
	pub := publicKey(key)
	if pub == nil {
		return nil, &ErrPublicKeyExtraction{Algorithm: "Ed25519"}
	}

	// Wrap in OpaqueKey - pass key provider attributes directly
	opaqueKey, err := opaque.NewOpaqueKey(c, attrs, pub)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "create opaque key", Err: err}
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
func (c *compositeBackend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}

	// Get the key from the key provider
	key, err := c.backend.GetKey(attrs)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "get key", Err: err}
	}

	// Wrap in OpaqueKey for safe operations
	pub := publicKey(key)
	if pub == nil {
		return nil, &ErrPublicKeyExtraction{Algorithm: "retrieved"}
	}

	// Wrap in OpaqueKey - pass key provider attributes directly
	opaqueKey, err := opaque.NewOpaqueKey(c, attrs, pub)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "create opaque key", Err: err}
	}
	return opaqueKey, nil
}

// DeleteKey removes a key identified by its attributes.
// Returns an error if the key does not exist.
func (c *compositeBackend) DeleteKey(attrs *types.KeyAttributes) error {
	if attrs == nil {
		return ErrInvalidKeyAttributes
	}

	// Delete the key from the key provider
	if err := c.backend.DeleteKey(attrs); err != nil {
		return &ErrKeyOperation{Operation: "delete key", Err: err}
	}

	return nil
}

// ListKeys returns attributes for all keys managed by this xkms.
// Returns an empty slice if no keys exist.
func (c *compositeBackend) ListKeys() ([]*types.KeyAttributes, error) {
	// Get keys from key provider
	keys, err := c.backend.ListKeys()
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "list keys", Err: err}
	}

	return keys, nil
}

// RotateKey replaces an existing key with a newly generated key.
// This operation atomically deletes the old key and generates a new one
// with the same attributes.
//
// Returns the newly generated key wrapped in an OpaqueKey.
func (c *compositeBackend) RotateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}

	// Handle symmetric keys first
	if attrs.IsSymmetric() {
		// Delete the old key
		if err := c.DeleteKey(attrs); err != nil {
			return nil, &ErrKeyOperation{Operation: "delete old key during rotation", Err: err}
		}
		// Generate a new symmetric key
		symBackend, ok := c.backend.(types.SymmetricKeyProvider)
		if !ok {
			return nil, ErrSymmetricNotSupported
		}
		key, err := symBackend.GenerateSymmetricKey(attrs)
		if err != nil {
			return nil, err
		}
		return key, nil
	}

	// Delete the old key
	if err := c.DeleteKey(attrs); err != nil {
		return nil, &ErrKeyOperation{Operation: "delete old key during rotation", Err: err}
	}

	// Generate a new key based on the algorithm
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		return c.GenerateRSA(attrs)
	case x509.ECDSA:
		return c.GenerateECDSA(attrs)
	case x509.Ed25519:
		return c.GenerateEd25519(attrs)
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
