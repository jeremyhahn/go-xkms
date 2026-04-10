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

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// GetKeyByID retrieves a key using the Key ID format.
//
// The Key ID format is: backend:type:algo:keyname
// All segments except keyname are optional:
//   - "my-key" - shorthand for just keyname
//   - ":::my-key" - explicit form of above
//   - "pkcs11:::my-key" - specify backend only
//   - "pkcs11:signing:ecdsa-p256:my-key" - full specification
//
// If a backend is specified, it must match this backend's key provider.
// If no backend is specified, this backend's key provider is used.
//
// Example:
//
//	key, err := backend.GetKeyByID("my-key")
//	key, err := backend.GetKeyByID("pkcs11:signing:ecdsa-p256:my-key")
func (c *compositeBackend) GetKeyByID(keyID string) (crypto.PrivateKey, error) {
	attrs, err := c.parseAndValidateKeyID(keyID)
	if err != nil {
		return nil, err
	}

	// Retrieve the key from the key provider
	key, err := c.backend.GetKey(attrs)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "retrieve", KeyID: keyID, Err: err}
	}

	return key, nil
}

// GetSignerByID retrieves a crypto.Signer using the Key ID format.
// This is a convenience method that retrieves the key and ensures it
// implements the crypto.Signer interface.
//
// Example:
//
//	signer, err := backend.GetSignerByID("my-key")
//	signer, err := backend.GetSignerByID("tpm2:attestation:rsa:attestation-key")
//	signature, _ := signer.Sign(rand.Reader, digest, crypto.SHA256)
func (c *compositeBackend) GetSignerByID(keyID string) (crypto.Signer, error) {
	attrs, err := c.parseAndValidateKeyID(keyID)
	if err != nil {
		return nil, err
	}

	// Get signer from key provider
	signer, err := c.backend.Signer(attrs)
	if err != nil {
		return nil, &ErrCryptoOperation{Operation: "signer", KeyID: keyID, Err: err}
	}

	return signer, nil
}

// GetDecrypterByID retrieves a crypto.Decrypter using the Key ID format.
// This is a convenience method for RSA decryption operations.
//
// Example:
//
//	decrypter, err := backend.GetDecrypterByID("my-key")
//	decrypter, err := backend.GetDecrypterByID("awskms:encryption:rsa:rsa-key")
//	plaintext, _ := decrypter.Decrypt(rand.Reader, ciphertext, opts)
func (c *compositeBackend) GetDecrypterByID(keyID string) (crypto.Decrypter, error) {
	attrs, err := c.parseAndValidateKeyID(keyID)
	if err != nil {
		return nil, err
	}

	// Get decrypter from key provider
	decrypter, err := c.backend.Decrypter(attrs)
	if err != nil {
		return nil, &ErrCryptoOperation{Operation: "decrypter", KeyID: keyID, Err: err}
	}

	return decrypter, nil
}

// parseAndValidateKeyID parses a key ID and validates the key provider matches.
// If no backend is specified in the keyID, it uses this backend's key provider.
func (c *compositeBackend) parseAndValidateKeyID(keyID string) (*types.KeyAttributes, error) {
	// Parse the Key ID using the shared parser
	attrs, err := ParseKeyIDToAttributes(keyID)
	if err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}

	// If a backend was specified, verify it matches this backend's key provider
	if attrs.StoreType != "" {
		expectedBackend := c.backend.Type()
		expectedStoreType := backendTypeToStoreType(expectedBackend)
		if attrs.StoreType != expectedStoreType {
			return nil, &ErrBackendLookup{
				Sentinel: ErrBackendMismatch,
				Name:     string(expectedStoreType) + " (expected), " + string(attrs.StoreType) + " (got)",
			}
		}
	} else {
		// No backend specified - use this backend's key provider
		attrs.StoreType = backendTypeToStoreType(c.backend.Type())
	}

	return attrs, nil
}
