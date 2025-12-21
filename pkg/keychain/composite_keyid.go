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
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/types"
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
// If a backend is specified, it must match this keystore's backend.
// If no backend is specified, this keystore's backend is used.
//
// Example:
//
//	key, err := keystore.GetKeyByID("my-key")
//	key, err := keystore.GetKeyByID("pkcs11:signing:ecdsa-p256:my-key")
func (ks *compositeKeyStore) GetKeyByID(keyID string) (crypto.PrivateKey, error) {
	attrs, err := ks.parseAndValidateKeyID(keyID)
	if err != nil {
		return nil, err
	}

	// Retrieve the key from the backend
	key, err := ks.backend.GetKey(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve key %s: %w", keyID, err)
	}

	return key, nil
}

// GetSignerByID retrieves a crypto.Signer using the Key ID format.
// This is a convenience method that retrieves the key and ensures it
// implements the crypto.Signer interface.
//
// Example:
//
//	signer, err := keystore.GetSignerByID("my-key")
//	signer, err := keystore.GetSignerByID("tpm2:attestation:rsa:attestation-key")
//	signature, _ := signer.Sign(rand.Reader, digest, crypto.SHA256)
func (ks *compositeKeyStore) GetSignerByID(keyID string) (crypto.Signer, error) {
	attrs, err := ks.parseAndValidateKeyID(keyID)
	if err != nil {
		return nil, err
	}

	// Get signer from backend
	signer, err := ks.backend.Signer(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get signer for key %s: %w", keyID, err)
	}

	return signer, nil
}

// GetDecrypterByID retrieves a crypto.Decrypter using the Key ID format.
// This is a convenience method for RSA decryption operations.
//
// Example:
//
//	decrypter, err := keystore.GetDecrypterByID("my-key")
//	decrypter, err := keystore.GetDecrypterByID("awskms:encryption:rsa:rsa-key")
//	plaintext, _ := decrypter.Decrypt(rand.Reader, ciphertext, opts)
func (ks *compositeKeyStore) GetDecrypterByID(keyID string) (crypto.Decrypter, error) {
	attrs, err := ks.parseAndValidateKeyID(keyID)
	if err != nil {
		return nil, err
	}

	// Get decrypter from backend
	decrypter, err := ks.backend.Decrypter(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get decrypter for key %s: %w", keyID, err)
	}

	return decrypter, nil
}

// parseAndValidateKeyID parses a key ID and validates the backend matches.
// If no backend is specified in the keyID, it uses this keystore's backend.
func (ks *compositeKeyStore) parseAndValidateKeyID(keyID string) (*types.KeyAttributes, error) {
	// Parse the Key ID using the shared parser
	attrs, err := ParseKeyIDToAttributes(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key ID: %w", err)
	}

	// If a backend was specified, verify it matches this keystore
	if attrs.StoreType != "" {
		expectedBackend := ks.backend.Type()
		expectedStoreType := backendTypeToStoreType(expectedBackend)
		if attrs.StoreType != expectedStoreType {
			return nil, fmt.Errorf("%w: expected %s, got %s", ErrBackendMismatch, expectedStoreType, attrs.StoreType)
		}
	} else {
		// No backend specified - use this keystore's backend
		attrs.StoreType = backendTypeToStoreType(ks.backend.Type())
	}

	return attrs, nil
}
