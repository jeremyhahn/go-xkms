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

package jwe

import (
	"crypto"
	"fmt"
)

// XKMSEncrypter encrypts JWE using keys from a xkms/keystore.
// It provides hardware-backed JWE encryption by looking up public keys by ID.
//
// This is useful for integrating with hardware security modules (HSM), TPM,
// PKCS#11 devices, or any key management system where keys are identified by ID.
type XKMSEncrypter struct {
	keyEncAlg string
	encAlg    string
	getKey    func(keyID string) (crypto.PublicKey, error)
}

// NewXKMSEncrypter creates a new xkms-backed JWE encrypter.
//
// Parameters:
//   - keyEncAlg: Key encryption algorithm (e.g., "RSA-OAEP", "RSA-OAEP-256", "ECDH-ES+A256KW")
//   - encAlg: Content encryption algorithm (e.g., "A256GCM", "A192GCM")
//   - getKey: Function to retrieve public key by ID from xkms
//
// The getKey function should return a crypto.PublicKey (*rsa.PublicKey or *ecdsa.PublicKey)
// for the given key identifier, or an error if the key cannot be found.
//
// Example:
//
//	encrypter, err := jwe.NewXKMSEncrypter(
//	    "RSA-OAEP-256",
//	    "A256GCM",
//	    func(keyID string) (crypto.PublicKey, error) {
//	        return keystore.GetPublicKey(keyID)
//	    },
//	)
//	if err != nil {
//	    return err
//	}
//
//	jweString, err := encrypter.EncryptWithKeyID(plaintext, "tpm2:encryption-key")
func NewXKMSEncrypter(keyEncAlg, encAlg string, getKey func(string) (crypto.PublicKey, error)) (*XKMSEncrypter, error) {
	if getKey == nil {
		return nil, fmt.Errorf("getKey function cannot be nil")
	}

	// Validate algorithms
	if _, err := parseKeyAlgorithm(keyEncAlg); err != nil {
		return nil, err
	}
	if _, err := parseContentEncryption(encAlg); err != nil {
		return nil, err
	}

	return &XKMSEncrypter{
		keyEncAlg: keyEncAlg,
		encAlg:    encAlg,
		getKey:    getKey,
	}, nil
}

// EncryptWithKeyID encrypts plaintext using a key identified by keyID.
// The keyID is included in the JWE header for later key lookup during decryption.
//
// This method:
// 1. Retrieves the public key from the xkms using the provided keyID
// 2. Creates a JWE encrypter with that key
// 3. Encrypts the plaintext and includes the keyID in the JWE header
//
// Parameters:
//   - plaintext: The data to encrypt
//   - keyID: The key identifier (e.g., "tpm2:encryption-key", "pkcs11:rsa-2048", "hsm:key-001")
//
// Returns the JWE string in compact serialization format with kid header.
//
// Example:
//
//	jweString, err := encrypter.EncryptWithKeyID(
//	    []byte("sensitive data"),
//	    "tpm2:encryption-key",
//	)
func (e *XKMSEncrypter) EncryptWithKeyID(plaintext []byte, keyID string) (string, error) {
	if keyID == "" {
		return "", fmt.Errorf("keyID cannot be empty")
	}

	// Retrieve public key from xkms
	publicKey, err := e.getKey(keyID)
	if err != nil {
		return "", fmt.Errorf("failed to get key %s: %w", keyID, err)
	}

	// Create encrypter with the retrieved key
	encrypter, err := NewEncrypter(e.keyEncAlg, e.encAlg, publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to create encrypter: %w", err)
	}

	// Encrypt with kid in header
	header := map[string]interface{}{
		"kid": keyID,
	}

	return encrypter.EncryptWithHeader(plaintext, header)
}

// Encrypt encrypts plaintext using a key retrieved by keyID, but doesn't include
// the kid in the JWE header. Use EncryptWithKeyID instead for xkms integration
// where automatic key lookup during decryption is desired.
//
// Example:
//
//	jweString, err := encrypter.Encrypt(plaintext, "tpm2:encryption-key")
func (e *XKMSEncrypter) Encrypt(plaintext []byte, keyID string) (string, error) {
	if keyID == "" {
		return "", fmt.Errorf("keyID cannot be empty")
	}

	publicKey, err := e.getKey(keyID)
	if err != nil {
		return "", fmt.Errorf("failed to get key %s: %w", keyID, err)
	}

	encrypter, err := NewEncrypter(e.keyEncAlg, e.encAlg, publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to create encrypter: %w", err)
	}

	return encrypter.Encrypt(plaintext)
}

// XKMSDecrypter decrypts JWE using private keys from a xkms/keystore.
// It provides hardware-backed JWE decryption using the crypto.Decrypter interface.
//
// This allows decryption using keys stored in hardware security modules (HSM),
// TPM, PKCS#11 devices, or any system that implements crypto.Decrypter.
type XKMSDecrypter struct {
	getDecrypter func(keyID string) (crypto.Decrypter, error)
}

// NewXKMSDecrypter creates a new xkms-backed JWE decrypter.
//
// Parameters:
//   - getDecrypter: Function to retrieve crypto.Decrypter by key ID from xkms
//
// The getDecrypter function should return a crypto.Decrypter implementation
// for the given key identifier. This interface is implemented by *rsa.PrivateKey,
// *ecdsa.PrivateKey, and many HSM/TPM wrappers.
//
// Example:
//
//	decrypter := jwe.NewXKMSDecrypter(func(keyID string) (crypto.Decrypter, error) {
//	    return keystore.GetDecrypter(keyID)
//	})
//
//	plaintext, err := decrypter.DecryptWithAutoKeyID(jweString)
func NewXKMSDecrypter(getDecrypter func(string) (crypto.Decrypter, error)) *XKMSDecrypter {
	return &XKMSDecrypter{
		getDecrypter: getDecrypter,
	}
}

// DecryptWithAutoKeyID decrypts a JWE by automatically extracting the kid from
// the header and retrieving the corresponding private key from the xkms.
//
// This method:
// 1. Extracts the kid from the JWE protected header
// 2. Retrieves the decrypter from the xkms using that kid
// 3. Decrypts the JWE and returns the plaintext
//
// Parameters:
//   - jweString: The JWE in compact serialization format
//
// Returns the decrypted plaintext.
//
// Example:
//
//	plaintext, err := decrypter.DecryptWithAutoKeyID(jweString)
func (d *XKMSDecrypter) DecryptWithAutoKeyID(jweString string) ([]byte, error) {
	// Extract kid from JWE header
	kid, err := ExtractKID(jweString)
	if err != nil {
		return nil, fmt.Errorf("failed to extract kid: %w", err)
	}

	if kid == "" {
		return nil, fmt.Errorf("JWE header does not contain kid field")
	}

	return d.DecryptWithKeyID(jweString, kid)
}

// DecryptWithKeyID decrypts a JWE using a specific key ID.
// This allows explicit key selection instead of relying on the kid header.
//
// This is useful when:
//   - The JWE doesn't have a kid header
//   - You want to use a different key than specified in the header
//   - You're implementing custom key selection logic
//
// Parameters:
//   - jweString: The JWE in compact serialization format
//   - keyID: The key identifier to use for decryption
//
// Returns the decrypted plaintext.
//
// Example:
//
//	plaintext, err := decrypter.DecryptWithKeyID(jweString, "tpm2:encryption-key")
func (d *XKMSDecrypter) DecryptWithKeyID(jweString string, keyID string) ([]byte, error) {
	if keyID == "" {
		return nil, fmt.Errorf("keyID cannot be empty")
	}

	// Retrieve decrypter from xkms
	decrypter, err := d.getDecrypter(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get decrypter for key %s: %w", keyID, err)
	}

	// Decrypt JWE using standard decrypter
	dec := NewDecrypter()
	return dec.Decrypt(jweString, decrypter)
}

// Decrypt is an alias for DecryptWithAutoKeyID for convenience.
// It automatically extracts the kid from the JWE header and uses it to
// retrieve the appropriate decryption key from the xkms.
//
// Example:
//
//	plaintext, err := decrypter.Decrypt(jweString)
func (d *XKMSDecrypter) Decrypt(jweString string) ([]byte, error) {
	return d.DecryptWithAutoKeyID(jweString)
}
