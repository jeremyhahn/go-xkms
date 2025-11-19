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
	"crypto/elliptic"
	"crypto/x509"
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// GetKeyByID retrieves a key using the extended Key ID format.
// The Key ID is parsed to extract all components and mapped to internal storage ID.
//
// The Key ID format is: backend:type:algo:keyname
//
// Example:
//
//	key, err := keystore.GetKeyByID("pkcs11:signing:ecdsa-p256:my-key")
func (ks *compositeKeyStore) GetKeyByID(keyID string) (crypto.PrivateKey, error) {
	// Parse the extended Key ID
	backendStr, keyType, algo, keyname, err := ParseKeyID(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key ID: %w", err)
	}

	// Convert backend string to BackendType
	backendType, err := keyIDToBackendType(backendStr)
	if err != nil {
		return nil, fmt.Errorf("failed to convert backend type: %w", err)
	}

	// Verify the backend matches the keystore's backend
	expectedBackend := ks.backend.Type()
	if backendType != expectedBackend {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrBackendMismatch, expectedBackend, backendType)
	}

	// Convert string components to enums
	keyTypeEnum, err := keyTypeToEnum(keyType)
	if err != nil {
		return nil, fmt.Errorf("failed to convert key type: %w", err)
	}

	algoEnum, err := algorithmToEnum(algo)
	if err != nil {
		return nil, fmt.Errorf("failed to convert algorithm: %w", err)
	}

	// Build KeyAttributes with all required fields
	attrs := &types.KeyAttributes{
		CN:        keyname,
		KeyType:   keyTypeEnum,
		StoreType: backendTypeToStoreType(backendType),
	}

	// Populate algorithm-specific attributes for validation
	switch a := algoEnum.(type) {
	case x509.PublicKeyAlgorithm:
		attrs.KeyAlgorithm = a
		switch a {
		case x509.RSA:
			// RSA requires RSAAttributes for validation
			// Use default key size since we don't know it when retrieving
			attrs.RSAAttributes = &types.RSAAttributes{
				KeySize: 2048, // Default, actual size comes from stored key
			}
		case x509.ECDSA:
			// Extract curve from algo string
			curve, err := extractECDSACurve(algo)
			if err != nil {
				return nil, fmt.Errorf("failed to extract ECDSA curve: %w", err)
			}
			// Need to convert string to elliptic.Curve
			var ellipticCurve elliptic.Curve
			switch curve {
			case "P-256":
				ellipticCurve = elliptic.P256()
			case "P-384":
				ellipticCurve = elliptic.P384()
			case "P-521":
				ellipticCurve = elliptic.P521()
			default:
				return nil, fmt.Errorf("unsupported curve: %s", curve)
			}
			attrs.ECCAttributes = &types.ECCAttributes{
				Curve: ellipticCurve,
			}
		}
	case types.SymmetricAlgorithm:
		attrs.SymmetricAlgorithm = a
		// AES requires AESAttributes for validation
		var keySize int
		switch a {
		case types.SymmetricAES128GCM:
			keySize = 128
		case types.SymmetricAES192GCM:
			keySize = 192
		default:
			keySize = 256
		}
		attrs.AESAttributes = &types.AESAttributes{
			KeySize:   keySize,
			NonceSize: 12, // Standard GCM nonce size
		}
	}

	// Retrieve the key from the backend
	key, err := ks.backend.GetKey(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve key %s: %w", keyID, err)
	}

	return key, nil
}

// GetSignerByID retrieves a crypto.Signer using the extended Key ID format.
// This is a convenience method that retrieves the key and ensures it
// implements the crypto.Signer interface.
//
// Example:
//
//	signer, err := keystore.GetSignerByID("tpm2:attestation:rsa:attestation-key")
//	signature, _ := signer.Sign(rand.Reader, digest, crypto.SHA256)
func (ks *compositeKeyStore) GetSignerByID(keyID string) (crypto.Signer, error) {
	// Parse the extended Key ID
	backendStr, keyType, algo, keyname, err := ParseKeyID(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key ID: %w", err)
	}

	// Convert backend string to BackendType
	backendType, err := keyIDToBackendType(backendStr)
	if err != nil {
		return nil, fmt.Errorf("failed to convert backend type: %w", err)
	}

	// Verify backend match
	expectedBackend := ks.backend.Type()
	if backendType != expectedBackend {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrBackendMismatch, expectedBackend, backendType)
	}

	// Convert string components to enums
	keyTypeEnum, err := keyTypeToEnum(keyType)
	if err != nil {
		return nil, fmt.Errorf("failed to convert key type: %w", err)
	}

	algoEnum, err := algorithmToEnum(algo)
	if err != nil {
		return nil, fmt.Errorf("failed to convert algorithm: %w", err)
	}

	// Build KeyAttributes
	attrs := &types.KeyAttributes{
		CN:        keyname,
		KeyType:   keyTypeEnum,
		StoreType: backendTypeToStoreType(backendType),
	}

	// Populate algorithm-specific attributes for validation
	switch a := algoEnum.(type) {
	case x509.PublicKeyAlgorithm:
		attrs.KeyAlgorithm = a
		switch a {
		case x509.RSA:
			attrs.RSAAttributes = &types.RSAAttributes{
				KeySize: 2048, // Default, actual size comes from stored key
			}
		case x509.ECDSA:
			curve, err := extractECDSACurve(algo)
			if err != nil {
				return nil, fmt.Errorf("failed to extract ECDSA curve: %w", err)
			}
			var ellipticCurve elliptic.Curve
			switch curve {
			case "P-256":
				ellipticCurve = elliptic.P256()
			case "P-384":
				ellipticCurve = elliptic.P384()
			case "P-521":
				ellipticCurve = elliptic.P521()
			default:
				return nil, fmt.Errorf("unsupported curve: %s", curve)
			}
			attrs.ECCAttributes = &types.ECCAttributes{
				Curve: ellipticCurve,
			}
		}
	case types.SymmetricAlgorithm:
		attrs.SymmetricAlgorithm = a
		var keySize int
		switch a {
		case types.SymmetricAES128GCM:
			keySize = 128
		case types.SymmetricAES192GCM:
			keySize = 192
		default:
			keySize = 256
		}
		attrs.AESAttributes = &types.AESAttributes{
			KeySize:   keySize,
			NonceSize: 12,
		}
	}

	// Get signer from backend
	signer, err := ks.backend.Signer(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get signer for key %s: %w", keyID, err)
	}

	return signer, nil
}

// GetDecrypterByID retrieves a crypto.Decrypter using the extended Key ID format.
// This is a convenience method for RSA decryption operations.
//
// Example:
//
//	decrypter, err := keystore.GetDecrypterByID("awskms:encryption:rsa:rsa-key")
//	plaintext, _ := decrypter.Decrypt(rand.Reader, ciphertext, opts)
func (ks *compositeKeyStore) GetDecrypterByID(keyID string) (crypto.Decrypter, error) {
	// Parse the extended Key ID
	backendStr, keyType, algo, keyname, err := ParseKeyID(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key ID: %w", err)
	}

	// Convert backend string to BackendType
	backendType, err := keyIDToBackendType(backendStr)
	if err != nil {
		return nil, fmt.Errorf("failed to convert backend type: %w", err)
	}

	// Verify backend match
	expectedBackend := ks.backend.Type()
	if backendType != expectedBackend {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrBackendMismatch, expectedBackend, backendType)
	}

	// Convert string components to enums
	keyTypeEnum, err := keyTypeToEnum(keyType)
	if err != nil {
		return nil, fmt.Errorf("failed to convert key type: %w", err)
	}

	algoEnum, err := algorithmToEnum(algo)
	if err != nil {
		return nil, fmt.Errorf("failed to convert algorithm: %w", err)
	}

	// Build KeyAttributes
	attrs := &types.KeyAttributes{
		CN:        keyname,
		KeyType:   keyTypeEnum,
		StoreType: backendTypeToStoreType(backendType),
	}

	// Populate algorithm-specific attributes for validation
	switch a := algoEnum.(type) {
	case x509.PublicKeyAlgorithm:
		attrs.KeyAlgorithm = a
		switch a {
		case x509.RSA:
			attrs.RSAAttributes = &types.RSAAttributes{
				KeySize: 2048, // Default, actual size comes from stored key
			}
		case x509.ECDSA:
			curve, err := extractECDSACurve(algo)
			if err != nil {
				return nil, fmt.Errorf("failed to extract ECDSA curve: %w", err)
			}
			var ellipticCurve elliptic.Curve
			switch curve {
			case "P-256":
				ellipticCurve = elliptic.P256()
			case "P-384":
				ellipticCurve = elliptic.P384()
			case "P-521":
				ellipticCurve = elliptic.P521()
			default:
				return nil, fmt.Errorf("unsupported curve: %s", curve)
			}
			attrs.ECCAttributes = &types.ECCAttributes{
				Curve: ellipticCurve,
			}
		}
	case types.SymmetricAlgorithm:
		attrs.SymmetricAlgorithm = a
		var keySize int
		switch a {
		case types.SymmetricAES128GCM:
			keySize = 128
		case types.SymmetricAES192GCM:
			keySize = 192
		default:
			keySize = 256
		}
		attrs.AESAttributes = &types.AESAttributes{
			KeySize:   keySize,
			NonceSize: 12,
		}
	}

	// Get decrypter from backend
	decrypter, err := ks.backend.Decrypter(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get decrypter for key %s: %w", keyID, err)
	}

	return decrypter, nil
}
