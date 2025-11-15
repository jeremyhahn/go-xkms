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

import "errors"

// Core keystore errors
var (
	// ErrAlreadyInitialized indicates the keychain has already been initialized.
	ErrAlreadyInitialized = errors.New("keystore: already initialized")

	// ErrNotInitialized indicates the keychain has not been initialized.
	ErrNotInitialized = errors.New("keystore: not initialized")

	// ErrInvalidKeyType indicates an unsupported or invalid key type.
	ErrInvalidKeyType = errors.New("keystore: invalid key type")

	// ErrInvalidKeyAlgorithm indicates an unsupported or invalid key algorithm.
	ErrInvalidKeyAlgorithm = errors.New("keystore: invalid key algorithm")

	// ErrInvalidPassword indicates the provided password is invalid.
	ErrInvalidPassword = errors.New("keystore: invalid password")

	// ErrInvalidPasswordLength indicates the password does not meet length requirements.
	ErrInvalidPasswordLength = errors.New("keystore: invalid password length")

	// ErrPasswordRequired indicates a password is required but was not provided.
	ErrPasswordRequired = errors.New("keystore: password required")

	// ErrSOPinRequired indicates a security officer PIN is required.
	ErrSOPinRequired = errors.New("keystore: security officer PIN required")

	// ErrUserPinRequired indicates a user PIN is required.
	ErrUserPinRequired = errors.New("keystore: user PIN required")

	// ErrInvalidKeyAttributes indicates the key attributes are invalid or incomplete.
	ErrInvalidKeyAttributes = errors.New("keystore: invalid key attributes")

	// ErrInvalidParentAttributes indicates the parent key attributes are invalid.
	ErrInvalidParentAttributes = errors.New("keystore: invalid parent key attributes")

	// ErrInvalidRSAAttributes indicates the RSA key attributes are invalid.
	ErrInvalidRSAAttributes = errors.New("keystore: invalid RSA key attributes")

	// ErrInvalidECCAttributes indicates the ECC key attributes are invalid.
	ErrInvalidECCAttributes = errors.New("keystore: invalid ECC key attributes")

	// ErrInvalidCurve indicates an unsupported elliptic curve.
	ErrInvalidCurve = errors.New("keystore: invalid ECC curve")

	// ErrInvalidHashFunction indicates an unsupported or invalid hash function.
	ErrInvalidHashFunction = errors.New("keystore: invalid hash function")

	// ErrInvalidSignatureAlgorithm indicates an unsupported signature algorithm.
	ErrInvalidSignatureAlgorithm = errors.New("keystore: invalid signature algorithm")

	// ErrInvalidSignatureScheme indicates an invalid signature scheme.
	ErrInvalidSignatureScheme = errors.New("keystore: invalid signature scheme")

	// ErrInvalidPrivateKey indicates the private key is invalid or malformed.
	ErrInvalidPrivateKey = errors.New("keystore: invalid private key")

	// ErrInvalidPrivateKeyRSA indicates the RSA private key is invalid.
	ErrInvalidPrivateKeyRSA = errors.New("keystore: invalid RSA private key")

	// ErrInvalidPrivateKeyECDSA indicates the ECDSA private key is invalid.
	ErrInvalidPrivateKeyECDSA = errors.New("keystore: invalid ECDSA private key")

	// ErrInvalidPrivateKeyEd25519 indicates the Ed25519 private key is invalid.
	ErrInvalidPrivateKeyEd25519 = errors.New("keystore: invalid Ed25519 private key")

	// ErrInvalidOpaquePrivateKey indicates the opaque private key is invalid.
	ErrInvalidOpaquePrivateKey = errors.New("keystore: invalid opaque private key")

	// ErrInvalidPublicKeyRSA indicates the RSA public key is invalid.
	ErrInvalidPublicKeyRSA = errors.New("keystore: invalid RSA public key")

	// ErrInvalidPublicKeyECDSA indicates the ECDSA public key is invalid.
	ErrInvalidPublicKeyECDSA = errors.New("keystore: invalid ECDSA public key")

	// ErrInvalidKeyStore indicates the keychain instance is invalid.
	ErrInvalidKeyStore = errors.New("keystore: invalid key store")

	// ErrInvalidKeyID indicates the key identifier is invalid.
	ErrInvalidKeyID = errors.New("keystore: invalid key ID")

	// ErrKeyAlreadyExists indicates a key with the same identifier already exists.
	ErrKeyAlreadyExists = errors.New("keystore: key already exists")

	// ErrKeyNotFound indicates the requested key was not found.
	ErrKeyNotFound = errors.New("keystore: key not found")

	// ErrInvalidKeyPartition indicates an invalid storage partition.
	ErrInvalidKeyPartition = errors.New("keystore: invalid key partition")

	// ErrInvalidBlobName indicates an invalid blob name.
	ErrInvalidBlobName = errors.New("keystore: invalid blob name")

	// ErrInvalidEncodingPEM indicates invalid PEM encoding.
	ErrInvalidEncodingPEM = errors.New("keystore: invalid PEM encoding")

	// ErrUnsupportedKeyAlgorithm indicates an unsupported key algorithm.
	ErrUnsupportedKeyAlgorithm = errors.New("keystore: unsupported key algorithm")

	// ErrInvalidSignerOpts indicates invalid signer options.
	ErrInvalidSignerOpts = errors.New("keystore: invalid signer opts")

	// ErrInvalidPermanentIdentifier indicates an invalid permanent identifier.
	ErrInvalidPermanentIdentifier = errors.New("keystore: invalid permanent-identifier")

	// ErrFileIntegrityCheckFailed indicates a file integrity verification failed.
	ErrFileIntegrityCheckFailed = errors.New("keystore: file integrity check failed")

	// ErrSignatureVerification indicates signature verification failed.
	ErrSignatureVerification = errors.New("keystore: signature verification failed")

	// ErrInvalidKeyedHashSecret indicates an invalid keyed hash secret.
	ErrInvalidKeyedHashSecret = errors.New("keystore: invalid keyed hash secret")

	// ErrIssuerAttributeRequired indicates the issuer common name is required.
	ErrIssuerAttributeRequired = errors.New("keystore: issuer common name attribute required")

	// ErrInvalidJOSESignatureAlgorithm indicates an invalid JOSE signature algorithm.
	ErrInvalidJOSESignatureAlgorithm = errors.New("keystore: invalid JOSE signature algorithm")
)

// Backend-specific errors
var (
	// ErrFileAlreadyExists indicates a file already exists in the backend.
	ErrFileAlreadyExists = errors.New("keystore: file already exists")

	// ErrFileNotFound indicates a file was not found in the backend.
	ErrFileNotFound = errors.New("keystore: file not found")

	// ErrBackendNotSupported indicates the backend is not supported.
	ErrBackendNotSupported = errors.New("keystore: backend not supported")

	// ErrBackendNotInitialized indicates the backend has not been initialized.
	ErrBackendNotInitialized = errors.New("keystore: backend not initialized")

	// ErrBackendNotFound indicates the backend is not registered in the registry.
	ErrBackendNotFound = errors.New("keystore: backend not found")

	// ErrBackendRequired indicates a backend is required but was not provided.
	ErrBackendRequired = errors.New("keystore: backend is required")

	// ErrBackendClosed indicates the backend has been closed and cannot be used.
	ErrBackendClosed = errors.New("keystore: backend is closed")
)

// Storage errors
var (
	// ErrCertStorageRequired indicates certificate storage is required but was not provided.
	ErrCertStorageRequired = errors.New("keystore: certificate storage is required")

	// ErrStorageClosed indicates the storage has been closed and cannot be used.
	ErrStorageClosed = errors.New("keystore: storage is closed")

	// ErrCertNotFound indicates the requested certificate was not found.
	ErrCertNotFound = errors.New("keystore: certificate not found")

	// ErrCertAlreadyExists indicates a certificate with the same identifier already exists.
	ErrCertAlreadyExists = errors.New("keystore: certificate already exists")
)

// Operation errors
var (
	// ErrOperationNotSupported indicates the operation is not supported.
	ErrOperationNotSupported = errors.New("keystore: operation not supported")

	// ErrUnsupportedOperation is an alias for ErrOperationNotSupported for backward compatibility.
	ErrUnsupportedOperation = ErrOperationNotSupported

	// ErrOperationFailed indicates a generic operation failure.
	ErrOperationFailed = errors.New("keystore: operation failed")

	// ErrDecryptionFailed indicates decryption failed.
	ErrDecryptionFailed = errors.New("keystore: decryption failed")

	// ErrEncryptionFailed indicates encryption failed.
	ErrEncryptionFailed = errors.New("keystore: encryption failed")

	// ErrSigningFailed indicates signing operation failed.
	ErrSigningFailed = errors.New("keystore: signing failed")

	// ErrVerificationFailed indicates verification operation failed.
	ErrVerificationFailed = errors.New("keystore: verification failed")
)
