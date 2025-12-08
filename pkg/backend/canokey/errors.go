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

//go:build pkcs11

package canokey

import "errors"

var (
	// ErrUnsupportedAlgorithm is returned when an unsupported wrapping key algorithm
	// or cryptographic operation is requested. This typically occurs when attempting
	// to use a key type that the CanoKey or this implementation does not support
	// for envelope encryption.
	ErrUnsupportedAlgorithm = errors.New("canokey: unsupported algorithm")

	// ErrFirmwareRequired is returned when a requested operation requires a newer
	// CanoKey firmware version than what is currently available. For example,
	// Ed25519/X25519 operations require firmware 3.0.0+.
	ErrFirmwareRequired = errors.New("canokey: firmware version 3.0.0+ required")

	// ErrNotInitialized is returned when operations are attempted on an
	// uninitialized backend.
	ErrNotInitialized = errors.New("canokey: backend not initialized")

	// ErrConfigRequired is returned when a nil configuration is provided.
	ErrConfigRequired = errors.New("canokey: config is required")

	// ErrLibraryLoadFailed is returned when the PKCS#11 library cannot be loaded.
	ErrLibraryLoadFailed = errors.New("canokey: failed to load PKCS#11 library")

	// ErrNoDeviceFound is returned when no CanoKey device is detected.
	ErrNoDeviceFound = errors.New("canokey: no CanoKey device found")

	// ErrInvalidLength is returned when an invalid length is specified for random
	// number generation.
	ErrInvalidLength = errors.New("canokey: invalid length, must be > 0")

	// ErrLengthExceedsMaximum is returned when the requested random bytes exceed
	// the maximum allowed per call (1024 bytes).
	ErrLengthExceedsMaximum = errors.New("canokey: length exceeds maximum 1024 bytes per call")

	// ErrNotSigner is returned when a key does not implement crypto.Signer.
	ErrNotSigner = errors.New("canokey: key does not implement crypto.Signer")

	// ErrSealOptionsRequired is returned when seal options are not provided or
	// are missing required fields.
	ErrSealOptionsRequired = errors.New("canokey: seal options with KeyAttributes required")

	// ErrUnsealOptionsRequired is returned when unseal options are not provided or
	// are missing required fields.
	ErrUnsealOptionsRequired = errors.New("canokey: unseal options with KeyAttributes required")

	// ErrSealedDataRequired is returned when sealed data is nil.
	ErrSealedDataRequired = errors.New("canokey: sealed data is required")

	// ErrBackendMismatch is returned when sealed data was created by a different backend.
	ErrBackendMismatch = errors.New("canokey: sealed data was not created by canokey backend")

	// ErrKeyIDMismatch is returned when the key ID in sealed data doesn't match
	// the key ID in unseal options.
	ErrKeyIDMismatch = errors.New("canokey: key ID mismatch")

	// ErrMissingEncryptedDEK is returned when encrypted DEK is not found in metadata.
	ErrMissingEncryptedDEK = errors.New("canokey: encrypted DEK not found in sealed data metadata")

	// ErrInvalidDEKSize is returned when the decrypted DEK is not the expected size.
	ErrInvalidDEKSize = errors.New("canokey: invalid DEK size")

	// ErrInvalidNonceSize is returned when the nonce size is invalid.
	ErrInvalidNonceSize = errors.New("canokey: invalid nonce size")

	// ErrRSAKeyRequired is returned when a non-RSA key is used for an operation
	// that requires RSA.
	ErrRSAKeyRequired = errors.New("canokey: sealing requires RSA key")

	// ErrInvalidPINLength is returned when the PIN length is invalid.
	ErrInvalidPINLength = errors.New("canokey: PIN must be 6-8 characters")

	// ErrPINRequired is returned when PIN is empty.
	ErrPINRequired = errors.New("canokey: PIN is required")

	// ErrKeyStorageRequired is returned when key storage is not configured.
	ErrKeyStorageRequired = errors.New("canokey: key storage is required")

	// ErrCertStorageRequired is returned when certificate storage is not configured.
	ErrCertStorageRequired = errors.New("canokey: certificate storage is required")

	// ErrMissingMetadata is returned when encrypted data is missing required metadata.
	ErrMissingMetadata = errors.New("canokey: missing metadata in encrypted data")

	// ErrMissingWrapAlgorithm is returned when wrap algorithm is missing from metadata.
	ErrMissingWrapAlgorithm = errors.New("canokey: missing wrapAlgorithm in metadata")

	// ErrCiphertextTooShort is returned when ciphertext is shorter than expected.
	ErrCiphertextTooShort = errors.New("canokey: ciphertext too short")

	// ErrEncryptedDEKTooShort is returned when encrypted DEK is shorter than expected.
	ErrEncryptedDEKTooShort = errors.New("canokey: encrypted DEK too short")

	// ErrInvalidEphemeralKey is returned when an ephemeral key cannot be unmarshaled.
	ErrInvalidEphemeralKey = errors.New("canokey: failed to unmarshal ephemeral public key")

	// ErrDecrypterNoPrivateKey is returned when a decrypter doesn't expose its private key.
	ErrDecrypterNoPrivateKey = errors.New("canokey: decrypter does not expose private key")

	// ErrInvalidEd25519KeySize is returned when an Ed25519 key has invalid size.
	ErrInvalidEd25519KeySize = errors.New("canokey: invalid Ed25519 key size")

	// ErrInvalidEd25519PublicKey is returned when an Ed25519 public key is invalid.
	ErrInvalidEd25519PublicKey = errors.New("canokey: invalid Ed25519 public key")

	// ErrInvalidEd25519PrivateKey is returned when an Ed25519 private key is invalid.
	ErrInvalidEd25519PrivateKey = errors.New("canokey: invalid Ed25519 private key")

	// ErrWrapAttributesRequired is returned when WrapAttributes are not provided
	// for symmetric key operations.
	ErrWrapAttributesRequired = errors.New("canokey: WrapAttributes required for CanoKey symmetric keys")

	// ErrInvalidAESKeySize is returned when an invalid AES key size is specified.
	ErrInvalidAESKeySize = errors.New("canokey: invalid AES key size")

	// ErrUnsupportedCurve is returned when an unsupported ECDSA curve is used.
	ErrUnsupportedCurve = errors.New("canokey: unsupported ECDSA curve")

	// ErrNotEd25519Key is returned when a key is not Ed25519 but Ed25519 is required.
	ErrNotEd25519Key = errors.New("canokey: key is not Ed25519")

	// ErrNotECDSAKey is returned when a key is not ECDSA but ECDSA is required.
	ErrNotECDSAKey = errors.New("canokey: key is not ECDSA")
)
