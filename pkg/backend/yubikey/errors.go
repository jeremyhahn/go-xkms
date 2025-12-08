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

package yubikey

import "errors"

var (
	// ErrUnsupportedAlgorithm is returned when an unsupported wrapping key algorithm
	// or cryptographic operation is requested. This typically occurs when attempting
	// to use a key type (e.g., P-521 ECDSA) that the YubiKey or this implementation
	// does not support for envelope encryption.
	ErrUnsupportedAlgorithm = errors.New("yubikey: unsupported algorithm")

	// ErrFirmwareRequired is returned when a requested operation requires a newer
	// YubiKey firmware version than what is currently available. For example,
	// Ed25519/X25519 operations require firmware 5.7+.
	ErrFirmwareRequired = errors.New("yubikey: firmware version 5.7+ required")

	// ErrConfigRequired is returned when no configuration is provided to NewBackend.
	ErrConfigRequired = errors.New("yubikey: config is required")

	// ErrNotInitialized is returned when an operation is attempted on an
	// uninitialized backend. Call Initialize() before using the backend.
	ErrNotInitialized = errors.New("yubikey: backend not initialized")

	// ErrNoDevice is returned when no YubiKey device is found during initialization.
	ErrNoDevice = errors.New("yubikey: no YubiKey device found")

	// ErrInvalidLength is returned when a requested operation has an invalid length parameter.
	ErrInvalidLength = errors.New("yubikey: invalid length")

	// ErrMaxLengthExceeded is returned when the requested length exceeds the maximum
	// allowed value for the operation (e.g., 1024 bytes for RNG).
	ErrMaxLengthExceeded = errors.New("yubikey: length exceeds maximum")

	// ErrSlotRequired is returned when a PIV slot must be specified in the config
	// but is not provided.
	ErrSlotRequired = errors.New("yubikey: PIV slot must be specified in config")

	// ErrInvalidKeySize is returned when an invalid RSA key size is requested.
	// Valid sizes are 1024, 2048, 3072, and 4096 bits.
	ErrInvalidKeySize = errors.New("yubikey: invalid RSA key size")

	// ErrCurveRequired is returned when an ECC curve must be specified but is not provided.
	ErrCurveRequired = errors.New("yubikey: ECC curve is required")

	// ErrP521NotSupported is returned when P-521 curve is requested.
	// YubiKey PIV does not support P-521.
	ErrP521NotSupported = errors.New("yubikey: P-521 not supported by YubiKey PIV")

	// ErrUnsupportedCurve is returned when an unsupported elliptic curve is requested.
	ErrUnsupportedCurve = errors.New("yubikey: unsupported curve")

	// ErrNotSigner is returned when a generated or retrieved key does not implement
	// the crypto.Signer interface when it is expected to.
	ErrNotSigner = errors.New("yubikey: generated key does not implement crypto.Signer")

	// ErrSealOptionsRequired is returned when seal options with KeyAttributes are required
	// but not provided.
	ErrSealOptionsRequired = errors.New("yubikey: seal options with KeyAttributes required")

	// ErrSealedDataRequired is returned when sealed data is required but not provided.
	ErrSealedDataRequired = errors.New("yubikey: sealed data is required")

	// ErrBackendMismatch is returned when attempting to unseal data that was not
	// created by the yubikey backend.
	ErrBackendMismatch = errors.New("yubikey: sealed data was not created by yubikey backend")

	// ErrUnsealOptionsRequired is returned when unseal options with KeyAttributes are required
	// but not provided.
	ErrUnsealOptionsRequired = errors.New("yubikey: unseal options with KeyAttributes required")

	// ErrKeyIDMismatch is returned when the key ID in the sealed data does not match
	// the key ID in the unseal options.
	ErrKeyIDMismatch = errors.New("yubikey: key ID mismatch")

	// ErrEncryptedDEKNotFound is returned when the encrypted DEK is not found in
	// the sealed data metadata.
	ErrEncryptedDEKNotFound = errors.New("yubikey: encrypted DEK not found in sealed data metadata")

	// ErrInvalidDEKSize is returned when the decrypted DEK has an unexpected size.
	// Expected size is 32 bytes for AES-256.
	ErrInvalidDEKSize = errors.New("yubikey: invalid DEK size")

	// ErrInvalidNonceSize is returned when the nonce in the sealed data has an
	// unexpected size for the GCM cipher.
	ErrInvalidNonceSize = errors.New("yubikey: invalid nonce size")

	// ErrRSAKeyRequired is returned when an RSA key is required for sealing but
	// a different key type is provided.
	ErrRSAKeyRequired = errors.New("yubikey: sealing requires RSA key")

	// ErrCiphertextTooShort is returned when the ciphertext is too short to contain
	// the required components (nonce, ciphertext, tag).
	ErrCiphertextTooShort = errors.New("yubikey: ciphertext too short")

	// ErrMissingMetadata is returned when required metadata is missing from
	// encrypted data.
	ErrMissingMetadata = errors.New("yubikey: missing metadata in encrypted data")

	// ErrMissingEncryptedDEK is returned when the encrypted DEK is missing from
	// the metadata.
	ErrMissingEncryptedDEK = errors.New("yubikey: missing encryptedDEK in metadata")

	// ErrUnsupportedEncryptionAlgorithm is returned when an unsupported encryption
	// algorithm is encountered in encrypted data.
	ErrUnsupportedEncryptionAlgorithm = errors.New("yubikey: unsupported algorithm")

	// ErrEncryptedDEKTooShort is returned when the encrypted DEK is too short to
	// contain the required components.
	ErrEncryptedDEKTooShort = errors.New("yubikey: encrypted DEK too short")

	// ErrCiphertextAndTagTooShort is returned when the ciphertext and tag combined
	// are too short.
	ErrCiphertextAndTagTooShort = errors.New("yubikey: ciphertext and tag too short")

	// ErrUnmarshalPublicKeyFailed is returned when unmarshaling an ephemeral public key fails.
	ErrUnmarshalPublicKeyFailed = errors.New("yubikey: failed to unmarshal ephemeral public key")

	// ErrDecrypterNoPrivateKey is returned when a decrypter does not expose the
	// private key needed for ECDH operations.
	ErrDecrypterNoPrivateKey = errors.New("yubikey: decrypter does not expose private key")

	// ErrNotECDSA is returned when an ECDSA key is expected but a different key type is provided.
	ErrNotECDSA = errors.New("yubikey: wrapping key is not ECDSA")

	// ErrNotEd25519 is returned when an Ed25519 key is expected but a different key type is provided.
	ErrNotEd25519 = errors.New("yubikey: wrapping key is not Ed25519")

	// ErrDecrypterNoEd25519PrivateKey is returned when a decrypter does not expose
	// an Ed25519 private key for X25519 conversion.
	ErrDecrypterNoEd25519PrivateKey = errors.New("yubikey: decrypter does not expose Ed25519 private key for X25519 conversion")

	// ErrInvalidEd25519PublicKeySize is returned when an Ed25519 public key has an invalid size.
	ErrInvalidEd25519PublicKeySize = errors.New("yubikey: invalid Ed25519 public key size")

	// ErrInvalidEd25519PublicKey is returned when an Ed25519 public key cannot be parsed.
	ErrInvalidEd25519PublicKey = errors.New("yubikey: invalid Ed25519 public key")

	// ErrInvalidEd25519PrivateKeySize is returned when an Ed25519 private key has an invalid size.
	ErrInvalidEd25519PrivateKeySize = errors.New("yubikey: invalid Ed25519 private key size")

	// ErrUnexpectedKeyType is returned when a key has an unexpected type.
	ErrUnexpectedKeyType = errors.New("yubikey: unexpected key type")
)
