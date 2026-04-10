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

package phone

import "errors"

var (
	// ErrInvalidConfig indicates the phone backend configuration is invalid.
	ErrInvalidConfig = errors.New("phone backend: invalid configuration")

	// ErrInvalidTransport indicates the transport type is not supported.
	// Valid transports are "ble" and "tcp".
	ErrInvalidTransport = errors.New("phone backend: invalid transport type")

	// ErrMissingDeviceAddress indicates the device address (BLE MAC or TCP host:port)
	// is not configured.
	ErrMissingDeviceAddress = errors.New("phone backend: device address is required")

	// ErrMissingNoiseStaticKey indicates the Noise static private key is not configured.
	ErrMissingNoiseStaticKey = errors.New("phone backend: noise static key is required")

	// ErrMissingPhoneStaticKey indicates the Noise static public key for the paired phone
	// is not configured.
	ErrMissingPhoneStaticKey = errors.New("phone backend: phone static key is required")

	// ErrNotConnected indicates no active connection to the phone.
	ErrNotConnected = errors.New("phone backend: not connected to phone")

	// ErrBackendClosed indicates the backend has been closed.
	ErrBackendClosed = errors.New("phone backend: closed")

	// ErrConnectionLost indicates the connection to the phone was lost.
	ErrConnectionLost = errors.New("phone backend: connection lost")

	// ErrKeyNotFound indicates the requested key does not exist on the phone.
	ErrKeyNotFound = errors.New("phone backend: key not found")

	// ErrKeyExists indicates a key with the given identifier already exists.
	ErrKeyExists = errors.New("phone backend: key already exists")

	// ErrUnsupportedAlgorithm indicates the requested algorithm is not supported by the phone.
	ErrUnsupportedAlgorithm = errors.New("phone backend: unsupported algorithm")

	// ErrOperationTimeout indicates the phone did not respond within the timeout.
	ErrOperationTimeout = errors.New("phone backend: operation timeout")

	// ErrUserCancelled indicates the user cancelled the operation on the phone.
	ErrUserCancelled = errors.New("phone backend: user cancelled")

	// ErrBiometricFailed indicates biometric verification failed on the phone.
	ErrBiometricFailed = errors.New("phone backend: biometric verification failed")

	// ErrAttestationFailed indicates key attestation verification failed.
	ErrAttestationFailed = errors.New("phone backend: attestation verification failed")

	// ErrRotationNotSupported indicates in-place key rotation is not supported.
	ErrRotationNotSupported = errors.New("phone backend: key rotation not supported")

	// ErrExportNotSupported indicates private key export is not supported (hardware-backed).
	ErrExportNotSupported = errors.New("phone backend: private key export not supported")

	// ErrImportNotSupported indicates private key import is not supported (hardware-backed).
	ErrImportNotSupported = errors.New("phone backend: private key import not supported")

	// ErrTransportUnavailable indicates the requested transport (BLE/TCP) is not available.
	ErrTransportUnavailable = errors.New("phone backend: transport unavailable")

	// ErrProtocolError indicates a JSON-RPC protocol error.
	ErrProtocolError = errors.New("phone backend: protocol error")

	// ErrInvalidPublicKey indicates the public key data from the phone is invalid.
	ErrInvalidPublicKey = errors.New("phone backend: invalid public key")

	// ErrInvalidResponse indicates the phone returned an invalid or unexpected response.
	ErrInvalidResponse = errors.New("phone backend: invalid response")

	// ErrSigningFailed indicates the phone failed to sign the digest.
	ErrSigningFailed = errors.New("phone backend: signing failed")

	// ErrNilBackend indicates the signer was created with a nil backend reference.
	ErrNilBackend = errors.New("phone backend: nil backend")

	// ErrNilPublicKey indicates the signer was created with a nil public key.
	ErrNilPublicKey = errors.New("phone backend: nil public key")

	// ErrEmptyKeyID indicates the signer was created with an empty key identifier.
	ErrEmptyKeyID = errors.New("phone backend: empty key ID")

	// ErrEmptyAlgorithm indicates the signer was created with an empty algorithm.
	ErrEmptyAlgorithm = errors.New("phone backend: empty algorithm")

	// ErrInvalidKeyAttributes indicates nil or invalid key attributes were provided.
	ErrInvalidKeyAttributes = errors.New("phone backend: invalid key attributes")

	// ErrInvalidPeerPublicKey indicates the peer public key is empty or malformed.
	ErrInvalidPeerPublicKey = errors.New("phone backend: invalid peer public key")

	// ErrEmptySharedSecret indicates the phone returned an empty shared secret from ECDH.
	ErrEmptySharedSecret = errors.New("phone backend: empty shared secret")

	// ErrInvalidKDFParams indicates the KDF parameters are invalid.
	ErrInvalidKDFParams = errors.New("phone backend: invalid KDF parameters")

	// ErrUnsupportedKDFAlgorithm indicates the requested KDF algorithm is not supported.
	// Only HKDF (RFC 5869) is currently supported for the phone backend.
	ErrUnsupportedKDFAlgorithm = errors.New("phone backend: unsupported KDF algorithm")

	// ErrUnsupportedHashAlgorithm indicates the requested hash algorithm is not supported
	// for the KDF operation.
	ErrUnsupportedHashAlgorithm = errors.New("phone backend: unsupported hash algorithm")

	// ErrKDFDerivationFailed indicates the KDF key derivation operation failed.
	ErrKDFDerivationFailed = errors.New("phone backend: KDF derivation failed")

	// ErrSymmetricEncryptFailed indicates the phone failed to perform symmetric encryption.
	ErrSymmetricEncryptFailed = errors.New("phone backend: symmetric encryption failed")

	// ErrSymmetricDecryptFailed indicates the phone failed to perform symmetric decryption.
	ErrSymmetricDecryptFailed = errors.New("phone backend: symmetric decryption failed")

	// ErrInvalidRpID indicates the relying party ID is empty or invalid.
	ErrInvalidRpID = errors.New("phone backend: invalid relying party ID")

	// ErrInvalidClientDataHash indicates the client data hash is empty or invalid.
	ErrInvalidClientDataHash = errors.New("phone backend: invalid client data hash")

	// ErrInvalidCredentialID indicates the FIDO2 credential ID is empty or invalid.
	ErrInvalidCredentialID = errors.New("phone backend: invalid credential ID")

	// ErrChainVerificationFailed indicates the attestation certificate chain could
	// not be verified against the configured trust store roots.
	ErrChainVerificationFailed = errors.New("phone backend: certificate chain verification failed")

	// ErrInsufficientSecurityLevel indicates the attestation security level reported
	// by the phone is below the configured minimum requirement.
	ErrInsufficientSecurityLevel = errors.New("phone backend: security level below minimum")

	// ErrInvalidCertificate indicates a DER-encoded certificate could not be parsed.
	ErrInvalidCertificate = errors.New("phone backend: invalid certificate in chain")

	// ErrTrustStoreInit indicates the trust store failed to initialize.
	ErrTrustStoreInit = errors.New("phone backend: trust store initialization failed")

	// ErrUnsupportedPlatform indicates the configured platform has no registered
	// verifier. Import the platform package to register it
	// (e.g., _ "github.com/jeremyhahn/go-xkms/pkg/backend/phone/android").
	ErrUnsupportedPlatform = errors.New("phone backend: unsupported platform")
)
