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

// Package pairing provides the generic device pairing protocol for xKey.
// It includes the Noise XX handshake, JSON-RPC message routing, transport
// abstractions, bridge routing, and attestation. Both phone and agent
// device types reuse this package.
package pairing

import "errors"

// Pairing protocol errors.
var (
	// ErrNotConnected indicates no active connection to the device.
	ErrNotConnected = errors.New("pairing: not connected")

	// ErrConnectionFailed indicates the connection attempt failed.
	ErrConnectionFailed = errors.New("pairing: connection failed")

	// ErrDeviceNotFound indicates the device was not found during scan.
	ErrDeviceNotFound = errors.New("pairing: device not found")

	// ErrPairingFailed indicates pairing with the device failed.
	ErrPairingFailed = errors.New("pairing: pairing failed")

	// ErrTimeout indicates an operation exceeded its deadline.
	ErrTimeout = errors.New("pairing: operation timeout")

	// ErrNoiseHandshakeFailed indicates the Noise protocol handshake failed.
	ErrNoiseHandshakeFailed = errors.New("pairing: noise handshake failed")

	// ErrEncryptionFailed indicates message encryption failed.
	ErrEncryptionFailed = errors.New("pairing: encryption failed")

	// ErrDecryptionFailed indicates message decryption failed.
	ErrDecryptionFailed = errors.New("pairing: decryption failed")

	// ErrInvalidResponse indicates the device returned an invalid or malformed response.
	ErrInvalidResponse = errors.New("pairing: invalid response")

	// ErrUserCancelled indicates the user cancelled the operation on the device.
	ErrUserCancelled = errors.New("pairing: user cancelled")

	// ErrBiometricFailed indicates biometric verification failed on the device.
	ErrBiometricFailed = errors.New("pairing: biometric verification failed")

	// ErrKeyNotFound indicates the requested key does not exist on the device.
	ErrKeyNotFound = errors.New("pairing: key not found")

	// ErrProtocolError indicates a protocol-level error in communication.
	ErrProtocolError = errors.New("pairing: protocol error")

	// ErrFragmentationError indicates an error during message fragmentation or reassembly.
	ErrFragmentationError = errors.New("pairing: fragmentation error")

	// ErrBackendClosed indicates the backend has been closed and cannot process requests.
	ErrBackendClosed = errors.New("pairing: backend closed")

	// ErrInvalidCredentialID indicates the credential ID is invalid or empty.
	ErrInvalidCredentialID = errors.New("pairing: invalid credential ID")

	// ErrUnsupportedAlgorithm indicates the requested algorithm is not supported.
	ErrUnsupportedAlgorithm = errors.New("pairing: unsupported algorithm")

	// ErrExportNotSupported indicates private key export is not supported.
	ErrExportNotSupported = errors.New("pairing: export not supported")

	// ErrImportNotSupported indicates private key import is not supported.
	ErrImportNotSupported = errors.New("pairing: import not supported")

	// ErrInvalidKeyHandle indicates the key handle is invalid.
	ErrInvalidKeyHandle = errors.New("pairing: invalid key handle")

	// ErrMaxRetriesExceeded indicates the maximum number of retries was exceeded.
	ErrMaxRetriesExceeded = errors.New("pairing: max retries exceeded")

	// ErrInvalidFragment indicates a received fragment is invalid.
	ErrInvalidFragment = errors.New("pairing: invalid fragment")

	// ErrSequenceNumber indicates a sequence number mismatch in fragmented messages.
	ErrSequenceNumber = errors.New("pairing: sequence number mismatch")

	// ErrMTUTooSmall indicates the negotiated MTU is too small for the operation.
	ErrMTUTooSmall = errors.New("pairing: MTU too small")

	// ErrSessionExpired indicates the Noise session has expired and needs renegotiation.
	ErrSessionExpired = errors.New("pairing: session expired")

	// ErrInvalidNoiseMessage indicates a malformed Noise protocol message.
	ErrInvalidNoiseMessage = errors.New("pairing: invalid noise message")

	// ErrStaticKeyMismatch indicates the device's static key doesn't match the expected key.
	ErrStaticKeyMismatch = errors.New("pairing: static key mismatch")

	// ErrStorageFull indicates the device's key storage is full.
	ErrStorageFull = errors.New("pairing: storage full")

	// ErrKeyExists indicates a key with the given ID already exists.
	ErrKeyExists = errors.New("pairing: key already exists")

	// ErrBackendDenied indicates the requested backend is not accessible due to sharing policy.
	ErrBackendDenied = errors.New("pairing: backend access denied")

	// ErrAttestationFailed indicates key attestation verification failed.
	ErrAttestationFailed = errors.New("pairing: attestation verification failed")

	// ErrAttestationNotSupported indicates the backend does not support key attestation.
	ErrAttestationNotSupported = errors.New("pairing: attestation not supported")

	// ErrOperationDenied indicates the requested operation is not permitted by sharing policy.
	ErrOperationDenied = errors.New("pairing: operation denied by policy")

	// ErrInvalidPublicKey indicates the public key data is invalid or malformed.
	ErrInvalidPublicKey = errors.New("pairing: invalid public key")

	// ErrDecryptFailed indicates decryption of the provided ciphertext failed.
	ErrDecryptFailed = errors.New("pairing: ciphertext decryption failed")

	// ErrHMACFailed indicates HMAC computation or verification failed.
	ErrHMACFailed = errors.New("pairing: HMAC operation failed")

	// ErrECDHFailed indicates ECDH key agreement failed.
	ErrECDHFailed = errors.New("pairing: ECDH key agreement failed")

	// ErrInvalidFormat indicates an invalid export format was requested.
	ErrInvalidFormat = errors.New("pairing: invalid format")

	// ErrInvalidRpID indicates the relying party ID is invalid or empty.
	ErrInvalidRpID = errors.New("pairing: invalid relying party ID")

	// ErrInvalidClientDataHash indicates the client data hash is invalid or empty.
	ErrInvalidClientDataHash = errors.New("pairing: invalid client data hash")

	// ErrBridgeNotConnected indicates the xkmsd transport client is not connected.
	ErrBridgeNotConnected = errors.New("pairing: bridge xkmsd client not connected")

	// ErrBridgeInvalidParams indicates the request parameters are invalid or malformed.
	ErrBridgeInvalidParams = errors.New("pairing: bridge invalid request parameters")

	// ErrBridgeBackendDenied indicates the requested backend is denied by the bridge access policy.
	ErrBridgeBackendDenied = errors.New("pairing: bridge backend access denied")

	// ErrPairingRejected indicates the user rejected the pairing confirmation.
	ErrPairingRejected = errors.New("pairing: pairing rejected by user")

	// ErrUntrustedDevice indicates the device is not trusted (no expected remote key) and
	// TrustNewDevices is false. Use TrustNewDevices=true for initial pairing flows.
	ErrUntrustedDevice = errors.New("pairing: untrusted device - no expected remote key and trust-new-devices is false")

	// ErrTPM2DirectAccessRequired indicates the operation requires direct TPM2 access
	// and cannot be performed via the bridge.
	ErrTPM2DirectAccessRequired = errors.New("pairing: operation requires direct TPM2 access")

	// ErrShareDenied indicates key sharing is denied by policy.
	ErrShareDenied = errors.New("pairing: key sharing denied by policy")

	// ErrShareNotExportable indicates the key cannot be exported for sharing.
	ErrShareNotExportable = errors.New("pairing: key not exportable for sharing")

	// ErrSharePolicyNotFound indicates no sharing policy exists for the key.
	ErrSharePolicyNotFound = errors.New("pairing: sharing policy not found")

	// ErrShareInvalidKeyType indicates the key type is not valid for the sharing operation.
	ErrShareInvalidKeyType = errors.New("pairing: invalid key type for sharing")

	// ErrBackupFailed indicates backup creation failed.
	ErrBackupFailed = errors.New("pairing: backup creation failed")

	// ErrBackupRestoreFailed indicates backup restore failed.
	ErrBackupRestoreFailed = errors.New("pairing: backup restore failed")

	// ErrBackupNotFound indicates the requested backup was not found.
	ErrBackupNotFound = errors.New("pairing: backup not found")

	// ErrOATHCredentialNotFound indicates the requested OATH credential was not found.
	ErrOATHCredentialNotFound = errors.New("pairing: OATH credential not found")

	// ErrOATHGenerateFailed indicates OATH OTP code generation failed.
	ErrOATHGenerateFailed = errors.New("pairing: OATH code generation failed")

	// ErrOATHStoreFailed indicates an OATH store operation failed.
	ErrOATHStoreFailed = errors.New("pairing: OATH store operation failed")

	// ErrPIVSlotNotFound indicates the requested PIV slot was not found.
	ErrPIVSlotNotFound = errors.New("pairing: PIV slot not found")

	// ErrPIVSlotOccupied indicates the PIV slot already contains a key or certificate.
	ErrPIVSlotOccupied = errors.New("pairing: PIV slot already occupied")

	// ErrPIVSignFailed indicates PIV signing operation failed.
	ErrPIVSignFailed = errors.New("pairing: PIV signing failed")

	// ErrPIVInvalidSlot indicates an invalid PIV slot identifier was provided.
	ErrPIVInvalidSlot = errors.New("pairing: invalid PIV slot identifier")

	// ErrSyncFailed indicates synchronization failed.
	ErrSyncFailed = errors.New("pairing: sync failed")

	// ErrSyncConflict indicates a sync conflict was detected.
	ErrSyncConflict = errors.New("pairing: sync conflict detected")

	// ErrSyncRemoteUnavailable indicates the remote device is unavailable for sync.
	ErrSyncRemoteUnavailable = errors.New("pairing: sync remote device unavailable")

	// ErrSyncNoData indicates no data available for sync.
	ErrSyncNoData = errors.New("pairing: no data available for sync")

	// ErrSyncVersionMismatch indicates a sync protocol version mismatch.
	ErrSyncVersionMismatch = errors.New("pairing: sync version mismatch")
)
