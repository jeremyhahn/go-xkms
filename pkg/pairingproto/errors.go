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
package pairingproto

import (
	"errors"
	"strconv"
)

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

	// ErrInvalidResponse indicates the device returned an invalid or malformed response.
	ErrInvalidResponse = errors.New("pairing: invalid response")

	// ErrUserCancelled indicates the user cancelled the operation on the device.
	ErrUserCancelled = errors.New("pairing: user cancelled")

	// ErrBiometricFailed indicates biometric verification failed on the device.
	ErrBiometricFailed = errors.New("pairing: biometric verification failed")

	// ErrUserVerificationNotEnrolled indicates the device has no biometric or
	// device credential enrolled to verify its user with.
	ErrUserVerificationNotEnrolled = errors.New("pairing: no biometric or device credential enrolled")

	// ErrUserVerificationLockout indicates the device has locked user
	// authentication out after too many failed attempts.
	ErrUserVerificationLockout = errors.New("pairing: user authentication locked out")

	// ErrNotPaired indicates the device holds no pairing with this desktop.
	ErrNotPaired = errors.New("pairing: device is not paired with this desktop")

	// ErrKeyNotFound indicates the requested key does not exist on the device.
	ErrKeyNotFound = errors.New("pairing: key not found")

	// ErrProtocolError indicates a protocol-level error in communication.
	ErrProtocolError = errors.New("pairing: protocol error")

	// ErrMessageTooLarge indicates a message exceeds the transport's frame
	// limit. A transport reports it as a *MessageTooLargeError.
	ErrMessageTooLarge = errors.New("pairing: message exceeds the transport limit")

	// ErrFragmentationError indicates an error during message fragmentation or reassembly.
	ErrFragmentationError = errors.New("pairing: fragmentation error")

	// ErrBackendClosed indicates the backend has been closed and cannot process requests.
	ErrBackendClosed = errors.New("pairing: backend closed")

	// ErrDuplicateRequestID indicates a request reused the ID of another
	// request still awaiting its response. The second request is refused
	// rather than registered: the router routes responses by ID, so allowing
	// the collision would silently orphan whichever request registered first
	// -- it would never see its channel again, since the second registration
	// overwrites it in the pending map. A late or duplicate answer that does
	// reach a reused ID is separately guarded by generation matching (see
	// Request.Generation); this check is about not losing a route at all,
	// which generation does not protect against.
	ErrDuplicateRequestID = errors.New("pairing: request ID already in flight")

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

	// ErrUSBUnavailable indicates this binary was built without USB phone
	// transport support (the "usb" build tag): the gousb/libusb dependency
	// is excluded from static and CGO_ENABLED=0 builds.
	ErrUSBUnavailable = errors.New("pairing: usb transport not built (build with -tags usb)")

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

	// ErrTPMNotConfigured is returned when a TCG/IDevID enrollment method is
	// invoked on a host with no TPM wired into the bridge. It means the feature
	// is unavailable here, which is distinct from the operation having failed.
	ErrTPMNotConfigured = errors.New("pairing: no TPM is configured on this host")

	// ErrTPMUnavailable is returned when this host appears to have a TPM but
	// xkey cannot reach it. On Linux this is almost always a permissions
	// problem on the device node. It is deliberately distinct from
	// ErrTPMNotConfigured: the feature is supposed to work here and does not,
	// which is something an operator can fix.
	ErrTPMUnavailable = errors.New("pairing: this host has a TPM but xkey cannot reach it")

	// ErrTPMOperationFailed wraps a failure reported by the TPM itself. The
	// cause travels with it so the phone learns what actually went wrong.
	ErrTPMOperationFailed = errors.New("pairing: TPM operation failed")

	// ErrEKCertificateMissing is returned when the TPM has no manufacturer
	// Endorsement Key certificate. Without it a CA cannot establish that the
	// TPM is genuine, so enrollment cannot proceed.
	ErrEKCertificateMissing = errors.New("pairing: the TPM has no endorsement key certificate")

	// ErrTPMKeyNotProvisioned is returned when the IAK or IDevID key has not
	// been created yet. Provision the TPM before enrolling.
	ErrTPMKeyNotProvisioned = errors.New("pairing: TPM key is not provisioned")

	// ErrInvalidCertificate is returned when a certificate supplied by the peer
	// is not parseable X.509. A CA-issued certificate that will not parse must
	// never reach the TPM.
	ErrInvalidCertificate = errors.New("pairing: certificate is not valid X.509")

	// ErrPCRBankUnavailable is returned when the requested PCR bank is not
	// available on this TPM, so a quote over those registers cannot be produced.
	ErrPCRBankUnavailable = errors.New("pairing: requested PCR bank is unavailable")

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

	// ErrBackupPasswordRequired indicates a remote.createBackup or
	// remote.restoreBackup request carried no password. It travels wrapped
	// with ErrBridgeInvalidParams.
	ErrBackupPasswordRequired = errors.New("pairing: backup password is required")

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

	// ErrOATHNotConfigured is returned when a remote.oath* method is invoked
	// but no OATH credential store has been wired into the bridge. The
	// feature is unavailable on this host, which is distinct from the
	// request having failed.
	ErrOATHNotConfigured = errors.New("pairing: no OATH credential store is configured on this host")

	// ErrPIVNotConfigured is returned when a remote.piv* method needs PIV
	// certificate storage that has not been wired into the bridge for the
	// requested backend.
	ErrPIVNotConfigured = errors.New("pairing: no PIV certificate storage is configured for this backend")

	// ErrSyncNotConfigured is returned when a remote.sync* method needs a
	// sync data source (trust store, OATH, or passwords) that has not been
	// wired into the bridge.
	ErrSyncNotConfigured = errors.New("pairing: sync is not configured on this host")

	// ErrBackupNotConfigured is returned when a remote.*Backup* method needs
	// the backup service, which has not been wired into the bridge.
	ErrBackupNotConfigured = errors.New("pairing: backup is not configured on this host")

	// ErrSyncApprovalRequired is returned by remote.syncPasswords,
	// remote.syncOATH and remote.syncAll when no desktop approval mechanism
	// is configured on the bridge. These three methods export the vault
	// (passwords, OATH secrets) to the phone, unlike remote.syncTrustStore
	// (public certificates) and remote.syncStatus (metadata), which are not
	// gated. A bridge with no SyncApproval configured refuses them rather
	// than exporting secrets with no desktop-side check at all -- fail
	// closed, matching every other optional bridge collaborator that
	// defaults to "unconfigured" rather than "unchecked".
	ErrSyncApprovalRequired = errors.New("pairing: exporting secrets to the phone requires desktop approval, which is not configured on this host")

	// ErrSyncNotApproved is returned when the configured SyncApproval
	// function refused this specific request: the operator declined a live
	// prompt, no --allow-sync session flag was supplied, or enterprise
	// policy locks secret export off.
	ErrSyncNotApproved = errors.New("pairing: the desktop refused to export secrets to the phone")

	// ErrFeatureNotConfigured is the generic client-side counterpart of
	// ErrorCodeFeatureUnavailable: the peer understood the method but its
	// collaborator was not wired in on that host.
	ErrFeatureNotConfigured = errors.New("pairing: feature not configured on peer")
)

// DetailError appends detail text directly after a wrapped error while
// preserving errors.Is / errors.As matching of the wrapped error through
// Unwrap. The detail text carries its own leading separator.
type DetailError struct {
	Err    error
	Detail string
}

// Error implements the error interface.
func (e *DetailError) Error() string {
	return e.Err.Error() + e.Detail
}

// Unwrap returns the wrapped cause.
func (e *DetailError) Unwrap() error {
	return e.Err
}

// SentinelCauseError attaches an underlying cause to a package sentinel
// error so errors.Is matches both the sentinel and the cause.
// MessageTooLargeError reports a message a transport refused because it
// exceeds the transport's frame limit. It matches ErrMessageTooLarge and,
// like every framing refusal, ErrProtocolError.
type MessageTooLargeError struct {
	Size  int
	Limit int
}

// Error implements error.
func (e *MessageTooLargeError) Error() string {
	return ErrMessageTooLarge.Error() + ": " + strconv.Itoa(e.Size) + " bytes, limit " + strconv.Itoa(e.Limit)
}

// Unwrap returns ErrMessageTooLarge and ErrProtocolError.
func (e *MessageTooLargeError) Unwrap() []error {
	return []error{ErrMessageTooLarge, ErrProtocolError}
}

type SentinelCauseError struct {
	Sentinel error
	Cause    error
}

// Error implements the error interface.
func (e *SentinelCauseError) Error() string {
	return e.Sentinel.Error() + ": " + e.Cause.Error()
}

// Unwrap returns the sentinel and the cause for errors.Is / errors.As.
func (e *SentinelCauseError) Unwrap() []error {
	return []error{e.Sentinel, e.Cause}
}

// USBError reports a failed libusb operation of the USB AOA transport. Op
// names the operation; Err keeps the libusb cause for errors.Is / errors.As.
type USBError struct {
	Op  string
	Err error
}

// Error implements the error interface.
func (e *USBError) Error() string {
	return "pairing: usb " + e.Op + ": " + e.Err.Error()
}

// Unwrap returns the libusb cause.
func (e *USBError) Unwrap() error {
	return e.Err
}
