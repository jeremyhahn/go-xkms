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

// Package phone provides a FIDO2 key backend that communicates with
// Android phones via BLE for hardware-backed key storage and operations.
package phone

import (
	"errors"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// DefaultLiveAttestTimeout bounds a responder's post-handshake LiveAttest
// round trip (TCPPairingConfig.LiveAttest, BLEPeripheralConfig.LiveAttest):
// the laptop's local.attestDevice challenge to the phone, which prompts the
// phone's user for biometric confirmation before it answers. Matches the
// CLI's own connect-and-call budget for the same proof (defaultSessionTimeout,
// cmd/xkey/cmd/device_session.go).
const DefaultLiveAttestTimeout = 120 * time.Second

// ErrLiveAttestationUnavailable indicates a connection required the #129
// challenge-response proof and no verifier was supplied to produce one.
//
// It is a refusal, deliberately. The alternative — treating a missing verifier
// as "no check configured" — would make the control vanish on exactly the
// mistake it is most likely to meet: a caller that sets
// RequireLiveAttestation from a pairing record and forgets to wire LiveAttest.
// Corrupt or absent authorization machinery must never be less restrictive
// than the policy it implements.
var ErrLiveAttestationUnavailable = errors.New("phone: this device requires a live attestation proof but no verifier was configured")

// Errors delegated to pairing package. These are returned by pairing code
// and must be the same values so errors.Is() works correctly.
var (
	ErrNotConnected             = pairingproto.ErrNotConnected
	ErrConnectionFailed         = pairingproto.ErrConnectionFailed
	ErrDeviceNotFound           = pairingproto.ErrDeviceNotFound
	ErrPairingFailed            = pairingproto.ErrPairingFailed
	ErrTimeout                  = pairingproto.ErrTimeout
	ErrNoiseHandshakeFailed     = bootstrap.ErrNoiseHandshakeFailed
	ErrEncryptionFailed         = bootstrap.ErrNoiseEncryptionFailed
	ErrDecryptionFailed         = bootstrap.ErrNoiseDecryptionFailed
	ErrInvalidResponse          = pairingproto.ErrInvalidResponse
	ErrUserCancelled            = pairingproto.ErrUserCancelled
	ErrBiometricFailed          = pairingproto.ErrBiometricFailed
	ErrKeyNotFound              = pairingproto.ErrKeyNotFound
	ErrProtocolError            = pairingproto.ErrProtocolError
	ErrFragmentationError       = pairingproto.ErrFragmentationError
	ErrBackendClosed            = pairingproto.ErrBackendClosed
	ErrInvalidCredentialID      = pairingproto.ErrInvalidCredentialID
	ErrUnsupportedAlgorithm     = pairingproto.ErrUnsupportedAlgorithm
	ErrExportNotSupported       = pairingproto.ErrExportNotSupported
	ErrImportNotSupported       = pairingproto.ErrImportNotSupported
	ErrInvalidKeyHandle         = pairingproto.ErrInvalidKeyHandle
	ErrMaxRetriesExceeded       = pairingproto.ErrMaxRetriesExceeded
	ErrInvalidFragment          = pairingproto.ErrInvalidFragment
	ErrSequenceNumber           = pairingproto.ErrSequenceNumber
	ErrMTUTooSmall              = pairingproto.ErrMTUTooSmall
	ErrSessionExpired           = pairingproto.ErrSessionExpired
	ErrInvalidNoiseMessage      = bootstrap.ErrNoiseInvalidMessage
	ErrStaticKeyMismatch        = bootstrap.ErrNoiseStaticKeyMismatch
	ErrStorageFull              = pairingproto.ErrStorageFull
	ErrKeyExists                = pairingproto.ErrKeyExists
	ErrBackendDenied            = pairingproto.ErrBackendDenied
	ErrAttestationFailed        = pairingproto.ErrAttestationFailed
	ErrAttestationNotSupported  = pairingproto.ErrAttestationNotSupported
	ErrInvalidAttestationNonce  = pairing.ErrInvalidAttestationNonce
	ErrTPM2Required             = pairing.ErrTPM2Required
	ErrOperationDenied          = pairingproto.ErrOperationDenied
	ErrInvalidPublicKey         = pairingproto.ErrInvalidPublicKey
	ErrDecryptFailed            = pairingproto.ErrDecryptFailed
	ErrHMACFailed               = pairingproto.ErrHMACFailed
	ErrECDHFailed               = pairingproto.ErrECDHFailed
	ErrInvalidFormat            = pairingproto.ErrInvalidFormat
	ErrInvalidRpID              = pairingproto.ErrInvalidRpID
	ErrInvalidClientDataHash    = pairingproto.ErrInvalidClientDataHash
	ErrBridgeNotConnected       = pairingproto.ErrBridgeNotConnected
	ErrBridgeInvalidParams      = pairingproto.ErrBridgeInvalidParams
	ErrBridgeBackendDenied      = pairingproto.ErrBridgeBackendDenied
	ErrPairingRejected          = pairingproto.ErrPairingRejected
	ErrUntrustedDevice          = pairingproto.ErrUntrustedDevice
	ErrTPM2DirectAccessRequired = pairingproto.ErrTPM2DirectAccessRequired
	ErrShareDenied              = pairingproto.ErrShareDenied
	ErrShareNotExportable       = pairingproto.ErrShareNotExportable
	ErrSharePolicyNotFound      = pairingproto.ErrSharePolicyNotFound
	ErrShareInvalidKeyType      = pairingproto.ErrShareInvalidKeyType
	ErrBackupFailed             = pairingproto.ErrBackupFailed
	ErrBackupRestoreFailed      = pairingproto.ErrBackupRestoreFailed
	ErrBackupNotFound           = pairingproto.ErrBackupNotFound
	ErrOATHCredentialNotFound   = pairingproto.ErrOATHCredentialNotFound
	ErrOATHGenerateFailed       = pairingproto.ErrOATHGenerateFailed
	ErrOATHStoreFailed          = pairingproto.ErrOATHStoreFailed
	ErrPIVSlotNotFound          = pairingproto.ErrPIVSlotNotFound
	ErrPIVSlotOccupied          = pairingproto.ErrPIVSlotOccupied
	ErrPIVSignFailed            = pairingproto.ErrPIVSignFailed
	ErrPIVInvalidSlot           = pairingproto.ErrPIVInvalidSlot
	ErrSyncFailed               = pairingproto.ErrSyncFailed
	ErrSyncConflict             = pairingproto.ErrSyncConflict
	ErrSyncRemoteUnavailable    = pairingproto.ErrSyncRemoteUnavailable
	ErrSyncNoData               = pairingproto.ErrSyncNoData
	ErrSyncVersionMismatch      = pairingproto.ErrSyncVersionMismatch
)

// Phone-specific errors that are NOT in the pairing package.
// These are for BLE transport, BlueZ D-Bus, and other phone-only concerns.
var (
	// ErrBLEUnavailable indicates Bluetooth Low Energy is not available on this system.
	ErrBLEUnavailable = errors.New("phone: bluetooth unavailable")

	// ErrBLEPeripheralStopped indicates the peripheral has been stopped and
	// will accept no further connections. Once Stop has released the
	// peripheral's static key there is nothing left for a session to use.
	ErrBLEPeripheralStopped = errors.New("phone: ble peripheral stopped")

	// ErrAdapterDisabled indicates the Bluetooth adapter is disabled.
	ErrAdapterDisabled = errors.New("phone: bluetooth adapter disabled")

	// ErrServiceNotFound indicates the xKey BLE service was not found on the device.
	ErrServiceNotFound = errors.New("phone: xKey service not found")

	// ErrCharacteristicNotFound indicates a required BLE characteristic was not found.
	ErrCharacteristicNotFound = errors.New("phone: characteristic not found")

	// ErrDBusStaleObject indicates a BlueZ D-Bus stale object that was removed.
	// The caller should re-scan and retry with a fresh address.
	ErrDBusStaleObject = errors.New("phone: bluez dbus stale object removed")

	// ErrShutdownIncomplete indicates a shutdown finished without being able to
	// confirm that everything it was responsible for had stopped.
	//
	// The component IS shut down; it accepts no further work and needs no
	// second call.
	//
	// IT DOES NOT BY ITSELF MEAN A KEY WAS RETAINED. It used to, and the
	// promise outlived the code: BLEPeripheral.Stop also returns this when an
	// advertisement could not be taken down, which leaves the peripheral
	// possibly discoverable but cannot reach the protected pages — those are
	// read by the accepted connections alone, and a confirmed join frees them
	// whatever the advertisement did. A caller that reads this sentinel as
	// "retained" therefore holds locked pages it could have freed.
	//
	// The safe rule for a caller that SUPPLIED a key: this error means the
	// component could not prove it finished, so do not destroy the key on the
	// strength of it. Each component documents which of its conditions retains
	// the key; see BLEPeripheral.Stop.
	ErrShutdownIncomplete = errors.New("phone: shutdown could not confirm everything finished")
)

// MessageError is a typed error that carries a preformatted message. It
// replaces inline formatted-error constructions that do not wrap a cause.
type MessageError struct {
	Msg string
}

// Error implements the error interface.
func (e *MessageError) Error() string {
	return e.Msg
}

// SentinelCauseError attaches an underlying cause to a package sentinel
// error so errors.Is matches both the sentinel and the cause.
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

// WrappedError wraps an underlying cause with a contextual message while
// preserving errors.Is / errors.As matching through Unwrap. It replaces
// inline formatted-error constructions that wrap another error.
type WrappedError struct {
	Msg string
	Err error
}

// Error implements the error interface.
func (e *WrappedError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

// Unwrap returns the wrapped cause.
func (e *WrappedError) Unwrap() error {
	return e.Err
}
