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

	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// Errors delegated to pairing package. These are returned by pairing code
// and must be the same values so errors.Is() works correctly.
var (
	ErrNotConnected             = pairing.ErrNotConnected
	ErrConnectionFailed         = pairing.ErrConnectionFailed
	ErrDeviceNotFound           = pairing.ErrDeviceNotFound
	ErrPairingFailed            = pairing.ErrPairingFailed
	ErrTimeout                  = pairing.ErrTimeout
	ErrNoiseHandshakeFailed     = pairing.ErrNoiseHandshakeFailed
	ErrEncryptionFailed         = pairing.ErrEncryptionFailed
	ErrDecryptionFailed         = pairing.ErrDecryptionFailed
	ErrInvalidResponse          = pairing.ErrInvalidResponse
	ErrUserCancelled            = pairing.ErrUserCancelled
	ErrBiometricFailed          = pairing.ErrBiometricFailed
	ErrKeyNotFound              = pairing.ErrKeyNotFound
	ErrProtocolError            = pairing.ErrProtocolError
	ErrFragmentationError       = pairing.ErrFragmentationError
	ErrBackendClosed            = pairing.ErrBackendClosed
	ErrInvalidCredentialID      = pairing.ErrInvalidCredentialID
	ErrUnsupportedAlgorithm     = pairing.ErrUnsupportedAlgorithm
	ErrExportNotSupported       = pairing.ErrExportNotSupported
	ErrImportNotSupported       = pairing.ErrImportNotSupported
	ErrInvalidKeyHandle         = pairing.ErrInvalidKeyHandle
	ErrMaxRetriesExceeded       = pairing.ErrMaxRetriesExceeded
	ErrInvalidFragment          = pairing.ErrInvalidFragment
	ErrSequenceNumber           = pairing.ErrSequenceNumber
	ErrMTUTooSmall              = pairing.ErrMTUTooSmall
	ErrSessionExpired           = pairing.ErrSessionExpired
	ErrInvalidNoiseMessage      = pairing.ErrInvalidNoiseMessage
	ErrStaticKeyMismatch        = pairing.ErrStaticKeyMismatch
	ErrStorageFull              = pairing.ErrStorageFull
	ErrKeyExists                = pairing.ErrKeyExists
	ErrBackendDenied            = pairing.ErrBackendDenied
	ErrAttestationFailed        = pairing.ErrAttestationFailed
	ErrAttestationNotSupported  = pairing.ErrAttestationNotSupported
	ErrInvalidAttestationNonce  = pairing.ErrInvalidAttestationNonce
	ErrTPM2Required             = pairing.ErrTPM2Required
	ErrOperationDenied          = pairing.ErrOperationDenied
	ErrInvalidPublicKey         = pairing.ErrInvalidPublicKey
	ErrDecryptFailed            = pairing.ErrDecryptFailed
	ErrHMACFailed               = pairing.ErrHMACFailed
	ErrECDHFailed               = pairing.ErrECDHFailed
	ErrInvalidFormat            = pairing.ErrInvalidFormat
	ErrInvalidRpID              = pairing.ErrInvalidRpID
	ErrInvalidClientDataHash    = pairing.ErrInvalidClientDataHash
	ErrBridgeNotConnected       = pairing.ErrBridgeNotConnected
	ErrBridgeInvalidParams      = pairing.ErrBridgeInvalidParams
	ErrBridgeBackendDenied      = pairing.ErrBridgeBackendDenied
	ErrPairingRejected          = pairing.ErrPairingRejected
	ErrUntrustedDevice          = pairing.ErrUntrustedDevice
	ErrTPM2DirectAccessRequired = pairing.ErrTPM2DirectAccessRequired
	ErrShareDenied              = pairing.ErrShareDenied
	ErrShareNotExportable       = pairing.ErrShareNotExportable
	ErrSharePolicyNotFound      = pairing.ErrSharePolicyNotFound
	ErrShareInvalidKeyType      = pairing.ErrShareInvalidKeyType
	ErrBackupFailed             = pairing.ErrBackupFailed
	ErrBackupRestoreFailed      = pairing.ErrBackupRestoreFailed
	ErrBackupNotFound           = pairing.ErrBackupNotFound
	ErrOATHCredentialNotFound   = pairing.ErrOATHCredentialNotFound
	ErrOATHGenerateFailed       = pairing.ErrOATHGenerateFailed
	ErrOATHStoreFailed          = pairing.ErrOATHStoreFailed
	ErrPIVSlotNotFound          = pairing.ErrPIVSlotNotFound
	ErrPIVSlotOccupied          = pairing.ErrPIVSlotOccupied
	ErrPIVSignFailed            = pairing.ErrPIVSignFailed
	ErrPIVInvalidSlot           = pairing.ErrPIVInvalidSlot
	ErrSyncFailed               = pairing.ErrSyncFailed
	ErrSyncConflict             = pairing.ErrSyncConflict
	ErrSyncRemoteUnavailable    = pairing.ErrSyncRemoteUnavailable
	ErrSyncNoData               = pairing.ErrSyncNoData
	ErrSyncVersionMismatch      = pairing.ErrSyncVersionMismatch
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

	// ErrUSBUnavailable indicates this binary was built without USB phone
	// transport support (the "usb" build tag): the gousb/libusb dependency
	// is excluded from static and CGO_ENABLED=0 builds.
	ErrUSBUnavailable = errors.New("phone: usb transport not built (build with -tags usb)")

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
