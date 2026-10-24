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

package pairingproto

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrors_AllErrorsDefined(t *testing.T) {
	definedErrors := []error{
		ErrNotConnected,
		ErrConnectionFailed,
		ErrDeviceNotFound,
		ErrPairingFailed,
		ErrTimeout,
		ErrInvalidResponse,
		ErrUserCancelled,
		ErrBiometricFailed,
		ErrKeyNotFound,
		ErrProtocolError,
		ErrMessageTooLarge,
		ErrFragmentationError,
		ErrBackendClosed,
		ErrInvalidCredentialID,
		ErrUnsupportedAlgorithm,
		ErrExportNotSupported,
		ErrImportNotSupported,
		ErrInvalidKeyHandle,
		ErrMaxRetriesExceeded,
		ErrInvalidFragment,
		ErrSequenceNumber,
		ErrMTUTooSmall,
		ErrSessionExpired,
		ErrStorageFull,
		ErrKeyExists,
		ErrBackendDenied,
		ErrAttestationFailed,
		ErrAttestationNotSupported,
		ErrOperationDenied,
		ErrInvalidPublicKey,
		ErrDecryptFailed,
		ErrHMACFailed,
		ErrECDHFailed,
		ErrInvalidFormat,
		ErrBridgeNotConnected,
		ErrBridgeInvalidParams,
		ErrBridgeBackendDenied,
		ErrPairingRejected,
		ErrUntrustedDevice,
		ErrTPM2DirectAccessRequired,
		ErrShareDenied,
		ErrShareNotExportable,
		ErrSharePolicyNotFound,
		ErrShareInvalidKeyType,
		ErrBackupFailed,
		ErrBackupRestoreFailed,
		ErrBackupNotFound,
		ErrOATHCredentialNotFound,
		ErrOATHGenerateFailed,
		ErrOATHStoreFailed,
		ErrPIVSlotNotFound,
		ErrPIVSlotOccupied,
		ErrPIVSignFailed,
		ErrPIVInvalidSlot,
		ErrSyncFailed,
		ErrSyncConflict,
		ErrSyncRemoteUnavailable,
		ErrSyncNoData,
		ErrSyncVersionMismatch,
	}

	for _, err := range definedErrors {
		require.NotNil(t, err)
		assert.NotEmpty(t, err.Error())
	}
}

func TestErrors_Uniqueness(t *testing.T) {
	definedErrors := []error{
		ErrNotConnected,
		ErrConnectionFailed,
		ErrDeviceNotFound,
		ErrPairingFailed,
		ErrTimeout,
		ErrInvalidResponse,
		ErrUserCancelled,
		ErrBiometricFailed,
		ErrKeyNotFound,
		ErrProtocolError,
		ErrMessageTooLarge,
		ErrFragmentationError,
		ErrBackendClosed,
		ErrInvalidCredentialID,
		ErrUnsupportedAlgorithm,
		ErrExportNotSupported,
		ErrImportNotSupported,
		ErrInvalidKeyHandle,
		ErrMaxRetriesExceeded,
		ErrInvalidFragment,
		ErrSequenceNumber,
		ErrMTUTooSmall,
		ErrSessionExpired,
		ErrStorageFull,
		ErrKeyExists,
		ErrBackendDenied,
		ErrAttestationFailed,
		ErrAttestationNotSupported,
		ErrOperationDenied,
		ErrInvalidPublicKey,
		ErrDecryptFailed,
		ErrHMACFailed,
		ErrECDHFailed,
		ErrInvalidFormat,
	}

	seen := make(map[string]bool)
	for _, err := range definedErrors {
		msg := err.Error()
		assert.False(t, seen[msg], "duplicate error message: %s", msg)
		seen[msg] = true
	}
}

func TestErrors_PrefixConvention(t *testing.T) {
	definedErrors := []error{
		ErrNotConnected,
		ErrConnectionFailed,
		ErrDeviceNotFound,
		ErrBackendClosed,
	}

	for _, err := range definedErrors {
		assert.Contains(t, err.Error(), "pairing:")
	}
}

func TestErrors_IsChecks(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		target error
		want   bool
	}{
		{
			name:   "ErrNotConnected matches itself",
			err:    ErrNotConnected,
			target: ErrNotConnected,
			want:   true,
		},
		{
			name:   "ErrNotConnected does not match ErrTimeout",
			err:    ErrNotConnected,
			target: ErrTimeout,
			want:   false,
		},
		{
			name:   "wrapped ErrKeyNotFound matches ErrKeyNotFound",
			err:    errors.Join(errors.New("outer"), ErrKeyNotFound),
			target: ErrKeyNotFound,
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := errors.Is(tt.err, tt.target)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestDetailError_Error verifies the wrapped error message is followed
// directly by the detail text, with no separator inserted, and that
// errors.Is still matches the wrapped sentinel through Unwrap.
func TestDetailError_Error(t *testing.T) {
	err := &DetailError{Err: ErrDeviceNotFound, Detail: ": no matching device"}

	assert.Equal(t, "pairing: device not found: no matching device", err.Error())
	assert.True(t, errors.Is(err, ErrDeviceNotFound))
}

// TestSentinelCauseError_Error verifies the message joins the sentinel and
// the cause, and that errors.Is matches both through Unwrap.
func TestSentinelCauseError_Error(t *testing.T) {
	cause := errors.New("connection reset")
	err := &SentinelCauseError{Sentinel: ErrConnectionFailed, Cause: cause}

	assert.Equal(t, "pairing: connection failed: connection reset", err.Error())
	assert.True(t, errors.Is(err, ErrConnectionFailed))
	assert.True(t, errors.Is(err, cause))
}

func TestMessageTooLargeError(t *testing.T) {
	err := error(&MessageTooLargeError{Size: 70000, Limit: MaxUSBMessageSize})

	assert.Contains(t, err.Error(), "70000 bytes")
	assert.Contains(t, err.Error(), fmt.Sprintf("limit %d", MaxUSBMessageSize))
	assert.ErrorIs(t, err, ErrMessageTooLarge)
	assert.ErrorIs(t, err, ErrProtocolError, "a size refusal is still a protocol error")
	assert.NotErrorIs(t, err, ErrConnectionFailed)
}

// TestUSBError_Error pins the message format and that the libusb cause stays
// reachable, so a caller can still match a specific libusb failure.
func TestUSBError_Error(t *testing.T) {
	cause := errors.New("LIBUSB_ERROR_ACCESS")
	err := &USBError{Op: "start AOA mode", Err: cause}

	assert.Equal(t, "pairing: usb start AOA mode: LIBUSB_ERROR_ACCESS", err.Error())
	assert.True(t, errors.Is(err, cause))
	assert.False(t, errors.Is(err, ErrConnectionFailed))
}
