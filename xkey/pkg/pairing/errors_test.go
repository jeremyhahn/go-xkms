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

package pairing

import (
	"errors"
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
		ErrNoiseHandshakeFailed,
		ErrEncryptionFailed,
		ErrDecryptionFailed,
		ErrInvalidResponse,
		ErrUserCancelled,
		ErrBiometricFailed,
		ErrKeyNotFound,
		ErrProtocolError,
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
		ErrInvalidNoiseMessage,
		ErrStaticKeyMismatch,
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
		ErrNoiseHandshakeFailed,
		ErrEncryptionFailed,
		ErrDecryptionFailed,
		ErrInvalidResponse,
		ErrUserCancelled,
		ErrBiometricFailed,
		ErrKeyNotFound,
		ErrProtocolError,
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
		ErrInvalidNoiseMessage,
		ErrStaticKeyMismatch,
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
