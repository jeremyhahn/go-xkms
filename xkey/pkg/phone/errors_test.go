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

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allDelegatedErrors returns every error that is delegated to pairing.
func allDelegatedErrors() []error {
	return []error{
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
		ErrInvalidAttestationNonce,
		ErrTPM2Required,
		ErrOperationDenied,
		ErrInvalidPublicKey,
		ErrDecryptFailed,
		ErrHMACFailed,
		ErrECDHFailed,
		ErrInvalidFormat,
		ErrInvalidRpID,
		ErrInvalidClientDataHash,
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
}

// allPhoneOnlyErrors returns every error that is phone-specific (not delegated).
func allPhoneOnlyErrors() []error {
	return []error{
		ErrBLEUnavailable,
		ErrAdapterDisabled,
		ErrServiceNotFound,
		ErrCharacteristicNotFound,
		ErrDBusStaleObject,
	}
}

func TestErrors_AllErrorsDefined(t *testing.T) {
	allErrors := append(allDelegatedErrors(), allPhoneOnlyErrors()...)
	for _, err := range allErrors {
		require.NotNil(t, err)
		assert.NotEmpty(t, err.Error())
	}
}

func TestErrors_Uniqueness(t *testing.T) {
	allErrors := append(allDelegatedErrors(), allPhoneOnlyErrors()...)
	seen := make(map[string]bool)
	for _, err := range allErrors {
		msg := err.Error()
		assert.False(t, seen[msg], "duplicate error message: %s", msg)
		seen[msg] = true
	}
}

func TestErrors_DelegatedErrorsUsePairingPrefix(t *testing.T) {
	for _, err := range allDelegatedErrors() {
		assert.Contains(t, err.Error(), "pairing:",
			"delegated error should have pairing: prefix: %s", err.Error())
	}
}

func TestErrors_PhoneOnlyErrorsUsePhonePrefix(t *testing.T) {
	for _, err := range allPhoneOnlyErrors() {
		assert.Contains(t, err.Error(), "phone:",
			"phone-only error should have phone: prefix: %s", err.Error())
	}
}

func TestErrors_DelegatedErrorsMatchPairing(t *testing.T) {
	// Verify that delegated errors are the exact same sentinel values as
	// in the pairing package so errors.Is() works across packages.
	tests := []struct {
		phoneErr   error
		pairingErr error
	}{
		{ErrNotConnected, pairing.ErrNotConnected},
		{ErrConnectionFailed, pairing.ErrConnectionFailed},
		{ErrDeviceNotFound, pairing.ErrDeviceNotFound},
		{ErrPairingFailed, pairing.ErrPairingFailed},
		{ErrTimeout, pairing.ErrTimeout},
		{ErrNoiseHandshakeFailed, pairing.ErrNoiseHandshakeFailed},
		{ErrEncryptionFailed, pairing.ErrEncryptionFailed},
		{ErrDecryptionFailed, pairing.ErrDecryptionFailed},
		{ErrInvalidResponse, pairing.ErrInvalidResponse},
		{ErrUserCancelled, pairing.ErrUserCancelled},
		{ErrBiometricFailed, pairing.ErrBiometricFailed},
		{ErrKeyNotFound, pairing.ErrKeyNotFound},
		{ErrProtocolError, pairing.ErrProtocolError},
		{ErrFragmentationError, pairing.ErrFragmentationError},
		{ErrBackendClosed, pairing.ErrBackendClosed},
		{ErrBackupFailed, pairing.ErrBackupFailed},
		{ErrSyncFailed, pairing.ErrSyncFailed},
		{ErrInvalidAttestationNonce, pairing.ErrInvalidAttestationNonce},
		{ErrTPM2Required, pairing.ErrTPM2Required},
	}

	for _, tt := range tests {
		assert.True(t, errors.Is(tt.phoneErr, tt.pairingErr),
			"phone.%v should match pairing.%v", tt.phoneErr, tt.pairingErr)
		assert.True(t, errors.Is(tt.pairingErr, tt.phoneErr),
			"pairing.%v should match phone.%v (same value)", tt.pairingErr, tt.phoneErr)
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
		{
			name:   "phone.ErrNotConnected matches pairing.ErrNotConnected",
			err:    ErrNotConnected,
			target: pairing.ErrNotConnected,
			want:   true,
		},
		{
			name:   "phone.ErrBLEUnavailable does not match pairing errors",
			err:    ErrBLEUnavailable,
			target: pairing.ErrNotConnected,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := errors.Is(tt.err, tt.target)
			assert.Equal(t, tt.want, got)
		})
	}
}
