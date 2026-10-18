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
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
)

func TestErrors_AllDefined(t *testing.T) {
	allErrors := []struct {
		name string
		err  error
	}{
		{"ErrInvalidConfig", ErrInvalidConfig},
		{"ErrInvalidTransport", ErrInvalidTransport},
		{"ErrMissingDeviceAddress", ErrMissingDeviceAddress},
		{"ErrMissingNoiseStaticKey", ErrMissingNoiseStaticKey},
		{"ErrMissingPhoneStaticKey", ErrMissingPhoneStaticKey},
		{"ErrNotConnected", ErrNotConnected},
		{"ErrBackendClosed", ErrBackendClosed},
		{"ErrConnectionLost", ErrConnectionLost},
		{"ErrKeyNotFound", ErrKeyNotFound},
		{"ErrKeyExists", ErrKeyExists},
		{"ErrUnsupportedAlgorithm", ErrUnsupportedAlgorithm},
		{"ErrOperationTimeout", ErrOperationTimeout},
		{"ErrUserCancelled", ErrUserCancelled},
		{"ErrBiometricFailed", ErrBiometricFailed},
		{"ErrAttestationFailed", ErrAttestationFailed},
		{"ErrRotationNotSupported", ErrRotationNotSupported},
		{"ErrExportNotSupported", ErrExportNotSupported},
		{"ErrImportNotSupported", ErrImportNotSupported},
		{"ErrTransportUnavailable", ErrTransportUnavailable},
		{"ErrProtocolError", ErrProtocolError},
		{"ErrInvalidPublicKey", ErrInvalidPublicKey},
		{"ErrInvalidResponse", ErrInvalidResponse},
		{"ErrSigningFailed", ErrSigningFailed},
		{"ErrNilBackend", ErrNilBackend},
		{"ErrNilPublicKey", ErrNilPublicKey},
		{"ErrEmptyKeyID", ErrEmptyKeyID},
		{"ErrEmptyAlgorithm", ErrEmptyAlgorithm},
		{"ErrInvalidKeyAttributes", ErrInvalidKeyAttributes},
		{"ErrInvalidPeerPublicKey", ErrInvalidPeerPublicKey},
		{"ErrEmptySharedSecret", ErrEmptySharedSecret},
		{"ErrInvalidKDFParams", ErrInvalidKDFParams},
		{"ErrSymmetricEncryptFailed", ErrSymmetricEncryptFailed},
		{"ErrSymmetricDecryptFailed", ErrSymmetricDecryptFailed},
	}

	for _, tc := range allErrors {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err == nil {
				t.Errorf("error %s is nil", tc.name)
			}
		})
	}
}

func TestErrors_Uniqueness(t *testing.T) {
	allErrors := []error{
		ErrInvalidConfig,
		ErrInvalidTransport,
		ErrMissingDeviceAddress,
		ErrMissingNoiseStaticKey,
		ErrMissingPhoneStaticKey,
		ErrNotConnected,
		ErrBackendClosed,
		ErrConnectionLost,
		ErrKeyNotFound,
		ErrKeyExists,
		ErrUnsupportedAlgorithm,
		ErrOperationTimeout,
		ErrUserCancelled,
		ErrBiometricFailed,
		ErrAttestationFailed,
		ErrRotationNotSupported,
		ErrExportNotSupported,
		ErrImportNotSupported,
		ErrTransportUnavailable,
		ErrProtocolError,
		ErrInvalidPublicKey,
		ErrInvalidResponse,
		ErrSigningFailed,
		ErrNilBackend,
		ErrNilPublicKey,
		ErrEmptyKeyID,
		ErrEmptyAlgorithm,
		ErrInvalidKeyAttributes,
		ErrInvalidPeerPublicKey,
		ErrEmptySharedSecret,
		ErrInvalidKDFParams,
		ErrSymmetricEncryptFailed,
		ErrSymmetricDecryptFailed,
	}

	seen := make(map[string]int)
	for i, err := range allErrors {
		msg := err.Error()
		if prevIdx, exists := seen[msg]; exists {
			t.Errorf("duplicate error message %q at index %d and %d", msg, prevIdx, i)
		}
		seen[msg] = i
	}
}

func TestErrors_PrefixConvention(t *testing.T) {
	const prefix = "phone backend:"

	allErrors := []struct {
		name string
		err  error
	}{
		{"ErrInvalidConfig", ErrInvalidConfig},
		{"ErrInvalidTransport", ErrInvalidTransport},
		{"ErrMissingDeviceAddress", ErrMissingDeviceAddress},
		{"ErrMissingNoiseStaticKey", ErrMissingNoiseStaticKey},
		{"ErrMissingPhoneStaticKey", ErrMissingPhoneStaticKey},
		{"ErrNotConnected", ErrNotConnected},
		{"ErrBackendClosed", ErrBackendClosed},
		{"ErrConnectionLost", ErrConnectionLost},
		// ErrKeyNotFound is the shared backend.ErrKeyNotFound sentinel (#801), so
		// it carries the "backend:" prefix, not this package's. ErrKeyExists
		// is backend.ErrKeyAlreadyExists (#1599) for the same reason.
		{"ErrUnsupportedAlgorithm", ErrUnsupportedAlgorithm},
		{"ErrOperationTimeout", ErrOperationTimeout},
		{"ErrUserCancelled", ErrUserCancelled},
		{"ErrBiometricFailed", ErrBiometricFailed},
		{"ErrAttestationFailed", ErrAttestationFailed},
		{"ErrRotationNotSupported", ErrRotationNotSupported},
		{"ErrExportNotSupported", ErrExportNotSupported},
		{"ErrImportNotSupported", ErrImportNotSupported},
		{"ErrTransportUnavailable", ErrTransportUnavailable},
		{"ErrProtocolError", ErrProtocolError},
		{"ErrInvalidPublicKey", ErrInvalidPublicKey},
		{"ErrInvalidResponse", ErrInvalidResponse},
		{"ErrSigningFailed", ErrSigningFailed},
		{"ErrNilBackend", ErrNilBackend},
		{"ErrNilPublicKey", ErrNilPublicKey},
		{"ErrEmptyKeyID", ErrEmptyKeyID},
		{"ErrEmptyAlgorithm", ErrEmptyAlgorithm},
		{"ErrInvalidKeyAttributes", ErrInvalidKeyAttributes},
		{"ErrInvalidPeerPublicKey", ErrInvalidPeerPublicKey},
		{"ErrEmptySharedSecret", ErrEmptySharedSecret},
		{"ErrInvalidKDFParams", ErrInvalidKDFParams},
		{"ErrSymmetricEncryptFailed", ErrSymmetricEncryptFailed},
		{"ErrSymmetricDecryptFailed", ErrSymmetricDecryptFailed},
	}

	for _, tc := range allErrors {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			if !strings.HasPrefix(msg, prefix) {
				t.Errorf("error %s message %q does not start with prefix %q", tc.name, msg, prefix)
			}
		})
	}
}

func TestErrors_ErrorInterface(t *testing.T) {
	// Verify all errors satisfy the error interface and produce non-empty messages.
	allErrors := []error{
		ErrInvalidConfig,
		ErrBackendClosed,
		ErrKeyNotFound,
		ErrProtocolError,
		ErrSigningFailed,
	}

	for _, err := range allErrors {
		if err.Error() == "" {
			t.Errorf("error message should not be empty for %v", err)
		}
	}
}

// TestErrKeyNotFound_IsBackendSentinel pins the #801 GetKey contract: the
// phone backend's not-found result must satisfy errors.Is against the shared
// backend sentinel, like every other backend.
func TestErrKeyNotFound_IsBackendSentinel(t *testing.T) {
	if !errors.Is(ErrKeyNotFound, backend.ErrKeyNotFound) {
		t.Fatal("phone.ErrKeyNotFound must be backend.ErrKeyNotFound")
	}
	if errors.Is(ErrConnectionLost, backend.ErrKeyNotFound) {
		t.Fatal("a lost connection must not be classified as not-found")
	}
}

// TestErrKeyExists_IsBackendSentinel pins the #1599 get-or-generate contract:
// the phone backend's key-exists result must satisfy errors.Is against the
// shared backend sentinel, so a caller that lost a generate race recovers.
func TestErrKeyExists_IsBackendSentinel(t *testing.T) {
	if !errors.Is(ErrKeyExists, backend.ErrKeyAlreadyExists) {
		t.Fatal("phone.ErrKeyExists must be backend.ErrKeyAlreadyExists")
	}
	if errors.Is(ErrConnectionLost, backend.ErrKeyAlreadyExists) {
		t.Fatal("a lost connection must not be classified as key-exists")
	}
}
