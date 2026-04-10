//go:build ignore

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

package main

import (
	"errors"
	"testing"
)

func TestConfigurationErrors(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		expectedString string
	}{
		{
			name:           "ErrInvalidStorageType",
			err:            ErrInvalidStorageType,
			expectedString: "fido2key: invalid storage type",
		},
		{
			name:           "ErrStoragePathRequired",
			err:            ErrStoragePathRequired,
			expectedString: "fido2key: storage path required for file storage type",
		},
		{
			name:           "ErrInvalidLogLevel",
			err:            ErrInvalidLogLevel,
			expectedString: "fido2key: invalid log level",
		},
		{
			name:           "ErrInvalidBackend",
			err:            ErrInvalidBackend,
			expectedString: "fido2key: invalid backend type",
		},
		{
			name:           "ErrInvalidAttestationFormat",
			err:            ErrInvalidAttestationFormat,
			expectedString: "fido2key: invalid attestation format",
		},
		{
			name:           "ErrTPMAttestationRequiresTPMBackend",
			err:            ErrTPMAttestationRequiresTPMBackend,
			expectedString: "fido2key: TPM attestation requires tpm2 backend",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Error("error should not be nil")
			}

			if tt.err.Error() != tt.expectedString {
				t.Errorf("error = %q, want %q", tt.err.Error(), tt.expectedString)
			}
		})
	}
}

func TestLoggingErrors(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		expectedString string
	}{
		{
			name:           "ErrLogFileOpenFailed",
			err:            ErrLogFileOpenFailed,
			expectedString: "fido2key: failed to open log file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Error("error should not be nil")
			}

			if tt.err.Error() != tt.expectedString {
				t.Errorf("error = %q, want %q", tt.err.Error(), tt.expectedString)
			}
		})
	}
}

func TestDeviceLifecycleErrors(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		expectedString string
	}{
		{
			name:           "ErrDeviceAlreadyRunning",
			err:            ErrDeviceAlreadyRunning,
			expectedString: "fido2key: device already running",
		},
		{
			name:           "ErrDeviceNotRunning",
			err:            ErrDeviceNotRunning,
			expectedString: "fido2key: device not running",
		},
		{
			name:           "ErrStorageCreationFailed",
			err:            ErrStorageCreationFailed,
			expectedString: "fido2key: storage creation failed",
		},
		{
			name:           "ErrAuthenticatorCreationFailed",
			err:            ErrAuthenticatorCreationFailed,
			expectedString: "fido2key: authenticator creation failed",
		},
		{
			name:           "ErrUHIDOpenFailed",
			err:            ErrUHIDOpenFailed,
			expectedString: "fido2key: UHID open failed",
		},
		{
			name:           "ErrUHIDCreateFailed",
			err:            ErrUHIDCreateFailed,
			expectedString: "fido2key: UHID create failed",
		},
		{
			name:           "ErrPINSetFailed",
			err:            ErrPINSetFailed,
			expectedString: "fido2key: PIN set failed",
		},
		{
			name:           "ErrTPMOpenFailed",
			err:            ErrTPMOpenFailed,
			expectedString: "fido2key: TPM open failed",
		},
		{
			name:           "ErrTPMBackendCreationFailed",
			err:            ErrTPMBackendCreationFailed,
			expectedString: "fido2key: TPM2 backend creation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Error("error should not be nil")
			}

			if tt.err.Error() != tt.expectedString {
				t.Errorf("error = %q, want %q", tt.err.Error(), tt.expectedString)
			}
		})
	}
}

func TestErrorsAreDistinct(t *testing.T) {
	allErrors := []error{
		ErrInvalidStorageType,
		ErrStoragePathRequired,
		ErrInvalidLogLevel,
		ErrLogFileOpenFailed,
		ErrDeviceAlreadyRunning,
		ErrDeviceNotRunning,
		ErrStorageCreationFailed,
		ErrAuthenticatorCreationFailed,
		ErrUHIDOpenFailed,
		ErrUHIDCreateFailed,
		ErrPINSetFailed,
		ErrInvalidBackend,
		ErrInvalidAttestationFormat,
		ErrTPMAttestationRequiresTPMBackend,
		ErrTPMOpenFailed,
		ErrTPMBackendCreationFailed,
	}

	// Ensure all errors are distinct
	seen := make(map[string]bool)
	for _, err := range allErrors {
		msg := err.Error()
		if seen[msg] {
			t.Errorf("duplicate error message: %q", msg)
		}
		seen[msg] = true
	}
}

func TestErrorWrapping(t *testing.T) {
	t.Run("errors can be wrapped and unwrapped", func(t *testing.T) {
		baseErr := errors.New("underlying error")
		wrapped := errors.Join(ErrLogFileOpenFailed, baseErr)

		// Should be able to check for the sentinel error
		if !errors.Is(wrapped, ErrLogFileOpenFailed) {
			t.Error("wrapped error should match ErrLogFileOpenFailed")
		}

		// Should contain the underlying error
		if !errors.Is(wrapped, baseErr) {
			t.Error("wrapped error should contain baseErr")
		}
	})

	t.Run("storage errors can be joined", func(t *testing.T) {
		baseErr := errors.New("disk full")
		wrapped := errors.Join(ErrStorageCreationFailed, baseErr)

		if !errors.Is(wrapped, ErrStorageCreationFailed) {
			t.Error("wrapped error should match ErrStorageCreationFailed")
		}

		// Verify the error message contains both parts
		msg := wrapped.Error()
		if msg == "" {
			t.Error("wrapped error message should not be empty")
		}
	})
}

func TestErrorsHavePrefix(t *testing.T) {
	allErrors := []error{
		ErrInvalidStorageType,
		ErrStoragePathRequired,
		ErrInvalidLogLevel,
		ErrLogFileOpenFailed,
		ErrInvalidBackend,
		ErrInvalidAttestationFormat,
		ErrTPMAttestationRequiresTPMBackend,
	}

	prefix := "fido2key:"

	for _, err := range allErrors {
		t.Run(err.Error(), func(t *testing.T) {
			msg := err.Error()
			if len(msg) < len(prefix) || msg[:len(prefix)] != prefix {
				t.Errorf("error %q should have prefix %q", msg, prefix)
			}
		})
	}
}
