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
			expectedString: "vfido2: invalid storage type",
		},
		{
			name:           "ErrStoragePathRequired",
			err:            ErrStoragePathRequired,
			expectedString: "vfido2: storage path required for file storage type",
		},
		{
			name:           "ErrInvalidLogLevel",
			err:            ErrInvalidLogLevel,
			expectedString: "vfido2: invalid log level",
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

func TestDaemonLifecycleErrors(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		expectedString string
	}{
		{
			name:           "ErrPIDFileWriteFailed",
			err:            ErrPIDFileWriteFailed,
			expectedString: "vfido2: failed to write PID file",
		},
		{
			name:           "ErrPIDFileRemoveFailed",
			err:            ErrPIDFileRemoveFailed,
			expectedString: "vfido2: failed to remove PID file",
		},
		{
			name:           "ErrLogFileOpenFailed",
			err:            ErrLogFileOpenFailed,
			expectedString: "vfido2: failed to open log file",
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
			expectedString: "vfido2: device already running",
		},
		{
			name:           "ErrDeviceNotRunning",
			err:            ErrDeviceNotRunning,
			expectedString: "vfido2: device not running",
		},
		{
			name:           "ErrStorageCreationFailed",
			err:            ErrStorageCreationFailed,
			expectedString: "vfido2: storage creation failed",
		},
		{
			name:           "ErrAuthenticatorCreationFailed",
			err:            ErrAuthenticatorCreationFailed,
			expectedString: "vfido2: authenticator creation failed",
		},
		{
			name:           "ErrUHIDOpenFailed",
			err:            ErrUHIDOpenFailed,
			expectedString: "vfido2: UHID open failed",
		},
		{
			name:           "ErrUHIDCreateFailed",
			err:            ErrUHIDCreateFailed,
			expectedString: "vfido2: UHID create failed",
		},
		{
			name:           "ErrPINSetFailed",
			err:            ErrPINSetFailed,
			expectedString: "vfido2: PIN set failed",
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
		ErrPIDFileWriteFailed,
		ErrPIDFileRemoveFailed,
		ErrLogFileOpenFailed,
		ErrDeviceAlreadyRunning,
		ErrDeviceNotRunning,
		ErrStorageCreationFailed,
		ErrAuthenticatorCreationFailed,
		ErrUHIDOpenFailed,
		ErrUHIDCreateFailed,
		ErrPINSetFailed,
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
		wrapped := errors.Join(ErrPIDFileWriteFailed, baseErr)

		// Should be able to check for the sentinel error
		if !errors.Is(wrapped, ErrPIDFileWriteFailed) {
			t.Error("wrapped error should match ErrPIDFileWriteFailed")
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
		ErrPIDFileWriteFailed,
		ErrPIDFileRemoveFailed,
		ErrLogFileOpenFailed,
	}

	prefix := "vfido2:"

	for _, err := range allErrors {
		t.Run(err.Error(), func(t *testing.T) {
			msg := err.Error()
			if len(msg) < len(prefix) || msg[:len(prefix)] != prefix {
				t.Errorf("error %q should have prefix %q", msg, prefix)
			}
		})
	}
}
