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

package ccid

import (
	"errors"
	"testing"
)

func TestSentinelErrors_NotNil(t *testing.T) {
	errs := []struct {
		name string
		err  error
	}{
		{"ErrDeviceNotAvailable", ErrDeviceNotAvailable},
		{"ErrDeviceAlreadyRunning", ErrDeviceAlreadyRunning},
		{"ErrDeviceNotRunning", ErrDeviceNotRunning},
		{"ErrAPDUTooLong", ErrAPDUTooLong},
		{"ErrAPDUMalformed", ErrAPDUMalformed},
		{"ErrUnsupportedInstruction", ErrUnsupportedInstruction},
		{"ErrSessionNotFound", ErrSessionNotFound},
		{"ErrNilHandler", ErrNilHandler},
		{"ErrNilLogger", ErrNilLogger},
		{"ErrNilService", ErrNilService},
		{"ErrCCIDMessageTooShort", ErrCCIDMessageTooShort},
		{"ErrCCIDUnsupportedMessage", ErrCCIDUnsupportedMessage},
		{"ErrLoginFailed", ErrLoginFailed},
		{"ErrSignFailed", ErrSignFailed},
		{"ErrVerifyFailed", ErrVerifyFailed},
		{"ErrEncryptFailed", ErrEncryptFailed},
		{"ErrDecryptFailed", ErrDecryptFailed},
		{"ErrKeyGenerationFailed", ErrKeyGenerationFailed},
		{"ErrCertificateReadFailed", ErrCertificateReadFailed},
		{"ErrAppletNotSelected", ErrAppletNotSelected},
	}

	for _, tt := range errs {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Errorf("%s is nil", tt.name)
			}
			if tt.err.Error() == "" {
				t.Errorf("%s has empty message", tt.name)
			}
		})
	}
}

func TestSentinelErrors_Distinct(t *testing.T) {
	errs := []error{
		ErrDeviceNotAvailable,
		ErrDeviceAlreadyRunning,
		ErrDeviceNotRunning,
		ErrAPDUTooLong,
		ErrAPDUMalformed,
		ErrUnsupportedInstruction,
		ErrSessionNotFound,
		ErrNilHandler,
		ErrNilLogger,
		ErrNilService,
		ErrCCIDMessageTooShort,
		ErrCCIDUnsupportedMessage,
		ErrLoginFailed,
		ErrSignFailed,
		ErrVerifyFailed,
		ErrEncryptFailed,
		ErrDecryptFailed,
		ErrKeyGenerationFailed,
		ErrCertificateReadFailed,
		ErrAppletNotSelected,
	}

	for i, e1 := range errs {
		for j, e2 := range errs {
			if i != j && errors.Is(e1, e2) {
				t.Errorf("Error %v should not match error %v", e1, e2)
			}
		}
	}
}

func TestCCIDError(t *testing.T) {
	cause := errors.New("underlying cause")
	err := NewCCIDError("test-op", cause)

	if err.Operation != "test-op" {
		t.Errorf("Operation = %q, want %q", err.Operation, "test-op")
	}

	if !errors.Is(err, cause) {
		t.Error("CCIDError should wrap the cause")
	}

	if err.Error() == "" {
		t.Error("CCIDError.Error() returned empty string")
	}

	// Verify the error message contains both operation and cause
	msg := err.Error()
	if msg != "ccid: test-op: underlying cause" {
		t.Errorf("Error message = %q, want %q", msg, "ccid: test-op: underlying cause")
	}
}

func TestCCIDError_Unwrap(t *testing.T) {
	cause := ErrDeviceNotAvailable
	err := NewCCIDError("open", cause)

	if !errors.Is(err, ErrDeviceNotAvailable) {
		t.Error("Unwrap should return ErrDeviceNotAvailable")
	}
}

func TestCCIDError_AsType(t *testing.T) {
	err := NewCCIDError("test", errors.New("cause"))

	var ccidErr *CCIDError
	if !errors.As(err, &ccidErr) {
		t.Error("errors.As should succeed for *CCIDError")
	}

	if ccidErr.Operation != "test" {
		t.Errorf("Operation = %q, want %q", ccidErr.Operation, "test")
	}
}
