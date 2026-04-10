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

package xkms

import (
	"errors"
	"fmt"
	"testing"
)

func TestErrorCode_String(t *testing.T) {
	tests := []struct {
		name     string
		code     ErrorCode
		expected string
	}{
		{"Unknown", ErrCodeUnknown, "Unknown"},
		{"Connection", ErrCodeConnection, "ConnectionFailed"},
		{"NotConnected", ErrCodeNotConnected, "NotConnected"},
		{"NotFound", ErrCodeNotFound, "NotFound"},
		{"InvalidRequest", ErrCodeInvalidRequest, "InvalidRequest"},
		{"Timeout", ErrCodeTimeout, "Timeout"},
		{"Authentication", ErrCodeAuthentication, "Authentication"},
		{"Permission", ErrCodePermission, "Permission"},
		{"BackendUnavailable", ErrCodeBackendUnavailable, "BackendUnavailable"},
		{"ProtocolUnsupported", ErrCodeProtocolUnsupported, "ProtocolUnsupported"},
		{"OperationUnsupported", ErrCodeOperationUnsupported, "OperationUnsupported"},
		{"NilService", ErrCodeNilService, "NilService"},
		{"InvalidCode", ErrorCode(999), "ErrorCode(999)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.code.String()
			if result != tt.expected {
				t.Errorf("ErrorCode.String() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestXKMSError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *XKMSError
		expected string
	}{
		{
			name: "SimpleMessage",
			err: &XKMSError{
				Code:    ErrCodeNotFound,
				Message: "key not found",
			},
			expected: "key not found",
		},
		{
			name: "WithOperation",
			err: &XKMSError{
				Code:      ErrCodeNotFound,
				Message:   "key not found",
				Operation: "GetKey",
			},
			expected: "GetKey: key not found",
		},
		{
			name: "WithUnderlying",
			err: &XKMSError{
				Code:       ErrCodeConnection,
				Message:    "connection failed",
				Underlying: errors.New("network error"),
			},
			expected: "connection failed: network error",
		},
		{
			name: "WithOperationAndUnderlying",
			err: &XKMSError{
				Code:       ErrCodeConnection,
				Message:    "connection failed",
				Operation:  "Connect",
				Underlying: errors.New("network error"),
			},
			expected: "Connect: connection failed: network error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("XKMSError.Error() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestXKMSError_Unwrap(t *testing.T) {
	t.Run("WithUnderlying", func(t *testing.T) {
		underlying := errors.New("underlying error")
		err := &XKMSError{
			Code:       ErrCodeConnection,
			Message:    "connection failed",
			Underlying: underlying,
		}

		unwrapped := err.Unwrap()
		if unwrapped != underlying {
			t.Errorf("Unwrap() = %v, want %v", unwrapped, underlying)
		}
	})

	t.Run("WithoutUnderlying", func(t *testing.T) {
		err := &XKMSError{
			Code:    ErrCodeNotFound,
			Message: "not found",
		}

		unwrapped := err.Unwrap()
		if unwrapped != nil {
			t.Errorf("Unwrap() = %v, want nil", unwrapped)
		}
	})
}

func TestXKMSError_Is(t *testing.T) {
	tests := []struct {
		name     string
		err      *XKMSError
		target   error
		expected bool
	}{
		{
			name:     "MatchSameCode",
			err:      &XKMSError{Code: ErrCodeNotFound, Message: "test"},
			target:   &XKMSError{Code: ErrCodeNotFound, Message: "different"},
			expected: true,
		},
		{
			name:     "NoMatchDifferentCode",
			err:      &XKMSError{Code: ErrCodeNotFound, Message: "test"},
			target:   &XKMSError{Code: ErrCodeConnection, Message: "test"},
			expected: false,
		},
		{
			name:     "MatchErrUnsupportedProtocol",
			err:      &XKMSError{Code: ErrCodeProtocolUnsupported, Message: "test"},
			target:   ErrUnsupportedProtocol,
			expected: true,
		},
		{
			name:     "MatchErrConnectionFailed",
			err:      &XKMSError{Code: ErrCodeConnection, Message: "test"},
			target:   ErrConnectionFailed,
			expected: true,
		},
		{
			name:     "MatchErrNotConnected",
			err:      &XKMSError{Code: ErrCodeNotConnected, Message: "test"},
			target:   ErrNotConnected,
			expected: true,
		},
		{
			name:     "MatchErrNotSupported",
			err:      &XKMSError{Code: ErrCodeOperationUnsupported, Message: "test"},
			target:   ErrNotSupported,
			expected: true,
		},
		{
			name:     "MatchErrNilService",
			err:      &XKMSError{Code: ErrCodeNilService, Message: "test"},
			target:   ErrNilService,
			expected: true,
		},
		{
			name:     "MatchErrKeyNotFound",
			err:      &XKMSError{Code: ErrCodeNotFound, Message: "test"},
			target:   ErrKeyNotFound,
			expected: true,
		},
		{
			name:     "MatchErrCertificateNotFound",
			err:      &XKMSError{Code: ErrCodeNotFound, Message: "test"},
			target:   ErrCertificateNotFound,
			expected: true,
		},
		{
			name:     "MatchErrBackendNotFound",
			err:      &XKMSError{Code: ErrCodeNotFound, Message: "test"},
			target:   ErrBackendNotFound,
			expected: true,
		},
		{
			name:     "MatchErrInvalidRequest",
			err:      &XKMSError{Code: ErrCodeInvalidRequest, Message: "test"},
			target:   ErrInvalidRequest,
			expected: true,
		},
		{
			name:     "NoMatchUnrelatedError",
			err:      &XKMSError{Code: ErrCodeNotFound, Message: "test"},
			target:   errors.New("random error"),
			expected: false,
		},
		{
			name:     "NoMatchUnknownCode",
			err:      &XKMSError{Code: ErrCodeUnknown, Message: "test"},
			target:   ErrKeyNotFound,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Is(tt.target)
			if result != tt.expected {
				t.Errorf("Is(%v) = %v, want %v", tt.target, result, tt.expected)
			}
		})
	}
}

func TestErrorsIs_Integration(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		target   error
		expected bool
	}{
		{
			name:     "DirectXKMSErrorMatchesSentinel",
			err:      &XKMSError{Code: ErrCodeNotFound, Message: "key not found"},
			target:   ErrKeyNotFound,
			expected: true,
		},
		{
			name:     "WrappedXKMSErrorMatchesSentinel",
			err:      fmt.Errorf("operation failed: %w", &XKMSError{Code: ErrCodeNotFound, Message: "key not found"}),
			target:   ErrKeyNotFound,
			expected: true,
		},
		{
			name:     "WrappedXKMSErrorMatchesXKMSError",
			err:      fmt.Errorf("operation failed: %w", &XKMSError{Code: ErrCodeNotFound, Message: "key not found"}),
			target:   &XKMSError{Code: ErrCodeNotFound},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := errors.Is(tt.err, tt.target)
			if result != tt.expected {
				t.Errorf("errors.Is() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestErrorsAs_Integration(t *testing.T) {
	t.Run("DirectXKMSError", func(t *testing.T) {
		err := &XKMSError{
			Code:      ErrCodeNotFound,
			Message:   "key not found",
			Operation: "GetKey",
		}

		var ke *XKMSError
		if !errors.As(err, &ke) {
			t.Fatal("errors.As() returned false, expected true")
		}

		if ke.Code != ErrCodeNotFound {
			t.Errorf("Code = %v, want %v", ke.Code, ErrCodeNotFound)
		}
		if ke.Operation != "GetKey" {
			t.Errorf("Operation = %q, want %q", ke.Operation, "GetKey")
		}
	})

	t.Run("WrappedXKMSError", func(t *testing.T) {
		innerErr := &XKMSError{
			Code:      ErrCodeConnection,
			Message:   "connection failed",
			Operation: "Connect",
		}
		err := fmt.Errorf("outer error: %w", innerErr)

		var ke *XKMSError
		if !errors.As(err, &ke) {
			t.Fatal("errors.As() returned false, expected true")
		}

		if ke.Code != ErrCodeConnection {
			t.Errorf("Code = %v, want %v", ke.Code, ErrCodeConnection)
		}
	})

	t.Run("NonXKMSError", func(t *testing.T) {
		err := errors.New("plain error")

		var ke *XKMSError
		if errors.As(err, &ke) {
			t.Error("errors.As() returned true, expected false")
		}
	})
}

func TestNewError(t *testing.T) {
	t.Run("CreatesErrorWithCodeAndMessage", func(t *testing.T) {
		err := NewError(ErrCodeNotFound, "resource not found")

		if err.Code != ErrCodeNotFound {
			t.Errorf("Code = %v, want %v", err.Code, ErrCodeNotFound)
		}
		if err.Message != "resource not found" {
			t.Errorf("Message = %q, want %q", err.Message, "resource not found")
		}
		if err.Operation != "" {
			t.Errorf("Operation = %q, want empty", err.Operation)
		}
		if err.Underlying != nil {
			t.Errorf("Underlying = %v, want nil", err.Underlying)
		}
	})
}

func TestNewErrorWithOperation(t *testing.T) {
	t.Run("CreatesErrorWithOperation", func(t *testing.T) {
		err := NewErrorWithOperation(ErrCodeConnection, "Connect", "dial failed")

		if err.Code != ErrCodeConnection {
			t.Errorf("Code = %v, want %v", err.Code, ErrCodeConnection)
		}
		if err.Message != "dial failed" {
			t.Errorf("Message = %q, want %q", err.Message, "dial failed")
		}
		if err.Operation != "Connect" {
			t.Errorf("Operation = %q, want %q", err.Operation, "Connect")
		}
	})
}

func TestWrapError(t *testing.T) {
	t.Run("WrapsExistingError", func(t *testing.T) {
		underlying := errors.New("network error")
		err := WrapError(ErrCodeConnection, "connection failed", underlying)

		if err.Code != ErrCodeConnection {
			t.Errorf("Code = %v, want %v", err.Code, ErrCodeConnection)
		}
		if err.Underlying != underlying {
			t.Errorf("Underlying = %v, want %v", err.Underlying, underlying)
		}

		// Verify errors.Is works through wrapping
		if !errors.Is(err, underlying) {
			t.Error("errors.Is(err, underlying) = false, want true")
		}
	})
}

func TestWrapErrorWithOperation(t *testing.T) {
	t.Run("WrapsWithOperation", func(t *testing.T) {
		underlying := errors.New("timeout")
		err := WrapErrorWithOperation(ErrCodeTimeout, "Sign", "operation timed out", underlying)

		if err.Code != ErrCodeTimeout {
			t.Errorf("Code = %v, want %v", err.Code, ErrCodeTimeout)
		}
		if err.Operation != "Sign" {
			t.Errorf("Operation = %q, want %q", err.Operation, "Sign")
		}
		if err.Underlying != underlying {
			t.Errorf("Underlying = %v, want %v", err.Underlying, underlying)
		}
	})
}

func TestIsNotFound(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"NilError", nil, false},
		{"ErrKeyNotFound", ErrKeyNotFound, true},
		{"ErrCertificateNotFound", ErrCertificateNotFound, true},
		{"ErrBackendNotFound", ErrBackendNotFound, true},
		{"XKMSErrorNotFound", &XKMSError{Code: ErrCodeNotFound, Message: "test"}, true},
		{"XKMSErrorConnection", &XKMSError{Code: ErrCodeConnection, Message: "test"}, false},
		{"PlainError", errors.New("not found"), false},
		{"WrappedKeyNotFound", fmt.Errorf("wrapped: %w", ErrKeyNotFound), true},
		{"WrappedXKMSErrorNotFound", fmt.Errorf("wrapped: %w", &XKMSError{Code: ErrCodeNotFound}), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsNotFound(tt.err)
			if result != tt.expected {
				t.Errorf("IsNotFound() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"NilError", nil, false},
		{"ErrConnectionFailed", ErrConnectionFailed, true},
		{"XKMSErrorConnection", &XKMSError{Code: ErrCodeConnection, Message: "test"}, true},
		{"XKMSErrorTimeout", &XKMSError{Code: ErrCodeTimeout, Message: "test"}, true},
		{"XKMSErrorBackendUnavailable", &XKMSError{Code: ErrCodeBackendUnavailable, Message: "test"}, true},
		{"XKMSErrorNotFound", &XKMSError{Code: ErrCodeNotFound, Message: "test"}, false},
		{"XKMSErrorAuthentication", &XKMSError{Code: ErrCodeAuthentication, Message: "test"}, false},
		{"PlainError", errors.New("some error"), false},
		{"WrappedConnectionFailed", fmt.Errorf("wrapped: %w", ErrConnectionFailed), true},
		{"WrappedXKMSErrorTimeout", fmt.Errorf("wrapped: %w", &XKMSError{Code: ErrCodeTimeout}), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsRetryable(tt.err)
			if result != tt.expected {
				t.Errorf("IsRetryable() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsConnectionError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"NilError", nil, false},
		{"ErrConnectionFailed", ErrConnectionFailed, true},
		{"ErrNotConnected", ErrNotConnected, true},
		{"XKMSErrorConnection", &XKMSError{Code: ErrCodeConnection, Message: "test"}, true},
		{"XKMSErrorNotConnected", &XKMSError{Code: ErrCodeNotConnected, Message: "test"}, true},
		{"XKMSErrorTimeout", &XKMSError{Code: ErrCodeTimeout, Message: "test"}, false},
		{"PlainError", errors.New("connection error"), false},
		{"WrappedNotConnected", fmt.Errorf("wrapped: %w", ErrNotConnected), true},
		{"WrappedXKMSErrorConnection", fmt.Errorf("wrapped: %w", &XKMSError{Code: ErrCodeConnection}), true},
		{"WrappedXKMSErrorNotConnected", fmt.Errorf("wrapped: %w", &XKMSError{Code: ErrCodeNotConnected}), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsConnectionError(tt.err)
			if result != tt.expected {
				t.Errorf("IsConnectionError() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsAuthenticationError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"NilError", nil, false},
		{"XKMSErrorAuthentication", &XKMSError{Code: ErrCodeAuthentication, Message: "test"}, true},
		{"XKMSErrorPermission", &XKMSError{Code: ErrCodePermission, Message: "test"}, false},
		{"PlainError", errors.New("auth error"), false},
		{"WrappedXKMSErrorAuth", fmt.Errorf("wrapped: %w", &XKMSError{Code: ErrCodeAuthentication}), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsAuthenticationError(tt.err)
			if result != tt.expected {
				t.Errorf("IsAuthenticationError() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsPermissionError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"NilError", nil, false},
		{"XKMSErrorPermission", &XKMSError{Code: ErrCodePermission, Message: "test"}, true},
		{"XKMSErrorAuthentication", &XKMSError{Code: ErrCodeAuthentication, Message: "test"}, false},
		{"PlainError", errors.New("permission denied"), false},
		{"WrappedXKMSErrorPermission", fmt.Errorf("wrapped: %w", &XKMSError{Code: ErrCodePermission}), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsPermissionError(tt.err)
			if result != tt.expected {
				t.Errorf("IsPermissionError() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsInvalidRequest(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"NilError", nil, false},
		{"ErrInvalidRequest", ErrInvalidRequest, true},
		{"XKMSErrorInvalidRequest", &XKMSError{Code: ErrCodeInvalidRequest, Message: "test"}, true},
		{"XKMSErrorNotFound", &XKMSError{Code: ErrCodeNotFound, Message: "test"}, false},
		{"PlainError", errors.New("invalid"), false},
		{"WrappedInvalidRequest", fmt.Errorf("wrapped: %w", ErrInvalidRequest), true},
		{"WrappedXKMSErrorInvalid", fmt.Errorf("wrapped: %w", &XKMSError{Code: ErrCodeInvalidRequest}), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsInvalidRequest(tt.err)
			if result != tt.expected {
				t.Errorf("IsInvalidRequest() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsTimeout(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"NilError", nil, false},
		{"XKMSErrorTimeout", &XKMSError{Code: ErrCodeTimeout, Message: "test"}, true},
		{"XKMSErrorConnection", &XKMSError{Code: ErrCodeConnection, Message: "test"}, false},
		{"PlainError", errors.New("timeout"), false},
		{"WrappedXKMSErrorTimeout", fmt.Errorf("wrapped: %w", &XKMSError{Code: ErrCodeTimeout}), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsTimeout(tt.err)
			if result != tt.expected {
				t.Errorf("IsTimeout() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetErrorCode(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected ErrorCode
	}{
		{"NilError", nil, ErrCodeUnknown},
		{"XKMSErrorNotFound", &XKMSError{Code: ErrCodeNotFound, Message: "test"}, ErrCodeNotFound},
		{"XKMSErrorTimeout", &XKMSError{Code: ErrCodeTimeout, Message: "test"}, ErrCodeTimeout},
		{"PlainError", errors.New("error"), ErrCodeUnknown},
		{"WrappedXKMSError", fmt.Errorf("wrapped: %w", &XKMSError{Code: ErrCodeConnection}), ErrCodeConnection},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetErrorCode(tt.err)
			if result != tt.expected {
				t.Errorf("GetErrorCode() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestConvertSentinelError(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		expectedCode ErrorCode
		isNil        bool
	}{
		{"NilError", nil, ErrCodeUnknown, true},
		{"ErrUnsupportedProtocol", ErrUnsupportedProtocol, ErrCodeProtocolUnsupported, false},
		{"ErrConnectionFailed", ErrConnectionFailed, ErrCodeConnection, false},
		{"ErrNotConnected", ErrNotConnected, ErrCodeNotConnected, false},
		{"ErrNotSupported", ErrNotSupported, ErrCodeOperationUnsupported, false},
		{"ErrNilService", ErrNilService, ErrCodeNilService, false},
		{"ErrKeyNotFound", ErrKeyNotFound, ErrCodeNotFound, false},
		{"ErrCertificateNotFound", ErrCertificateNotFound, ErrCodeNotFound, false},
		{"ErrBackendNotFound", ErrBackendNotFound, ErrCodeNotFound, false},
		{"ErrInvalidRequest", ErrInvalidRequest, ErrCodeInvalidRequest, false},
		{"PlainError", errors.New("unknown error"), ErrCodeUnknown, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConvertSentinelError(tt.err)
			if tt.isNil {
				if result != nil {
					t.Errorf("ConvertSentinelError() = %v, want nil", result)
				}
				return
			}

			if result == nil {
				t.Fatal("ConvertSentinelError() = nil, want non-nil")
			}

			if result.Code != tt.expectedCode {
				t.Errorf("Code = %v, want %v", result.Code, tt.expectedCode)
			}
		})
	}

	t.Run("AlreadyXKMSError", func(t *testing.T) {
		original := &XKMSError{
			Code:      ErrCodeTimeout,
			Message:   "operation timed out",
			Operation: "Sign",
		}

		result := ConvertSentinelError(original)

		if result != original {
			t.Error("ConvertSentinelError() did not return same XKMSError instance")
		}
	})

	t.Run("WrappedSentinelError", func(t *testing.T) {
		wrapped := fmt.Errorf("operation failed: %w", ErrKeyNotFound)
		result := ConvertSentinelError(wrapped)

		if result.Code != ErrCodeNotFound {
			t.Errorf("Code = %v, want %v", result.Code, ErrCodeNotFound)
		}

		// Should be able to unwrap to the original
		if !errors.Is(result, ErrKeyNotFound) {
			t.Error("Converted error should unwrap to original sentinel")
		}
	})
}

func TestBackwardCompatibility(t *testing.T) {
	// This test ensures that code using the original sentinel errors
	// continues to work correctly with the new typed error system.

	t.Run("SentinelErrorsStillWork", func(t *testing.T) {
		// Verify sentinel errors can still be used directly
		if errors.Is(ErrKeyNotFound, ErrCertificateNotFound) {
			t.Error("Different sentinel errors should not match")
		}

		// Verify sentinel errors are distinct
		allSentinels := []error{
			ErrUnsupportedProtocol,
			ErrConnectionFailed,
			ErrNotConnected,
			ErrNotSupported,
			ErrNilService,
			ErrKeyNotFound,
			ErrCertificateNotFound,
			ErrBackendNotFound,
			ErrInvalidRequest,
		}

		for i, e1 := range allSentinels {
			for j, e2 := range allSentinels {
				if i != j && errors.Is(e1, e2) {
					t.Errorf("Sentinel errors %v and %v should not match", e1, e2)
				}
			}
		}
	})

	t.Run("XKMSErrorMatchesSentinels", func(t *testing.T) {
		// Verify XKMSError with appropriate codes match sentinel errors
		testCases := []struct {
			err      *XKMSError
			sentinel error
		}{
			{&XKMSError{Code: ErrCodeProtocolUnsupported}, ErrUnsupportedProtocol},
			{&XKMSError{Code: ErrCodeConnection}, ErrConnectionFailed},
			{&XKMSError{Code: ErrCodeNotConnected}, ErrNotConnected},
			{&XKMSError{Code: ErrCodeOperationUnsupported}, ErrNotSupported},
			{&XKMSError{Code: ErrCodeNilService}, ErrNilService},
			{&XKMSError{Code: ErrCodeNotFound}, ErrKeyNotFound},
			{&XKMSError{Code: ErrCodeInvalidRequest}, ErrInvalidRequest},
		}

		for _, tc := range testCases {
			if !errors.Is(tc.err, tc.sentinel) {
				t.Errorf("XKMSError{Code: %v} should match sentinel %v", tc.err.Code, tc.sentinel)
			}
		}
	})

	t.Run("WrappedErrorsWork", func(t *testing.T) {
		// Simulate a function returning wrapped XKMSError
		err := fmt.Errorf("GetKey operation: %w", &XKMSError{
			Code:    ErrCodeNotFound,
			Message: "key 'test-key' not found",
		})

		// Legacy code should still be able to check for ErrKeyNotFound
		if !errors.Is(err, ErrKeyNotFound) {
			t.Error("Wrapped XKMSError should match ErrKeyNotFound sentinel")
		}

		// New code can extract rich error information
		var ke *XKMSError
		if !errors.As(err, &ke) {
			t.Fatal("Should be able to extract XKMSError")
		}

		if ke.Code != ErrCodeNotFound {
			t.Errorf("Extracted error code = %v, want %v", ke.Code, ErrCodeNotFound)
		}
	})
}

func TestErrorChaining(t *testing.T) {
	// Test deeply nested error chains
	t.Run("DeepErrorChain", func(t *testing.T) {
		root := errors.New("network unreachable")
		level1 := fmt.Errorf("dial failed: %w", root)
		level2 := WrapError(ErrCodeConnection, "connection failed", level1)
		level3 := fmt.Errorf("Connect operation: %w", level2)

		// Should be able to find root error
		if !errors.Is(level3, root) {
			t.Error("Should find root error through chain")
		}

		// Should be able to find XKMSError
		var ke *XKMSError
		if !errors.As(level3, &ke) {
			t.Fatal("Should find XKMSError in chain")
		}

		if ke.Code != ErrCodeConnection {
			t.Errorf("Code = %v, want %v", ke.Code, ErrCodeConnection)
		}

		// Should match sentinel
		if !errors.Is(level3, ErrConnectionFailed) {
			t.Error("Should match ErrConnectionFailed sentinel")
		}
	})
}
