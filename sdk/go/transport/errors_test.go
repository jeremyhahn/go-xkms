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

package transport

import (
	"errors"
	"fmt"
	"testing"
)

func TestErrorCodeString(t *testing.T) {
	tests := []struct {
		code     ErrorCode
		expected string
	}{
		{ErrCodeUnknown, "Unknown"},
		{ErrCodeNotConnected, "NotConnected"},
		{ErrCodeConnectionFailed, "ConnectionFailed"},
		{ErrCodeConnectionClosed, "ConnectionClosed"},
		{ErrCodeTimeout, "Timeout"},
		{ErrCodeStreamClosed, "StreamClosed"},
		{ErrCodeStreamNotSupported, "StreamNotSupported"},
		{ErrCodeInvalidConfig, "InvalidConfig"},
		{ErrCodeMethodNotFound, "MethodNotFound"},
		{ErrCodeInvalidRequest, "InvalidRequest"},
		{ErrCodeInvalidResponse, "InvalidResponse"},
		{ErrCodeTLSHandshakeFailed, "TLSHandshakeFailed"},
		{ErrCodeAuthenticationFailed, "AuthenticationFailed"},
		{ErrorCode(999), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.code.String(); got != tt.expected {
				t.Errorf("ErrorCode.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestTransportErrorError(t *testing.T) {
	tests := []struct {
		name     string
		err      *TransportError
		contains []string
	}{
		{
			name: "simple error",
			err: &TransportError{
				Code:    ErrCodeConnectionFailed,
				Message: "connection refused",
			},
			contains: []string{"connection refused"},
		},
		{
			name: "error with operation",
			err: &TransportError{
				Code:      ErrCodeTimeout,
				Message:   "request timed out",
				Operation: "Connect",
			},
			contains: []string{"Connect", "request timed out"},
		},
		{
			name: "error with address",
			err: &TransportError{
				Code:    ErrCodeConnectionFailed,
				Message: "connection failed",
				Address: "localhost:8080",
			},
			contains: []string{"connection failed", "localhost:8080"},
		},
		{
			name: "error with underlying",
			err: &TransportError{
				Code:       ErrCodeConnectionFailed,
				Message:    "connection failed",
				Underlying: fmt.Errorf("network unreachable"),
			},
			contains: []string{"connection failed", "network unreachable"},
		},
		{
			name: "full error",
			err: &TransportError{
				Code:       ErrCodeTimeout,
				Message:    "request timed out",
				Operation:  "GenerateKey",
				Address:    "localhost:9000",
				Underlying: fmt.Errorf("context deadline exceeded"),
			},
			contains: []string{"GenerateKey", "request timed out", "localhost:9000", "context deadline exceeded"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			for _, s := range tt.contains {
				if !containsString(errStr, s) {
					t.Errorf("error string %q should contain %q", errStr, s)
				}
			}
		})
	}
}

func TestTransportErrorUnwrap(t *testing.T) {
	underlying := fmt.Errorf("underlying error")
	err := &TransportError{
		Code:       ErrCodeConnectionFailed,
		Message:    "connection failed",
		Underlying: underlying,
	}

	unwrapped := err.Unwrap()
	if unwrapped != underlying {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, underlying)
	}

	// Test with nil underlying
	errNoUnderlying := &TransportError{
		Code:    ErrCodeTimeout,
		Message: "timeout",
	}
	if errNoUnderlying.Unwrap() != nil {
		t.Error("Unwrap() should return nil when no underlying error")
	}
}

func TestTransportErrorIs(t *testing.T) {
	tests := []struct {
		name   string
		err    *TransportError
		target error
		want   bool
	}{
		{
			name:   "match sentinel ErrNotConnected",
			err:    &TransportError{Code: ErrCodeNotConnected, Message: "not connected"},
			target: ErrNotConnected,
			want:   true,
		},
		{
			name:   "match sentinel ErrConnectionFailed",
			err:    &TransportError{Code: ErrCodeConnectionFailed, Message: "failed"},
			target: ErrConnectionFailed,
			want:   true,
		},
		{
			name:   "match sentinel ErrConnectionClosed",
			err:    &TransportError{Code: ErrCodeConnectionClosed, Message: "closed"},
			target: ErrConnectionClosed,
			want:   true,
		},
		{
			name:   "match sentinel ErrTimeout",
			err:    &TransportError{Code: ErrCodeTimeout, Message: "timeout"},
			target: ErrTimeout,
			want:   true,
		},
		{
			name:   "match sentinel ErrStreamClosed",
			err:    &TransportError{Code: ErrCodeStreamClosed, Message: "stream closed"},
			target: ErrStreamClosed,
			want:   true,
		},
		{
			name:   "match sentinel ErrStreamNotSupported",
			err:    &TransportError{Code: ErrCodeStreamNotSupported, Message: "not supported"},
			target: ErrStreamNotSupported,
			want:   true,
		},
		{
			name:   "match sentinel ErrInvalidConfig",
			err:    &TransportError{Code: ErrCodeInvalidConfig, Message: "invalid"},
			target: ErrInvalidConfig,
			want:   true,
		},
		{
			name:   "match sentinel ErrMethodNotFound",
			err:    &TransportError{Code: ErrCodeMethodNotFound, Message: "not found"},
			target: ErrMethodNotFound,
			want:   true,
		},
		{
			name:   "match sentinel ErrInvalidRequest",
			err:    &TransportError{Code: ErrCodeInvalidRequest, Message: "invalid"},
			target: ErrInvalidRequest,
			want:   true,
		},
		{
			name:   "match sentinel ErrInvalidResponse",
			err:    &TransportError{Code: ErrCodeInvalidResponse, Message: "invalid"},
			target: ErrInvalidResponse,
			want:   true,
		},
		{
			name:   "match sentinel ErrTLSHandshakeFailed",
			err:    &TransportError{Code: ErrCodeTLSHandshakeFailed, Message: "failed"},
			target: ErrTLSHandshakeFailed,
			want:   true,
		},
		{
			name:   "match sentinel ErrAuthenticationFailed",
			err:    &TransportError{Code: ErrCodeAuthenticationFailed, Message: "failed"},
			target: ErrAuthenticationFailed,
			want:   true,
		},
		{
			name:   "match same TransportError code",
			err:    &TransportError{Code: ErrCodeTimeout, Message: "timeout"},
			target: &TransportError{Code: ErrCodeTimeout, Message: "different message"},
			want:   true,
		},
		{
			name:   "no match different code",
			err:    &TransportError{Code: ErrCodeTimeout, Message: "timeout"},
			target: ErrConnectionFailed,
			want:   false,
		},
		{
			name:   "no match unknown error",
			err:    &TransportError{Code: ErrCodeUnknown, Message: "unknown"},
			target: ErrNotConnected,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := errors.Is(tt.err, tt.target); got != tt.want {
				t.Errorf("errors.Is() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewTransportError(t *testing.T) {
	err := NewTransportError(ErrCodeConnectionFailed, "connection failed")

	if err.Code != ErrCodeConnectionFailed {
		t.Errorf("expected code %v, got %v", ErrCodeConnectionFailed, err.Code)
	}
	if err.Message != "connection failed" {
		t.Errorf("expected message 'connection failed', got %q", err.Message)
	}
	if err.Operation != "" {
		t.Errorf("expected empty operation, got %q", err.Operation)
	}
}

func TestNewTransportErrorWithOperation(t *testing.T) {
	err := NewTransportErrorWithOperation(ErrCodeTimeout, "Connect", "connection timed out")

	if err.Code != ErrCodeTimeout {
		t.Errorf("expected code %v, got %v", ErrCodeTimeout, err.Code)
	}
	if err.Message != "connection timed out" {
		t.Errorf("expected message 'connection timed out', got %q", err.Message)
	}
	if err.Operation != "Connect" {
		t.Errorf("expected operation 'Connect', got %q", err.Operation)
	}
}

func TestWrapTransportError(t *testing.T) {
	underlying := fmt.Errorf("network error")
	err := WrapTransportError(ErrCodeConnectionFailed, "connection failed", underlying)

	if err.Code != ErrCodeConnectionFailed {
		t.Errorf("expected code %v, got %v", ErrCodeConnectionFailed, err.Code)
	}
	if err.Underlying != underlying {
		t.Error("underlying error not set correctly")
	}
}

func TestWrapTransportErrorWithAddress(t *testing.T) {
	underlying := fmt.Errorf("network error")
	err := WrapTransportErrorWithAddress(ErrCodeConnectionFailed, "connection failed", "localhost:8080", underlying)

	if err.Code != ErrCodeConnectionFailed {
		t.Errorf("expected code %v, got %v", ErrCodeConnectionFailed, err.Code)
	}
	if err.Address != "localhost:8080" {
		t.Errorf("expected address 'localhost:8080', got %q", err.Address)
	}
	if err.Underlying != underlying {
		t.Error("underlying error not set correctly")
	}
}

func TestConfigError(t *testing.T) {
	t.Run("error message", func(t *testing.T) {
		err := &ConfigError{
			Field:   "Timeout",
			Message: "cannot be negative",
		}

		expected := "transport config: Timeout: cannot be negative"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("is ErrInvalidConfig", func(t *testing.T) {
		err := &ConfigError{
			Field:   "Address",
			Message: "cannot be empty",
		}

		if !errors.Is(err, ErrInvalidConfig) {
			t.Error("ConfigError should match ErrInvalidConfig")
		}
	})

	t.Run("is same field ConfigError", func(t *testing.T) {
		err1 := &ConfigError{Field: "Timeout", Message: "msg1"}
		err2 := &ConfigError{Field: "Timeout", Message: "msg2"}

		if !errors.Is(err1, err2) {
			t.Error("ConfigErrors with same field should match")
		}
	})

	t.Run("is different field ConfigError", func(t *testing.T) {
		err1 := &ConfigError{Field: "Timeout", Message: "msg"}
		err2 := &ConfigError{Field: "Address", Message: "msg"}

		if errors.Is(err1, err2) {
			t.Error("ConfigErrors with different fields should not match")
		}
	})
}

func TestErrorHelperFunctions(t *testing.T) {
	t.Run("IsNotConnected", func(t *testing.T) {
		if IsNotConnected(nil) {
			t.Error("nil error should return false")
		}
		if !IsNotConnected(ErrNotConnected) {
			t.Error("ErrNotConnected should return true")
		}
		if !IsNotConnected(&TransportError{Code: ErrCodeNotConnected}) {
			t.Error("TransportError with ErrCodeNotConnected should return true")
		}
		if IsNotConnected(ErrTimeout) {
			t.Error("ErrTimeout should return false")
		}
	})

	t.Run("IsConnectionFailed", func(t *testing.T) {
		if IsConnectionFailed(nil) {
			t.Error("nil error should return false")
		}
		if !IsConnectionFailed(ErrConnectionFailed) {
			t.Error("ErrConnectionFailed should return true")
		}
		if !IsConnectionFailed(&TransportError{Code: ErrCodeConnectionFailed}) {
			t.Error("TransportError with ErrCodeConnectionFailed should return true")
		}
	})

	t.Run("IsConnectionClosed", func(t *testing.T) {
		if IsConnectionClosed(nil) {
			t.Error("nil error should return false")
		}
		if !IsConnectionClosed(ErrConnectionClosed) {
			t.Error("ErrConnectionClosed should return true")
		}
	})

	t.Run("IsTimeout", func(t *testing.T) {
		if IsTimeout(nil) {
			t.Error("nil error should return false")
		}
		if !IsTimeout(ErrTimeout) {
			t.Error("ErrTimeout should return true")
		}
	})

	t.Run("IsStreamClosed", func(t *testing.T) {
		if IsStreamClosed(nil) {
			t.Error("nil error should return false")
		}
		if !IsStreamClosed(ErrStreamClosed) {
			t.Error("ErrStreamClosed should return true")
		}
	})

	t.Run("IsStreamNotSupported", func(t *testing.T) {
		if IsStreamNotSupported(nil) {
			t.Error("nil error should return false")
		}
		if !IsStreamNotSupported(ErrStreamNotSupported) {
			t.Error("ErrStreamNotSupported should return true")
		}
	})

	t.Run("IsInvalidConfig", func(t *testing.T) {
		if IsInvalidConfig(nil) {
			t.Error("nil error should return false")
		}
		if !IsInvalidConfig(ErrInvalidConfig) {
			t.Error("ErrInvalidConfig should return true")
		}
		if !IsInvalidConfig(&ConfigError{Field: "test"}) {
			t.Error("ConfigError should return true")
		}
	})
}

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"ErrConnectionFailed", ErrConnectionFailed, true},
		{"ErrConnectionClosed", ErrConnectionClosed, true},
		{"ErrTimeout", ErrTimeout, true},
		{"ErrNotConnected", ErrNotConnected, false},
		{"ErrStreamClosed", ErrStreamClosed, false},
		{
			"TransportError ConnectionFailed",
			&TransportError{Code: ErrCodeConnectionFailed},
			true,
		},
		{
			"TransportError ConnectionClosed",
			&TransportError{Code: ErrCodeConnectionClosed},
			true,
		},
		{
			"TransportError Timeout",
			&TransportError{Code: ErrCodeTimeout},
			true,
		},
		{
			"TransportError NotConnected",
			&TransportError{Code: ErrCodeNotConnected},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRetryable(tt.err); got != tt.want {
				t.Errorf("IsRetryable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetErrorCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorCode
	}{
		{"nil error", nil, ErrCodeUnknown},
		{"ErrNotConnected", ErrNotConnected, ErrCodeNotConnected},
		{"ErrConnectionFailed", ErrConnectionFailed, ErrCodeConnectionFailed},
		{"ErrConnectionClosed", ErrConnectionClosed, ErrCodeConnectionClosed},
		{"ErrTimeout", ErrTimeout, ErrCodeTimeout},
		{"ErrStreamClosed", ErrStreamClosed, ErrCodeStreamClosed},
		{"ErrStreamNotSupported", ErrStreamNotSupported, ErrCodeStreamNotSupported},
		{"ErrInvalidConfig", ErrInvalidConfig, ErrCodeInvalidConfig},
		{"ErrMethodNotFound", ErrMethodNotFound, ErrCodeMethodNotFound},
		{"ErrInvalidRequest", ErrInvalidRequest, ErrCodeInvalidRequest},
		{"ErrInvalidResponse", ErrInvalidResponse, ErrCodeInvalidResponse},
		{"ErrTLSHandshakeFailed", ErrTLSHandshakeFailed, ErrCodeTLSHandshakeFailed},
		{"ErrAuthenticationFailed", ErrAuthenticationFailed, ErrCodeAuthenticationFailed},
		{
			"TransportError",
			&TransportError{Code: ErrCodeTimeout},
			ErrCodeTimeout,
		},
		{"unknown error", fmt.Errorf("some error"), ErrCodeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetErrorCode(tt.err); got != tt.want {
				t.Errorf("GetErrorCode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSentinelErrors(t *testing.T) {
	// Verify all sentinel errors are distinct
	sentinels := []error{
		ErrNotConnected,
		ErrConnectionFailed,
		ErrConnectionClosed,
		ErrTimeout,
		ErrStreamClosed,
		ErrStreamNotSupported,
		ErrInvalidConfig,
		ErrMethodNotFound,
		ErrInvalidRequest,
		ErrInvalidResponse,
		ErrTLSHandshakeFailed,
		ErrAuthenticationFailed,
	}

	for i, err1 := range sentinels {
		for j, err2 := range sentinels {
			if i != j && errors.Is(err1, err2) {
				t.Errorf("sentinel errors %v and %v should not match", err1, err2)
			}
		}
	}
}

// containsString checks if s contains substr
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
