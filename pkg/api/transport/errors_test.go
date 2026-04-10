// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package transport

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorCode_String(t *testing.T) {
	tests := []struct {
		code ErrorCode
		want string
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
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.code.String())
		})
	}
}

func TestTransportError_Error(t *testing.T) {
	tests := []struct {
		name string
		err  *TransportError
		want string
	}{
		{
			name: "message only",
			err:  &TransportError{Message: "something failed"},
			want: "something failed",
		},
		{
			name: "with operation",
			err:  &TransportError{Operation: "Connect", Message: "refused"},
			want: "Connect: refused",
		},
		{
			name: "with address",
			err:  &TransportError{Message: "timeout", Address: "localhost:8080"},
			want: "timeout: (address: localhost:8080)",
		},
		{
			name: "with operation and address",
			err:  &TransportError{Operation: "Health", Message: "unreachable", Address: "10.0.0.1:443"},
			want: "Health: unreachable: (address: 10.0.0.1:443)",
		},
		{
			name: "with underlying error",
			err: &TransportError{
				Message:    "connection refused",
				Underlying: errors.New("dial tcp: connection refused"),
			},
			want: "connection refused: dial tcp: connection refused",
		},
		{
			name: "full context",
			err: &TransportError{
				Operation:  "Request",
				Message:    "failed",
				Address:    "srv:443",
				Underlying: errors.New("EOF"),
			},
			want: "Request: failed: (address: srv:443): EOF",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.err.Error())
		})
	}
}

func TestTransportError_Unwrap(t *testing.T) {
	underlying := errors.New("root cause")
	te := &TransportError{
		Code:       ErrCodeTimeout,
		Message:    "request timed out",
		Underlying: underlying,
	}
	assert.Equal(t, underlying, te.Unwrap())

	te2 := &TransportError{Code: ErrCodeTimeout, Message: "no underlying"}
	assert.Nil(t, te2.Unwrap())
}

func TestTransportError_Is_SentinelErrors(t *testing.T) {
	tests := []struct {
		code     ErrorCode
		sentinel error
	}{
		{ErrCodeNotConnected, ErrNotConnected},
		{ErrCodeConnectionFailed, ErrConnectionFailed},
		{ErrCodeConnectionClosed, ErrConnectionClosed},
		{ErrCodeTimeout, ErrTimeout},
		{ErrCodeStreamClosed, ErrStreamClosed},
		{ErrCodeStreamNotSupported, ErrStreamNotSupported},
		{ErrCodeInvalidConfig, ErrInvalidConfig},
		{ErrCodeMethodNotFound, ErrMethodNotFound},
		{ErrCodeInvalidRequest, ErrInvalidRequest},
		{ErrCodeInvalidResponse, ErrInvalidResponse},
		{ErrCodeTLSHandshakeFailed, ErrTLSHandshakeFailed},
		{ErrCodeAuthenticationFailed, ErrAuthenticationFailed},
	}
	for _, tt := range tests {
		t.Run(tt.code.String(), func(t *testing.T) {
			te := &TransportError{Code: tt.code, Message: "test"}
			assert.True(t, errors.Is(te, tt.sentinel))
		})
	}
}

func TestTransportError_Is_SameCode(t *testing.T) {
	te1 := &TransportError{Code: ErrCodeTimeout, Message: "a"}
	te2 := &TransportError{Code: ErrCodeTimeout, Message: "b"}
	assert.True(t, te1.Is(te2))

	te3 := &TransportError{Code: ErrCodeNotConnected, Message: "c"}
	assert.False(t, te1.Is(te3))
}

func TestTransportError_Is_UnknownCode(t *testing.T) {
	te := &TransportError{Code: ErrCodeUnknown, Message: "unknown"}
	assert.False(t, te.Is(errors.New("random error")))
}

func TestNewTransportError(t *testing.T) {
	te := NewTransportError(ErrCodeTimeout, "timed out")
	require.NotNil(t, te)
	assert.Equal(t, ErrCodeTimeout, te.Code)
	assert.Equal(t, "timed out", te.Message)
	assert.Empty(t, te.Operation)
	assert.Empty(t, te.Address)
	assert.Nil(t, te.Underlying)
}

func TestNewTransportErrorWithOperation(t *testing.T) {
	te := NewTransportErrorWithOperation(ErrCodeConnectionFailed, "Connect", "refused")
	require.NotNil(t, te)
	assert.Equal(t, ErrCodeConnectionFailed, te.Code)
	assert.Equal(t, "Connect", te.Operation)
	assert.Equal(t, "refused", te.Message)
}

func TestWrapTransportError(t *testing.T) {
	cause := errors.New("underlying")
	te := WrapTransportError(ErrCodeConnectionClosed, "lost", cause)
	require.NotNil(t, te)
	assert.Equal(t, ErrCodeConnectionClosed, te.Code)
	assert.Equal(t, "lost", te.Message)
	assert.Equal(t, cause, te.Underlying)
	assert.True(t, errors.Is(te, cause))
}

func TestWrapTransportErrorWithAddress(t *testing.T) {
	cause := errors.New("EOF")
	te := WrapTransportErrorWithAddress(ErrCodeConnectionClosed, "disconnected", "10.0.0.1:443", cause)
	require.NotNil(t, te)
	assert.Equal(t, "10.0.0.1:443", te.Address)
	assert.Contains(t, te.Error(), "10.0.0.1:443")
}

func TestConfigError_Error(t *testing.T) {
	ce := &ConfigError{Field: "Timeout", Message: "cannot be negative"}
	assert.Equal(t, "transport config: Timeout: cannot be negative", ce.Error())
}

func TestConfigError_Is_ErrInvalidConfig(t *testing.T) {
	ce := &ConfigError{Field: "Address", Message: "empty"}
	assert.True(t, errors.Is(ce, ErrInvalidConfig))
}

func TestConfigError_Is_SameField(t *testing.T) {
	ce1 := &ConfigError{Field: "Timeout", Message: "a"}
	ce2 := &ConfigError{Field: "Timeout", Message: "b"}
	assert.True(t, ce1.Is(ce2))

	ce3 := &ConfigError{Field: "Address", Message: "a"}
	assert.False(t, ce1.Is(ce3))
}

func TestConfigError_Is_UnrelatedError(t *testing.T) {
	ce := &ConfigError{Field: "Address", Message: "empty"}
	assert.False(t, ce.Is(errors.New("random")))
}

func TestIsNotConnected(t *testing.T) {
	assert.True(t, IsNotConnected(ErrNotConnected))
	assert.True(t, IsNotConnected(&TransportError{Code: ErrCodeNotConnected}))
	assert.True(t, IsNotConnected(fmt.Errorf("wrapped: %w", ErrNotConnected)))
	assert.False(t, IsNotConnected(ErrTimeout))
	assert.False(t, IsNotConnected(nil))
}

func TestIsConnectionFailed(t *testing.T) {
	assert.True(t, IsConnectionFailed(ErrConnectionFailed))
	assert.True(t, IsConnectionFailed(&TransportError{Code: ErrCodeConnectionFailed}))
	assert.False(t, IsConnectionFailed(nil))
	assert.False(t, IsConnectionFailed(ErrTimeout))
}

func TestIsConnectionClosed(t *testing.T) {
	assert.True(t, IsConnectionClosed(ErrConnectionClosed))
	assert.False(t, IsConnectionClosed(nil))
	assert.False(t, IsConnectionClosed(ErrTimeout))
}

func TestIsTimeout(t *testing.T) {
	assert.True(t, IsTimeout(ErrTimeout))
	assert.True(t, IsTimeout(&TransportError{Code: ErrCodeTimeout}))
	assert.False(t, IsTimeout(nil))
	assert.False(t, IsTimeout(ErrNotConnected))
}

func TestIsStreamClosed(t *testing.T) {
	assert.True(t, IsStreamClosed(ErrStreamClosed))
	assert.False(t, IsStreamClosed(nil))
	assert.False(t, IsStreamClosed(ErrTimeout))
}

func TestIsStreamNotSupported(t *testing.T) {
	assert.True(t, IsStreamNotSupported(ErrStreamNotSupported))
	assert.False(t, IsStreamNotSupported(nil))
	assert.False(t, IsStreamNotSupported(ErrTimeout))
}

func TestIsInvalidConfig(t *testing.T) {
	assert.True(t, IsInvalidConfig(ErrInvalidConfig))
	assert.True(t, IsInvalidConfig(&ConfigError{Field: "X", Message: "Y"}))
	assert.False(t, IsInvalidConfig(nil))
	assert.False(t, IsInvalidConfig(ErrTimeout))
}

func TestIsRetryable(t *testing.T) {
	assert.True(t, IsRetryable(ErrConnectionFailed))
	assert.True(t, IsRetryable(ErrConnectionClosed))
	assert.True(t, IsRetryable(ErrTimeout))
	assert.True(t, IsRetryable(&TransportError{Code: ErrCodeConnectionFailed}))
	assert.True(t, IsRetryable(&TransportError{Code: ErrCodeConnectionClosed}))
	assert.True(t, IsRetryable(&TransportError{Code: ErrCodeTimeout}))
	assert.False(t, IsRetryable(nil))
	assert.False(t, IsRetryable(ErrNotConnected))
	assert.False(t, IsRetryable(ErrInvalidConfig))
	assert.False(t, IsRetryable(&TransportError{Code: ErrCodeInvalidRequest}))
}

func TestGetErrorCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorCode
	}{
		{"nil", nil, ErrCodeUnknown},
		{"transport error", &TransportError{Code: ErrCodeTimeout}, ErrCodeTimeout},
		{"sentinel not connected", ErrNotConnected, ErrCodeNotConnected},
		{"sentinel connection failed", ErrConnectionFailed, ErrCodeConnectionFailed},
		{"sentinel connection closed", ErrConnectionClosed, ErrCodeConnectionClosed},
		{"sentinel timeout", ErrTimeout, ErrCodeTimeout},
		{"sentinel stream closed", ErrStreamClosed, ErrCodeStreamClosed},
		{"sentinel stream not supported", ErrStreamNotSupported, ErrCodeStreamNotSupported},
		{"sentinel invalid config", ErrInvalidConfig, ErrCodeInvalidConfig},
		{"sentinel method not found", ErrMethodNotFound, ErrCodeMethodNotFound},
		{"sentinel invalid request", ErrInvalidRequest, ErrCodeInvalidRequest},
		{"sentinel invalid response", ErrInvalidResponse, ErrCodeInvalidResponse},
		{"sentinel TLS handshake", ErrTLSHandshakeFailed, ErrCodeTLSHandshakeFailed},
		{"sentinel auth failed", ErrAuthenticationFailed, ErrCodeAuthenticationFailed},
		{"unknown error", errors.New("random"), ErrCodeUnknown},
		{"wrapped sentinel", fmt.Errorf("wrap: %w", ErrTimeout), ErrCodeTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, GetErrorCode(tt.err))
		})
	}
}
