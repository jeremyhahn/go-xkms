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

package transport

import (
	"errors"
	"fmt"
)

// Sentinel errors for transport operations.
// These are the base error types that can be checked with errors.Is().
var (
	// ErrNotConnected is returned when attempting an operation on a
	// transport that is not connected.
	ErrNotConnected = errors.New("transport: not connected")

	// ErrConnectionFailed is returned when the transport fails to
	// establish a connection to the server.
	ErrConnectionFailed = errors.New("transport: connection failed")

	// ErrConnectionClosed is returned when the connection was closed
	// unexpectedly or by the server.
	ErrConnectionClosed = errors.New("transport: connection closed")

	// ErrTimeout is returned when an operation exceeds its timeout.
	ErrTimeout = errors.New("transport: operation timed out")

	// ErrStreamClosed is returned when attempting to use a closed stream.
	ErrStreamClosed = errors.New("transport: stream closed")

	// ErrStreamNotSupported is returned when requesting a stream on a
	// transport that doesn't support streaming.
	ErrStreamNotSupported = errors.New("transport: streaming not supported")

	// ErrInvalidConfig is returned when the transport configuration is invalid.
	ErrInvalidConfig = errors.New("transport: invalid configuration")

	// ErrMethodNotFound is returned when the requested method is not found.
	ErrMethodNotFound = errors.New("transport: method not found")

	// ErrInvalidRequest is returned when the request is malformed or invalid.
	ErrInvalidRequest = errors.New("transport: invalid request")

	// ErrInvalidResponse is returned when the response is malformed or invalid.
	ErrInvalidResponse = errors.New("transport: invalid response")

	// ErrTLSHandshakeFailed is returned when TLS handshake fails.
	ErrTLSHandshakeFailed = errors.New("transport: TLS handshake failed")

	// ErrAuthenticationFailed is returned when authentication fails.
	ErrAuthenticationFailed = errors.New("transport: authentication failed")
)

// ErrorCode represents the category of transport error.
type ErrorCode int

const (
	// ErrCodeUnknown indicates an unclassified error.
	ErrCodeUnknown ErrorCode = iota

	// ErrCodeNotConnected indicates the transport is not connected.
	ErrCodeNotConnected

	// ErrCodeConnectionFailed indicates a connection failure.
	ErrCodeConnectionFailed

	// ErrCodeConnectionClosed indicates the connection was closed.
	ErrCodeConnectionClosed

	// ErrCodeTimeout indicates an operation timeout.
	ErrCodeTimeout

	// ErrCodeStreamClosed indicates a stream was closed.
	ErrCodeStreamClosed

	// ErrCodeStreamNotSupported indicates streaming is not supported.
	ErrCodeStreamNotSupported

	// ErrCodeInvalidConfig indicates invalid configuration.
	ErrCodeInvalidConfig

	// ErrCodeMethodNotFound indicates the method was not found.
	ErrCodeMethodNotFound

	// ErrCodeInvalidRequest indicates an invalid request.
	ErrCodeInvalidRequest

	// ErrCodeInvalidResponse indicates an invalid response.
	ErrCodeInvalidResponse

	// ErrCodeTLSHandshakeFailed indicates TLS handshake failure.
	ErrCodeTLSHandshakeFailed

	// ErrCodeAuthenticationFailed indicates authentication failure.
	ErrCodeAuthenticationFailed
)

// String returns a human-readable name for the error code.
func (c ErrorCode) String() string {
	switch c {
	case ErrCodeNotConnected:
		return "NotConnected"
	case ErrCodeConnectionFailed:
		return "ConnectionFailed"
	case ErrCodeConnectionClosed:
		return "ConnectionClosed"
	case ErrCodeTimeout:
		return "Timeout"
	case ErrCodeStreamClosed:
		return "StreamClosed"
	case ErrCodeStreamNotSupported:
		return "StreamNotSupported"
	case ErrCodeInvalidConfig:
		return "InvalidConfig"
	case ErrCodeMethodNotFound:
		return "MethodNotFound"
	case ErrCodeInvalidRequest:
		return "InvalidRequest"
	case ErrCodeInvalidResponse:
		return "InvalidResponse"
	case ErrCodeTLSHandshakeFailed:
		return "TLSHandshakeFailed"
	case ErrCodeAuthenticationFailed:
		return "AuthenticationFailed"
	default:
		return "Unknown"
	}
}

// TransportError is a structured error type that provides detailed
// information about transport-layer errors.
type TransportError struct {
	// Code is the error classification code.
	Code ErrorCode

	// Message is a human-readable error message.
	Message string

	// Operation is the name of the operation that failed (optional).
	Operation string

	// Address is the server address involved (optional).
	Address string

	// Underlying is the wrapped error that caused this error (optional).
	Underlying error
}

// Error implements the error interface.
func (e *TransportError) Error() string {
	var parts []string

	if e.Operation != "" {
		parts = append(parts, e.Operation)
	}

	parts = append(parts, e.Message)

	if e.Address != "" {
		parts = append(parts, fmt.Sprintf("(address: %s)", e.Address))
	}

	msg := ""
	for i, p := range parts {
		if i > 0 {
			msg += ": "
		}
		msg += p
	}

	if e.Underlying != nil {
		return fmt.Sprintf("%s: %v", msg, e.Underlying)
	}
	return msg
}

// Unwrap returns the underlying error for use with errors.Unwrap.
func (e *TransportError) Unwrap() error {
	return e.Underlying
}

// Is implements error comparison for errors.Is().
func (e *TransportError) Is(target error) bool {
	// Check if target is a TransportError with the same code
	var te *TransportError
	if errors.As(target, &te) {
		return e.Code == te.Code
	}

	// Check against sentinel errors
	switch e.Code {
	case ErrCodeNotConnected:
		return target == ErrNotConnected
	case ErrCodeConnectionFailed:
		return target == ErrConnectionFailed
	case ErrCodeConnectionClosed:
		return target == ErrConnectionClosed
	case ErrCodeTimeout:
		return target == ErrTimeout
	case ErrCodeStreamClosed:
		return target == ErrStreamClosed
	case ErrCodeStreamNotSupported:
		return target == ErrStreamNotSupported
	case ErrCodeInvalidConfig:
		return target == ErrInvalidConfig
	case ErrCodeMethodNotFound:
		return target == ErrMethodNotFound
	case ErrCodeInvalidRequest:
		return target == ErrInvalidRequest
	case ErrCodeInvalidResponse:
		return target == ErrInvalidResponse
	case ErrCodeTLSHandshakeFailed:
		return target == ErrTLSHandshakeFailed
	case ErrCodeAuthenticationFailed:
		return target == ErrAuthenticationFailed
	}

	return false
}

// NewTransportError creates a new TransportError with the given code and message.
func NewTransportError(code ErrorCode, message string) *TransportError {
	return &TransportError{
		Code:    code,
		Message: message,
	}
}

// NewTransportErrorWithOperation creates a new TransportError with operation context.
func NewTransportErrorWithOperation(code ErrorCode, operation, message string) *TransportError {
	return &TransportError{
		Code:      code,
		Message:   message,
		Operation: operation,
	}
}

// WrapTransportError wraps an existing error with transport context.
func WrapTransportError(code ErrorCode, message string, err error) *TransportError {
	return &TransportError{
		Code:       code,
		Message:    message,
		Underlying: err,
	}
}

// WrapTransportErrorWithAddress wraps an error with transport and address context.
func WrapTransportErrorWithAddress(code ErrorCode, message, address string, err error) *TransportError {
	return &TransportError{
		Code:       code,
		Message:    message,
		Address:    address,
		Underlying: err,
	}
}

// ConfigError represents a configuration validation error.
type ConfigError struct {
	// Field is the name of the configuration field with the error.
	Field string

	// Message describes what is wrong with the configuration.
	Message string
}

// Error implements the error interface.
func (e *ConfigError) Error() string {
	return fmt.Sprintf("transport config: %s: %s", e.Field, e.Message)
}

// Is implements error comparison for errors.Is().
func (e *ConfigError) Is(target error) bool {
	if target == ErrInvalidConfig {
		return true
	}

	var ce *ConfigError
	if errors.As(target, &ce) {
		return e.Field == ce.Field
	}

	return false
}

// IsNotConnected returns true if the error indicates the transport is not connected.
func IsNotConnected(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrNotConnected)
}

// IsConnectionFailed returns true if the error indicates a connection failure.
func IsConnectionFailed(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrConnectionFailed)
}

// IsConnectionClosed returns true if the error indicates the connection was closed.
func IsConnectionClosed(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrConnectionClosed)
}

// IsTimeout returns true if the error indicates a timeout.
func IsTimeout(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrTimeout)
}

// IsStreamClosed returns true if the error indicates the stream was closed.
func IsStreamClosed(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrStreamClosed)
}

// IsStreamNotSupported returns true if streaming is not supported.
func IsStreamNotSupported(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrStreamNotSupported)
}

// IsInvalidConfig returns true if the error indicates invalid configuration.
func IsInvalidConfig(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrInvalidConfig)
}

// IsRetryable returns true if the error is potentially retryable.
// Retryable errors include connection failures, connection closed, and timeouts.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	// Check sentinel errors
	if errors.Is(err, ErrConnectionFailed) ||
		errors.Is(err, ErrConnectionClosed) ||
		errors.Is(err, ErrTimeout) {
		return true
	}

	// Check TransportError codes
	var te *TransportError
	if errors.As(err, &te) {
		switch te.Code {
		case ErrCodeConnectionFailed, ErrCodeConnectionClosed, ErrCodeTimeout:
			return true
		}
	}

	return false
}

// GetErrorCode extracts the ErrorCode from an error, returning ErrCodeUnknown
// if the error is not a TransportError.
func GetErrorCode(err error) ErrorCode {
	if err == nil {
		return ErrCodeUnknown
	}

	var te *TransportError
	if errors.As(err, &te) {
		return te.Code
	}

	// Map sentinel errors to codes
	switch {
	case errors.Is(err, ErrNotConnected):
		return ErrCodeNotConnected
	case errors.Is(err, ErrConnectionFailed):
		return ErrCodeConnectionFailed
	case errors.Is(err, ErrConnectionClosed):
		return ErrCodeConnectionClosed
	case errors.Is(err, ErrTimeout):
		return ErrCodeTimeout
	case errors.Is(err, ErrStreamClosed):
		return ErrCodeStreamClosed
	case errors.Is(err, ErrStreamNotSupported):
		return ErrCodeStreamNotSupported
	case errors.Is(err, ErrInvalidConfig):
		return ErrCodeInvalidConfig
	case errors.Is(err, ErrMethodNotFound):
		return ErrCodeMethodNotFound
	case errors.Is(err, ErrInvalidRequest):
		return ErrCodeInvalidRequest
	case errors.Is(err, ErrInvalidResponse):
		return ErrCodeInvalidResponse
	case errors.Is(err, ErrTLSHandshakeFailed):
		return ErrCodeTLSHandshakeFailed
	case errors.Is(err, ErrAuthenticationFailed):
		return ErrCodeAuthenticationFailed
	}

	return ErrCodeUnknown
}
