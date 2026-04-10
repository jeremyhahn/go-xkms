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
	pkgtransport "github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// Sentinel errors re-exported from pkg/transport.
var (
	ErrNotConnected         = pkgtransport.ErrNotConnected
	ErrConnectionFailed     = pkgtransport.ErrConnectionFailed
	ErrConnectionClosed     = pkgtransport.ErrConnectionClosed
	ErrTimeout              = pkgtransport.ErrTimeout
	ErrStreamClosed         = pkgtransport.ErrStreamClosed
	ErrStreamNotSupported   = pkgtransport.ErrStreamNotSupported
	ErrInvalidConfig        = pkgtransport.ErrInvalidConfig
	ErrMethodNotFound       = pkgtransport.ErrMethodNotFound
	ErrInvalidRequest       = pkgtransport.ErrInvalidRequest
	ErrInvalidResponse      = pkgtransport.ErrInvalidResponse
	ErrTLSHandshakeFailed   = pkgtransport.ErrTLSHandshakeFailed
	ErrAuthenticationFailed = pkgtransport.ErrAuthenticationFailed
)

// Error code type and constants re-exported from pkg/transport.
type ErrorCode = pkgtransport.ErrorCode

const (
	ErrCodeUnknown              = pkgtransport.ErrCodeUnknown
	ErrCodeNotConnected         = pkgtransport.ErrCodeNotConnected
	ErrCodeConnectionFailed     = pkgtransport.ErrCodeConnectionFailed
	ErrCodeConnectionClosed     = pkgtransport.ErrCodeConnectionClosed
	ErrCodeTimeout              = pkgtransport.ErrCodeTimeout
	ErrCodeStreamClosed         = pkgtransport.ErrCodeStreamClosed
	ErrCodeStreamNotSupported   = pkgtransport.ErrCodeStreamNotSupported
	ErrCodeInvalidConfig        = pkgtransport.ErrCodeInvalidConfig
	ErrCodeMethodNotFound       = pkgtransport.ErrCodeMethodNotFound
	ErrCodeInvalidRequest       = pkgtransport.ErrCodeInvalidRequest
	ErrCodeInvalidResponse      = pkgtransport.ErrCodeInvalidResponse
	ErrCodeTLSHandshakeFailed   = pkgtransport.ErrCodeTLSHandshakeFailed
	ErrCodeAuthenticationFailed = pkgtransport.ErrCodeAuthenticationFailed
)

// Error types re-exported from pkg/transport.
type TransportError = pkgtransport.TransportError
type ConfigError = pkgtransport.ConfigError

// NewTransportError creates a new TransportError with the given code and message.
func NewTransportError(code ErrorCode, message string) *TransportError {
	return pkgtransport.NewTransportError(code, message)
}

// NewTransportErrorWithOperation creates a new TransportError with operation context.
func NewTransportErrorWithOperation(code ErrorCode, operation, message string) *TransportError {
	return pkgtransport.NewTransportErrorWithOperation(code, operation, message)
}

// WrapTransportError wraps an existing error with transport context.
func WrapTransportError(code ErrorCode, message string, err error) *TransportError {
	return pkgtransport.WrapTransportError(code, message, err)
}

// WrapTransportErrorWithAddress wraps an error with transport and address context.
func WrapTransportErrorWithAddress(code ErrorCode, message, address string, err error) *TransportError {
	return pkgtransport.WrapTransportErrorWithAddress(code, message, address, err)
}

// IsNotConnected returns true if the error indicates the transport is not connected.
func IsNotConnected(err error) bool {
	return pkgtransport.IsNotConnected(err)
}

// IsConnectionFailed returns true if the error indicates a connection failure.
func IsConnectionFailed(err error) bool {
	return pkgtransport.IsConnectionFailed(err)
}

// IsConnectionClosed returns true if the error indicates the connection was closed.
func IsConnectionClosed(err error) bool {
	return pkgtransport.IsConnectionClosed(err)
}

// IsTimeout returns true if the error indicates a timeout.
func IsTimeout(err error) bool {
	return pkgtransport.IsTimeout(err)
}

// IsStreamClosed returns true if the error indicates the stream was closed.
func IsStreamClosed(err error) bool {
	return pkgtransport.IsStreamClosed(err)
}

// IsStreamNotSupported returns true if streaming is not supported.
func IsStreamNotSupported(err error) bool {
	return pkgtransport.IsStreamNotSupported(err)
}

// IsInvalidConfig returns true if the error indicates invalid configuration.
func IsInvalidConfig(err error) bool {
	return pkgtransport.IsInvalidConfig(err)
}

// IsRetryable returns true if the error is potentially retryable.
func IsRetryable(err error) bool {
	return pkgtransport.IsRetryable(err)
}

// GetErrorCode extracts the ErrorCode from an error, returning ErrCodeUnknown
// if the error is not a TransportError.
func GetErrorCode(err error) ErrorCode {
	return pkgtransport.GetErrorCode(err)
}
