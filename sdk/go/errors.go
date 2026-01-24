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

package keychain

import (
	"errors"
	"fmt"
)

// ErrorCode represents the type of error that occurred.
type ErrorCode int

const (
	// ErrCodeUnknown indicates an unknown or unclassified error.
	ErrCodeUnknown ErrorCode = iota
	// ErrCodeConnection indicates a connection establishment failure.
	ErrCodeConnection
	// ErrCodeNotConnected indicates the client is not connected.
	ErrCodeNotConnected
	// ErrCodeNotFound indicates a requested resource was not found.
	ErrCodeNotFound
	// ErrCodeInvalidRequest indicates the request was malformed or invalid.
	ErrCodeInvalidRequest
	// ErrCodeTimeout indicates the operation timed out.
	ErrCodeTimeout
	// ErrCodeAuthentication indicates an authentication failure.
	ErrCodeAuthentication
	// ErrCodePermission indicates insufficient permissions.
	ErrCodePermission
	// ErrCodeBackendUnavailable indicates the backend is unavailable.
	ErrCodeBackendUnavailable
	// ErrCodeProtocolUnsupported indicates the protocol is not supported.
	ErrCodeProtocolUnsupported
	// ErrCodeOperationUnsupported indicates the operation is not supported.
	ErrCodeOperationUnsupported
	// ErrCodeNilService indicates a nil service was provided.
	ErrCodeNilService
)

// String returns a human-readable name for the error code.
func (c ErrorCode) String() string {
	switch c {
	case ErrCodeUnknown:
		return "Unknown"
	case ErrCodeConnection:
		return "ConnectionFailed"
	case ErrCodeNotConnected:
		return "NotConnected"
	case ErrCodeNotFound:
		return "NotFound"
	case ErrCodeInvalidRequest:
		return "InvalidRequest"
	case ErrCodeTimeout:
		return "Timeout"
	case ErrCodeAuthentication:
		return "Authentication"
	case ErrCodePermission:
		return "Permission"
	case ErrCodeBackendUnavailable:
		return "BackendUnavailable"
	case ErrCodeProtocolUnsupported:
		return "ProtocolUnsupported"
	case ErrCodeOperationUnsupported:
		return "OperationUnsupported"
	case ErrCodeNilService:
		return "NilService"
	default:
		return fmt.Sprintf("ErrorCode(%d)", c)
	}
}

// KeychainError is a typed error that provides detailed information about
// errors that occur during keychain operations.
type KeychainError struct {
	// Code is the error classification code.
	Code ErrorCode
	// Message is a human-readable error message.
	Message string
	// Operation is the name of the operation that failed (optional).
	Operation string
	// Underlying is the wrapped error that caused this error (optional).
	Underlying error
}

// Error implements the error interface.
func (e *KeychainError) Error() string {
	var msg string
	if e.Operation != "" {
		msg = fmt.Sprintf("%s: %s", e.Operation, e.Message)
	} else {
		msg = e.Message
	}

	if e.Underlying != nil {
		return fmt.Sprintf("%s: %v", msg, e.Underlying)
	}
	return msg
}

// Unwrap returns the underlying error for use with errors.Unwrap and errors.Is.
func (e *KeychainError) Unwrap() error {
	return e.Underlying
}

// Is implements error comparison for errors.Is().
// It matches against both the specific KeychainError and sentinel errors.
func (e *KeychainError) Is(target error) bool {
	// Check if target is a KeychainError with the same code
	var ke *KeychainError
	if errors.As(target, &ke) {
		return e.Code == ke.Code
	}

	// Check against sentinel errors for backward compatibility
	switch e.Code {
	case ErrCodeProtocolUnsupported:
		return target == ErrUnsupportedProtocol
	case ErrCodeConnection:
		return target == ErrConnectionFailed
	case ErrCodeNotConnected:
		return target == ErrNotConnected
	case ErrCodeOperationUnsupported:
		return target == ErrNotSupported
	case ErrCodeNilService:
		return target == ErrNilService
	case ErrCodeNotFound:
		return target == ErrKeyNotFound || target == ErrCertificateNotFound || target == ErrBackendNotFound
	case ErrCodeInvalidRequest:
		return target == ErrInvalidRequest
	}

	return false
}

// NewError creates a new KeychainError with the specified code and message.
func NewError(code ErrorCode, message string) *KeychainError {
	return &KeychainError{
		Code:    code,
		Message: message,
	}
}

// NewErrorWithOperation creates a new KeychainError with operation context.
func NewErrorWithOperation(code ErrorCode, operation, message string) *KeychainError {
	return &KeychainError{
		Code:      code,
		Message:   message,
		Operation: operation,
	}
}

// WrapError wraps an existing error with a KeychainError.
func WrapError(code ErrorCode, message string, err error) *KeychainError {
	return &KeychainError{
		Code:       code,
		Message:    message,
		Underlying: err,
	}
}

// WrapErrorWithOperation wraps an error with operation context.
func WrapErrorWithOperation(code ErrorCode, operation, message string, err error) *KeychainError {
	return &KeychainError{
		Code:       code,
		Message:    message,
		Operation:  operation,
		Underlying: err,
	}
}

// IsNotFound returns true if the error indicates a resource was not found.
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}

	// Check sentinel errors
	if errors.Is(err, ErrKeyNotFound) || errors.Is(err, ErrCertificateNotFound) || errors.Is(err, ErrBackendNotFound) {
		return true
	}

	// Check KeychainError
	var ke *KeychainError
	if errors.As(err, &ke) {
		return ke.Code == ErrCodeNotFound
	}

	return false
}

// IsRetryable returns true if the error is potentially retryable.
// Retryable errors include connection failures, timeouts, and backend unavailability.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	// Check sentinel errors
	if errors.Is(err, ErrConnectionFailed) {
		return true
	}

	// Check KeychainError
	var ke *KeychainError
	if errors.As(err, &ke) {
		switch ke.Code {
		case ErrCodeConnection, ErrCodeTimeout, ErrCodeBackendUnavailable:
			return true
		}
	}

	return false
}

// IsConnectionError returns true if the error is related to connection issues.
func IsConnectionError(err error) bool {
	if err == nil {
		return false
	}

	// Check sentinel errors
	if errors.Is(err, ErrConnectionFailed) || errors.Is(err, ErrNotConnected) {
		return true
	}

	// Check KeychainError
	var ke *KeychainError
	if errors.As(err, &ke) {
		switch ke.Code {
		case ErrCodeConnection, ErrCodeNotConnected:
			return true
		}
	}

	return false
}

// IsAuthenticationError returns true if the error is related to authentication.
func IsAuthenticationError(err error) bool {
	if err == nil {
		return false
	}

	var ke *KeychainError
	if errors.As(err, &ke) {
		return ke.Code == ErrCodeAuthentication
	}

	return false
}

// IsPermissionError returns true if the error is related to permissions.
func IsPermissionError(err error) bool {
	if err == nil {
		return false
	}

	var ke *KeychainError
	if errors.As(err, &ke) {
		return ke.Code == ErrCodePermission
	}

	return false
}

// IsInvalidRequest returns true if the error indicates an invalid request.
func IsInvalidRequest(err error) bool {
	if err == nil {
		return false
	}

	// Check sentinel error
	if errors.Is(err, ErrInvalidRequest) {
		return true
	}

	var ke *KeychainError
	if errors.As(err, &ke) {
		return ke.Code == ErrCodeInvalidRequest
	}

	return false
}

// IsTimeout returns true if the error indicates a timeout.
func IsTimeout(err error) bool {
	if err == nil {
		return false
	}

	var ke *KeychainError
	if errors.As(err, &ke) {
		return ke.Code == ErrCodeTimeout
	}

	return false
}

// GetErrorCode extracts the ErrorCode from an error, returning ErrCodeUnknown
// if the error is not a KeychainError.
func GetErrorCode(err error) ErrorCode {
	if err == nil {
		return ErrCodeUnknown
	}

	var ke *KeychainError
	if errors.As(err, &ke) {
		return ke.Code
	}

	return ErrCodeUnknown
}

// ConvertSentinelError converts a sentinel error to a KeychainError.
// If the error is not a recognized sentinel error, it wraps it as unknown.
func ConvertSentinelError(err error) *KeychainError {
	if err == nil {
		return nil
	}

	// Already a KeychainError
	var ke *KeychainError
	if errors.As(err, &ke) {
		return ke
	}

	// Map sentinel errors to KeychainError
	switch {
	case errors.Is(err, ErrUnsupportedProtocol):
		return &KeychainError{
			Code:       ErrCodeProtocolUnsupported,
			Message:    ErrUnsupportedProtocol.Error(),
			Underlying: err,
		}
	case errors.Is(err, ErrConnectionFailed):
		return &KeychainError{
			Code:       ErrCodeConnection,
			Message:    ErrConnectionFailed.Error(),
			Underlying: err,
		}
	case errors.Is(err, ErrNotConnected):
		return &KeychainError{
			Code:       ErrCodeNotConnected,
			Message:    ErrNotConnected.Error(),
			Underlying: err,
		}
	case errors.Is(err, ErrNotSupported):
		return &KeychainError{
			Code:       ErrCodeOperationUnsupported,
			Message:    ErrNotSupported.Error(),
			Underlying: err,
		}
	case errors.Is(err, ErrNilService):
		return &KeychainError{
			Code:       ErrCodeNilService,
			Message:    ErrNilService.Error(),
			Underlying: err,
		}
	case errors.Is(err, ErrKeyNotFound):
		return &KeychainError{
			Code:       ErrCodeNotFound,
			Message:    ErrKeyNotFound.Error(),
			Underlying: err,
		}
	case errors.Is(err, ErrCertificateNotFound):
		return &KeychainError{
			Code:       ErrCodeNotFound,
			Message:    ErrCertificateNotFound.Error(),
			Underlying: err,
		}
	case errors.Is(err, ErrBackendNotFound):
		return &KeychainError{
			Code:       ErrCodeNotFound,
			Message:    ErrBackendNotFound.Error(),
			Underlying: err,
		}
	case errors.Is(err, ErrInvalidRequest):
		return &KeychainError{
			Code:       ErrCodeInvalidRequest,
			Message:    ErrInvalidRequest.Error(),
			Underlying: err,
		}
	default:
		return &KeychainError{
			Code:       ErrCodeUnknown,
			Message:    err.Error(),
			Underlying: err,
		}
	}
}
