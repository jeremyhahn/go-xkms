// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package errors provides typed errors for the Trusted CA SDK.
package errors

import (
	"errors"
	"fmt"
)

// CAError is the base error type for all SDK errors.
type CAError struct {
	// Code is the error code category.
	Code ErrorCode

	// Op is the operation that failed.
	Op string

	// Message is the human-readable error message.
	Message string

	// Err is the underlying error, if any.
	Err error

	// Context contains additional error context.
	Context map[string]interface{}
}

// Error implements the error interface.
func (e *CAError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %s: %v", e.Code, e.Op, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s: %s", e.Code, e.Op, e.Message)
}

// Unwrap returns the underlying error.
func (e *CAError) Unwrap() error {
	return e.Err
}

// Is reports whether the error matches the target.
func (e *CAError) Is(target error) bool {
	t, ok := target.(*CAError)
	if !ok {
		return false
	}
	return e.Code == t.Code
}

// IsRetryable returns true if the error can be retried.
func (e *CAError) IsRetryable() bool {
	return e.Code.IsRetryable()
}

// WithContext adds context to the error and returns the error for chaining.
func (e *CAError) WithContext(key string, value interface{}) *CAError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// WithCause sets the wrapped error and returns the error for chaining.
func (e *CAError) WithCause(err error) *CAError {
	e.Err = err
	return e
}

// New creates a new CAError.
func New(code ErrorCode, op, message string) *CAError {
	return &CAError{
		Code:    code,
		Op:      op,
		Message: message,
	}
}

// Wrap wraps an existing error with a CAError.
func Wrap(err error, code ErrorCode, op, message string) *CAError {
	return &CAError{
		Code:    code,
		Op:      op,
		Message: message,
		Err:     err,
	}
}

// General error constructors

// NewInvalidInput creates an invalid input error.
func NewInvalidInput(op, message string) *CAError {
	return New(CodeInvalidInput, op, message)
}

// NewNotFound creates a not found error.
func NewNotFound(op, message string) *CAError {
	return New(CodeNotFound, op, message)
}

// NewAlreadyExists creates an already exists error.
func NewAlreadyExists(op, message string) *CAError {
	return New(CodeAlreadyExists, op, message)
}

// NewUnauthorized creates an unauthorized error.
func NewUnauthorized(op, message string) *CAError {
	return New(CodeUnauthorized, op, message)
}

// NewForbidden creates a forbidden error.
func NewForbidden(op, message string) *CAError {
	return New(CodeForbidden, op, message)
}

// NewConflict creates a conflict error.
func NewConflict(op, message string) *CAError {
	return New(CodeConflict, op, message)
}

// NewInternal creates an internal error.
func NewInternal(op, message string) *CAError {
	return New(CodeInternal, op, message)
}

// NewUnavailable creates an unavailable error.
func NewUnavailable(op, message string) *CAError {
	return New(CodeUnavailable, op, message)
}

// NewTimeout creates a timeout error.
func NewTimeout(op, message string) *CAError {
	return New(CodeTimeout, op, message)
}

// NewCanceled creates a canceled error.
func NewCanceled(op, message string) *CAError {
	return New(CodeCanceled, op, message)
}

// NewConnection creates a connection error.
func NewConnection(op, message string) *CAError {
	return New(CodeConnection, op, message)
}

// NewNotInitialized creates a not initialized error.
func NewNotInitialized(op, message string) *CAError {
	return New(CodeNotInitialized, op, message)
}

// NewConfiguration creates a configuration error.
func NewConfiguration(op, message string) *CAError {
	return New(CodeConfiguration, op, message)
}

// NewResourceExhausted creates a resource exhausted error.
func NewResourceExhausted(op, message string) *CAError {
	return New(CodeResourceExhausted, op, message)
}

// NewUnimplemented creates an unimplemented error.
func NewUnimplemented(op, message string) *CAError {
	return New(CodeUnimplemented, op, message)
}

// NewNotImplemented is an alias for NewUnimplemented for convenience.
func NewNotImplemented(op, message string) *CAError {
	return New(CodeUnimplemented, op, message)
}

// NewPreconditionFailed creates a precondition failed error.
func NewPreconditionFailed(op, message string) *CAError {
	return New(CodePreconditionFailed, op, message)
}

// NewRateLimited creates a rate limited error.
func NewRateLimited(op, message string) *CAError {
	return New(CodeRateLimited, op, message)
}

// NewTransport creates a transport error.
func NewTransport(op, message string) *CAError {
	return New(CodeTransport, op, message)
}

// Helper functions for error inspection

// Code returns the error code from an error.
// Returns CodeUnknown if the error is not a CAError.
func Code(err error) ErrorCode {
	var ce *CAError
	if errors.As(err, &ce) {
		return ce.Code
	}
	return CodeUnknown
}

// Is returns true if the error has the specified code.
func Is(err error, code ErrorCode) bool {
	return Code(err) == code
}

// IsRetryable returns true if the error can be retried.
func IsRetryable(err error) bool {
	var ce *CAError
	if errors.As(err, &ce) {
		return ce.IsRetryable()
	}
	return false
}

// IsClientError returns true if the error is a client-side error.
func IsClientError(err error) bool {
	return Code(err).IsClientError()
}

// IsServerError returns true if the error is a server-side error.
func IsServerError(err error) bool {
	return Code(err).IsServerError()
}

// IsNotFound returns true if the error is a not found error.
func IsNotFound(err error) bool {
	return Code(err) == CodeNotFound
}

// IsAlreadyExists returns true if the error is an already exists error.
func IsAlreadyExists(err error) bool {
	return Code(err) == CodeAlreadyExists
}

// IsInvalidInput returns true if the error is an invalid input error.
func IsInvalidInput(err error) bool {
	return Code(err) == CodeInvalidInput
}

// IsUnauthorized returns true if the error is an unauthorized error.
func IsUnauthorized(err error) bool {
	return Code(err) == CodeUnauthorized
}

// IsForbidden returns true if the error is a forbidden error.
func IsForbidden(err error) bool {
	return Code(err) == CodeForbidden
}

// IsConflict returns true if the error is a conflict error.
func IsConflict(err error) bool {
	return Code(err) == CodeConflict
}

// IsTimeout returns true if the error is a timeout error.
func IsTimeout(err error) bool {
	return Code(err) == CodeTimeout
}

// IsUnavailable returns true if the error is an unavailable error.
func IsUnavailable(err error) bool {
	return Code(err) == CodeUnavailable
}

// IsCanceled returns true if the error is a canceled error.
func IsCanceled(err error) bool {
	return Code(err) == CodeCanceled
}

// IsUnimplemented returns true if the error is an unimplemented error.
func IsUnimplemented(err error) bool {
	return Code(err) == CodeUnimplemented
}

// IsInternal returns true if the error is an internal error.
func IsInternal(err error) bool {
	return Code(err) == CodeInternal
}

// Op returns the operation from an error.
func Op(err error) string {
	var ce *CAError
	if errors.As(err, &ce) {
		return ce.Op
	}
	return ""
}

// Message returns the message from an error.
func Message(err error) string {
	var ce *CAError
	if errors.As(err, &ce) {
		return ce.Message
	}
	return err.Error()
}

// Context returns the context map from an error.
func Context(err error) map[string]interface{} {
	var ce *CAError
	if errors.As(err, &ce) {
		return ce.Context
	}
	return nil
}
