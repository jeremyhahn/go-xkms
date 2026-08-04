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

package errors

import (
	"fmt"
	"time"
)

// TrustedCAError represents internal go-xkms errors that can cross
// gRPC boundaries and be converted to ACME Problem Documents.
type TrustedCAError struct {
	Type      ErrorType
	Detail    string
	Cause     error // preserves the original error chain for errors.Is/As
	SubErrors []SubError

	// RetryAfter indicates how long a client should wait before retrying
	// the request that resulted in this error.
	RetryAfter time.Duration

	// Instance provides a URI reference that identifies the specific
	// occurrence of the problem (e.g., for UserActionRequired).
	Instance string
}

// SubError represents a sub-error specific to an identifier that is
// related to a top-level TrustedCAError.
type SubError struct {
	*TrustedCAError
	Identifier ACMEIdentifier
}

// ACMEIdentifier represents an ACME identifier (domain, IP, etc.).
type ACMEIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Error implements the error interface, returning the error detail.
func (e *TrustedCAError) Error() string {
	return e.Detail
}

// Unwrap implements multi-error unwrapping (Go 1.20+).
// Returns both the ErrorType and the Cause so errors.Is works
// for both the typed category and the original sentinel.
func (e *TrustedCAError) Unwrap() []error {
	if e.Cause != nil {
		return []error{e.Type, e.Cause}
	}
	return []error{e.Type}
}

// WithSubErrors returns a new TrustedCAError with the provided sub-errors added.
func (e *TrustedCAError) WithSubErrors(subErrs []SubError) *TrustedCAError {
	return &TrustedCAError{
		Type:       e.Type,
		Detail:     e.Detail,
		Cause:      e.Cause,
		SubErrors:  append(e.SubErrors, subErrs...),
		RetryAfter: e.RetryAfter,
		Instance:   e.Instance,
	}
}

// WithInstance returns a new TrustedCAError with the provided instance URI.
func (e *TrustedCAError) WithInstance(instance string) *TrustedCAError {
	return &TrustedCAError{
		Type:       e.Type,
		Detail:     e.Detail,
		Cause:      e.Cause,
		SubErrors:  e.SubErrors,
		RetryAfter: e.RetryAfter,
		Instance:   instance,
	}
}

// WithRetryAfter returns a new TrustedCAError with the provided retry duration.
func (e *TrustedCAError) WithRetryAfter(d time.Duration) *TrustedCAError {
	return &TrustedCAError{
		Type:       e.Type,
		Detail:     e.Detail,
		Cause:      e.Cause,
		SubErrors:  e.SubErrors,
		RetryAfter: d,
		Instance:   e.Instance,
	}
}

// WithCause returns a new TrustedCAError with the provided cause error.
func (e *TrustedCAError) WithCause(cause error) *TrustedCAError {
	return &TrustedCAError{
		Type:       e.Type,
		Detail:     e.Detail,
		Cause:      cause,
		SubErrors:  e.SubErrors,
		RetryAfter: e.RetryAfter,
		Instance:   e.Instance,
	}
}

// IsErrorType implements the errors.Is interface for comparing error types.
func (e *TrustedCAError) Is(target error) bool {
	if t, ok := target.(ErrorType); ok {
		return e.Type == t
	}
	if t, ok := target.(*TrustedCAError); ok {
		return e.Type == t.Type
	}
	return false
}

// NewTrustedCAError creates a new TrustedCAError with the specified type and message.
func NewTrustedCAError(errType ErrorType, msg string) error {
	return &TrustedCAError{
		Type:   errType,
		Detail: msg,
	}
}

// newTrustedCAErrorf creates a new TrustedCAError with a formatted message.
func newTrustedCAErrorf(errType ErrorType, msg string, args ...any) error {
	return &TrustedCAError{
		Type:   errType,
		Detail: fmt.Sprintf(msg, args...),
	}
}

// newTrustedCAErrorWithCause creates a new TrustedCAError that wraps a cause error,
// preserving the error chain for errors.Is and errors.As.
func newTrustedCAErrorWithCause(errType ErrorType, cause error, msg string, args ...any) error {
	return &TrustedCAError{
		Type:   errType,
		Detail: fmt.Sprintf(msg, args...),
		Cause:  cause,
	}
}

// NewTrustedCAErrorWithRetryAfter creates a new TrustedCAError with a retry duration.
func NewTrustedCAErrorWithRetryAfter(errType ErrorType, retryAfter time.Duration, msg string, args ...any) error {
	return &TrustedCAError{
		Type:       errType,
		Detail:     fmt.Sprintf(msg, args...),
		RetryAfter: retryAfter,
	}
}

// NewTrustedCAErrorWithInstance creates a new TrustedCAError with an instance URI.
func NewTrustedCAErrorWithInstance(errType ErrorType, instance string, msg string, args ...any) error {
	return &TrustedCAError{
		Type:     errType,
		Detail:   fmt.Sprintf(msg, args...),
		Instance: instance,
	}
}

// IsType checks if err is a TrustedCAError matching the target error type.
// This is a convenience function for typed error checking.
func IsType(err error, target ErrorType) bool {
	if err == nil {
		return false
	}
	if tce, ok := err.(*TrustedCAError); ok {
		return tce.Type == target
	}
	return false
}

// GetType extracts the ErrorType from an error if it is a TrustedCAError.
// Returns the type and true if successful, or zero value and false otherwise.
func GetType(err error) (ErrorType, bool) {
	if tce, ok := err.(*TrustedCAError); ok {
		return tce.Type, true
	}
	return 0, false
}

// GetRetryAfter extracts the RetryAfter duration from an error if available.
// Returns the duration and true if available, or zero and false otherwise.
func GetRetryAfter(err error) (time.Duration, bool) {
	if tce, ok := err.(*TrustedCAError); ok && tce.RetryAfter > 0 {
		return tce.RetryAfter, true
	}
	return 0, false
}

// GetInstance extracts the Instance URI from an error if available.
// Returns the instance and true if available, or empty string and false otherwise.
func GetInstance(err error) (string, bool) {
	if tce, ok := err.(*TrustedCAError); ok && tce.Instance != "" {
		return tce.Instance, true
	}
	return "", false
}

// GetSubErrors extracts the sub-errors from an error if available.
// Returns the sub-errors and true if available, or nil and false otherwise.
func GetSubErrors(err error) ([]SubError, bool) {
	if tce, ok := err.(*TrustedCAError); ok && len(tce.SubErrors) > 0 {
		return tce.SubErrors, true
	}
	return nil, false
}
