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

package kms

import (
	"errors"
	"fmt"
	"strings"
)

// Error represents a KMS error.
type Error struct {
	Code    ErrorCode
	Message string
	Cause   error
	Context map[string]interface{}
}

// ErrorCode represents the type of KMS error.
type ErrorCode string

const (
	// ErrorCodeNotFound indicates a resource was not found.
	ErrorCodeNotFound ErrorCode = "NOT_FOUND"

	// ErrorCodeInvalidInput indicates invalid input data.
	ErrorCodeInvalidInput ErrorCode = "INVALID_INPUT"

	// ErrorCodeInternal indicates an internal error.
	ErrorCodeInternal ErrorCode = "INTERNAL_ERROR"

	// ErrorCodeKeyNotFound indicates a cryptographic key was not found.
	ErrorCodeKeyNotFound ErrorCode = "KEY_NOT_FOUND"
)

// Error implements the error interface.
func (e *Error) Error() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s: %s", e.Code, e.Message)

	// Include context in error message for debugging
	if len(e.Context) > 0 {
		for k, v := range e.Context {
			fmt.Fprintf(&sb, " [%s=%v]", k, v)
		}
	}

	if e.Cause != nil {
		fmt.Fprintf(&sb, ": %v", e.Cause)
	}

	return sb.String()
}

// Unwrap returns the underlying cause.
func (e *Error) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches the target.
func (e *Error) Is(target error) bool {
	if t, ok := target.(*Error); ok {
		return e.Code == t.Code
	}
	return false
}

// WithCause returns a new error with the given cause.
// This creates a copy to avoid modifying shared package-level errors.
func (e *Error) WithCause(cause error) *Error {
	newContext := make(map[string]interface{})
	for k, v := range e.Context {
		newContext[k] = v
	}
	return &Error{
		Code:    e.Code,
		Message: e.Message,
		Cause:   cause,
		Context: newContext,
	}
}

// WithContext returns a new error with the given context key-value pair.
// This creates a copy to avoid modifying shared package-level errors.
func (e *Error) WithContext(key string, value interface{}) *Error {
	newContext := make(map[string]interface{})
	for k, v := range e.Context {
		newContext[k] = v
	}
	newContext[key] = value
	return &Error{
		Code:    e.Code,
		Message: e.Message,
		Cause:   e.Cause,
		Context: newContext,
	}
}

// Predefined errors
var (
	// ErrNotFound indicates a resource was not found.
	ErrNotFound = &Error{
		Code:    ErrorCodeNotFound,
		Message: "resource not found",
	}

	// ErrInvalidInput indicates invalid input data.
	ErrInvalidInput = &Error{
		Code:    ErrorCodeInvalidInput,
		Message: "invalid input",
	}

	// ErrInternal indicates an internal error.
	ErrInternal = &Error{
		Code:    ErrorCodeInternal,
		Message: "internal error",
	}

	// ErrKeyNotFound indicates a cryptographic key was not found.
	ErrKeyNotFound = &Error{
		Code:    ErrorCodeKeyNotFound,
		Message: "key not found",
	}
)

// NewError creates a new error with the given code and message.
func NewError(code ErrorCode, message string) *Error {
	return &Error{
		Code:    code,
		Message: message,
	}
}

// IsNotFound checks if the error is a not found error.
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	// First check the error message - this catches wrapped errors
	errStr := err.Error()
	if strings.Contains(errStr, "not_found:") || strings.Contains(errStr, "entity not found") {
		return true
	}
	// Then check if the error itself is a not found error type
	var e *Error
	if errors.As(err, &e) {
		return e.Code == ErrorCodeNotFound || e.Code == ErrorCodeKeyNotFound
	}
	return false
}

// IsKeyNotFound checks if the error indicates a key was not found.
func IsKeyNotFound(err error) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Code == ErrorCodeKeyNotFound
	}
	return false
}
