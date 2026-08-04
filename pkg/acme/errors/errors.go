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

// Package errors provides typed error definitions for the go-xkms project.
// All errors are declared as types rather than inline errors, following the
// project's error handling conventions.
package errors

import (
	"errors"
	"fmt"
	"time"
)

// Sentinel errors for rate limiting operations.
var (
	// ErrBucketNotFound indicates that the rate limit bucket was not found.
	ErrBucketNotFound = errors.New("bucket not found")

	// ErrInvalidCost indicates that the cost specified was < 0.
	ErrInvalidCost = errors.New("invalid cost, must be >= 0")

	// ErrInvalidCostOverLimit indicates that the cost specified was > limit.Burst.
	ErrInvalidCostOverLimit = errors.New("invalid cost, must be <= limit.Burst")

	// ErrNilLimit indicates that a nil limit was provided.
	ErrNilLimit = errors.New("limit must not be nil")

	// ErrInvalidBurst indicates that the burst value is invalid.
	ErrInvalidBurst = errors.New("burst must be > 0")

	// ErrInvalidCount indicates that the count value is invalid.
	ErrInvalidCount = errors.New("count must be > 0")

	// ErrInvalidPeriod indicates that the period value is invalid.
	ErrInvalidPeriod = errors.New("period must be > 0")

	// ErrDuplicateBucket indicates a duplicate bucket key in a batch operation.
	ErrDuplicateBucket = errors.New("duplicate bucket key in batch")

	// ErrInvalidResetTransaction indicates invalid reset transaction flags.
	ErrInvalidResetTransaction = errors.New("reset transaction cannot have check or spend flags")

	// ErrLimitDisabled indicates that the specified limit is disabled.
	ErrLimitDisabled = errors.New("limit disabled")
)

// Sentinel errors for nonce operations.
var (
	// ErrInvalidNonceLength indicates an invalid nonce length.
	ErrInvalidNonceLength = errors.New("invalid nonce length")

	// ErrInvalidNoncePrefix indicates an invalid nonce prefix.
	ErrInvalidNoncePrefix = errors.New("invalid nonce prefix")

	// ErrNonceDecryptFailed indicates nonce decryption failure.
	ErrNonceDecryptFailed = errors.New("unable to decrypt nonce")

	// ErrNonceTooHigh indicates the nonce counter is higher than the latest issued.
	ErrNonceTooHigh = errors.New("nonce greater than highest dispensed nonce")

	// ErrNonceTooLow indicates the nonce counter is lower than the earliest valid.
	ErrNonceTooLow = errors.New("nonce less than lowest eligible nonce")

	// ErrNonceAlreadyUsed indicates the nonce has already been redeemed.
	ErrNonceAlreadyUsed = errors.New("nonce already redeemed")

	// ErrNoncePrefixMismatch indicates the nonce prefix does not match.
	ErrNoncePrefixMismatch = errors.New("nonce prefix mismatch")
)

// RateLimitError represents a rate limit exceeded error with retry information.
type RateLimitError struct {
	// Message is the human-readable error message.
	Message string

	// RetryAfter is the duration after which the client may retry.
	RetryAfter time.Duration

	// LimitName identifies which rate limit was exceeded.
	LimitName string

	// Burst is the maximum burst capacity of the limit.
	Burst int64

	// Period is the rate limit time window.
	Period time.Duration
}

// Error implements the error interface.
func (e *RateLimitError) Error() string {
	return e.Message
}

// Unwrap returns nil as this is a terminal error type.
func (e *RateLimitError) Unwrap() error {
	return nil
}

// NewRateLimitError creates a new RateLimitError.
func NewRateLimitError(message string, retryAfter time.Duration, limitName string, burst int64, period time.Duration) *RateLimitError {
	return &RateLimitError{
		Message:    message,
		RetryAfter: retryAfter,
		LimitName:  limitName,
		Burst:      burst,
		Period:     period,
	}
}

// NonceError represents a nonce validation error.
type NonceError struct {
	// Message is the human-readable error message.
	Message string

	// Cause is the underlying error if any.
	Cause error
}

// Error implements the error interface.
func (e *NonceError) Error() string {
	return e.Message
}

// Unwrap returns the underlying cause.
func (e *NonceError) Unwrap() error {
	return e.Cause
}

// NewNonceError creates a new NonceError.
func NewNonceError(message string, cause error) *NonceError {
	return &NonceError{
		Message: message,
		Cause:   cause,
	}
}

// ValidationError represents a validation failure.
type ValidationError struct {
	// Field is the name of the field that failed validation.
	Field string

	// Message is the validation error message.
	Message string

	// Value is the invalid value (if safe to include).
	Value interface{}
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	if e.Value != nil {
		return fmt.Sprintf("validation error for %s: %s (value: %v)", e.Field, e.Message, e.Value)
	}
	return fmt.Sprintf("validation error for %s: %s", e.Field, e.Message)
}

// NewValidationError creates a new ValidationError.
func NewValidationError(field, message string, value interface{}) *ValidationError {
	return &ValidationError{
		Field:   field,
		Message: message,
		Value:   value,
	}
}

// TransactionError represents an error during a rate limit transaction.
type TransactionError struct {
	// BucketKey is the bucket key where the error occurred.
	BucketKey string

	// Operation is the operation that failed (get, set, increment, delete).
	Operation string

	// Cause is the underlying error.
	Cause error
}

// Error implements the error interface.
func (e *TransactionError) Error() string {
	return fmt.Sprintf("transaction error during %s for bucket %s: %v", e.Operation, e.BucketKey, e.Cause)
}

// Unwrap returns the underlying cause.
func (e *TransactionError) Unwrap() error {
	return e.Cause
}

// NewTransactionError creates a new TransactionError.
func NewTransactionError(bucketKey, operation string, cause error) *TransactionError {
	return &TransactionError{
		BucketKey: bucketKey,
		Operation: operation,
		Cause:     cause,
	}
}

// Is reports whether target matches err.
func Is(err, target error) bool {
	return errors.Is(err, target)
}

// As finds the first error in err's chain that matches target.
func As(err error, target interface{}) bool {
	return errors.As(err, target)
}
