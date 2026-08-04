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

package interceptors

import "errors"

// Interceptor error types.
var (
	// ErrInsufficientTime indicates there is not enough remaining time
	// to process the request before the deadline.
	ErrInsufficientTime = errors.New("interceptors: insufficient time for request processing")

	// ErrNilHandler indicates a nil handler was provided.
	ErrNilHandler = errors.New("interceptors: handler cannot be nil")

	// ErrInvalidOverhead indicates an invalid return overhead duration.
	ErrInvalidOverhead = errors.New("interceptors: return overhead must be >= 0")
)

// DeadlineError represents a deadline-related error with additional context.
type DeadlineError struct {
	// Message is the human-readable error message.
	Message string

	// Remaining is the time remaining before the deadline when rejected.
	Remaining int64

	// RequiredMinimum is the minimum time required to process the request.
	RequiredMinimum int64

	// Cause is the underlying error if any.
	Cause error
}

// Error implements the error interface.
func (e *DeadlineError) Error() string {
	return e.Message
}

// Unwrap returns the underlying cause.
func (e *DeadlineError) Unwrap() error {
	return e.Cause
}

// NewDeadlineError creates a new DeadlineError.
func NewDeadlineError(message string, remaining, requiredMinimum int64, cause error) *DeadlineError {
	return &DeadlineError{
		Message:         message,
		Remaining:       remaining,
		RequiredMinimum: requiredMinimum,
		Cause:           cause,
	}
}
