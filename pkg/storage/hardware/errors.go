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

// Package hardware provides hardware-backed certificate storage implementations
// for PKCS#11 HSMs and TPM2 devices.
package hardware

import (
	"errors"
	"fmt"
)

var (
	// ErrCapacityExceeded indicates hardware storage is full
	ErrCapacityExceeded = errors.New("hardware certificate storage capacity exceeded")

	// ErrCertificateTooLarge indicates certificate exceeds maximum size
	ErrCertificateTooLarge = errors.New("certificate exceeds maximum size for hardware storage")

	// ErrNotSupported indicates hardware doesn't support the operation
	ErrNotSupported = errors.New("operation not supported by hardware")

	// ErrHardwareUnavailable indicates hardware storage is inaccessible
	ErrHardwareUnavailable = errors.New("hardware certificate storage unavailable")

	// ErrNVIndexUnavailable indicates TPM NV index conflicts with existing data
	ErrNVIndexUnavailable = errors.New("TPM NV index already in use")

	// ErrStorageClosed indicates storage has been closed
	ErrStorageClosed = errors.New("storage has been closed")

	// ErrInvalidCertificate indicates certificate is invalid or corrupted
	ErrInvalidCertificate = errors.New("invalid or corrupted certificate")

	// ErrTokenFull indicates PKCS#11 token has no free object slots
	ErrTokenFull = errors.New("PKCS#11 token is full")

	// ErrNilContext indicates a nil PKCS#11 context was provided
	ErrNilContext = errors.New("PKCS#11 context cannot be nil")

	// ErrInvalidSession indicates an invalid or closed PKCS#11 session
	ErrInvalidSession = errors.New("invalid or closed PKCS#11 session")

	// ErrNilTPM indicates a nil TPM connection was provided
	ErrNilTPM = errors.New("TPM connection cannot be nil")

	// ErrInvalidBaseIndex indicates TPM base index is out of valid range
	ErrInvalidBaseIndex = errors.New("TPM base index out of valid NV RAM range")

	// ErrInvalidCertSize indicates certificate size is outside acceptable limits
	ErrInvalidCertSize = errors.New("certificate size outside acceptable limits")

	// ErrNilStorage indicates a nil storage backend was provided
	ErrNilStorage = errors.New("storage backend cannot be nil")
)

// IsCapacityError returns true if the error indicates a capacity-related issue
// (full storage or certificate too large).
func IsCapacityError(err error) bool {
	return errors.Is(err, ErrCapacityExceeded) ||
		errors.Is(err, ErrCertificateTooLarge) ||
		errors.Is(err, ErrTokenFull)
}

// IsHardwareError returns true if the error is hardware-related and suggests
// that the hardware backend may be unavailable or in an error state.
func IsHardwareError(err error) bool {
	return errors.Is(err, ErrHardwareUnavailable) ||
		errors.Is(err, ErrNVIndexUnavailable) ||
		errors.Is(err, ErrNotSupported)
}

// OperationError wraps an error with operation context
type OperationError struct {
	Op  string // Operation name (e.g., "create certificate object", "delete NV index")
	Err error  // Underlying error
}

func (e *OperationError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("operation failed: %s", e.Op)
	}
	return fmt.Sprintf("%s: %v", e.Op, e.Err)
}

func (e *OperationError) Unwrap() error {
	return e.Err
}

// NewOperationError creates a new operation error
func NewOperationError(op string, err error) error {
	return &OperationError{Op: op, Err: err}
}
