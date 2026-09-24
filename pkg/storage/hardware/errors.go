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

// Package hardware provides hardware-backed certificate storage implementations
// for PKCS#11 HSMs and TPM2 devices.
package hardware

import (
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"
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

	// ErrIDReservedForChain is returned when a certificate id has a shape the
	// chain encoding reserves: <id>-chain, which is what the storage key
	// certs/<id>-chain.pem and the PKCS#11 label prefix of <id>'s chain spell,
	// or <id>-chain-<n>, the CKA_ID of a chain member. Refusing both on every
	// path that accepts an id keeps the key space unambiguous by
	// construction: a key or object of those shapes can only ever name a
	// chain record.
	ErrIDReservedForChain = errors.New("certificate id has a shape reserved for chain records (<id>-chain or <id>-chain-<n>)")

	// ErrInvalidCertificate indicates certificate is invalid or corrupted
	ErrInvalidCertificate = errors.New("invalid or corrupted certificate")

	// ErrCertRecordMissingHeader is returned when a TPM2 NV blob at a
	// certificate index does not carry the required magic header and ID
	// length field. Every record this storage writes carries one; a blob
	// without it is not a supported shape to read, not a legacy layout to
	// infer an identity for.
	ErrCertRecordMissingHeader = errors.New("TPM2 NV certificate record is missing its magic header")

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

	// ErrDeleteNotSupportedOnToken indicates the token silently no-op'd a
	// C_DestroyObject call. YubiKey PIV is a known offender: its libykcs11
	// accepts DestroyObject but leaves the slot object intact because PIV
	// slots can only be overwritten or reset, never individually deleted.
	ErrDeleteNotSupportedOnToken = errors.New("hardware: token silently rejected cert deletion")

	// ErrSOSessionRequired indicates the storage was configured with
	// requireSO=true but no SO PIN was supplied. The operation would fall
	// through to a CKU_USER session that the token rejects with
	// CKR_USER_TYPE_INVALID (notably YubiKey PIV). The caller must provide
	// an SO PIN (for YubiKey, the PIV management key hex string) when
	// constructing the storage.
	ErrSOSessionRequired = errors.New("PKCS#11 token requires SO session but no SO PIN was provided")
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

// isCKR reports whether err is, or wraps, a pkcs11.Error carrying the given
// Cryptoki return code (CKR_*). Call sites use this instead of comparing err
// to a pkcs11.Error value with == so a wrapped Cryptoki error still
// classifies correctly.
func isCKR(err error, code uint) bool {
	var ckErr pkcs11.Error
	return errors.As(err, &ckErr) && ckErr == pkcs11.Error(code)
}
