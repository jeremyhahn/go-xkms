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

package pin

import (
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

var (
	// ErrPINNotSet is returned when a PIN has not been set.
	ErrPINNotSet = errors.New("pin: PIN not set")

	// ErrPINLocked is returned when the PIN is locked due to too many failed attempts.
	ErrPINLocked = errors.New("pin: locked out due to too many failed attempts")

	// ErrPINInvalid is returned when the provided PIN is incorrect.
	ErrPINInvalid = errors.New("pin: invalid PIN")

	// ErrSOPINRequired is returned when SO PIN authorization is required.
	ErrSOPINRequired = errors.New("pin: SO PIN authorization required")

	// ErrPINTooShort is returned when a PIN does not meet minimum length requirements.
	ErrPINTooShort = errors.New("pin: PIN must be at least 6 characters")

	// ErrPINAlreadySet is returned when attempting to set a PIN that is already set.
	ErrPINAlreadySet = errors.New("pin: PIN already set, use Change instead")

	// ErrInvalidCurrentPIN is returned when the current PIN verification fails during a change.
	ErrInvalidCurrentPIN = errors.New("pin: current PIN verification failed")

	// ErrStateCorrupted is returned when the state file contains invalid data.
	ErrStateCorrupted = errors.New("pin: state file corrupted")

	// ErrStrategyNotSet is returned when no PIN strategy has been configured.
	ErrStrategyNotSet = errors.New("pin: no PIN strategy configured")

	// ErrHierarchyAuthMismatch is returned when the TPM hierarchy already has
	// auth from a previous session whose local state was lost (e.g., ~/.xkey
	// deleted) and the provided PIN does not match. A factory reset of the
	// TPM hierarchies is required to recover.
	ErrHierarchyAuthMismatch = errors.New("pin: TPM hierarchy auth mismatch, factory reset required")

	// ErrUnsupportedHashAlgorithm is returned when an unknown hash algorithm
	// is specified in a HashConfig or PINRecord.
	ErrUnsupportedHashAlgorithm = errors.New("pin: unsupported hash algorithm")
)

// ErrStoragePersistFailed is returned when persisting a PIN blob to storage fails.
type ErrStoragePersistFailed struct {
	Key   string
	Cause error
}

func (e *ErrStoragePersistFailed) Error() string {
	return fmt.Sprintf("pin: failed to persist %q to storage: %s", e.Key, e.Cause)
}

func (e *ErrStoragePersistFailed) Unwrap() error {
	return e.Cause
}

// ErrStorageLoadFailed is returned when loading a PIN blob from storage fails
// for a reason other than not-found.
type ErrStorageLoadFailed struct {
	Key   string
	Cause error
}

func (e *ErrStorageLoadFailed) Error() string {
	return fmt.Sprintf("pin: failed to load %q from storage: %s", e.Key, e.Cause)
}

func (e *ErrStorageLoadFailed) Unwrap() error {
	return e.Cause
}

// ErrUnsupportedPBKDF2Hash is returned when an unsupported hash function is
// specified for PBKDF2 key derivation.
type ErrUnsupportedPBKDF2Hash struct {
	Hash types.HashName
}

func (e *ErrUnsupportedPBKDF2Hash) Error() string {
	return fmt.Sprintf("pin: unsupported PBKDF2 hash function: %s", e.Hash)
}

// ErrTPMLocked is returned when the TPM is locked out due to dictionary
// attack protection.
type ErrTPMLocked struct {
	Status *LockoutStatus
}

func (e *ErrTPMLocked) Error() string {
	return fmt.Sprintf("pin: TPM locked, recovery in %d seconds", e.Status.RecoverySeconds)
}

// ErrPINInvalidWithStatus extends the PIN invalid condition with lockout
// status information so the caller can display remaining attempts.
type ErrPINInvalidWithStatus struct {
	Status *LockoutStatus
}

func (e *ErrPINInvalidWithStatus) Error() string {
	remaining := e.Status.MaxAttempts - e.Status.FailedAttempts
	return fmt.Sprintf("pin: invalid PIN, %d of %d attempts remaining", remaining, e.Status.MaxAttempts)
}
