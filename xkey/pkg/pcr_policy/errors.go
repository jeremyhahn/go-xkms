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

package pcrpolicy

import (
	"errors"
	"fmt"
)

var (
	// ErrNilKVStore is returned when a nil kvstore.KVStore is provided.
	ErrNilKVStore = errors.New("pcrpolicy: nil KVStore")

	// ErrPolicyNotFound is returned when no policy exists for the given name.
	ErrPolicyNotFound = errors.New("pcrpolicy: policy not found")

	// ErrInvalidName is returned when the policy name is empty.
	ErrInvalidName = errors.New("pcrpolicy: name cannot be empty")

	// ErrInvalidBank is returned when the PCR bank is not a supported algorithm.
	ErrInvalidBank = errors.New("pcrpolicy: unsupported PCR bank")

	// ErrNoPCRs is returned when the PCR map is nil or empty.
	ErrNoPCRs = errors.New("pcrpolicy: PCR map cannot be empty")

	// ErrMultipleAutoUnseal is returned when attempting to set auto-unseal
	// while another policy already has it (internal invariant violation).
	ErrMultipleAutoUnseal = errors.New("pcrpolicy: multiple auto-unseal policies detected")

	// ErrStoreClosed is returned when the store has been closed.
	ErrStoreClosed = errors.New("pcrpolicy: store is closed")

	// ErrDeleteAutoUnseal is returned when attempting to delete the
	// policy that is currently designated as the auto-unseal policy.
	ErrDeleteAutoUnseal = errors.New("pcrpolicy: cannot delete the active auto-unseal policy")
)

// ErrDAOCreation is returned when the DAO layer fails to initialize.
type ErrDAOCreation struct {
	Cause error
}

// Error implements the error interface.
func (e ErrDAOCreation) Error() string {
	return fmt.Sprintf("pcrpolicy: failed to create DAO: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrDAOCreation) Unwrap() error {
	return e.Cause
}
