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

package audit

import (
	"errors"
	"fmt"
)

var (
	// ErrNilBackend is returned when a nil storage backend is provided.
	ErrNilBackend = errors.New("audit: nil storage backend")

	// ErrStoreClosed is returned when an operation is attempted on a closed store.
	ErrStoreClosed = errors.New("audit: store is closed")

	// ErrNilKVStore is returned when a nil KVStore is provided to the DAO store.
	ErrNilKVStore = errors.New("audit: nil kvstore")
)

// ErrDAOCreation is returned when the DAO layer fails to initialize.
type ErrDAOCreation struct {
	Cause error
}

// Error implements the error interface.
func (e ErrDAOCreation) Error() string {
	return fmt.Sprintf("audit: failed to create DAO: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrDAOCreation) Unwrap() error {
	return e.Cause
}

// ErrMigration is returned when migration from old storage format fails.
type ErrMigration struct {
	Key   string
	Cause error
}

// Error implements the error interface.
func (e ErrMigration) Error() string {
	return fmt.Sprintf("audit: migration failed for key %q: %v", e.Key, e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrMigration) Unwrap() error {
	return e.Cause
}
