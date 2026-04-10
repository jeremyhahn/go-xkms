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

package tokenstore

import (
	"errors"
	"fmt"
)

var (
	// ErrNilBackend is returned when a nil storage backend is provided.
	ErrNilBackend = errors.New("tokenstore: nil storage backend")

	// ErrStoreClosed is returned when the store has been closed.
	ErrStoreClosed = errors.New("tokenstore: store is closed")

	// ErrTokenNotFound is returned when no token exists for the given key.
	ErrTokenNotFound = errors.New("tokenstore: token not found")

	// ErrInvalidServer is returned when the server URL is empty.
	ErrInvalidServer = errors.New("tokenstore: server URL cannot be empty")

	// ErrNilEntry is returned when a nil token entry is provided.
	ErrNilEntry = errors.New("tokenstore: nil token entry")

	// ErrTokenExpired is returned when a token has expired.
	ErrTokenExpired = errors.New("tokenstore: token has expired")
)

// ErrDAOCreation is returned when the DAO layer fails to initialize.
type ErrDAOCreation struct {
	Cause error
}

// Error implements the error interface.
func (e ErrDAOCreation) Error() string {
	return fmt.Sprintf("tokenstore: failed to create DAO: %v", e.Cause)
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
	return fmt.Sprintf("tokenstore: migration failed for key %q: %v", e.Key, e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrMigration) Unwrap() error {
	return e.Cause
}
