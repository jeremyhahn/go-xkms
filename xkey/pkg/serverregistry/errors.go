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

// Package serverregistry tracks xkms server connections and their CA certificate
// fingerprints, enabling TLS trust resolution via the Trust Store.
package serverregistry

import (
	"errors"
	"fmt"
)

var (
	// ErrNilBackend is returned when a nil storage backend is provided.
	ErrNilBackend = errors.New("serverregistry: nil storage backend")

	// ErrNilKVStore is returned when a nil KVStore is provided.
	ErrNilKVStore = errors.New("serverregistry: nil kvstore")

	// ErrStoreClosed is returned when operations are attempted on a closed registry.
	ErrStoreClosed = errors.New("serverregistry: store is closed")

	// ErrServerNotFound is returned when a server entry cannot be found.
	ErrServerNotFound = errors.New("serverregistry: server not found")

	// ErrInvalidURL is returned when the server URL is empty.
	ErrInvalidURL = errors.New("serverregistry: server URL cannot be empty")

	// ErrNilEntry is returned when a nil server entry is provided.
	ErrNilEntry = errors.New("serverregistry: nil server entry")

	// ErrServerExists is returned when attempting to register a server that already exists.
	ErrServerExists = errors.New("serverregistry: server already registered")
)

// ErrDAOCreation is returned when the DAO fails to initialize.
type ErrDAOCreation struct {
	Cause error
}

// Error returns the error message.
func (e ErrDAOCreation) Error() string {
	return fmt.Sprintf("serverregistry: failed to create DAO: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrDAOCreation) Unwrap() error {
	return e.Cause
}

// ErrMigration is returned when migration from legacy storage fails.
type ErrMigration struct {
	Cause error
}

// Error returns the error message.
func (e ErrMigration) Error() string {
	return fmt.Sprintf("serverregistry: migration failed: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrMigration) Unwrap() error {
	return e.Cause
}
