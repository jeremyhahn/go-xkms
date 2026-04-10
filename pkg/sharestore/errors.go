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

package sharestore

import "errors"

var (
	// ErrNilBackend is returned when a nil storage backend is provided.
	ErrNilBackend = errors.New("sharestore: nil storage backend")

	// ErrStoreClosed is returned when operations are attempted on a closed store.
	ErrStoreClosed = errors.New("sharestore: store is closed")

	// ErrShareNotFound is returned when a requested share does not exist.
	ErrShareNotFound = errors.New("sharestore: share not found")

	// ErrInvalidServerURL is returned when a server URL is empty.
	ErrInvalidServerURL = errors.New("sharestore: server URL cannot be empty")

	// ErrInvalidGroupID is returned when a group ID is empty.
	ErrInvalidGroupID = errors.New("sharestore: group ID cannot be empty")

	// ErrNilEntry is returned when a nil share entry is provided.
	ErrNilEntry = errors.New("sharestore: nil share entry")

	// ErrShareExists is returned when a share for the server+group already exists.
	ErrShareExists = errors.New("sharestore: share already exists")

	// ErrEmptyShare is returned when share data is empty.
	ErrEmptyShare = errors.New("sharestore: share data cannot be empty")
)

// ErrDAOCreation is returned when the DAO layer fails to initialize.
type ErrDAOCreation struct {
	Cause error
}

// Error returns a human-readable description of the DAO creation failure.
func (e ErrDAOCreation) Error() string {
	return "sharestore: failed to create DAO: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e ErrDAOCreation) Unwrap() error {
	return e.Cause
}
