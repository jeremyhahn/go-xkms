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

	// ErrInvalidDir is returned when a file store is opened with no
	// directory.
	ErrInvalidDir = errors.New("tokenstore: store directory cannot be empty")
)

// OpenError is returned when the file-backed store cannot be opened.
type OpenError struct {
	Dir   string
	Cause error
}

// Error implements the error interface.
func (e *OpenError) Error() string {
	return fmt.Sprintf("tokenstore: open %s: %v", e.Dir, e.Cause)
}

// Unwrap returns the underlying cause.
func (e *OpenError) Unwrap() error { return e.Cause }

// AmbiguousServerNameError is returned when a server name selects logins to
// more than one server (different TLS identities), so no login is chosen.
type AmbiguousServerNameError struct {
	Name    string
	Servers int
}

// Error implements the error interface.
func (e *AmbiguousServerNameError) Error() string {
	return fmt.Sprintf("tokenstore: server name %q matches logins to %d different servers; log out of the stale ones or set XKMSD_TOKEN",
		e.Name, e.Servers)
}

// LoginExpiredError is returned when the stored login for a server has
// expired. It matches ErrTokenExpired.
type LoginExpiredError struct {
	ServerURL string
}

// Error implements the error interface.
func (e *LoginExpiredError) Error() string {
	return fmt.Sprintf("tokenstore: the login for %s has expired; run `xkey auth refresh --server %s` or log in again",
		e.ServerURL, e.ServerURL)
}

// Is reports a match with ErrTokenExpired.
func (e *LoginExpiredError) Is(target error) bool { return target == ErrTokenExpired }

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
