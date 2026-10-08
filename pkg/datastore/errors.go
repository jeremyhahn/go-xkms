// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package datastore

import (
	"errors"
	"fmt"
)

var (
	// ErrNilConfig is returned by Open when it is given no configuration.
	ErrNilConfig = errors.New("datastore: config is required")

	// ErrNilClient is returned by New when it is given no client.
	ErrNilClient = errors.New("datastore: a go-qrdb client is required")

	// ErrDatabaseNameRequired is returned by DatabaseKVStore for an empty
	// database name.
	ErrDatabaseNameRequired = errors.New("datastore: a database name is required")
)

// ErrUnsupportedStorageBackend indicates an unsupported remote storage
// transport was specified.
type ErrUnsupportedStorageBackend struct {
	Backend string
}

// Error returns the error message.
func (e *ErrUnsupportedStorageBackend) Error() string {
	return fmt.Sprintf("unsupported storage backend: %s", e.Backend)
}

// ErrUnsupportedDatastoreMode indicates config.DatastoreConfig.Mode named a
// value other than "standalone" or "remote". config.Validate rejects this
// before Open is reachable through a validated *config.Config; this is
// defense-in-depth for an embedded caller that constructs one without
// validating it.
type ErrUnsupportedDatastoreMode struct {
	Mode string
}

// Error returns the error message.
func (e *ErrUnsupportedDatastoreMode) Error() string {
	return fmt.Sprintf("unsupported datastore mode: %s", e.Mode)
}

// ErrOpenDatastore wraps a failure to open the shared datastore in the named
// mode.
type ErrOpenDatastore struct {
	Mode string
	Err  error
}

// Error returns the error message.
func (e *ErrOpenDatastore) Error() string {
	return fmt.Sprintf("datastore: failed to open %s datastore: %v", e.Mode, e.Err)
}

// Unwrap exposes Err so errors.Is/errors.As can reach it.
func (e *ErrOpenDatastore) Unwrap() error {
	return e.Err
}

// ErrDialRemote wraps a failure to build, or connect, the client for a
// remote datastore.
type ErrDialRemote struct {
	Transport string
	Address   string
	Err       error
}

// Error returns the error message.
func (e *ErrDialRemote) Error() string {
	return fmt.Sprintf("datastore: failed to dial %s datastore at %q: %v", e.Transport, e.Address, e.Err)
}

// Unwrap exposes Err so errors.Is/errors.As can reach it.
func (e *ErrDialRemote) Unwrap() error {
	return e.Err
}

// ErrEnsureDatabase wraps a failure to confirm or create the named go-qrdb
// database.
type ErrEnsureDatabase struct {
	Name string
	Err  error
}

// Error returns the error message.
func (e *ErrEnsureDatabase) Error() string {
	return fmt.Sprintf("datastore: failed to ensure database %q: %v", e.Name, e.Err)
}

// Unwrap exposes Err so errors.Is/errors.As can reach it.
func (e *ErrEnsureDatabase) Unwrap() error {
	return e.Err
}

// ErrDatabaseScope wraps a failure to scope the go-qrdb client to the named
// database once it is confirmed to exist.
type ErrDatabaseScope struct {
	Name string
	Err  error
}

// Error returns the error message.
func (e *ErrDatabaseScope) Error() string {
	return fmt.Sprintf("datastore: failed to scope client to database %q: %v", e.Name, e.Err)
}

// Unwrap exposes Err so errors.Is/errors.As can reach it.
func (e *ErrDatabaseScope) Unwrap() error {
	return e.Err
}

// ErrCallContext wraps a failure to derive the context a call into go-qrdb
// runs on (WithCallContext) -- an embedded node with no service principal,
// for instance. The call never reaches go-qrdb.
type ErrCallContext struct {
	Err error
}

// Error returns the error message.
func (e *ErrCallContext) Error() string {
	return fmt.Sprintf("datastore: failed to derive the call context: %v", e.Err)
}

// Unwrap exposes Err so errors.Is/errors.As can reach it.
func (e *ErrCallContext) Unwrap() error {
	return e.Err
}
