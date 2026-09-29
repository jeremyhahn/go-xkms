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

import "fmt"

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
