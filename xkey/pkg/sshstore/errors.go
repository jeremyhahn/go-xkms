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

package sshstore

// MissingDataDirError is returned by ResolveBackend when no barrier backend
// was supplied and dataDir is empty, so no plain-engine root can be resolved.
type MissingDataDirError struct{}

// Error implements the error interface.
func (e *MissingDataDirError) Error() string {
	return "sshstore: dataDir is required when no barrier backend is supplied"
}

// NilDestinationError is returned by MigrateLegacyStores when dst is nil.
type NilDestinationError struct{}

// Error implements the error interface.
func (e *NilDestinationError) Error() string {
	return "sshstore: destination backend is required"
}

// MigrationError wraps a failure encountered while migrating a legacy
// plain-file SSH store into the barrier-encrypted backend. Dir names the
// legacy store directory and Op names the failing step (stat, open, scan,
// close, rename).
type MigrationError struct {
	Dir string
	Op  string
	Err error
}

// Error implements the error interface.
func (e *MigrationError) Error() string {
	return "sshstore: migrate " + e.Dir + ": " + e.Op + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *MigrationError) Unwrap() error { return e.Err }
