// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package records

// StoreError reports a failed DAO operation on the record at Path.
type StoreError struct {
	Op   string
	Path string
	Err  error
}

// Error implements the error interface.
func (e *StoreError) Error() string {
	return "ssh/records: " + e.Op + " " + e.Path + ": " + e.Err.Error()
}

// Unwrap returns the underlying DAO error.
func (e *StoreError) Unwrap() error { return e.Err }

// ConflictError reports a write to the record at Path that kept losing the
// race against concurrent writers of the same record.
type ConflictError struct {
	Op   string
	Path string
}

// Error implements the error interface.
func (e *ConflictError) Error() string {
	return "ssh/records: " + e.Op + " " + e.Path + ": concurrent writers kept changing the record"
}
