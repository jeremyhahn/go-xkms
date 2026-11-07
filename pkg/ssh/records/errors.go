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

// LegacyRecordError reports a pre-DAO record at Path that does not decode or
// does not hold a valid record.
type LegacyRecordError struct {
	Path string
	Err  error
}

// Error implements the error interface.
func (e *LegacyRecordError) Error() string {
	return "ssh/records: legacy record " + e.Path + ": " + e.Err.Error()
}

// Unwrap returns the decode or validation error.
func (e *LegacyRecordError) Unwrap() error { return e.Err }

// LegacyPathError reports a pre-DAO record stored at Path whose own scope,
// owner and name address the record at Record instead.
type LegacyPathError struct {
	Path   string
	Record string
}

// Error implements the error interface.
func (e *LegacyPathError) Error() string {
	return "ssh/records: legacy record " + e.Path + " names the record " + e.Record
}

// LegacyOwnerConflictError reports a pre-DAO record at Path whose record
// another owner already holds in the table.
type LegacyOwnerConflictError struct {
	Path string
}

// Error implements the error interface.
func (e *LegacyOwnerConflictError) Error() string {
	return "ssh/records: legacy record " + e.Path + " is held by another owner"
}
