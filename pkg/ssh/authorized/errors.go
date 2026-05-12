// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package authorized

// NilInputError is returned when a required argument is nil or zero.
// Field names the offending argument.
type NilInputError struct {
	Field string
}

// Error implements the error interface.
func (e *NilInputError) Error() string {
	return "ssh/authorized: nil input: " + e.Field
}

// MalformedLineError is returned by ParseLine when the input does not
// match the OpenSSH authorized_keys grammar. The underlying
// x/crypto/ssh parse failure is preserved via Unwrap for callers that
// need the specific cause.
type MalformedLineError struct {
	Line string
	Err  error
}

// Error implements the error interface.
func (e *MalformedLineError) Error() string {
	return "ssh/authorized: malformed line: " + e.Err.Error()
}

// Unwrap returns the underlying parse error.
func (e *MalformedLineError) Unwrap() error { return e.Err }

// NotFoundError is returned by Store.Get / Verify when the requested
// entry does not exist.
type NotFoundError struct {
	Scope string
	Owner string
	Name  string
}

// Error implements the error interface.
func (e *NotFoundError) Error() string {
	return "ssh/authorized: entry not found: " + e.Scope + "/" + e.Owner + "/" + e.Name
}

// DuplicateError is returned by Store.Add when an entry already exists
// for (scope, owner, name). Non-idempotent: callers who intend to
// overwrite must Remove first.
type DuplicateError struct {
	Scope string
	Owner string
	Name  string
}

// Error implements the error interface.
func (e *DuplicateError) Error() string {
	return "ssh/authorized: entry already exists: " + e.Scope + "/" + e.Owner + "/" + e.Name
}

// InvalidNameError is returned when a name cannot be used as a
// storage-path component (empty, contains '/' or NUL).
type InvalidNameError struct {
	Value  string
	Reason string
}

// Error implements the error interface.
func (e *InvalidNameError) Error() string {
	return "ssh/authorized: invalid name: " + e.Reason
}

// StorageError wraps an underlying storage-backend failure.
type StorageError struct {
	Op  string
	Err error
}

// Error implements the error interface.
func (e *StorageError) Error() string {
	return "ssh/authorized: storage " + e.Op + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *StorageError) Unwrap() error { return e.Err }

// SerializationError is returned when the stored envelope cannot be
// encoded or decoded.
type SerializationError struct {
	Op  string
	Err error
}

// Error implements the error interface.
func (e *SerializationError) Error() string {
	return "ssh/authorized: serialize " + e.Op + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *SerializationError) Unwrap() error { return e.Err }
