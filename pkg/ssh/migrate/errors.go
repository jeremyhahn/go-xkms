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

package migrate

import "strconv"

// NilInputError reports a required Run argument that is nil.
type NilInputError struct {
	Field string
}

// Error implements the error interface.
func (e *NilInputError) Error() string {
	return "ssh/migrate: " + e.Field + " is nil"
}

// OpenError reports a DAO store that could not be opened.
type OpenError struct {
	Store string
	Err   error
}

// Error implements the error interface.
func (e *OpenError) Error() string {
	return "ssh/migrate: open " + e.Store + " store: " + e.Err.Error()
}

// Unwrap returns the store's error.
func (e *OpenError) Unwrap() error { return e.Err }

// ListError reports that the old store's keys could not be listed.
type ListError struct {
	Err error
}

// Error implements the error interface.
func (e *ListError) Error() string {
	return "ssh/migrate: list legacy store: " + e.Err.Error()
}

// Unwrap returns the backend's error.
func (e *ListError) Unwrap() error { return e.Err }

// RecordError reports the old record at Path that failed at Op ("read",
// "import" or "delete") and was left in the old store.
type RecordError struct {
	Path string
	Op   string
	Err  error
}

// Error implements the error interface.
func (e *RecordError) Error() string {
	return "ssh/migrate: " + e.Op + " " + e.Path + ": " + e.Err.Error()
}

// Unwrap returns the backend's or the store's error.
func (e *RecordError) Unwrap() error { return e.Err }

// RecordsFailedError collects the *RecordError of every record one Run left
// in the old store.
type RecordsFailedError struct {
	Errs []error
}

// Error implements the error interface.
func (e *RecordsFailedError) Error() string {
	msg := "ssh/migrate: " + strconv.Itoa(len(e.Errs)) + " record(s) failed"
	for _, err := range e.Errs {
		msg += "; " + err.Error()
	}
	return msg
}

// Unwrap returns the per-record errors, so errors.As finds each one.
func (e *RecordsFailedError) Unwrap() []error { return e.Errs }
