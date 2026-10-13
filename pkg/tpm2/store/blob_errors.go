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

package store

import "errors"

var (
	// ErrNilDAOFactory is returned by NewBlobStore when it is given no DAO
	// factory.
	ErrNilDAOFactory = errors.New("blob store: a DAO factory is required")

	// ErrBlobNotFound is matched by the error a read of a blob that was never
	// stored returns.
	ErrBlobNotFound = errors.New("blob store: blob not found")

	// ErrBlobExists is matched by the error a write that may not overwrite
	// returns when the blob is already stored.
	ErrBlobExists = errors.New("blob store: blob already exists")
)

// InvalidBlobKeyError reports a tenant, name or extension that cannot be one
// segment of a blob's natural key.
type InvalidBlobKeyError struct {
	Field string
	Value string
}

// Error returns a human-readable description of the invalid segment.
func (e *InvalidBlobKeyError) Error() string {
	return "blob store: invalid " + e.Field + " " + e.Value
}

// BlobListError indicates a blob listing failed.
type BlobListError struct {
	Tenant string
	Ext    string
	Cause  error
}

// Error returns a human-readable description of the listing failure.
func (e *BlobListError) Error() string {
	return "blob store: failed to list " + e.Ext + " blobs of tenant " + e.Tenant + ": " + e.Cause.Error()
}

// Unwrap returns the underlying error.
func (e *BlobListError) Unwrap() error {
	return e.Cause
}

// BlobStoreCreateError indicates the blob store could not be created.
type BlobStoreCreateError struct {
	Cause error
}

// Error returns a human-readable description of the creation failure.
func (e *BlobStoreCreateError) Error() string {
	return "blob store: failed to create: " + e.Cause.Error()
}

// Unwrap returns the underlying error.
func (e *BlobStoreCreateError) Unwrap() error {
	return e.Cause
}

// BlobReadError indicates a blob read operation failed.
type BlobReadError struct {
	Name  string
	Cause error
}

// Error returns a human-readable description of the read failure.
func (e *BlobReadError) Error() string {
	return "blob store: failed to read " + e.Name + ": " + e.Cause.Error()
}

// Unwrap returns the underlying error.
func (e *BlobReadError) Unwrap() error {
	return e.Cause
}

// BlobWriteError indicates a blob write operation failed.
type BlobWriteError struct {
	Name  string
	Cause error
}

// Error returns a human-readable description of the write failure.
func (e *BlobWriteError) Error() string {
	return "blob store: failed to write " + e.Name + ": " + e.Cause.Error()
}

// Unwrap returns the underlying error.
func (e *BlobWriteError) Unwrap() error {
	return e.Cause
}

// BlobDeleteError indicates a blob delete operation failed.
type BlobDeleteError struct {
	Name  string
	Cause error
}

// Error returns a human-readable description of the delete failure.
func (e *BlobDeleteError) Error() string {
	return "blob store: failed to delete " + e.Name + ": " + e.Cause.Error()
}

// Unwrap returns the underlying error.
func (e *BlobDeleteError) Unwrap() error {
	return e.Cause
}
