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

package kvadapter

// NilBackendError is returned when a nil storage.Backend is provided
// to the adapter constructor.
type NilBackendError struct{}

// Error returns a human-readable description of the error.
func (e NilBackendError) Error() string {
	return "kvadapter: backend cannot be nil"
}

// PutError wraps a storage backend Put operation failure.
type PutError struct {
	Key string
	Err error
}

// Error returns a human-readable description of the put failure.
func (e *PutError) Error() string {
	return "kvadapter: put " + e.Key + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *PutError) Unwrap() error {
	return e.Err
}

// GetError wraps a storage backend Get operation failure.
type GetError struct {
	Key string
	Err error
}

// Error returns a human-readable description of the get failure.
func (e *GetError) Error() string {
	return "kvadapter: get " + e.Key + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *GetError) Unwrap() error {
	return e.Err
}

// DeleteError wraps a storage backend Delete operation failure.
type DeleteError struct {
	Key string
	Err error
}

// Error returns a human-readable description of the delete failure.
func (e *DeleteError) Error() string {
	return "kvadapter: delete " + e.Key + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *DeleteError) Unwrap() error {
	return e.Err
}

// ScanError wraps a storage backend Scan operation failure.
type ScanError struct {
	Prefix string
	Err    error
}

// Error returns a human-readable description of the scan failure.
func (e *ScanError) Error() string {
	return "kvadapter: scan " + e.Prefix + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ScanError) Unwrap() error {
	return e.Err
}

// ScanCallbackError wraps an error returned by a scan callback function.
type ScanCallbackError struct {
	Key string
	Err error
}

// Error returns a human-readable description of the callback failure.
func (e *ScanCallbackError) Error() string {
	return "kvadapter: scan callback " + e.Key + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ScanCallbackError) Unwrap() error {
	return e.Err
}

// ListError wraps a storage backend List operation failure.
type ListError struct {
	Prefix string
	Err    error
}

// Error returns a human-readable description of the list failure.
func (e *ListError) Error() string {
	return "kvadapter: list " + e.Prefix + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ListError) Unwrap() error {
	return e.Err
}

// ExistsError wraps a storage backend Exists operation failure.
type ExistsError struct {
	Key string
	Err error
}

// Error returns a human-readable description of the exists failure.
func (e *ExistsError) Error() string {
	return "kvadapter: exists " + e.Key + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ExistsError) Unwrap() error {
	return e.Err
}
