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

import (
	"errors"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

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

// ErrIndexingNotSupported is the sentinel reported by every secondary-index
// operation on KVStoreAdapter. Callers that can fall back to a full scan
// detect it with errors.Is; callers that require index support must treat it
// as fatal. The adapter never answers an index query with an empty result,
// so "no error" always means the returned data is authoritative.
var ErrIndexingNotSupported = errors.New("kvadapter: secondary indexing is not supported")

// IndexingNotSupportedError reports an index operation attempted against the
// KVStoreAdapter, which bridges an opaque byte-oriented storage.Backend and
// therefore cannot decode entity payloads to maintain or evaluate indexes.
// It unwraps to ErrIndexingNotSupported.
type IndexingNotSupportedError struct {
	// Op is the adapter method that was called, such as "QueryIndex".
	Op string

	// Name is the index name, or the entity type for RegisterEntityIndexes.
	Name string
}

// Error returns a human-readable description of the unsupported operation.
func (e *IndexingNotSupportedError) Error() string {
	return "kvadapter: " + e.Op + " " + e.Name + ": secondary indexing is not supported"
}

// Unwrap returns ErrIndexingNotSupported so errors.Is identifies the class.
func (e *IndexingNotSupportedError) Unwrap() error {
	return ErrIndexingNotSupported
}

// Is additionally matches go-qrdb's ErrKVIndexUnsupported, the sentinel that
// go-qrdb's DAO uses to negotiate index capability.
//
// This is a protocol obligation, not a convenience. Since go-qrdb
// v0.8.0-alpha, pkg/dao asks an adapter to register indexes at construction
// and reads the reply to decide how to answer queries: an error matching
// kvstore.ErrIndexUnsupported means "this store has no index subsystem, plan
// full scans", and ANY OTHER error is a genuine construction failure. Before
// v0.8.0 the refusal was ignored, which is what the comment on
// RegisterEntityIndexes used to describe.
//
// This adapter genuinely cannot index -- it bridges an opaque byte-oriented
// storage.Backend and never decodes entity payloads -- so the honest answer
// is the capability sentinel. Reporting only the local sentinel made the DAO
// read a capability signal as a hard failure and refuse to construct at all:
// 28 tests across pkg/api/rest went red on the v0.9.0-alpha bump, every one
// of them "failed to create DAO".
//
// ErrIndexingNotSupported is kept as the local sentinel so existing callers
// that test for it keep working; both now match.
func (e *IndexingNotSupportedError) Is(target error) bool {
	return target == ErrIndexingNotSupported || target == qrdbsdk.ErrKVIndexUnsupported
}
