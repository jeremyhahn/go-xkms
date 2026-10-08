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

package pinadapter

// NilBackendError is returned when a nil storage.Backend is provided to
// the adapter constructor.
type NilBackendError struct{}

// Error returns a human-readable description of the error.
func (e NilBackendError) Error() string {
	return "pinadapter: backend cannot be nil"
}

// GetError wraps a storage backend Get operation failure that is not a
// not-found condition (those are translated to pin.ErrNotFound).
type GetError struct {
	Key string
	Err error
}

// Error returns a human-readable description of the get failure.
func (e *GetError) Error() string {
	return "pinadapter: get " + e.Key + ": " + e.Err.Error()
}

// Unwrap returns the underlying error so errors.Is / errors.As work.
func (e *GetError) Unwrap() error {
	return e.Err
}

// PutError wraps a storage backend Put operation failure.
type PutError struct {
	Key string
	Err error
}

// Error returns a human-readable description of the put failure.
func (e *PutError) Error() string {
	return "pinadapter: put " + e.Key + ": " + e.Err.Error()
}

// Unwrap returns the underlying error so errors.Is / errors.As work.
func (e *PutError) Unwrap() error {
	return e.Err
}

// DeleteError wraps a storage backend Delete operation failure that is not
// a not-found condition (deleting an absent key succeeds).
type DeleteError struct {
	Key string
	Err error
}

// Error returns a human-readable description of the delete failure.
func (e *DeleteError) Error() string {
	return "pinadapter: delete " + e.Key + ": " + e.Err.Error()
}

// Unwrap returns the underlying error so errors.Is / errors.As work.
func (e *DeleteError) Unwrap() error {
	return e.Err
}
