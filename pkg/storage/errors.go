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

package storage

import "errors"

var (
	// ErrClosed is returned when attempting to use a closed storage.
	ErrClosed = errors.New("storage: closed")

	// ErrNotFound is returned when a key or certificate is not found.
	ErrNotFound = errors.New("storage: not found")

	// ErrCompareAndSwapUnsupported is returned when a CompareAndSwap is requested
	// of a backend (or a wrapper over one) that does not implement
	// CompareAndSwapper.
	ErrCompareAndSwapUnsupported = errors.New("storage: backend does not support compare-and-swap")

	// ErrCompareAndDeleteUnsupported is returned when a CompareAndDelete is
	// requested of a backend (or a wrapper over one) that does not implement
	// CompareAndDeleter.
	ErrCompareAndDeleteUnsupported = errors.New("storage: backend does not support compare-and-delete")

	// ErrAlreadyExists is returned when attempting to save a key or certificate that already exists.
	ErrAlreadyExists = errors.New("storage: already exists")

	// ErrInvalidID is returned when an ID is invalid or empty.
	ErrInvalidID = errors.New("storage: invalid ID")

	// ErrInvalidData is returned when data is invalid or malformed.
	ErrInvalidData = errors.New("storage: invalid data")

	// ErrEnginePathRequired is returned by OpenEngine when the selected engine
	// needs a filesystem path but none was provided.
	ErrEnginePathRequired = errors.New("storage: engine path required")

	// ErrUnknownEngine is returned by OpenEngine for an unrecognized engine kind.
	ErrUnknownEngine = errors.New("storage: unknown engine kind")
)
