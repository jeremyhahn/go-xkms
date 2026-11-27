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

import qrdbstorage "github.com/jeremyhahn/go-qrdb/sdk/go/storage"

// NewMemoryBackend creates a new in-memory storage backend backed by the
// go-qrdb in-memory engine (the single canonical memory engine in the stack —
// xkms ships no map/mutex implementation of its own). The backend is
// thread-safe, stores defensive copies, returns ErrNotFound for missing keys,
// and returns ErrClosed once Close has been called.
func NewMemoryBackend() (Backend, error) {
	return NewEngineBackend(qrdbstorage.NewMemoryStorage()), nil
}

// NewMemory creates a new in-memory storage backend. This is a convenience
// function that panics on error (which never happens for the memory engine).
func NewMemory() Backend {
	backend, err := NewMemoryBackend()
	if err != nil {
		panic("failed to create memory backend: " + err.Error())
	}
	return backend
}

// New creates a new in-memory storage backend.
// This is a convenience function for testing and development.
func New() Backend {
	return NewMemory()
}
