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

import "github.com/jeremyhahn/go-xkms/pkg/storage/qrdb"

func init() {
	// Align qrdb's not-found sentinel with storage.ErrNotFound so that
	// errors.Is works across packages without circular imports.
	qrdb.SetNotFoundError(ErrNotFound)
}

// NewFile creates a file-based storage backend at the given path.
// Delegates to the go-qrdb embedded file engine. Each key-value pair is
// stored as a separate file under the directory. The entire QRDB stack
// is initialized in-process. Close() tears down all resources.
func NewFile(path string) (Backend, error) {
	backend, err := qrdb.NewFile(path)
	if err != nil {
		return nil, err
	}
	return backend, nil
}

// NewPebble creates a PebbleDB storage backend at the given path.
// Delegates to the go-qrdb embedded PebbleDB engine. Uses a test-optimized
// PebbleDB configuration suitable for lightweight embedded usage. The entire
// QRDB stack is initialized in-process. Close() tears down all resources.
func NewPebble(path string) (Backend, error) {
	backend, err := qrdb.NewPebble(path)
	if err != nil {
		return nil, err
	}
	return backend, nil
}
