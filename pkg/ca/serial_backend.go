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

package ca

import (
	"context"
	"math/big"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// SerialKeyPrefix is the key namespace under which used serial numbers are
// recorded in the backing storage.
const SerialKeyPrefix = "ca/serials/"

// backendStorage is a durable serial-number Storage backed by a
// storage.Backend (the hosted datastore). Each issued serial is recorded as a
// key, so uniqueness survives process restarts and replicates under Raft —
// eliminating the serial collisions the in-memory store risks. It is the
// production Storage implementation; NewMemoryStorage is for tests only.
type backendStorage struct {
	backend storage.Backend
	prefix  string
}

// NewBackendStorage creates a durable serial Storage over the given backend.
// Serials are recorded under SerialKeyPrefix as their base-10 string form.
func NewBackendStorage(backend storage.Backend) Storage {
	return &backendStorage{backend: backend, prefix: SerialKeyPrefix}
}

// key returns the storage key for a serial number.
func (b *backendStorage) key(serial *big.Int) string {
	return b.prefix + serial.Text(10)
}

// SerialExists reports whether the serial number has already been recorded.
func (b *backendStorage) SerialExists(serial *big.Int) (bool, error) {
	if serial == nil {
		return false, &SerialValidationError{Reason: "serial number is nil"}
	}
	exists, err := b.backend.Exists(context.Background(), b.key(serial))
	if err != nil {
		return false, &SerialStorageError{Op: "check", Err: err}
	}
	return exists, nil
}

// StoreSerial durably records a serial number as used. The write is flushed by
// the backend before returning, satisfying the Storage durability contract.
func (b *backendStorage) StoreSerial(serial *big.Int) error {
	if serial == nil {
		return &SerialValidationError{Reason: "serial number is nil"}
	}
	if err := b.backend.Put(context.Background(), b.key(serial), []byte{1}); err != nil {
		return &SerialStorageError{Op: "store", Err: err}
	}
	return nil
}
