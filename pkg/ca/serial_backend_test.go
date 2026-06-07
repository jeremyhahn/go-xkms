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
	"errors"
	"math/big"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

func TestBackendStorage_StoreAndExists(t *testing.T) {
	store := NewBackendStorage(storage.NewMemory())
	serial := big.NewInt(123456789)

	exists, err := store.SerialExists(serial)
	if err != nil {
		t.Fatalf("SerialExists: %v", err)
	}
	if exists {
		t.Fatalf("SerialExists before store = true, want false")
	}

	if err := store.StoreSerial(serial); err != nil {
		t.Fatalf("StoreSerial: %v", err)
	}
	exists, err = store.SerialExists(serial)
	if err != nil {
		t.Fatalf("SerialExists: %v", err)
	}
	if !exists {
		t.Fatalf("SerialExists after store = false, want true")
	}
}

// TestBackendStorage_SurvivesNewInstance is the durability guard: a serial
// recorded by one Storage is visible to a fresh Storage over the same backend
// (modeling a process restart against a persistent datastore).
func TestBackendStorage_SurvivesNewInstance(t *testing.T) {
	backend := storage.NewMemory()
	serial := big.NewInt(987654321)

	if err := NewBackendStorage(backend).StoreSerial(serial); err != nil {
		t.Fatalf("StoreSerial: %v", err)
	}
	exists, err := NewBackendStorage(backend).SerialExists(serial)
	if err != nil {
		t.Fatalf("SerialExists: %v", err)
	}
	if !exists {
		t.Fatalf("serial did not survive a new Storage instance over the same backend")
	}
}

func TestBackendStorage_NilSerial(t *testing.T) {
	store := NewBackendStorage(storage.NewMemory())

	var verr *SerialValidationError
	if _, err := store.SerialExists(nil); !errors.As(err, &verr) {
		t.Fatalf("SerialExists(nil) = %v, want *SerialValidationError", err)
	}
	if err := store.StoreSerial(nil); !errors.As(err, &verr) {
		t.Fatalf("StoreSerial(nil) = %v, want *SerialValidationError", err)
	}
}

func TestBackendStorage_BackendErrorWrapped(t *testing.T) {
	backend := storage.NewMemory()
	_ = backend.Close() // subsequent ops return ErrClosed
	store := NewBackendStorage(backend)
	serial := big.NewInt(42)

	var serr *SerialStorageError
	if _, err := store.SerialExists(serial); !errors.As(err, &serr) {
		t.Fatalf("SerialExists on closed backend = %v, want *SerialStorageError", err)
	}
	if err := store.StoreSerial(serial); !errors.As(err, &serr) {
		t.Fatalf("StoreSerial on closed backend = %v, want *SerialStorageError", err)
	}
}

// TestBackendStorage_KeyNamespace verifies serials are stored under the
// documented prefix so they share a clean namespace in the datastore.
func TestBackendStorage_KeyNamespace(t *testing.T) {
	backend := storage.NewMemory()
	if err := NewBackendStorage(backend).StoreSerial(big.NewInt(7)); err != nil {
		t.Fatalf("StoreSerial: %v", err)
	}
	keys, err := backend.List(context.Background(), SerialKeyPrefix)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 || keys[0] != SerialKeyPrefix+"7" {
		t.Fatalf("keys = %v, want [%s7]", keys, SerialKeyPrefix)
	}
}
