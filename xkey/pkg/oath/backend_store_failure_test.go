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

package oath

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// errStorageFault is the failure faultyStorage injects.
var errStorageFault = errors.New("storage: injected fault")

// faultyStorage is an in-memory backend whose List, Get and Exists can be
// made to fail, standing in for a storage layer that is unreachable or
// returns entries that vanished between a List and the Get that follows it.
type faultyStorage struct {
	xkms.StorageBackend
	listErr   error
	getErr    error
	existsErr error
}

func (f *faultyStorage) List(ctx context.Context, prefix string) ([]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.StorageBackend.List(ctx, prefix)
}

func (f *faultyStorage) Get(ctx context.Context, key string) ([]byte, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.StorageBackend.Get(ctx, key)
}

func (f *faultyStorage) Exists(ctx context.Context, key string) (bool, error) {
	if f.existsErr != nil {
		return false, f.existsErr
	}
	return f.StorageBackend.Exists(ctx, key)
}

// newFaultyBackendStore returns a store over faultyStorage holding one
// valid credential, "seed".
func newFaultyBackendStore(t *testing.T) (*BackendStore, *faultyStorage) {
	t.Helper()
	backend := &faultyStorage{StorageBackend: xkms.NewStorageMemory()}
	store, err := NewBackendStore(backend, "oath/")
	if err != nil {
		t.Fatalf("NewBackendStore: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Errorf("Close: %v", closeErr)
		}
	})
	if err := store.Add(createTestCredential("seed", "Seed")); err != nil {
		t.Fatalf("Add seed: %v", err)
	}
	return store, backend
}

// TestBackendStore_StorageFailuresSurface checks that a storage error on any
// read path is returned to the caller rather than read as "no credential" —
// which, for Add, would let a duplicate name through.
func TestBackendStore_StorageFailuresSurface(t *testing.T) {
	operations := map[string]func(*BackendStore) error{
		"List": func(s *BackendStore) error { _, err := s.List(); return err },
		"Get":  func(s *BackendStore) error { _, err := s.Get("Seed"); return err },
		"Add":  func(s *BackendStore) error { return s.Add(createTestCredential("other", "Other")) },
	}
	faults := map[string]func(*faultyStorage){
		"list": func(f *faultyStorage) { f.listErr = errStorageFault },
		"get":  func(f *faultyStorage) { f.getErr = errStorageFault },
	}

	for faultName, inject := range faults {
		for opName, op := range operations {
			t.Run(faultName+" fault fails "+opName, func(t *testing.T) {
				store, backend := newFaultyBackendStore(t)
				inject(backend)
				if err := op(store); !errors.Is(err, errStorageFault) {
					t.Fatalf("%s: got %v, want the storage fault", opName, err)
				}
			})
		}
	}

	t.Run("exists fault fails Add and Update", func(t *testing.T) {
		store, backend := newFaultyBackendStore(t)
		backend.existsErr = errStorageFault
		if err := store.Add(createTestCredential("other", "Other")); !errors.Is(err, errStorageFault) {
			t.Errorf("Add: got %v, want the storage fault", err)
		}
		if err := store.Update(createTestCredential("seed", "Seed")); !errors.Is(err, errStorageFault) {
			t.Errorf("Update: got %v, want the storage fault", err)
		}
	})
}

// TestBackendStore_VanishedEntriesAreSkipped checks the List-then-Get race:
// an entry deleted between the two reads is skipped, not reported as an
// error, on every path that scans.
func TestBackendStore_VanishedEntriesAreSkipped(t *testing.T) {
	store, backend := newFaultyBackendStore(t)
	backend.getErr = xkms.ErrStorageNotFound

	creds, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("List: got %d credentials, want the vanished one skipped", len(creds))
	}
	if _, err := store.Get("seed"); !errors.Is(err, ErrCredentialNotFound) {
		t.Errorf("Get: got %v, want ErrCredentialNotFound", err)
	}
	if err := store.Add(createTestCredential("other", "Seed")); err != nil {
		t.Errorf("Add: a vanished entry must not count as a duplicate name: %v", err)
	}
}

// TestBackendStore_CorruptRecordIsAnError checks that a record that is not a
// credential fails the scan instead of being silently dropped.
func TestBackendStore_CorruptRecordIsAnError(t *testing.T) {
	store, backend := newFaultyBackendStore(t)
	if err := backend.Put(context.Background(), "oath/corrupt", []byte("{not json")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	var syntaxErr *json.SyntaxError
	if _, err := store.List(); !errors.As(err, &syntaxErr) {
		t.Errorf("List: got %v, want a JSON syntax error", err)
	}
	if _, err := store.Get("missing"); !errors.As(err, &syntaxErr) {
		t.Errorf("Get: got %v, want a JSON syntax error", err)
	}
	if err := store.Add(createTestCredential("other", "Other")); !errors.As(err, &syntaxErr) {
		t.Errorf("Add: got %v, want a JSON syntax error", err)
	}
}
