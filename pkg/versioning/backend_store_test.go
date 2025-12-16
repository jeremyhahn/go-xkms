// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package versioning

import (
	"strings"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
)

// mockStorageBackend is an in-memory implementation of storage.Backend for testing.
type mockStorageBackend struct {
	mu     sync.RWMutex
	data   map[string][]byte
	closed bool
}

func newMockStorageBackend() *mockStorageBackend {
	return &mockStorageBackend{
		data: make(map[string][]byte),
	}
}

func (m *mockStorageBackend) Get(key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	data, ok := m.data[key]
	if !ok {
		return nil, storage.ErrNotFound
	}

	// Return a copy
	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

func (m *mockStorageBackend) Put(key string, value []byte, opts *storage.Options) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Store a copy
	data := make([]byte, len(value))
	copy(data, value)
	m.data[key] = data
	return nil
}

func (m *mockStorageBackend) Delete(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.data[key]; !ok {
		return storage.ErrNotFound
	}
	delete(m.data, key)
	return nil
}

func (m *mockStorageBackend) List(prefix string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var keys []string
	for k := range m.data {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func (m *mockStorageBackend) Exists(key string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, ok := m.data[key]
	return ok, nil
}

func (m *mockStorageBackend) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.closed = true
	return nil
}

func TestBackendVersionStore(t *testing.T) {
	VersionStoreTestSuite(t, func() VersionStore {
		backend := newMockStorageBackend()
		return NewBackendVersionStore(backend)
	})
}

func TestBackendVersionStore_Concurrent(t *testing.T) {
	backend := newMockStorageBackend()
	store := NewBackendVersionStore(backend)
	defer func() { _ = store.Close() }()

	var wg sync.WaitGroup
	numGoroutines := 10
	versionsPerGoroutine := 10

	// Concurrent writes for different keys
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(keyNum int) {
			defer wg.Done()
			keyID := BackendKeyID("key", uint64(keyNum))

			for v := uint64(1); v <= uint64(versionsPerGoroutine); v++ {
				info := &VersionInfo{
					Version:      v,
					BackendKeyID: BackendKeyID(keyID, v),
					Algorithm:    "Ed25519",
					State:        KeyStateEnabled,
				}
				if err := store.CreateVersion(t.Context(), keyID, info); err != nil {
					t.Errorf("Concurrent CreateVersion failed: %v", err)
				}
			}
		}(i)
	}
	wg.Wait()

	// Verify all keys and versions were created
	keys, err := store.ListKeys(t.Context())
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(keys) != numGoroutines {
		t.Errorf("Expected %d keys, got %d", numGoroutines, len(keys))
	}

	for _, keyID := range keys {
		versions, err := store.ListVersions(t.Context(), keyID)
		if err != nil {
			t.Fatalf("ListVersions failed for %s: %v", keyID, err)
		}
		if len(versions) != versionsPerGoroutine {
			t.Errorf("Key %s: expected %d versions, got %d", keyID, versionsPerGoroutine, len(versions))
		}
	}
}

func TestBackendVersionStore_StorageKeyPrefix(t *testing.T) {
	backend := newMockStorageBackend()
	store := NewBackendVersionStore(backend)
	defer func() { _ = store.Close() }()

	// Create a version
	info := &VersionInfo{
		Version:      1,
		BackendKeyID: "test-key-v1",
		Algorithm:    "Ed25519",
		State:        KeyStateEnabled,
	}
	if err := store.CreateVersion(t.Context(), "test-key", info); err != nil {
		t.Fatalf("CreateVersion failed: %v", err)
	}

	// Verify the storage key has correct prefix
	keys, err := backend.List(keyPrefix)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("Expected 1 key, got %d", len(keys))
	}

	expectedKey := keyPrefix + "test-key"
	if keys[0] != expectedKey {
		t.Errorf("Storage key = %q, want %q", keys[0], expectedKey)
	}
}

func TestBackendVersionStore_JSONSerialization(t *testing.T) {
	backend := newMockStorageBackend()
	store := NewBackendVersionStore(backend)

	// Create a version with metadata
	info := &VersionInfo{
		Version:      1,
		BackendKeyID: "test-key-v1",
		Algorithm:    "Ed25519",
		State:        KeyStateEnabled,
		Metadata:     map[string]string{"purpose": "signing", "owner": "test"},
	}
	if err := store.CreateVersion(t.Context(), "test-key", info); err != nil {
		t.Fatalf("CreateVersion failed: %v", err)
	}

	// Get raw data from storage
	rawData, err := backend.Get(keyPrefix + "test-key")
	if err != nil {
		t.Fatalf("Get raw data failed: %v", err)
	}

	// Should be valid JSON
	if len(rawData) == 0 {
		t.Fatal("Raw data is empty")
	}
	if rawData[0] != '{' {
		t.Errorf("Raw data doesn't look like JSON: %s", string(rawData))
	}

	// Close and create new store with same backend
	_ = store.Close()
	store2 := NewBackendVersionStore(backend)
	defer func() { _ = store2.Close() }()

	// Should be able to read the data
	retrieved, err := store2.GetVersionInfo(t.Context(), "test-key", 1)
	if err != nil {
		t.Fatalf("GetVersionInfo after reload failed: %v", err)
	}

	if retrieved.Version != 1 {
		t.Errorf("Version = %d, want 1", retrieved.Version)
	}
	if retrieved.Metadata["purpose"] != "signing" {
		t.Errorf("Metadata[purpose] = %q, want %q", retrieved.Metadata["purpose"], "signing")
	}
	if retrieved.Metadata["owner"] != "test" {
		t.Errorf("Metadata[owner] = %q, want %q", retrieved.Metadata["owner"], "test")
	}
}

func TestBackendVersionStore_DeleteLastVersionRemovesKey(t *testing.T) {
	backend := newMockStorageBackend()
	store := NewBackendVersionStore(backend)
	defer func() { _ = store.Close() }()

	// Create a single version
	info := &VersionInfo{
		Version:      1,
		BackendKeyID: "test-key-v1",
		Algorithm:    "Ed25519",
		State:        KeyStateEnabled,
	}
	if err := store.CreateVersion(t.Context(), "test-key", info); err != nil {
		t.Fatalf("CreateVersion failed: %v", err)
	}

	// Verify storage has the key
	exists, err := backend.Exists(keyPrefix + "test-key")
	if err != nil {
		t.Fatalf("Exists check failed: %v", err)
	}
	if !exists {
		t.Fatal("Key should exist in storage")
	}

	// Delete the only version
	if err := store.DeleteVersion(t.Context(), "test-key", 1); err != nil {
		t.Fatalf("DeleteVersion failed: %v", err)
	}

	// Storage should no longer have the key
	exists, err = backend.Exists(keyPrefix + "test-key")
	if err != nil {
		t.Fatalf("Exists check after delete failed: %v", err)
	}
	if exists {
		t.Error("Key should not exist in storage after deleting last version")
	}
}
