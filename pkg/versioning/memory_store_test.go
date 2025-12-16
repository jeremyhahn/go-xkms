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
	"sync"
	"testing"
)

func TestMemoryVersionStore(t *testing.T) {
	VersionStoreTestSuite(t, func() VersionStore {
		return NewMemoryVersionStore()
	})
}

func TestMemoryVersionStore_Concurrent(t *testing.T) {
	store := NewMemoryVersionStore()
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

func TestMemoryVersionStore_CloseNilsMap(t *testing.T) {
	store := NewMemoryVersionStore()

	// Create some data
	info := &VersionInfo{
		Version:      1,
		BackendKeyID: "test-key-v1",
		Algorithm:    "Ed25519",
		State:        KeyStateEnabled,
	}
	if err := store.CreateVersion(t.Context(), "test-key", info); err != nil {
		t.Fatalf("CreateVersion failed: %v", err)
	}

	// Close
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Internal map should be nil
	if store.keys != nil {
		t.Error("Expected keys map to be nil after Close")
	}
}
