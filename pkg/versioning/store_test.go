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
	"context"
	"testing"
	"time"
)

func TestBackendKeyID(t *testing.T) {
	tests := []struct {
		keyID   string
		version uint64
		want    string
	}{
		{"mykey", 1, "mykey-v1"},
		{"mykey", 2, "mykey-v2"},
		{"mykey", 0, "mykey-v0"},
		{"mykey", 100, "mykey-v100"},
		{"test-key", 42, "test-key-v42"},
		{"", 1, "-v1"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := BackendKeyID(tt.keyID, tt.version)
			if got != tt.want {
				t.Errorf("BackendKeyID(%q, %d) = %q, want %q", tt.keyID, tt.version, got, tt.want)
			}
		})
	}
}

func TestUintToString(t *testing.T) {
	tests := []struct {
		n    uint64
		want string
	}{
		{0, "0"},
		{1, "1"},
		{10, "10"},
		{100, "100"},
		{12345, "12345"},
		{18446744073709551615, "18446744073709551615"}, // max uint64
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := uintToString(tt.n)
			if got != tt.want {
				t.Errorf("uintToString(%d) = %q, want %q", tt.n, got, tt.want)
			}
		})
	}
}

// VersionStoreTestSuite runs a standard test suite against any VersionStore implementation.
// This allows the same tests to be run against MemoryVersionStore, BackendVersionStore, etc.
func VersionStoreTestSuite(t *testing.T, createStore func() VersionStore) {
	t.Run("CreateAndGetVersion", func(t *testing.T) {
		store := createStore()
		defer func() { _ = store.Close() }()

		ctx := context.Background()
		keyID := "test-key"

		// Create version 1
		info := &VersionInfo{
			Version:      1,
			BackendKeyID: "test-key-v1",
			Algorithm:    "Ed25519",
			State:        KeyStateEnabled,
			Metadata:     map[string]string{"purpose": "signing"},
		}

		err := store.CreateVersion(ctx, keyID, info)
		if err != nil {
			t.Fatalf("CreateVersion failed: %v", err)
		}

		// Verify current version
		currentVersion, err := store.GetCurrentVersion(ctx, keyID)
		if err != nil {
			t.Fatalf("GetCurrentVersion failed: %v", err)
		}
		if currentVersion != 1 {
			t.Errorf("GetCurrentVersion = %d, want 1", currentVersion)
		}

		// Get version info
		retrieved, err := store.GetVersionInfo(ctx, keyID, 1)
		if err != nil {
			t.Fatalf("GetVersionInfo failed: %v", err)
		}

		if retrieved.Version != info.Version {
			t.Errorf("Version = %d, want %d", retrieved.Version, info.Version)
		}
		if retrieved.BackendKeyID != info.BackendKeyID {
			t.Errorf("BackendKeyID = %q, want %q", retrieved.BackendKeyID, info.BackendKeyID)
		}
		if retrieved.Algorithm != info.Algorithm {
			t.Errorf("Algorithm = %q, want %q", retrieved.Algorithm, info.Algorithm)
		}
		if retrieved.State != info.State {
			t.Errorf("State = %q, want %q", retrieved.State, info.State)
		}
		if retrieved.Metadata["purpose"] != "signing" {
			t.Errorf("Metadata[purpose] = %q, want %q", retrieved.Metadata["purpose"], "signing")
		}
	})

	t.Run("GetVersionInfoWithZero", func(t *testing.T) {
		store := createStore()
		defer func() { _ = store.Close() }()

		ctx := context.Background()
		keyID := "test-key"

		// Create version 1
		info := &VersionInfo{
			Version:      1,
			BackendKeyID: "test-key-v1",
			Algorithm:    "Ed25519",
			State:        KeyStateEnabled,
		}

		if err := store.CreateVersion(ctx, keyID, info); err != nil {
			t.Fatalf("CreateVersion failed: %v", err)
		}

		// Get version 0 (should return current version)
		retrieved, err := store.GetVersionInfo(ctx, keyID, 0)
		if err != nil {
			t.Fatalf("GetVersionInfo(0) failed: %v", err)
		}

		if retrieved.Version != 1 {
			t.Errorf("GetVersionInfo(0).Version = %d, want 1", retrieved.Version)
		}
	})

	t.Run("MultipleVersions", func(t *testing.T) {
		store := createStore()
		defer func() { _ = store.Close() }()

		ctx := context.Background()
		keyID := "test-key"

		// Create versions 1, 2, 3
		for i := uint64(1); i <= 3; i++ {
			info := &VersionInfo{
				Version:      i,
				BackendKeyID: BackendKeyID(keyID, i),
				Algorithm:    "Ed25519",
				State:        KeyStateEnabled,
			}
			if err := store.CreateVersion(ctx, keyID, info); err != nil {
				t.Fatalf("CreateVersion(%d) failed: %v", i, err)
			}
		}

		// Current version should be 3
		currentVersion, err := store.GetCurrentVersion(ctx, keyID)
		if err != nil {
			t.Fatalf("GetCurrentVersion failed: %v", err)
		}
		if currentVersion != 3 {
			t.Errorf("GetCurrentVersion = %d, want 3", currentVersion)
		}

		// List versions
		versions, err := store.ListVersions(ctx, keyID)
		if err != nil {
			t.Fatalf("ListVersions failed: %v", err)
		}
		if len(versions) != 3 {
			t.Fatalf("ListVersions returned %d versions, want 3", len(versions))
		}

		// Verify order (should be sorted by version)
		for i, v := range versions {
			expectedVersion := uint64(i + 1)
			if v.Version != expectedVersion {
				t.Errorf("versions[%d].Version = %d, want %d", i, v.Version, expectedVersion)
			}
		}
	})

	t.Run("SetCurrentVersion", func(t *testing.T) {
		store := createStore()
		defer func() { _ = store.Close() }()

		ctx := context.Background()
		keyID := "test-key"

		// Create versions 1 and 2
		for i := uint64(1); i <= 2; i++ {
			info := &VersionInfo{
				Version:      i,
				BackendKeyID: BackendKeyID(keyID, i),
				Algorithm:    "Ed25519",
				State:        KeyStateEnabled,
			}
			if err := store.CreateVersion(ctx, keyID, info); err != nil {
				t.Fatalf("CreateVersion(%d) failed: %v", i, err)
			}
		}

		// Current should be 2
		currentVersion, _ := store.GetCurrentVersion(ctx, keyID)
		if currentVersion != 2 {
			t.Errorf("Initial current version = %d, want 2", currentVersion)
		}

		// Set current to 1
		if err := store.SetCurrentVersion(ctx, keyID, 1); err != nil {
			t.Fatalf("SetCurrentVersion failed: %v", err)
		}

		currentVersion, _ = store.GetCurrentVersion(ctx, keyID)
		if currentVersion != 1 {
			t.Errorf("After SetCurrentVersion = %d, want 1", currentVersion)
		}
	})

	t.Run("UpdateVersionState", func(t *testing.T) {
		store := createStore()
		defer func() { _ = store.Close() }()

		ctx := context.Background()
		keyID := "test-key"

		info := &VersionInfo{
			Version:      1,
			BackendKeyID: "test-key-v1",
			Algorithm:    "Ed25519",
			State:        KeyStateEnabled,
		}
		if err := store.CreateVersion(ctx, keyID, info); err != nil {
			t.Fatalf("CreateVersion failed: %v", err)
		}

		// Update state
		if err := store.UpdateVersionState(ctx, keyID, 1, KeyStateDisabled); err != nil {
			t.Fatalf("UpdateVersionState failed: %v", err)
		}

		// Verify state changed
		retrieved, err := store.GetVersionInfo(ctx, keyID, 1)
		if err != nil {
			t.Fatalf("GetVersionInfo failed: %v", err)
		}
		if retrieved.State != KeyStateDisabled {
			t.Errorf("State = %q, want %q", retrieved.State, KeyStateDisabled)
		}
	})

	t.Run("DeleteVersion", func(t *testing.T) {
		store := createStore()
		defer func() { _ = store.Close() }()

		ctx := context.Background()
		keyID := "test-key"

		// Create versions 1 and 2
		for i := uint64(1); i <= 2; i++ {
			info := &VersionInfo{
				Version:      i,
				BackendKeyID: BackendKeyID(keyID, i),
				Algorithm:    "Ed25519",
				State:        KeyStateEnabled,
			}
			if err := store.CreateVersion(ctx, keyID, info); err != nil {
				t.Fatalf("CreateVersion(%d) failed: %v", i, err)
			}
		}

		// Delete version 1
		if err := store.DeleteVersion(ctx, keyID, 1); err != nil {
			t.Fatalf("DeleteVersion failed: %v", err)
		}

		// Verify version 1 is gone
		_, err := store.GetVersionInfo(ctx, keyID, 1)
		if err != ErrVersionNotFound {
			t.Errorf("GetVersionInfo after delete = %v, want ErrVersionNotFound", err)
		}

		// Current version should still be 2
		currentVersion, err := store.GetCurrentVersion(ctx, keyID)
		if err != nil {
			t.Fatalf("GetCurrentVersion failed: %v", err)
		}
		if currentVersion != 2 {
			t.Errorf("GetCurrentVersion = %d, want 2", currentVersion)
		}
	})

	t.Run("DeleteCurrentVersion", func(t *testing.T) {
		store := createStore()
		defer func() { _ = store.Close() }()

		ctx := context.Background()
		keyID := "test-key"

		// Create versions 1, 2, 3
		for i := uint64(1); i <= 3; i++ {
			info := &VersionInfo{
				Version:      i,
				BackendKeyID: BackendKeyID(keyID, i),
				Algorithm:    "Ed25519",
				State:        KeyStateEnabled,
			}
			if err := store.CreateVersion(ctx, keyID, info); err != nil {
				t.Fatalf("CreateVersion(%d) failed: %v", i, err)
			}
		}

		// Delete current version (3)
		if err := store.DeleteVersion(ctx, keyID, 3); err != nil {
			t.Fatalf("DeleteVersion(3) failed: %v", err)
		}

		// Current should now be 2 (highest remaining)
		currentVersion, err := store.GetCurrentVersion(ctx, keyID)
		if err != nil {
			t.Fatalf("GetCurrentVersion failed: %v", err)
		}
		if currentVersion != 2 {
			t.Errorf("GetCurrentVersion = %d, want 2", currentVersion)
		}
	})

	t.Run("DeleteKey", func(t *testing.T) {
		store := createStore()
		defer func() { _ = store.Close() }()

		ctx := context.Background()
		keyID := "test-key"

		// Create versions
		for i := uint64(1); i <= 2; i++ {
			info := &VersionInfo{
				Version:      i,
				BackendKeyID: BackendKeyID(keyID, i),
				Algorithm:    "Ed25519",
				State:        KeyStateEnabled,
			}
			if err := store.CreateVersion(ctx, keyID, info); err != nil {
				t.Fatalf("CreateVersion(%d) failed: %v", i, err)
			}
		}

		// Delete key
		if err := store.DeleteKey(ctx, keyID); err != nil {
			t.Fatalf("DeleteKey failed: %v", err)
		}

		// Key should be gone
		_, err := store.GetCurrentVersion(ctx, keyID)
		if err != ErrKeyNotFound {
			t.Errorf("GetCurrentVersion after delete = %v, want ErrKeyNotFound", err)
		}
	})

	t.Run("ListKeys", func(t *testing.T) {
		store := createStore()
		defer func() { _ = store.Close() }()

		ctx := context.Background()

		// Create multiple keys
		keys := []string{"alpha", "beta", "gamma"}
		for _, keyID := range keys {
			info := &VersionInfo{
				Version:      1,
				BackendKeyID: BackendKeyID(keyID, 1),
				Algorithm:    "Ed25519",
				State:        KeyStateEnabled,
			}
			if err := store.CreateVersion(ctx, keyID, info); err != nil {
				t.Fatalf("CreateVersion for %s failed: %v", keyID, err)
			}
		}

		// List keys
		listedKeys, err := store.ListKeys(ctx)
		if err != nil {
			t.Fatalf("ListKeys failed: %v", err)
		}

		if len(listedKeys) != len(keys) {
			t.Fatalf("ListKeys returned %d keys, want %d", len(listedKeys), len(keys))
		}

		// Verify all keys are present (should be sorted)
		for i, expected := range keys {
			if listedKeys[i] != expected {
				t.Errorf("listedKeys[%d] = %q, want %q", i, listedKeys[i], expected)
			}
		}
	})

	t.Run("ErrorKeyNotFound", func(t *testing.T) {
		store := createStore()
		defer func() { _ = store.Close() }()

		ctx := context.Background()

		_, err := store.GetCurrentVersion(ctx, "nonexistent")
		if err != ErrKeyNotFound {
			t.Errorf("GetCurrentVersion = %v, want ErrKeyNotFound", err)
		}

		_, err = store.GetVersionInfo(ctx, "nonexistent", 1)
		if err != ErrKeyNotFound {
			t.Errorf("GetVersionInfo = %v, want ErrKeyNotFound", err)
		}

		err = store.DeleteKey(ctx, "nonexistent")
		if err != ErrKeyNotFound {
			t.Errorf("DeleteKey = %v, want ErrKeyNotFound", err)
		}
	})

	t.Run("ErrorVersionNotFound", func(t *testing.T) {
		store := createStore()
		defer func() { _ = store.Close() }()

		ctx := context.Background()
		keyID := "test-key"

		// Create version 1
		info := &VersionInfo{
			Version:      1,
			BackendKeyID: "test-key-v1",
			Algorithm:    "Ed25519",
			State:        KeyStateEnabled,
		}
		if err := store.CreateVersion(ctx, keyID, info); err != nil {
			t.Fatalf("CreateVersion failed: %v", err)
		}

		// Try to get nonexistent version
		_, err := store.GetVersionInfo(ctx, keyID, 99)
		if err != ErrVersionNotFound {
			t.Errorf("GetVersionInfo(99) = %v, want ErrVersionNotFound", err)
		}

		// Try to set current to nonexistent version
		err = store.SetCurrentVersion(ctx, keyID, 99)
		if err != ErrVersionNotFound {
			t.Errorf("SetCurrentVersion(99) = %v, want ErrVersionNotFound", err)
		}

		// Try to delete nonexistent version
		err = store.DeleteVersion(ctx, keyID, 99)
		if err != ErrVersionNotFound {
			t.Errorf("DeleteVersion(99) = %v, want ErrVersionNotFound", err)
		}
	})

	t.Run("ErrorVersionExists", func(t *testing.T) {
		store := createStore()
		defer func() { _ = store.Close() }()

		ctx := context.Background()
		keyID := "test-key"

		info := &VersionInfo{
			Version:      1,
			BackendKeyID: "test-key-v1",
			Algorithm:    "Ed25519",
			State:        KeyStateEnabled,
		}

		// Create version 1
		if err := store.CreateVersion(ctx, keyID, info); err != nil {
			t.Fatalf("CreateVersion failed: %v", err)
		}

		// Try to create version 1 again
		err := store.CreateVersion(ctx, keyID, info)
		if err != ErrVersionExists {
			t.Errorf("CreateVersion duplicate = %v, want ErrVersionExists", err)
		}
	})

	t.Run("ErrorStoreClosed", func(t *testing.T) {
		store := createStore()

		// Close the store
		if err := store.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		ctx := context.Background()

		// All operations should fail with ErrStoreClosed
		_, err := store.GetCurrentVersion(ctx, "test")
		if err != ErrStoreClosed {
			t.Errorf("GetCurrentVersion after close = %v, want ErrStoreClosed", err)
		}

		_, err = store.GetVersionInfo(ctx, "test", 1)
		if err != ErrStoreClosed {
			t.Errorf("GetVersionInfo after close = %v, want ErrStoreClosed", err)
		}

		err = store.CreateVersion(ctx, "test", &VersionInfo{Version: 1})
		if err != ErrStoreClosed {
			t.Errorf("CreateVersion after close = %v, want ErrStoreClosed", err)
		}

		_, err = store.ListKeys(ctx)
		if err != ErrStoreClosed {
			t.Errorf("ListKeys after close = %v, want ErrStoreClosed", err)
		}
	})

	t.Run("MetadataIsolation", func(t *testing.T) {
		store := createStore()
		defer func() { _ = store.Close() }()

		ctx := context.Background()
		keyID := "test-key"

		// Create version with metadata
		metadata := map[string]string{"key": "value"}
		info := &VersionInfo{
			Version:      1,
			BackendKeyID: "test-key-v1",
			Algorithm:    "Ed25519",
			State:        KeyStateEnabled,
			Metadata:     metadata,
		}
		if err := store.CreateVersion(ctx, keyID, info); err != nil {
			t.Fatalf("CreateVersion failed: %v", err)
		}

		// Modify original metadata
		metadata["key"] = "modified"

		// Retrieved metadata should be unchanged
		retrieved, err := store.GetVersionInfo(ctx, keyID, 1)
		if err != nil {
			t.Fatalf("GetVersionInfo failed: %v", err)
		}
		if retrieved.Metadata["key"] != "value" {
			t.Errorf("Metadata was modified externally: got %q, want %q", retrieved.Metadata["key"], "value")
		}

		// Modify retrieved metadata
		retrieved.Metadata["key"] = "also-modified"

		// Original in store should be unchanged
		retrieved2, _ := store.GetVersionInfo(ctx, keyID, 1)
		if retrieved2.Metadata["key"] != "value" {
			t.Errorf("Metadata was modified via return value: got %q, want %q", retrieved2.Metadata["key"], "value")
		}
	})

	t.Run("TimestampHandling", func(t *testing.T) {
		store := createStore()
		defer func() { _ = store.Close() }()

		ctx := context.Background()
		keyID := "test-key"

		before := time.Now().Add(-time.Second)

		info := &VersionInfo{
			Version:      1,
			BackendKeyID: "test-key-v1",
			Algorithm:    "Ed25519",
			State:        KeyStateEnabled,
		}
		if err := store.CreateVersion(ctx, keyID, info); err != nil {
			t.Fatalf("CreateVersion failed: %v", err)
		}

		after := time.Now().Add(time.Second)

		retrieved, _ := store.GetVersionInfo(ctx, keyID, 1)

		// Created time should be set automatically
		if retrieved.Created.Before(before) || retrieved.Created.After(after) {
			t.Errorf("Created time %v not in expected range [%v, %v]", retrieved.Created, before, after)
		}

		// Updated time should be set
		if retrieved.Updated.Before(before) || retrieved.Updated.After(after) {
			t.Errorf("Updated time %v not in expected range [%v, %v]", retrieved.Updated, before, after)
		}
	})

	t.Run("GetKeyVersions", func(t *testing.T) {
		store := createStore()
		defer func() { _ = store.Close() }()

		ctx := context.Background()
		keyID := "test-key"

		// Create multiple versions
		for i := uint64(1); i <= 3; i++ {
			info := &VersionInfo{
				Version:      i,
				BackendKeyID: BackendKeyID(keyID, i),
				Algorithm:    "Ed25519",
				State:        KeyStateEnabled,
				Metadata:     map[string]string{"version": BackendKeyID("", i)},
			}
			if err := store.CreateVersion(ctx, keyID, info); err != nil {
				t.Fatalf("CreateVersion(%d) failed: %v", i, err)
			}
		}

		// Get all versions at once
		kv, err := store.GetKeyVersions(ctx, keyID)
		if err != nil {
			t.Fatalf("GetKeyVersions failed: %v", err)
		}

		// Verify KeyVersions structure
		if kv.KeyID != keyID {
			t.Errorf("KeyID = %q, want %q", kv.KeyID, keyID)
		}
		if kv.CurrentVersion != 3 {
			t.Errorf("CurrentVersion = %d, want 3", kv.CurrentVersion)
		}
		if len(kv.Versions) != 3 {
			t.Fatalf("Expected 3 versions, got %d", len(kv.Versions))
		}

		// Verify individual versions
		for i := uint64(1); i <= 3; i++ {
			v, ok := kv.Versions[i]
			if !ok {
				t.Errorf("Version %d not found", i)
				continue
			}
			if v.Version != i {
				t.Errorf("Version %d: Version field = %d", i, v.Version)
			}
			if v.BackendKeyID != BackendKeyID(keyID, i) {
				t.Errorf("Version %d: BackendKeyID = %q, want %q", i, v.BackendKeyID, BackendKeyID(keyID, i))
			}
		}
	})

	t.Run("GetKeyVersionsNotFound", func(t *testing.T) {
		store := createStore()
		defer func() { _ = store.Close() }()

		ctx := context.Background()

		_, err := store.GetKeyVersions(ctx, "nonexistent")
		if err != ErrKeyNotFound {
			t.Errorf("GetKeyVersions = %v, want ErrKeyNotFound", err)
		}
	})

	t.Run("GetKeyVersionsClosed", func(t *testing.T) {
		store := createStore()
		_ = store.Close()

		ctx := context.Background()

		_, err := store.GetKeyVersions(ctx, "test")
		if err != ErrStoreClosed {
			t.Errorf("GetKeyVersions after close = %v, want ErrStoreClosed", err)
		}
	})

	t.Run("ListVersionsClosed", func(t *testing.T) {
		store := createStore()
		_ = store.Close()

		ctx := context.Background()

		_, err := store.ListVersions(ctx, "test")
		if err != ErrStoreClosed {
			t.Errorf("ListVersions after close = %v, want ErrStoreClosed", err)
		}
	})

	t.Run("SetCurrentVersionClosed", func(t *testing.T) {
		store := createStore()
		_ = store.Close()

		ctx := context.Background()

		err := store.SetCurrentVersion(ctx, "test", 1)
		if err != ErrStoreClosed {
			t.Errorf("SetCurrentVersion after close = %v, want ErrStoreClosed", err)
		}
	})

	t.Run("UpdateVersionStateClosed", func(t *testing.T) {
		store := createStore()
		_ = store.Close()

		ctx := context.Background()

		err := store.UpdateVersionState(ctx, "test", 1, KeyStateDisabled)
		if err != ErrStoreClosed {
			t.Errorf("UpdateVersionState after close = %v, want ErrStoreClosed", err)
		}
	})

	t.Run("DeleteVersionClosed", func(t *testing.T) {
		store := createStore()
		_ = store.Close()

		ctx := context.Background()

		err := store.DeleteVersion(ctx, "test", 1)
		if err != ErrStoreClosed {
			t.Errorf("DeleteVersion after close = %v, want ErrStoreClosed", err)
		}
	})

	t.Run("DeleteKeyClosed", func(t *testing.T) {
		store := createStore()
		_ = store.Close()

		ctx := context.Background()

		err := store.DeleteKey(ctx, "test")
		if err != ErrStoreClosed {
			t.Errorf("DeleteKey after close = %v, want ErrStoreClosed", err)
		}
	})

	t.Run("UpdateVersionStateNotFound", func(t *testing.T) {
		store := createStore()
		defer func() { _ = store.Close() }()

		ctx := context.Background()
		keyID := "test-key"

		// Create a version
		info := &VersionInfo{
			Version:      1,
			BackendKeyID: "test-key-v1",
			Algorithm:    "Ed25519",
			State:        KeyStateEnabled,
		}
		if err := store.CreateVersion(ctx, keyID, info); err != nil {
			t.Fatalf("CreateVersion failed: %v", err)
		}

		// Try to update non-existent version
		err := store.UpdateVersionState(ctx, keyID, 99, KeyStateDisabled)
		if err != ErrVersionNotFound {
			t.Errorf("UpdateVersionState(99) = %v, want ErrVersionNotFound", err)
		}

		// Try to update for non-existent key
		err = store.UpdateVersionState(ctx, "nonexistent", 1, KeyStateDisabled)
		if err != ErrKeyNotFound {
			t.Errorf("UpdateVersionState(nonexistent) = %v, want ErrKeyNotFound", err)
		}
	})

	t.Run("ListVersionsNotFound", func(t *testing.T) {
		store := createStore()
		defer func() { _ = store.Close() }()

		ctx := context.Background()

		_, err := store.ListVersions(ctx, "nonexistent")
		if err != ErrKeyNotFound {
			t.Errorf("ListVersions = %v, want ErrKeyNotFound", err)
		}
	})

	t.Run("SetCurrentVersionNotFound", func(t *testing.T) {
		store := createStore()
		defer func() { _ = store.Close() }()

		ctx := context.Background()

		// Non-existent key
		err := store.SetCurrentVersion(ctx, "nonexistent", 1)
		if err != ErrKeyNotFound {
			t.Errorf("SetCurrentVersion(nonexistent) = %v, want ErrKeyNotFound", err)
		}
	})

	t.Run("DeleteVersionNotFound", func(t *testing.T) {
		store := createStore()
		defer func() { _ = store.Close() }()

		ctx := context.Background()

		// Non-existent key
		err := store.DeleteVersion(ctx, "nonexistent", 1)
		if err != ErrKeyNotFound {
			t.Errorf("DeleteVersion(nonexistent key) = %v, want ErrKeyNotFound", err)
		}
	})

	t.Run("GetKeyVersionsIsolation", func(t *testing.T) {
		store := createStore()
		defer func() { _ = store.Close() }()

		ctx := context.Background()
		keyID := "test-key"

		// Create a version with metadata
		info := &VersionInfo{
			Version:      1,
			BackendKeyID: "test-key-v1",
			Algorithm:    "Ed25519",
			State:        KeyStateEnabled,
			Metadata:     map[string]string{"key": "value"},
		}
		if err := store.CreateVersion(ctx, keyID, info); err != nil {
			t.Fatalf("CreateVersion failed: %v", err)
		}

		// Get key versions
		kv, err := store.GetKeyVersions(ctx, keyID)
		if err != nil {
			t.Fatalf("GetKeyVersions failed: %v", err)
		}

		// Modify returned data
		kv.CurrentVersion = 999
		kv.Versions[1].Metadata["key"] = "modified"

		// Get again - should be unchanged
		kv2, _ := store.GetKeyVersions(ctx, keyID)
		if kv2.CurrentVersion != 1 {
			t.Errorf("CurrentVersion was modified: got %d, want 1", kv2.CurrentVersion)
		}
		if kv2.Versions[1].Metadata["key"] != "value" {
			t.Errorf("Metadata was modified: got %q, want %q", kv2.Versions[1].Metadata["key"], "value")
		}
	})
}
