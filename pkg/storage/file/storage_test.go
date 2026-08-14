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

package file

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// Helper to create a temporary directory for tests
func setupTestDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "filestorage-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}

func TestNew(t *testing.T) {
	ctx := context.Background()
	t.Run("valid directory", func(t *testing.T) {
		dir := setupTestDir(t)

		store, err := New(dir)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if store == nil {
			t.Fatal("New() returned nil")
		}

		// Verify it implements Backend interface
		_ = store

		// Should start empty
		keys, err := store.List(ctx, "")
		if err != nil {
			t.Fatalf("List() error = %v", err)
		}
		if len(keys) != 0 {
			t.Errorf("New store should be empty, got %d keys", len(keys))
		}
	})

	t.Run("creates directory if not exists", func(t *testing.T) {
		dir := setupTestDir(t)
		newDir := filepath.Join(dir, "subdir", "nested")

		store, err := New(newDir)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if store == nil {
			t.Fatal("New() returned nil")
		}

		// Verify directory was created
		info, err := os.Stat(newDir)
		if err != nil {
			t.Fatalf("Directory not created: %v", err)
		}
		if !info.IsDir() {
			t.Error("Path is not a directory")
		}

		// Verify permissions
		if info.Mode().Perm() != 0700 {
			t.Errorf("Directory permissions = %o, want 0700", info.Mode().Perm())
		}
	})

	t.Run("empty directory error", func(t *testing.T) {
		_, err := New("")
		if err == nil {
			t.Error("New() with empty directory should return error")
		}
	})

	t.Run("relative path conversion", func(t *testing.T) {
		// Test that relative paths get converted to absolute paths
		relDir := "test-relative-dir"
		defer func() { _ = os.RemoveAll(relDir) }()

		store, err := New(relDir)
		if err != nil {
			t.Fatalf("New() with relative path error = %v", err)
		}
		if store == nil {
			t.Fatal("New() returned nil")
		}

		// Verify the directory exists
		absPath, err := filepath.Abs(relDir)
		if err != nil {
			t.Fatalf("Failed to get absolute path: %v", err)
		}
		info, err := os.Stat(absPath)
		if err != nil {
			t.Fatalf("Directory not created: %v", err)
		}
		if !info.IsDir() {
			t.Error("Path is not a directory")
		}
	})
}

func TestPutGet(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		key     string
		value   []byte
		wantErr bool
	}{
		{
			name:    "simple key-value",
			key:     "test-key",
			value:   []byte("test-value"),
			wantErr: false,
		},
		{
			name:    "empty value",
			key:     "empty",
			value:   []byte{},
			wantErr: false,
		},
		{
			name:    "binary data",
			key:     "binary",
			value:   []byte{0x00, 0x01, 0x02, 0xFF},
			wantErr: false,
		},
		{
			name:    "nested key",
			key:     "keys/nested/deep/key",
			value:   []byte("nested-value"),
			wantErr: false,
		},
		{
			name:    "overwrite existing",
			key:     "test-key",
			value:   []byte("new-value"),
			wantErr: false,
		},
	}

	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.Put(ctx, tt.key, tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("Put() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			got, err := store.Get(ctx, tt.key)
			if err != nil {
				t.Fatalf("Get() error = %v", err)
			}

			if !bytes.Equal(got, tt.value) {
				t.Errorf("Get() = %v, want %v", got, tt.value)
			}
		})
	}
}

func TestGetNotFound(t *testing.T) {
	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	_, err = store.Get(ctx, "nonexistent")
	if err != storage.ErrNotFound {
		t.Errorf("Get() error = %v, want %v", err, storage.ErrNotFound)
	}
}

func TestDelete(t *testing.T) {
	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	key := "delete-me"
	value := []byte("value")

	// Put a value
	if err := store.Put(ctx, key, value); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Verify it exists
	exists, err := store.Exists(ctx, key)
	if err != nil {
		t.Fatalf("Exists() error = %v", err)
	}
	if !exists {
		t.Error("Key should exist after Put()")
	}

	// Delete it
	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify it's gone
	exists, err = store.Exists(ctx, key)
	if err != nil {
		t.Fatalf("Exists() error = %v", err)
	}
	if exists {
		t.Error("Key should not exist after Delete()")
	}

	// Get should return ErrNotFound
	_, err = store.Get(ctx, key)
	if err != storage.ErrNotFound {
		t.Errorf("Get() after Delete() error = %v, want %v", err, storage.ErrNotFound)
	}
}

func TestDeleteNotFound(t *testing.T) {
	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	err = store.Delete(ctx, "nonexistent")
	if err != storage.ErrNotFound {
		t.Errorf("Delete() error = %v, want %v", err, storage.ErrNotFound)
	}
}

func TestList(t *testing.T) {
	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	// Put some test data
	testData := map[string][]byte{
		"users/alice":   []byte("alice-data"),
		"users/bob":     []byte("bob-data"),
		"users/charlie": []byte("charlie-data"),
		"config/app":    []byte("app-config"),
		"config/db":     []byte("db-config"),
		"root":          []byte("root-data"),
	}

	for key, value := range testData {
		if err := store.Put(ctx, key, value); err != nil {
			t.Fatalf("Put(%s) error = %v", key, err)
		}
	}

	tests := []struct {
		name     string
		prefix   string
		expected []string
	}{
		{
			name:   "list all",
			prefix: "",
			expected: []string{
				"config/app",
				"config/db",
				"root",
				"users/alice",
				"users/bob",
				"users/charlie",
			},
		},
		{
			name:   "list users prefix",
			prefix: "users/",
			expected: []string{
				"users/alice",
				"users/bob",
				"users/charlie",
			},
		},
		{
			name:   "list config prefix",
			prefix: "config/",
			expected: []string{
				"config/app",
				"config/db",
			},
		},
		{
			name:     "list nonexistent prefix",
			prefix:   "nonexistent/",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, err := store.List(ctx, tt.prefix)
			if err != nil {
				t.Fatalf("List() error = %v", err)
			}

			if len(keys) != len(tt.expected) {
				t.Errorf("List() returned %d keys, want %d", len(keys), len(tt.expected))
			}

			// Check all expected keys are present
			keyMap := make(map[string]bool)
			for _, key := range keys {
				keyMap[key] = true
			}

			for _, expected := range tt.expected {
				if !keyMap[expected] {
					t.Errorf("List() missing expected key: %s", expected)
				}
			}
		})
	}
}

func TestExists(t *testing.T) {
	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	key := "test-key"
	value := []byte("test-value")

	// Should not exist initially
	exists, err := store.Exists(ctx, key)
	if err != nil {
		t.Fatalf("Exists() error = %v", err)
	}
	if exists {
		t.Error("Key should not exist initially")
	}

	// Put the key
	if err := store.Put(ctx, key, value); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Should exist now
	exists, err = store.Exists(ctx, key)
	if err != nil {
		t.Fatalf("Exists() error = %v", err)
	}
	if !exists {
		t.Error("Key should exist after Put()")
	}

	// Delete the key
	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Should not exist after delete
	exists, err = store.Exists(ctx, key)
	if err != nil {
		t.Fatalf("Exists() error = %v", err)
	}
	if exists {
		t.Error("Key should not exist after Delete()")
	}
}

func TestFilePermissions(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name     string
		key      string
		value    []byte
		wantPerm os.FileMode
	}{
		{
			name:     "keys prefix",
			key:      "keys/mykey",
			value:    []byte("key-data"),
			wantPerm: 0600,
		},
		{
			name:     "certs prefix",
			key:      "certs/mycert.pem",
			value:    []byte("cert-data"),
			wantPerm: 0644,
		},
		{
			name:     "default permissions",
			key:      "other/data",
			value:    []byte("other-data"),
			wantPerm: 0600,
		},
	}

	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := store.Put(ctx, tt.key, tt.value); err != nil {
				t.Fatalf("Put() error = %v", err)
			}

			// Check file permissions (stored at <root>/<key>)
			filePath := filepath.Join(dir, tt.key)
			info, err := os.Stat(filePath)
			if err != nil {
				t.Fatalf("Stat() error = %v", err)
			}

			if info.Mode().Perm() != tt.wantPerm {
				t.Errorf("File permissions = %o, want %o", info.Mode().Perm(), tt.wantPerm)
			}
		})
	}
}

func TestFilePermissionsKeyPrefixBased(t *testing.T) {
	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	// keys/ prefix should get 0600 permissions
	key := "keys/perm-test"
	value := []byte("data")

	if err := store.Put(ctx, key, value); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	filePath := filepath.Join(dir, key)
	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}

	if info.Mode().Perm() != 0600 {
		t.Errorf("File permissions for keys/ = %o, want 0600", info.Mode().Perm())
	}
}

// TestPrefixCollisionRejected documents the flat-namespace contract of the file
// backend: a key and a sub-key under it cannot coexist on a filesystem (the same
// path cannot be both a file holding a value and a directory holding sub-keys).
// Writing a child of an existing key returns an error rather than corrupting
// state, and the parent is left intact. Callers must use namespace discipline —
// e.g. the qrdb barrier stores its metadata as a SIBLING key ("root_key.meta"),
// never a child ("root_key/meta") — see go-qrdb/pkg/seal/barrier.go.
func TestPrefixCollisionRejected(t *testing.T) {
	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.Put(ctx, "barrier/root_key", []byte("blob")); err != nil {
		t.Fatalf("Put(parent) error = %v", err)
	}
	// A child of an existing key cannot be stored on a flat-file backend.
	if err := store.Put(ctx, "barrier/root_key/meta", []byte("meta")); err == nil {
		t.Errorf("Put(child of existing key) should return an error on a flat-file backend")
	}
	// The parent remains intact and readable.
	if got, err := store.Get(ctx, "barrier/root_key"); err != nil || string(got) != "blob" {
		t.Fatalf("Get(parent) = %q, %v; want \"blob\", nil", got, err)
	}
}

func TestDirectoryCreation(t *testing.T) {
	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	key := "deeply/nested/path/to/key"
	value := []byte("nested-value")

	if err := store.Put(ctx, key, value); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Verify all directories were created
	dirPath := filepath.Join(dir, "deeply/nested/path/to")
	info, err := os.Stat(dirPath)
	if err != nil {
		t.Fatalf("Directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("Path is not a directory")
	}

	// Verify directory permissions
	if info.Mode().Perm() != 0700 {
		t.Errorf("Directory permissions = %o, want 0700", info.Mode().Perm())
	}

	// Verify the file was created
	got, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !bytes.Equal(got, value) {
		t.Errorf("Get() = %v, want %v", got, value)
	}
}

func TestConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	numGoroutines := 100
	numOperations := 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Test concurrent writes
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := fmt.Sprintf("key-%d-%d", id, j)
				value := []byte(fmt.Sprintf("value-%d-%d", id, j))

				if err := store.Put(ctx, key, value); err != nil {
					t.Errorf("Put() error = %v", err)
				}

				got, err := store.Get(ctx, key)
				if err != nil {
					t.Errorf("Get() error = %v", err)
				}

				if !bytes.Equal(got, value) {
					t.Errorf("Get() = %v, want %v", got, value)
				}
			}
		}(i)
	}

	wg.Wait()

	// Verify total count
	keys, err := store.List(ctx, "")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	expected := numGoroutines * numOperations
	if len(keys) != expected {
		t.Errorf("Expected %d keys, got %d", expected, len(keys))
	}
}

func TestConcurrentReadWrite(t *testing.T) {
	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	// Pre-populate with some data
	for i := 0; i < 100; i++ {
		key := fmt.Sprintf("key-%d", i)
		value := []byte(fmt.Sprintf("value-%d", i))
		if err := store.Put(ctx, key, value); err != nil {
			t.Fatalf("Put() error = %v", err)
		}
	}

	var wg sync.WaitGroup

	// Start readers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				key := fmt.Sprintf("key-%d", j)
				_, _ = store.Get(ctx, key)
			}
		}()
	}

	// Start writers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				key := fmt.Sprintf("key-%d", j)
				value := []byte(fmt.Sprintf("value-%d-%d", id, j))
				_ = store.Put(ctx, key, value)
			}
		}(i)
	}

	wg.Wait()
}

func TestConcurrentDeleteList(t *testing.T) {
	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	// Pre-populate with some data
	for i := 0; i < 100; i++ {
		key := fmt.Sprintf("key-%d", i)
		value := []byte(fmt.Sprintf("value-%d", i))
		if err := store.Put(ctx, key, value); err != nil {
			t.Fatalf("Put() error = %v", err)
		}
	}

	var wg sync.WaitGroup

	// Start deleters
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := id; j < 100; j += 25 {
				key := fmt.Sprintf("key-%d", j)
				_ = store.Delete(ctx, key)
			}
		}(i)
	}

	// Start listers
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				_, _ = store.List(ctx, "")
			}
		}()
	}

	wg.Wait()
}

func TestClose(t *testing.T) {
	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Put some data
	if err := store.Put(ctx, "key", []byte("value")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Close should succeed
	if err := store.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Should be able to close multiple times
	if err := store.Close(); err != nil {
		t.Errorf("Second Close() error = %v", err)
	}
}

func TestPutAndRetrieve(t *testing.T) {
	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	key := "test-key"
	value := []byte("test-value")

	if err := store.Put(ctx, key, value); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Verify the value was stored
	got, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if !bytes.Equal(got, value) {
		t.Errorf("Get() = %v, want %v", got, value)
	}
}

func TestEmptyList(t *testing.T) {
	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	// List on empty store should return empty slice
	keys, err := store.List(ctx, "")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if keys == nil {
		t.Error("List() should not return nil")
	}

	if len(keys) != 0 {
		t.Errorf("List() on empty store returned %d keys, want 0", len(keys))
	}
}

func TestOverwriteKey(t *testing.T) {
	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	key := "overwrite-test"
	value1 := []byte("first-value")
	value2 := []byte("second-value")

	// Put first value
	if err := store.Put(ctx, key, value1); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Verify first value
	got, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !bytes.Equal(got, value1) {
		t.Errorf("Get() = %v, want %v", got, value1)
	}

	// Overwrite with second value
	if err := store.Put(ctx, key, value2); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Verify second value
	got, err = store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !bytes.Equal(got, value2) {
		t.Errorf("Get() = %v, want %v", got, value2)
	}

	// Should still only be one key
	keys, err := store.List(ctx, "")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("Expected 1 key after overwrite, got %d", len(keys))
	}
}

func TestFilePermissionsForKey(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		wantPerm os.FileMode
	}{
		{
			name:     "keys prefix uses 0600",
			key:      "keys/test",
			wantPerm: 0600,
		},
		{
			name:     "certs prefix uses 0644",
			key:      "certs/test",
			wantPerm: 0644,
		},
		{
			name:     "other prefix uses default 0600",
			key:      "other/test",
			wantPerm: 0600,
		},
		{
			name:     "no prefix uses default 0600",
			key:      "test",
			wantPerm: 0600,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perms := filePermissionsForKey(tt.key)
			if perms != tt.wantPerm {
				t.Errorf("filePermissionsForKey() = %o, want %o", perms, tt.wantPerm)
			}
		})
	}
}

// TestPathConversionRoundTrip verifies key↔on-disk-path symmetry through the
// public API: a key written under the file backend is listed back verbatim
// (the engine owns the <root>/<key> mapping; this guards the round-trip).
func TestPathConversionRoundTrip(t *testing.T) {
	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer store.Close()

	for _, key := range []string{"testkey", "path/to/key", "a/b/c/d/e/f"} {
		if err := store.Put(ctx, key, []byte("v")); err != nil {
			t.Fatalf("Put(%q) error = %v", key, err)
		}
		keys, err := store.List(ctx, key)
		if err != nil {
			t.Fatalf("List(%q) error = %v", key, err)
		}
		found := false
		for _, k := range keys {
			if k == key {
				found = true
			}
		}
		if !found {
			t.Errorf("key %q did not round-trip through List: got %v", key, keys)
		}
	}
}

func TestListSorting(t *testing.T) {
	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	// Put keys in random order
	keys := []string{"zebra", "apple", "mango", "banana"}
	for _, key := range keys {
		if err := store.Put(ctx, key, []byte("value")); err != nil {
			t.Fatalf("Put(%s) error = %v", key, err)
		}
	}

	// List should return sorted
	got, err := store.List(ctx, "")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	expected := []string{"apple", "banana", "mango", "zebra"}
	if len(got) != len(expected) {
		t.Fatalf("List() returned %d keys, want %d", len(got), len(expected))
	}

	for i, key := range got {
		if key != expected[i] {
			t.Errorf("List()[%d] = %q, want %q", i, key, expected[i])
		}
	}
}

func TestExistsEdgeCases(t *testing.T) {
	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	t.Run("exists after delete returns false", func(t *testing.T) {
		key := "temp-key"
		if err := store.Put(ctx, key, []byte("data")); err != nil {
			t.Fatalf("Put() error = %v", err)
		}

		if err := store.Delete(ctx, key); err != nil {
			t.Fatalf("Delete() error = %v", err)
		}

		exists, err := store.Exists(ctx, key)
		if err != nil {
			t.Fatalf("Exists() error = %v", err)
		}
		if exists {
			t.Error("Key should not exist after deletion")
		}
	})

	t.Run("multiple exists checks", func(t *testing.T) {
		key := "multi-check"
		if err := store.Put(ctx, key, []byte("data")); err != nil {
			t.Fatalf("Put() error = %v", err)
		}

		for i := 0; i < 5; i++ {
			exists, err := store.Exists(ctx, key)
			if err != nil {
				t.Fatalf("Exists() iteration %d error = %v", i, err)
			}
			if !exists {
				t.Errorf("Key should exist on iteration %d", i)
			}
		}
	})
}

func TestErrorConditions(t *testing.T) {
	ctx := context.Background()
	t.Run("new with invalid path causes error during mkdir", func(t *testing.T) {
		// Create a file where we want to create a directory
		tempFile, err := os.CreateTemp("", "filestorage-test-")
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		tempPath := tempFile.Name()
		_ = tempFile.Close()
		defer func() { _ = os.Remove(tempPath) }()

		// Try to create storage with nested path under the file
		invalidPath := filepath.Join(tempPath, "subdir")
		_, err = New(invalidPath)
		if err == nil {
			t.Error("New() with invalid path should return error")
		}
	})

	// The error paths below are driven with POSIX conditions the kernel
	// enforces for every user — EISDIR, ENOTDIR, ENOTEMPTY, ENOENT — rather
	// than with chmod. Permission bits are bypassed by root, so a chmod-based
	// setup silently stops testing anything the moment the suite runs in a
	// container as uid 0, which is exactly where CI runs it.

	t.Run("get with read error", func(t *testing.T) {
		dir := setupTestDir(t)
		store, err := New(dir)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		defer func() { _ = store.Close() }()

		// A directory at the key's path makes the read fail with EISDIR.
		key := "test-key"
		if err := os.MkdirAll(filepath.Join(dir, key), 0700); err != nil {
			t.Fatalf("Failed to create dir: %v", err)
		}

		_, err = store.Get(ctx, key)
		if err == nil {
			t.Error("Get() on a directory should return error")
		}
		if err == storage.ErrNotFound {
			t.Error("Get() on a directory should not return ErrNotFound")
		}
	})

	t.Run("put with write error", func(t *testing.T) {
		dir := setupTestDir(t)
		store, err := New(dir)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		defer func() { _ = store.Close() }()

		// A regular file where a parent directory is expected makes the write
		// fail with ENOTDIR.
		if err := os.WriteFile(filepath.Join(dir, "notadir"), []byte("blocker"), 0600); err != nil {
			t.Fatalf("Failed to write blocker file: %v", err)
		}

		if err := store.Put(ctx, "notadir/file", []byte("data")); err == nil {
			t.Error("Put() beneath a regular file should return error")
		}
	})

	t.Run("delete with stat error", func(t *testing.T) {
		dir := setupTestDir(t)
		store, err := New(dir)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		defer func() { _ = store.Close() }()

		if err := os.WriteFile(filepath.Join(dir, "notadir"), []byte("blocker"), 0600); err != nil {
			t.Fatalf("Failed to write blocker file: %v", err)
		}

		err = store.Delete(ctx, "notadir/file")
		if err == nil {
			t.Error("Delete() with stat error should return error")
		}
		if err == storage.ErrNotFound {
			t.Error("Delete() with stat error should not return ErrNotFound")
		}
	})

	t.Run("delete with remove error", func(t *testing.T) {
		dir := setupTestDir(t)
		store, err := New(dir)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		defer func() { _ = store.Close() }()

		// A non-empty directory at the key's path makes the unlink fail with
		// ENOTEMPTY.
		key := "occupied"
		if err := os.MkdirAll(filepath.Join(dir, key, "child"), 0700); err != nil {
			t.Fatalf("Failed to create dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, key, "child", "f"), []byte("x"), 0600); err != nil {
			t.Fatalf("Failed to write nested file: %v", err)
		}

		err = store.Delete(ctx, key)
		if err == nil {
			t.Error("Delete() of a non-empty directory should return error")
		}
		if err == storage.ErrNotFound {
			t.Error("Delete() of a non-empty directory should not return ErrNotFound")
		}
	})

	t.Run("exists with stat error", func(t *testing.T) {
		dir := setupTestDir(t)
		store, err := New(dir)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		defer func() { _ = store.Close() }()

		if err := os.WriteFile(filepath.Join(dir, "notadir"), []byte("blocker"), 0600); err != nil {
			t.Fatalf("Failed to write blocker file: %v", err)
		}

		exists, err := store.Exists(ctx, "notadir/file")
		if err == nil {
			t.Error("Exists() with stat error should return error")
		}
		if exists {
			t.Error("Exists() must not report a key behind a stat error as present")
		}
	})
}

func TestValidateStorageKeyEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{
			name:    "path with middle traversal suffix",
			key:     "foo/bar/..",
			wantErr: false, // cleaned to "foo" which is valid
		},
		{
			name:    "path ending with separator and dotdot",
			key:     "foo/..",
			wantErr: false, // cleaned to "." which is allowed after cleaning
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateStorageKey(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateStorageKey(%q) error = %v, wantErr %v", tt.key, err, tt.wantErr)
			}
		})
	}
}
