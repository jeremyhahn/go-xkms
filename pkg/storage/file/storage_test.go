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
	"io/fs"
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

// TestStoredRecordsAreOwnerOnly verifies nothing the store writes is readable
// by group or other, whatever the key's prefix: private key material, PINs and
// sealed blobs share one store with certificates, so no prefix may widen it.
func TestStoredRecordsAreOwnerOnly(t *testing.T) {
	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	for _, key := range []string{"keys/mykey", "certs/mycert.pem", "other/data", "deeply/nested/path/to/key"} {
		if err := store.Put(ctx, key, []byte("data")); err != nil {
			t.Fatalf("Put(%q) error = %v", key, err)
		}
	}

	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s has mode %o; want no group or other access", path, perm)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir() error = %v", err)
	}
}

// TestKeyAndChildKeyCoexist documents that the store's namespace is flat: a
// key and a key nested beneath it are independent records, so writing one
// neither fails on nor disturbs the other.
func TestKeyAndChildKeyCoexist(t *testing.T) {
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
	if err := store.Put(ctx, "barrier/root_key/meta", []byte("meta")); err != nil {
		t.Fatalf("Put(child) error = %v", err)
	}
	for key, want := range map[string]string{"barrier/root_key": "blob", "barrier/root_key/meta": "meta"} {
		if got, err := store.Get(ctx, key); err != nil || string(got) != want {
			t.Errorf("Get(%q) = %q, %v; want %q, nil", key, got, err, want)
		}
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

func TestErrorConditions(t *testing.T) {
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
}
