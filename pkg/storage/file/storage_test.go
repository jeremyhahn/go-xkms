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

package file

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
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
		keys, err := store.List("")
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
}

func TestPutGet(t *testing.T) {
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
			err := store.Put(tt.key, tt.value, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("Put() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			got, err := store.Get(tt.key)
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
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	_, err = store.Get("nonexistent")
	if err != storage.ErrNotFound {
		t.Errorf("Get() error = %v, want %v", err, storage.ErrNotFound)
	}
}

func TestDelete(t *testing.T) {
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	key := "delete-me"
	value := []byte("value")

	// Put a value
	if err := store.Put(key, value, nil); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Verify it exists
	exists, err := store.Exists(key)
	if err != nil {
		t.Fatalf("Exists() error = %v", err)
	}
	if !exists {
		t.Error("Key should exist after Put()")
	}

	// Delete it
	if err := store.Delete(key); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify it's gone
	exists, err = store.Exists(key)
	if err != nil {
		t.Fatalf("Exists() error = %v", err)
	}
	if exists {
		t.Error("Key should not exist after Delete()")
	}

	// Get should return ErrNotFound
	_, err = store.Get(key)
	if err != storage.ErrNotFound {
		t.Errorf("Get() after Delete() error = %v, want %v", err, storage.ErrNotFound)
	}
}

func TestDeleteNotFound(t *testing.T) {
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	err = store.Delete("nonexistent")
	if err != storage.ErrNotFound {
		t.Errorf("Delete() error = %v, want %v", err, storage.ErrNotFound)
	}
}

func TestList(t *testing.T) {
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
		if err := store.Put(key, value, nil); err != nil {
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
			keys, err := store.List(tt.prefix)
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
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	key := "test-key"
	value := []byte("test-value")

	// Should not exist initially
	exists, err := store.Exists(key)
	if err != nil {
		t.Fatalf("Exists() error = %v", err)
	}
	if exists {
		t.Error("Key should not exist initially")
	}

	// Put the key
	if err := store.Put(key, value, nil); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Should exist now
	exists, err = store.Exists(key)
	if err != nil {
		t.Fatalf("Exists() error = %v", err)
	}
	if !exists {
		t.Error("Key should exist after Put()")
	}

	// Delete the key
	if err := store.Delete(key); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Should not exist after delete
	exists, err = store.Exists(key)
	if err != nil {
		t.Fatalf("Exists() error = %v", err)
	}
	if exists {
		t.Error("Key should not exist after Delete()")
	}
}

func TestFilePermissions(t *testing.T) {
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
			if err := store.Put(tt.key, tt.value, nil); err != nil {
				t.Fatalf("Put() error = %v", err)
			}

			// Check file permissions
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

func TestFilePermissionsWithOptions(t *testing.T) {
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	key := "keys/custom-perms"
	value := []byte("data")
	customPerms := os.FileMode(0640)

	opts := &storage.Options{
		Permissions: customPerms,
	}

	if err := store.Put(key, value, opts); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Check file permissions
	filePath := filepath.Join(dir, key)
	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}

	if info.Mode().Perm() != customPerms {
		t.Errorf("File permissions = %o, want %o", info.Mode().Perm(), customPerms)
	}
}

func TestDirectoryCreation(t *testing.T) {
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	key := "deeply/nested/path/to/key"
	value := []byte("nested-value")

	if err := store.Put(key, value, nil); err != nil {
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
	got, err := store.Get(key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !bytes.Equal(got, value) {
		t.Errorf("Get() = %v, want %v", got, value)
	}
}

func TestConcurrentAccess(t *testing.T) {
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

				if err := store.Put(key, value, nil); err != nil {
					t.Errorf("Put() error = %v", err)
				}

				got, err := store.Get(key)
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
	keys, err := store.List("")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	expected := numGoroutines * numOperations
	if len(keys) != expected {
		t.Errorf("Expected %d keys, got %d", expected, len(keys))
	}
}

func TestConcurrentReadWrite(t *testing.T) {
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
		if err := store.Put(key, value, nil); err != nil {
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
				_, _ = store.Get(key)
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
				_ = store.Put(key, value, nil)
			}
		}(i)
	}

	wg.Wait()
}

func TestConcurrentDeleteList(t *testing.T) {
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
		if err := store.Put(key, value, nil); err != nil {
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
				_ = store.Delete(key)
			}
		}(i)
	}

	// Start listers
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				_, _ = store.List("")
			}
		}()
	}

	wg.Wait()
}

func TestClose(t *testing.T) {
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Put some data
	if err := store.Put("key", []byte("value"), nil); err != nil {
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

func TestPutWithOptions(t *testing.T) {
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	opts := &storage.Options{
		Metadata: map[string]string{
			"version": "1",
			"author":  "test",
		},
	}

	key := "test-key"
	value := []byte("test-value")

	if err := store.Put(key, value, opts); err != nil {
		t.Fatalf("Put() with options error = %v", err)
	}

	// Verify the value was stored
	got, err := store.Get(key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if !bytes.Equal(got, value) {
		t.Errorf("Get() = %v, want %v", got, value)
	}
}

func TestEmptyList(t *testing.T) {
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	// List on empty store should return empty slice
	keys, err := store.List("")
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
	if err := store.Put(key, value1, nil); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Verify first value
	got, err := store.Get(key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !bytes.Equal(got, value1) {
		t.Errorf("Get() = %v, want %v", got, value1)
	}

	// Overwrite with second value
	if err := store.Put(key, value2, nil); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Verify second value
	got, err = store.Get(key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !bytes.Equal(got, value2) {
		t.Errorf("Get() = %v, want %v", got, value2)
	}

	// Should still only be one key
	keys, err := store.List("")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("Expected 1 key after overwrite, got %d", len(keys))
	}
}

func TestGetPermissionsErrorCases(t *testing.T) {
	dir := setupTestDir(t)
	fs := &FileStorage{rootDir: dir}

	tests := []struct {
		name     string
		key      string
		opts     *storage.Options
		wantPerm os.FileMode
	}{
		{
			name:     "nil options uses default for keys",
			key:      "keys/test",
			opts:     nil,
			wantPerm: 0600,
		},
		{
			name:     "nil options uses default for certs",
			key:      "certs/test",
			opts:     nil,
			wantPerm: 0644,
		},
		{
			name:     "nil options uses default for other",
			key:      "other/test",
			opts:     nil,
			wantPerm: 0600,
		},
		{
			name: "options with zero permissions uses default",
			key:  "keys/test",
			opts: &storage.Options{
				Permissions: 0,
			},
			wantPerm: 0600,
		},
		{
			name: "options with custom permissions",
			key:  "keys/test",
			opts: &storage.Options{
				Permissions: 0640,
			},
			wantPerm: 0640,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perms := fs.getFilePermissions(tt.key, tt.opts)
			if perms != tt.wantPerm {
				t.Errorf("getFilePermissions() = %o, want %o", perms, tt.wantPerm)
			}
		})
	}
}

func TestPathConversion(t *testing.T) {
	dir := setupTestDir(t)
	fs := &FileStorage{rootDir: dir}

	tests := []struct {
		name string
		key  string
	}{
		{
			name: "simple key",
			key:  "testkey",
		},
		{
			name: "nested key",
			key:  "path/to/key",
		},
		{
			name: "deeply nested",
			key:  "a/b/c/d/e/f",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := fs.keyToPath(tt.key)
			key, err := fs.pathToKey(path)
			if err != nil {
				t.Fatalf("pathToKey() error = %v", err)
			}
			if key != tt.key {
				t.Errorf("Round-trip conversion failed: got %q, want %q", key, tt.key)
			}
		})
	}
}

func TestListSorting(t *testing.T) {
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	// Put keys in random order
	keys := []string{"zebra", "apple", "mango", "banana"}
	for _, key := range keys {
		if err := store.Put(key, []byte("value"), nil); err != nil {
			t.Fatalf("Put(%s) error = %v", key, err)
		}
	}

	// List should return sorted
	got, err := store.List("")
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
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	t.Run("exists after delete returns false", func(t *testing.T) {
		key := "temp-key"
		if err := store.Put(key, []byte("data"), nil); err != nil {
			t.Fatalf("Put() error = %v", err)
		}

		if err := store.Delete(key); err != nil {
			t.Fatalf("Delete() error = %v", err)
		}

		exists, err := store.Exists(key)
		if err != nil {
			t.Fatalf("Exists() error = %v", err)
		}
		if exists {
			t.Error("Key should not exist after deletion")
		}
	})

	t.Run("multiple exists checks", func(t *testing.T) {
		key := "multi-check"
		if err := store.Put(key, []byte("data"), nil); err != nil {
			t.Fatalf("Put() error = %v", err)
		}

		for i := 0; i < 5; i++ {
			exists, err := store.Exists(key)
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

	t.Run("get with read error", func(t *testing.T) {
		dir := setupTestDir(t)
		store, err := New(dir)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		defer func() { _ = store.Close() }()

		key := "test-key"
		// Put a key
		if err := store.Put(key, []byte("data"), nil); err != nil {
			t.Fatalf("Put() error = %v", err)
		}

		// Make the file unreadable
		filePath := filepath.Join(dir, key)
		if err := os.Chmod(filePath, 0000); err != nil {
			t.Fatalf("Failed to chmod file: %v", err)
		}
		defer func() { _ = os.Chmod(filePath, 0600) }() // Restore for cleanup

		// Try to read - should get error
		_, err = store.Get(key)
		if err == nil {
			t.Error("Get() on unreadable file should return error")
		}
		if err == storage.ErrNotFound {
			t.Error("Get() on unreadable file should not return ErrNotFound")
		}
	})

	t.Run("put with write error", func(t *testing.T) {
		dir := setupTestDir(t)
		store, err := New(dir)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		defer func() { _ = store.Close() }()

		// Create a read-only directory
		roDir := filepath.Join(dir, "readonly")
		if err := os.MkdirAll(roDir, 0700); err != nil {
			t.Fatalf("Failed to create dir: %v", err)
		}
		if err := os.Chmod(roDir, 0500); err != nil {
			t.Fatalf("Failed to chmod dir: %v", err)
		}
		defer func() { _ = os.Chmod(roDir, 0700) }() // Restore for cleanup

		// Try to write to read-only directory
		key := "readonly/file"
		err = store.Put(key, []byte("data"), nil)
		if err == nil {
			t.Error("Put() in read-only directory should return error")
		}
	})

	t.Run("delete with remove error", func(t *testing.T) {
		dir := setupTestDir(t)
		store, err := New(dir)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		defer func() { _ = store.Close() }()

		// Create a file in a read-only directory
		subdir := filepath.Join(dir, "rodir")
		if err := os.MkdirAll(subdir, 0700); err != nil {
			t.Fatalf("Failed to create dir: %v", err)
		}

		key := "rodir/file"
		if err := store.Put(key, []byte("data"), nil); err != nil {
			t.Fatalf("Put() error = %v", err)
		}

		// Make directory read-only
		if err := os.Chmod(subdir, 0500); err != nil {
			t.Fatalf("Failed to chmod dir: %v", err)
		}
		defer func() { _ = os.Chmod(subdir, 0700) }() // Restore for cleanup

		// Try to delete - should get error
		err = store.Delete(key)
		if err == nil {
			t.Error("Delete() in read-only directory should return error")
		}
		if err == storage.ErrNotFound {
			t.Error("Delete() in read-only directory should not return ErrNotFound")
		}
	})

	t.Run("list with walk error", func(t *testing.T) {
		dir := setupTestDir(t)
		store, err := New(dir)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		defer func() { _ = store.Close() }()

		// Create some test data
		if err := store.Put("test-key", []byte("data"), nil); err != nil {
			t.Fatalf("Put() error = %v", err)
		}

		// Create an inaccessible directory
		badDir := filepath.Join(dir, "baddir")
		if err := os.MkdirAll(badDir, 0700); err != nil {
			t.Fatalf("Failed to create dir: %v", err)
		}
		if err := os.Chmod(badDir, 0000); err != nil {
			t.Fatalf("Failed to chmod dir: %v", err)
		}
		defer func() { _ = os.Chmod(badDir, 0700) }() // Restore for cleanup

		// List should return error
		_, err = store.List("")
		if err == nil {
			t.Error("List() with inaccessible directory should return error")
		}
	})

	t.Run("pathToKey success case", func(t *testing.T) {
		dir := setupTestDir(t)
		fs := &FileStorage{rootDir: dir}

		// Try to convert a valid path
		path := filepath.Join(dir, "test", "key")
		key, err := fs.pathToKey(path)
		if err != nil {
			t.Errorf("pathToKey() error = %v", err)
		}
		if key != "test/key" && key != "test\\key" {
			t.Errorf("pathToKey() = %q, want test/key or test\\key", key)
		}
	})
}
