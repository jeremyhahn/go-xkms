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

package memory

import (
	"bytes"
	"fmt"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
)

// TestNew verifies that New() creates a valid storage backend.
func TestNew(t *testing.T) {
	store := New()
	if store == nil {
		t.Fatal("New() returned nil")
	}

	// Verify it implements Backend interface
	var _ storage.Backend = store

	// Should start empty
	keys, err := store.List("")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("New store should be empty, got %d keys", len(keys))
	}
}

// TestPutGet verifies basic Put and Get operations.
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
			name:    "key with slashes",
			key:     "keys/rsa/test-key",
			value:   []byte("value-with-path"),
			wantErr: false,
		},
		{
			name:    "cert prefix",
			key:     "certs/ca-cert",
			value:   []byte("cert-data"),
			wantErr: false,
		},
	}

	store := New()
	defer store.Close()

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

// TestPutOverwrite verifies that Put overwrites existing values.
func TestPutOverwrite(t *testing.T) {
	store := New()
	defer store.Close()

	key := "test-key"
	value1 := []byte("value1")
	value2 := []byte("value2")

	// Put initial value
	if err := store.Put(key, value1, nil); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Verify initial value
	got, err := store.Get(key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !bytes.Equal(got, value1) {
		t.Errorf("Get() = %v, want %v", got, value1)
	}

	// Overwrite with new value
	if err := store.Put(key, value2, nil); err != nil {
		t.Fatalf("Put() overwrite error = %v", err)
	}

	// Verify new value
	got, err = store.Get(key)
	if err != nil {
		t.Fatalf("Get() after overwrite error = %v", err)
	}
	if !bytes.Equal(got, value2) {
		t.Errorf("Get() after overwrite = %v, want %v", got, value2)
	}
}

// TestGetNotFound verifies that Get returns ErrNotFound for non-existent keys.
func TestGetNotFound(t *testing.T) {
	store := New()
	defer store.Close()

	_, err := store.Get("nonexistent")
	if err != storage.ErrNotFound {
		t.Errorf("Get() error = %v, want %v", err, storage.ErrNotFound)
	}
}

// TestDelete verifies Delete operations.
func TestDelete(t *testing.T) {
	store := New()
	defer store.Close()

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

// TestDeleteNotFound verifies that Delete returns ErrNotFound for non-existent keys.
func TestDeleteNotFound(t *testing.T) {
	store := New()
	defer store.Close()

	err := store.Delete("nonexistent")
	if err != storage.ErrNotFound {
		t.Errorf("Delete() error = %v, want %v", err, storage.ErrNotFound)
	}
}

// TestList verifies List operations with various prefixes.
func TestList(t *testing.T) {
	store := New()
	defer store.Close()

	// Put some test data with different prefixes
	testData := map[string][]byte{
		"keys/rsa/key1":      []byte("rsa-key-1"),
		"keys/rsa/key2":      []byte("rsa-key-2"),
		"keys/ecdsa/key1":    []byte("ecdsa-key-1"),
		"certs/ca":           []byte("ca-cert"),
		"certs/intermediate": []byte("intermediate-cert"),
		"certs/leaf":         []byte("leaf-cert"),
		"config/tls":         []byte("tls-config"),
		"root":               []byte("root-data"),
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
				"certs/ca",
				"certs/intermediate",
				"certs/leaf",
				"config/tls",
				"keys/ecdsa/key1",
				"keys/rsa/key1",
				"keys/rsa/key2",
				"root",
			},
		},
		{
			name:   "list keys prefix",
			prefix: "keys/",
			expected: []string{
				"keys/ecdsa/key1",
				"keys/rsa/key1",
				"keys/rsa/key2",
			},
		},
		{
			name:   "list rsa keys",
			prefix: "keys/rsa/",
			expected: []string{
				"keys/rsa/key1",
				"keys/rsa/key2",
			},
		},
		{
			name:   "list certs prefix",
			prefix: "certs/",
			expected: []string{
				"certs/ca",
				"certs/intermediate",
				"certs/leaf",
			},
		},
		{
			name:     "list nonexistent prefix",
			prefix:   "nonexistent/",
			expected: []string{},
		},
		{
			name:   "list config prefix",
			prefix: "config/",
			expected: []string{
				"config/tls",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, err := store.List(tt.prefix)
			if err != nil {
				t.Fatalf("List() error = %v", err)
			}

			if len(keys) != len(tt.expected) {
				t.Errorf("List() returned %d keys, want %d\nGot: %v\nWant: %v",
					len(keys), len(tt.expected), keys, tt.expected)
				return
			}

			// Keys should be in sorted order and match expected
			for i, key := range keys {
				if key != tt.expected[i] {
					t.Errorf("List()[%d] = %s, want %s", i, key, tt.expected[i])
				}
			}
		})
	}
}

// TestExists verifies Exists operations.
func TestExists(t *testing.T) {
	store := New()
	defer store.Close()

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

// TestDefensiveCopyPut verifies that Put makes defensive copies.
func TestDefensiveCopyPut(t *testing.T) {
	store := New()
	defer store.Close()

	key := "test-key"
	original := []byte("original-value")

	// Make a copy to pass to Put
	value := make([]byte, len(original))
	copy(value, original)

	// Put the value
	if err := store.Put(key, value, nil); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Modify the original slice
	value[0] = 'X'

	// Get the value back
	got, err := store.Get(key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	// Should still have the original value (defensive copy worked)
	if !bytes.Equal(got, original) {
		t.Errorf("Get() = %v, want %v (defensive copy failed)", got, original)
	}
}

// TestDefensiveCopyGet verifies that Get makes defensive copies.
func TestDefensiveCopyGet(t *testing.T) {
	store := New()
	defer store.Close()

	key := "test-key"
	original := []byte("original-value")

	// Put the value
	if err := store.Put(key, original, nil); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Get the value
	got1, err := store.Get(key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	// Modify the returned slice
	got1[0] = 'X'

	// Get the value again
	got2, err := store.Get(key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	// Should still have the original value (defensive copy worked)
	if !bytes.Equal(got2, original) {
		t.Errorf("Second Get() = %v, want %v (defensive copy failed)", got2, original)
	}
}

// TestConcurrentWrites verifies thread-safety for concurrent writes.
func TestConcurrentWrites(t *testing.T) {
	store := New()
	defer store.Close()

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
					return
				}

				got, err := store.Get(key)
				if err != nil {
					t.Errorf("Get() error = %v", err)
					return
				}

				if !bytes.Equal(got, value) {
					t.Errorf("Get() = %v, want %v", got, value)
					return
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

// TestConcurrentReadWrite verifies thread-safety for concurrent reads and writes.
func TestConcurrentReadWrite(t *testing.T) {
	store := New()
	defer store.Close()

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

// TestConcurrentOperations verifies thread-safety for all operations concurrently.
func TestConcurrentOperations(t *testing.T) {
	store := New()
	defer store.Close()

	// Pre-populate
	for i := 0; i < 50; i++ {
		key := fmt.Sprintf("key-%d", i)
		value := []byte(fmt.Sprintf("value-%d", i))
		if err := store.Put(key, value, nil); err != nil {
			t.Fatalf("Put() error = %v", err)
		}
	}

	var wg sync.WaitGroup
	numGoroutines := 10

	// Concurrent reads
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				key := fmt.Sprintf("key-%d", j)
				_, _ = store.Get(key)
				_, _ = store.Exists(key)
			}
		}(i)
	}

	// Concurrent writes
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				key := fmt.Sprintf("key-%d", j)
				value := []byte(fmt.Sprintf("value-%d-%d", id, j))
				_ = store.Put(key, value, nil)
			}
		}(i)
	}

	// Concurrent lists
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				_, _ = store.List("")
				_, _ = store.List("key-")
			}
		}()
	}

	// Concurrent deletes and puts
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			key := fmt.Sprintf("temp-key-%d", id)
			value := []byte(fmt.Sprintf("temp-value-%d", id))
			for j := 0; j < 10; j++ {
				_ = store.Put(key, value, nil)
				_ = store.Delete(key)
			}
		}(i)
	}

	wg.Wait()
}

// TestClose verifies Close operations.
func TestClose(t *testing.T) {
	store := New()

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

// TestClosedStorage verifies that all operations return ErrClosed after Close.
func TestClosedStorage(t *testing.T) {
	store := New()

	// Put some initial data
	if err := store.Put("key", []byte("value"), nil); err != nil {
		t.Fatalf("Put() before close error = %v", err)
	}

	// Close the storage
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// All operations should return ErrClosed
	t.Run("Get after close", func(t *testing.T) {
		_, err := store.Get("key")
		if err != storage.ErrClosed {
			t.Errorf("Get() after close error = %v, want %v", err, storage.ErrClosed)
		}
	})

	t.Run("Put after close", func(t *testing.T) {
		err := store.Put("key2", []byte("value2"), nil)
		if err != storage.ErrClosed {
			t.Errorf("Put() after close error = %v, want %v", err, storage.ErrClosed)
		}
	})

	t.Run("Delete after close", func(t *testing.T) {
		err := store.Delete("key")
		if err != storage.ErrClosed {
			t.Errorf("Delete() after close error = %v, want %v", err, storage.ErrClosed)
		}
	})

	t.Run("List after close", func(t *testing.T) {
		_, err := store.List("")
		if err != storage.ErrClosed {
			t.Errorf("List() after close error = %v, want %v", err, storage.ErrClosed)
		}
	})

	t.Run("Exists after close", func(t *testing.T) {
		_, err := store.Exists("key")
		if err != storage.ErrClosed {
			t.Errorf("Exists() after close error = %v, want %v", err, storage.ErrClosed)
		}
	})
}

// TestPutWithOptions verifies that Put accepts Options for interface compatibility.
func TestPutWithOptions(t *testing.T) {
	store := New()
	defer store.Close()

	opts := &storage.Options{
		Metadata: map[string]string{
			"version": "1",
			"author":  "test",
		},
		Permissions: 0600,
		Path:        "/test/path",
	}

	key := "test-key"
	value := []byte("test-value")

	// Put with options should succeed (even though metadata isn't persisted)
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

// TestEmptyKey verifies behavior with empty keys.
func TestEmptyKey(t *testing.T) {
	store := New()
	defer store.Close()

	// Empty key should be valid
	key := ""
	value := []byte("value")

	if err := store.Put(key, value, nil); err != nil {
		t.Fatalf("Put() with empty key error = %v", err)
	}

	got, err := store.Get(key)
	if err != nil {
		t.Fatalf("Get() with empty key error = %v", err)
	}

	if !bytes.Equal(got, value) {
		t.Errorf("Get() = %v, want %v", got, value)
	}

	exists, err := store.Exists(key)
	if err != nil {
		t.Fatalf("Exists() with empty key error = %v", err)
	}
	if !exists {
		t.Error("Empty key should exist after Put()")
	}

	if err := store.Delete(key); err != nil {
		t.Fatalf("Delete() with empty key error = %v", err)
	}
}

// TestNilValue verifies behavior with nil values.
func TestNilValue(t *testing.T) {
	store := New()
	defer store.Close()

	key := "nil-key"

	// Put nil value (should store empty slice)
	if err := store.Put(key, nil, nil); err != nil {
		t.Fatalf("Put() with nil value error = %v", err)
	}

	got, err := store.Get(key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	// Should get empty slice back
	if got == nil || len(got) != 0 {
		t.Errorf("Get() after Put(nil) = %v, want empty slice", got)
	}
}

// TestLargeValue verifies behavior with large values.
func TestLargeValue(t *testing.T) {
	store := New()
	defer store.Close()

	key := "large-key"
	// Create a 10MB value
	value := make([]byte, 10*1024*1024)
	for i := range value {
		value[i] = byte(i % 256)
	}

	if err := store.Put(key, value, nil); err != nil {
		t.Fatalf("Put() with large value error = %v", err)
	}

	got, err := store.Get(key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if !bytes.Equal(got, value) {
		t.Error("Get() returned different data than Put()")
	}
}
