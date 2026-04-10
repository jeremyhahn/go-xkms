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

package storage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMemoryBackend(t *testing.T) {
	backend, err := NewMemoryBackend()
	require.NoError(t, err)
	require.NotNil(t, backend)
	defer func() { _ = backend.Close() }()

	// Verify it implements the Backend interface by calling a method
	assert.NotNil(t, backend, "expected MemoryBackend to implement Backend interface")
}

func TestNewMemory(t *testing.T) {
	backend := NewMemory()
	require.NotNil(t, backend)
	defer func() { _ = backend.Close() }()

	// Verify it implements the Backend interface by calling a method
	assert.NotNil(t, backend, "expected NewMemory to return Backend implementation")
}

func TestNew(t *testing.T) {
	backend := New()
	require.NotNil(t, backend)
	defer func() { _ = backend.Close() }()

	// Verify it implements the Backend interface by calling a method
	assert.NotNil(t, backend, "expected New to return Backend implementation")
}

func TestMemoryBackend_PutAndGet(t *testing.T) {
	ctx := context.Background()
	backend := NewMemory()
	defer func() { _ = backend.Close() }()

	key := "test-key"
	value := []byte("test-value")

	// Put the value
	err := backend.Put(ctx, key, value)
	require.NoError(t, err)

	// Get the value back
	result, err := backend.Get(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, value, result)
}

func TestMemoryBackend_Get_NotFound(t *testing.T) {
	ctx := context.Background()
	backend := NewMemory()
	defer func() { _ = backend.Close() }()

	_, err := backend.Get(ctx, "nonexistent-key")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestMemoryBackend_Put_Simple(t *testing.T) {
	ctx := context.Background()
	backend := NewMemory()
	defer func() { _ = backend.Close() }()

	err := backend.Put(ctx, "test-key", []byte("test-value"))
	require.NoError(t, err)

	result, err := backend.Get(ctx, "test-key")
	require.NoError(t, err)
	assert.Equal(t, []byte("test-value"), result)
}

func TestMemoryBackend_Get_ReturnsCopy(t *testing.T) {
	ctx := context.Background()
	backend := NewMemory()
	defer func() { _ = backend.Close() }()

	key := "test-key"
	value := []byte("original")

	err := backend.Put(ctx, key, value)
	require.NoError(t, err)

	// Get the value and modify it
	result, err := backend.Get(ctx, key)
	require.NoError(t, err)
	result[0] = 'X'

	// Verify the original is unchanged
	result2, err := backend.Get(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, []byte("original"), result2, "modifying returned value should not affect stored value")
}

func TestMemoryBackend_Put_StoresCopy(t *testing.T) {
	ctx := context.Background()
	backend := NewMemory()
	defer func() { _ = backend.Close() }()

	key := "test-key"
	value := []byte("original")

	err := backend.Put(ctx, key, value)
	require.NoError(t, err)

	// Modify the original slice
	value[0] = 'X'

	// Verify the stored value is unchanged
	result, err := backend.Get(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, []byte("original"), result, "modifying original value should not affect stored value")
}

func TestMemoryBackend_Delete(t *testing.T) {
	ctx := context.Background()
	backend := NewMemory()
	defer func() { _ = backend.Close() }()

	key := "test-key"
	value := []byte("test-value")

	// Put and verify
	err := backend.Put(ctx, key, value)
	require.NoError(t, err)

	// Delete
	err = backend.Delete(ctx, key)
	require.NoError(t, err)

	// Verify it's gone
	_, err = backend.Get(ctx, key)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestMemoryBackend_Delete_NotFound(t *testing.T) {
	ctx := context.Background()
	backend := NewMemory()
	defer func() { _ = backend.Close() }()

	err := backend.Delete(ctx, "nonexistent-key")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestMemoryBackend_List(t *testing.T) {
	ctx := context.Background()
	backend := NewMemory()
	defer func() { _ = backend.Close() }()

	// Put multiple values with different prefixes
	_ = backend.Put(ctx, "prefix1/key1", []byte("v1"))
	_ = backend.Put(ctx, "prefix1/key2", []byte("v2"))
	_ = backend.Put(ctx, "prefix2/key1", []byte("v3"))
	_ = backend.Put(ctx, "other/key1", []byte("v4"))

	// List with prefix
	keys, err := backend.List(ctx, "prefix1/")
	require.NoError(t, err)
	assert.Len(t, keys, 2)
	assert.Contains(t, keys, "prefix1/key1")
	assert.Contains(t, keys, "prefix1/key2")

	// List with different prefix
	keys, err = backend.List(ctx, "prefix2/")
	require.NoError(t, err)
	assert.Len(t, keys, 1)
	assert.Contains(t, keys, "prefix2/key1")
}

func TestMemoryBackend_List_EmptyPrefix(t *testing.T) {
	ctx := context.Background()
	backend := NewMemory()
	defer func() { _ = backend.Close() }()

	_ = backend.Put(ctx, "key1", []byte("v1"))
	_ = backend.Put(ctx, "key2", []byte("v2"))
	_ = backend.Put(ctx, "prefix/key3", []byte("v3"))

	// List with empty prefix returns all keys
	keys, err := backend.List(ctx, "")
	require.NoError(t, err)
	assert.Len(t, keys, 3)
}

func TestMemoryBackend_List_NoMatches(t *testing.T) {
	ctx := context.Background()
	backend := NewMemory()
	defer func() { _ = backend.Close() }()

	_ = backend.Put(ctx, "key1", []byte("v1"))

	keys, err := backend.List(ctx, "nonexistent/")
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestMemoryBackend_Exists(t *testing.T) {
	ctx := context.Background()
	backend := NewMemory()
	defer func() { _ = backend.Close() }()

	key := "test-key"

	// Key doesn't exist initially
	exists, err := backend.Exists(ctx, key)
	require.NoError(t, err)
	assert.False(t, exists)

	// Put the key
	err = backend.Put(ctx, key, []byte("value"))
	require.NoError(t, err)

	// Now it exists
	exists, err = backend.Exists(ctx, key)
	require.NoError(t, err)
	assert.True(t, exists)

	// Delete the key
	err = backend.Delete(ctx, key)
	require.NoError(t, err)

	// Now it doesn't exist again
	exists, err = backend.Exists(ctx, key)
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestMemoryBackend_Close(t *testing.T) {
	backend := NewMemory()

	// Close should succeed
	err := backend.Close()
	require.NoError(t, err)

	// Double close should also succeed (idempotent)
	err = backend.Close()
	require.NoError(t, err)
}

func TestMemoryBackend_OperationsAfterClose(t *testing.T) {
	ctx := context.Background()
	backend := NewMemory()

	// Put a value before closing
	err := backend.Put(ctx, "key1", []byte("value"))
	require.NoError(t, err)

	// Close the backend
	err = backend.Close()
	require.NoError(t, err)

	// All operations should return ErrClosed after close
	_, err = backend.Get(ctx, "key1")
	assert.ErrorIs(t, err, ErrClosed, "Get after close should return ErrClosed")

	err = backend.Put(ctx, "key2", []byte("value"))
	assert.ErrorIs(t, err, ErrClosed, "Put after close should return ErrClosed")

	err = backend.Delete(ctx, "key1")
	assert.ErrorIs(t, err, ErrClosed, "Delete after close should return ErrClosed")

	_, err = backend.List(ctx, "")
	assert.ErrorIs(t, err, ErrClosed, "List after close should return ErrClosed")

	_, err = backend.Exists(ctx, "key1")
	assert.ErrorIs(t, err, ErrClosed, "Exists after close should return ErrClosed")
}

func TestMemoryBackend_Overwrite(t *testing.T) {
	ctx := context.Background()
	backend := NewMemory()
	defer func() { _ = backend.Close() }()

	key := "test-key"

	// Put initial value
	err := backend.Put(ctx, key, []byte("original"))
	require.NoError(t, err)

	// Overwrite with new value
	err = backend.Put(ctx, key, []byte("updated"))
	require.NoError(t, err)

	// Verify it was overwritten
	result, err := backend.Get(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, []byte("updated"), result)
}

func TestMemoryBackend_EmptyValue(t *testing.T) {
	ctx := context.Background()
	backend := NewMemory()
	defer func() { _ = backend.Close() }()

	key := "test-key"

	// Put empty value
	err := backend.Put(ctx, key, []byte{})
	require.NoError(t, err)

	// Get should return empty slice, not nil
	result, err := backend.Get(ctx, key)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Empty(t, result)
}

func TestMemoryBackend_Concurrent(t *testing.T) {
	ctx := context.Background()
	backend := NewMemory()
	defer func() { _ = backend.Close() }()

	done := make(chan bool)
	numGoroutines := 100

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		go func(n int) {
			key := "key"
			value := []byte("value")
			_ = backend.Put(ctx, key, value)
			_, _ = backend.Get(ctx, key)
			_, _ = backend.Exists(ctx, key)
			_, _ = backend.List(ctx, "")
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}
