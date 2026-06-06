// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package objstore

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewKVStoreAdapter verifies the adapter satisfies the KVStore interface.
func TestNewKVStoreAdapter(t *testing.T) {
	store := newMockStorage()
	adapter := NewKVStoreAdapter(store)
	assert.NotNil(t, adapter)

	var _ = adapter
}

// TestKVStoreAdapter_PutAndGet verifies basic put and get operations.
func TestKVStoreAdapter_PutAndGet(t *testing.T) {
	store := newMockStorage()
	adapter := NewKVStoreAdapter(store)
	ctx := context.Background()

	err := adapter.Put(ctx, "test/key1", []byte("value1"))
	require.NoError(t, err)

	got, err := adapter.Get(ctx, "test/key1")
	require.NoError(t, err)
	assert.Equal(t, []byte("value1"), got)
}

// TestKVStoreAdapter_Get_NotFound verifies that Get returns a not-found error for missing keys.
func TestKVStoreAdapter_Get_NotFound(t *testing.T) {
	store := newMockStorage()
	adapter := NewKVStoreAdapter(store)
	ctx := context.Background()

	got, err := adapter.Get(ctx, "nonexistent")
	require.Error(t, err, "Get on missing key should return error")
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "not found")
}

// TestKVStoreAdapter_Get_StorageError verifies that non-not-found errors are propagated.
func TestKVStoreAdapter_Get_StorageError(t *testing.T) {
	store := newMockStorage()
	store.SetGetError(errors.New("disk failure"))
	adapter := NewKVStoreAdapter(store)
	ctx := context.Background()

	_, err := adapter.Get(ctx, "test/key1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disk failure")
}

// TestKVStoreAdapter_Put_StorageError verifies that put errors are propagated.
func TestKVStoreAdapter_Put_StorageError(t *testing.T) {
	store := newMockStorage()
	store.SetPutError(errors.New("disk full"))
	adapter := NewKVStoreAdapter(store)
	ctx := context.Background()

	err := adapter.Put(ctx, "test/key1", []byte("value"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disk full")
}

// TestKVStoreAdapter_Delete verifies delete operation.
func TestKVStoreAdapter_Delete(t *testing.T) {
	store := newMockStorage()
	adapter := NewKVStoreAdapter(store)
	ctx := context.Background()

	err := adapter.Put(ctx, "test/key1", []byte("value1"))
	require.NoError(t, err)

	err = adapter.Delete(ctx, "test/key1")
	require.NoError(t, err)

	got, err := adapter.Get(ctx, "test/key1")
	require.Error(t, err, "Get after delete should return not-found error")
	assert.Nil(t, got)
}

// TestKVStoreAdapter_Delete_NotFound verifies that deleting a non-existent key is idempotent.
func TestKVStoreAdapter_Delete_NotFound(t *testing.T) {
	store := newMockStorage()
	adapter := NewKVStoreAdapter(store)
	ctx := context.Background()

	err := adapter.Delete(ctx, "nonexistent")
	require.NoError(t, err)
}

// TestKVStoreAdapter_Delete_StorageError verifies that non-not-found delete errors are propagated.
func TestKVStoreAdapter_Delete_StorageError(t *testing.T) {
	store := newMockStorage()
	store.SetDeleteError(errors.New("permission denied"))
	adapter := NewKVStoreAdapter(store)
	ctx := context.Background()

	err := adapter.Delete(ctx, "test/key1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
}

// TestKVStoreAdapter_List verifies listing keys by prefix.
func TestKVStoreAdapter_List(t *testing.T) {
	store := newMockStorage()
	adapter := NewKVStoreAdapter(store)
	ctx := context.Background()

	require.NoError(t, adapter.Put(ctx, "prefix/a", []byte("1")))
	require.NoError(t, adapter.Put(ctx, "prefix/b", []byte("2")))
	require.NoError(t, adapter.Put(ctx, "other/c", []byte("3")))

	keys, err := adapter.List(ctx, "prefix/")
	require.NoError(t, err)
	assert.Equal(t, 2, len(keys))
}

// TestKVStoreAdapter_List_StorageError verifies list error propagation.
func TestKVStoreAdapter_List_StorageError(t *testing.T) {
	store := newMockStorage()
	store.SetListError(errors.New("list failed"))
	adapter := NewKVStoreAdapter(store)
	ctx := context.Background()

	_, err := adapter.List(ctx, "prefix/")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list failed")
}

// TestKVStoreAdapter_Exists verifies existence check.
func TestKVStoreAdapter_Exists(t *testing.T) {
	store := newMockStorage()
	adapter := NewKVStoreAdapter(store)
	ctx := context.Background()

	require.NoError(t, adapter.Put(ctx, "test/key1", []byte("value")))

	exists, err := adapter.Exists(ctx, "test/key1")
	require.NoError(t, err)
	assert.True(t, exists)

	exists, err = adapter.Exists(ctx, "nonexistent")
	require.NoError(t, err)
	assert.False(t, exists)
}

// TestKVStoreAdapter_Exists_StorageError verifies exists error propagation.
func TestKVStoreAdapter_Exists_StorageError(t *testing.T) {
	store := newMockStorage()
	store.SetExistsError(errors.New("exists failed"))
	adapter := NewKVStoreAdapter(store)
	ctx := context.Background()

	_, err := adapter.Exists(ctx, "test/key1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exists failed")
}

// TestKVStoreAdapter_Scan verifies scanning keys by prefix.
func TestKVStoreAdapter_Scan(t *testing.T) {
	store := newMockStorage()
	adapter := NewKVStoreAdapter(store)
	ctx := context.Background()

	require.NoError(t, adapter.Put(ctx, "scan/a", []byte("1")))
	require.NoError(t, adapter.Put(ctx, "scan/b", []byte("2")))
	require.NoError(t, adapter.Put(ctx, "other/c", []byte("3")))

	var scanned []string
	err := adapter.Scan(ctx, "scan/", func(key string, value []byte) error {
		scanned = append(scanned, key)
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 2, len(scanned))
}

// TestKVStoreAdapter_Scan_CallbackError verifies that callback errors stop iteration.
func TestKVStoreAdapter_Scan_CallbackError(t *testing.T) {
	store := newMockStorage()
	adapter := NewKVStoreAdapter(store)
	ctx := context.Background()

	require.NoError(t, adapter.Put(ctx, "scan/a", []byte("1")))
	require.NoError(t, adapter.Put(ctx, "scan/b", []byte("2")))

	callbackErr := errors.New("stop iteration")
	count := 0
	err := adapter.Scan(ctx, "scan/", func(key string, value []byte) error {
		count++
		return callbackErr
	})
	require.ErrorIs(t, err, callbackErr)
	assert.Equal(t, 1, count)
}

// TestKVStoreAdapter_Scan_ListError verifies that list errors during scan are propagated.
func TestKVStoreAdapter_Scan_ListError(t *testing.T) {
	store := newMockStorage()
	store.SetListError(errors.New("list failed"))
	adapter := NewKVStoreAdapter(store)
	ctx := context.Background()

	err := adapter.Scan(ctx, "scan/", func(key string, value []byte) error {
		return nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list failed")
}

// TestKVStoreAdapter_RegisterEntityIndexes verifies the no-op index registration.
func TestKVStoreAdapter_RegisterEntityIndexes(t *testing.T) {
	store := newMockStorage()
	adapter := NewKVStoreAdapter(store)

	err := adapter.RegisterEntityIndexes("test", []qrdbsdk.EntityIndex{
		{FieldName: "Name", JSONFieldName: "name"},
	})
	require.NoError(t, err)
}

// TestKVStoreAdapter_QueryIndex verifies that index queries return an error.
func TestKVStoreAdapter_QueryIndex(t *testing.T) {
	store := newMockStorage()
	adapter := NewKVStoreAdapter(store)
	ctx := context.Background()

	_, err := adapter.QueryIndex(ctx, "test.Name", []byte("value"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrIndexNotSupported)
}

// TestKVStoreAdapter_ScanIndex verifies that index scans return an error.
func TestKVStoreAdapter_ScanIndex(t *testing.T) {
	store := newMockStorage()
	adapter := NewKVStoreAdapter(store)
	ctx := context.Background()

	_, err := adapter.ScanIndex(ctx, "test.Name", []byte("a"), []byte("z"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrIndexNotSupported)
}

// TestKVStoreAdapter_PutOverwrite verifies that put overwrites existing values.
func TestKVStoreAdapter_PutOverwrite(t *testing.T) {
	store := newMockStorage()
	adapter := NewKVStoreAdapter(store)
	ctx := context.Background()

	require.NoError(t, adapter.Put(ctx, "test/key1", []byte("original")))
	require.NoError(t, adapter.Put(ctx, "test/key1", []byte("updated")))

	got, err := adapter.Get(ctx, "test/key1")
	require.NoError(t, err)
	assert.Equal(t, []byte("updated"), got)
}

// TestKVStoreAdapter_Scan_GetError verifies that get errors during scan are propagated.
func TestKVStoreAdapter_Scan_GetError(t *testing.T) {
	store := newMockStorage()
	adapter := NewKVStoreAdapter(store)
	ctx := context.Background()

	require.NoError(t, adapter.Put(ctx, "scan/a", []byte("1")))

	// Inject a get error after the list succeeds.
	store.SetGetError(errors.New("get failed"))

	err := adapter.Scan(ctx, "scan/", func(key string, value []byte) error {
		return nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get failed")
}

// TestErrIndexNotSupported verifies the error value.
func TestErrIndexNotSupported(t *testing.T) {
	assert.NotNil(t, ErrIndexNotSupported)
	assert.Contains(t, ErrIndexNotSupported.Error(), "index queries not supported")
}
