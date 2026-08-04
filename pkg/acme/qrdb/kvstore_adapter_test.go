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

package qrdb

import (
	"context"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKVStoreAdapterPut(t *testing.T) {
	t.Run("stores value through adapter", func(t *testing.T) {
		adapter := newTestAdapter()
		ctx := context.Background()

		err := adapter.Put(ctx, "key1", []byte("value1"))
		require.NoError(t, err)

		got, err := adapter.Get(ctx, "key1")
		require.NoError(t, err)
		assert.Equal(t, []byte("value1"), got)
	})

	t.Run("canceled context returns error", func(t *testing.T) {
		adapter := newTestAdapter()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := adapter.Put(ctx, "key1", []byte("value1"))
		require.Error(t, err)
	})
}

func TestKVStoreAdapterGet(t *testing.T) {
	t.Run("returns database error with ErrNotFound for missing key", func(t *testing.T) {
		adapter := newTestAdapter()
		ctx := context.Background()

		got, err := adapter.Get(ctx, "nonexistent")
		require.Error(t, err)
		assert.Nil(t, got)

		var de *qrdbsdk.DatabaseError
		require.ErrorAs(t, err, &de)
		assert.Equal(t, qrdbsdk.ErrNotFound, de.Code)
	})

	t.Run("retrieves existing value", func(t *testing.T) {
		adapter := newTestAdapter()
		ctx := context.Background()

		require.NoError(t, adapter.Put(ctx, "key1", []byte("value1")))

		got, err := adapter.Get(ctx, "key1")
		require.NoError(t, err)
		assert.Equal(t, []byte("value1"), got)
	})

	t.Run("canceled context returns error", func(t *testing.T) {
		adapter := newTestAdapter()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := adapter.Get(ctx, "key1")
		require.Error(t, err)
	})
}

func TestKVStoreAdapterDelete(t *testing.T) {
	t.Run("deletes existing key", func(t *testing.T) {
		adapter := newTestAdapter()
		ctx := context.Background()

		require.NoError(t, adapter.Put(ctx, "key1", []byte("value1")))
		require.NoError(t, adapter.Delete(ctx, "key1"))

		got, err := adapter.Get(ctx, "key1")
		require.Error(t, err) // database ErrNotFound
		assert.Nil(t, got)
	})

	t.Run("delete nonexistent key does not error", func(t *testing.T) {
		adapter := newTestAdapter()
		ctx := context.Background()

		err := adapter.Delete(ctx, "nonexistent")
		assert.NoError(t, err)
	})
}

func TestKVStoreAdapterScan(t *testing.T) {
	t.Run("iterates matching keys", func(t *testing.T) {
		adapter := newTestAdapter()
		ctx := context.Background()

		require.NoError(t, adapter.Put(ctx, "ns/a", []byte("1")))
		require.NoError(t, adapter.Put(ctx, "ns/b", []byte("2")))
		require.NoError(t, adapter.Put(ctx, "other/c", []byte("3")))

		var keys []string
		err := adapter.Scan(ctx, "ns/", func(key string, value []byte) error {
			keys = append(keys, key)
			return nil
		})
		require.NoError(t, err)
		assert.Len(t, keys, 2)
	})

	t.Run("callback error stops iteration", func(t *testing.T) {
		adapter := newTestAdapter()
		ctx := context.Background()

		require.NoError(t, adapter.Put(ctx, "a", []byte("1")))
		require.NoError(t, adapter.Put(ctx, "b", []byte("2")))

		callbackErr := NewError(ErrorCodeInternal, "stop")
		err := adapter.Scan(ctx, "", func(key string, value []byte) error {
			return callbackErr
		})
		require.Error(t, err)
	})

	t.Run("canceled context returns error", func(t *testing.T) {
		adapter := newTestAdapter()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := adapter.Scan(ctx, "", func(key string, value []byte) error {
			return nil
		})
		require.Error(t, err)
	})
}

func TestKVStoreAdapterList(t *testing.T) {
	t.Run("lists keys with prefix", func(t *testing.T) {
		adapter := newTestAdapter()
		ctx := context.Background()

		require.NoError(t, adapter.Put(ctx, "app/x", []byte("1")))
		require.NoError(t, adapter.Put(ctx, "app/y", []byte("2")))
		require.NoError(t, adapter.Put(ctx, "other/z", []byte("3")))

		keys, err := adapter.List(ctx, "app/")
		require.NoError(t, err)
		assert.Len(t, keys, 2)
	})

	t.Run("returns empty for no match", func(t *testing.T) {
		adapter := newTestAdapter()
		ctx := context.Background()

		keys, err := adapter.List(ctx, "nonexistent/")
		require.NoError(t, err)
		assert.Empty(t, keys)
	})
}

func TestKVStoreAdapterExists(t *testing.T) {
	t.Run("returns true for existing key", func(t *testing.T) {
		adapter := newTestAdapter()
		ctx := context.Background()

		require.NoError(t, adapter.Put(ctx, "key1", []byte("val")))

		exists, err := adapter.Exists(ctx, "key1")
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("returns false for missing key", func(t *testing.T) {
		adapter := newTestAdapter()
		ctx := context.Background()

		exists, err := adapter.Exists(ctx, "nonexistent")
		require.NoError(t, err)
		assert.False(t, exists)
	})
}

// newTestAdapter creates a KVStoreAdapter backed by a MemoryKVClient.
func newTestAdapter() qrdbsdk.KVStore {
	return NewKVStoreAdapter(NewMemoryKVClient())
}

// Compile-time interface compliance check.
var _ qrdbsdk.KVStore = (*kvStoreAdapter)(nil)
