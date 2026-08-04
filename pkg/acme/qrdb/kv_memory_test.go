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
	"errors"
	"sync"
	"testing"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryKVClientPut(t *testing.T) {
	t.Run("stores and retrieves value", func(t *testing.T) {
		kv := NewMemoryKVClient()
		ctx := context.Background()

		err := kv.Put(ctx, "key1", []byte("value1"))
		require.NoError(t, err)

		got, err := kv.Get(ctx, "key1")
		require.NoError(t, err)
		assert.Equal(t, []byte("value1"), got)
	})

	t.Run("empty key returns error", func(t *testing.T) {
		kv := NewMemoryKVClient()
		ctx := context.Background()

		err := kv.Put(ctx, "", []byte("value"))
		require.Error(t, err)

		var knf *db.KeyNotFoundError
		assert.True(t, errors.As(err, &knf))
	})

	t.Run("canceled context returns error", func(t *testing.T) {
		kv := NewMemoryKVClient()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := kv.Put(ctx, "key", []byte("value"))
		require.Error(t, err)
		assert.True(t, errors.Is(err, context.Canceled))
	})

	t.Run("value is copied on store", func(t *testing.T) {
		kv := NewMemoryKVClient()
		ctx := context.Background()

		original := []byte("original")
		err := kv.Put(ctx, "key1", original)
		require.NoError(t, err)

		// Mutate the original slice.
		original[0] = 'X'

		got, err := kv.Get(ctx, "key1")
		require.NoError(t, err)
		assert.Equal(t, []byte("original"), got)
	})

	t.Run("increments revision", func(t *testing.T) {
		kv := NewMemoryKVClient()
		ctx := context.Background()

		rev0 := kv.Revision()
		require.NoError(t, kv.Put(ctx, "k1", []byte("v1")))
		rev1 := kv.Revision()
		assert.Greater(t, rev1, rev0)
	})
}

func TestMemoryKVClientGet(t *testing.T) {
	t.Run("returns key not found for missing key", func(t *testing.T) {
		kv := NewMemoryKVClient()
		ctx := context.Background()

		_, err := kv.Get(ctx, "nonexistent")
		require.Error(t, err)

		var knf *db.KeyNotFoundError
		assert.True(t, errors.As(err, &knf))
		assert.Equal(t, "nonexistent", knf.Key)
	})

	t.Run("canceled context returns error", func(t *testing.T) {
		kv := NewMemoryKVClient()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := kv.Get(ctx, "key")
		require.Error(t, err)
	})

	t.Run("returns copy of stored value", func(t *testing.T) {
		kv := NewMemoryKVClient()
		ctx := context.Background()

		require.NoError(t, kv.Put(ctx, "key1", []byte("value1")))

		got1, err := kv.Get(ctx, "key1")
		require.NoError(t, err)

		// Mutate the returned slice.
		got1[0] = 'X'

		got2, err := kv.Get(ctx, "key1")
		require.NoError(t, err)
		assert.Equal(t, []byte("value1"), got2)
	})
}

func TestMemoryKVClientDelete(t *testing.T) {
	t.Run("deletes existing key", func(t *testing.T) {
		kv := NewMemoryKVClient()
		ctx := context.Background()

		require.NoError(t, kv.Put(ctx, "key1", []byte("value1")))
		require.NoError(t, kv.Delete(ctx, "key1"))

		_, err := kv.Get(ctx, "key1")
		require.Error(t, err)

		var knf *db.KeyNotFoundError
		assert.True(t, errors.As(err, &knf))
	})

	t.Run("delete nonexistent key does not error", func(t *testing.T) {
		kv := NewMemoryKVClient()
		ctx := context.Background()

		err := kv.Delete(ctx, "nonexistent")
		assert.NoError(t, err)
	})

	t.Run("canceled context returns error", func(t *testing.T) {
		kv := NewMemoryKVClient()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := kv.Delete(ctx, "key")
		require.Error(t, err)
	})

	t.Run("increments revision", func(t *testing.T) {
		kv := NewMemoryKVClient()
		ctx := context.Background()

		require.NoError(t, kv.Put(ctx, "k", []byte("v")))
		rev := kv.Revision()
		require.NoError(t, kv.Delete(ctx, "k"))
		assert.Greater(t, kv.Revision(), rev)
	})
}

func TestMemoryKVClientList(t *testing.T) {
	t.Run("lists keys with prefix", func(t *testing.T) {
		kv := NewMemoryKVClient()
		ctx := context.Background()

		require.NoError(t, kv.Put(ctx, "app/a", []byte("1")))
		require.NoError(t, kv.Put(ctx, "app/b", []byte("2")))
		require.NoError(t, kv.Put(ctx, "other/c", []byte("3")))

		keys, err := kv.List(ctx, "app/")
		require.NoError(t, err)
		assert.Len(t, keys, 2)
		assert.Contains(t, keys, "app/a")
		assert.Contains(t, keys, "app/b")
	})

	t.Run("returns sorted keys", func(t *testing.T) {
		kv := NewMemoryKVClient()
		ctx := context.Background()

		require.NoError(t, kv.Put(ctx, "z", []byte("1")))
		require.NoError(t, kv.Put(ctx, "a", []byte("2")))
		require.NoError(t, kv.Put(ctx, "m", []byte("3")))

		keys, err := kv.List(ctx, "")
		require.NoError(t, err)
		assert.Equal(t, []string{"a", "m", "z"}, keys)
	})

	t.Run("empty prefix returns all keys", func(t *testing.T) {
		kv := NewMemoryKVClient()
		ctx := context.Background()

		require.NoError(t, kv.Put(ctx, "a", []byte("1")))
		require.NoError(t, kv.Put(ctx, "b", []byte("2")))

		keys, err := kv.List(ctx, "")
		require.NoError(t, err)
		assert.Len(t, keys, 2)
	})

	t.Run("no matching keys returns empty slice", func(t *testing.T) {
		kv := NewMemoryKVClient()
		ctx := context.Background()

		keys, err := kv.List(ctx, "nonexistent/")
		require.NoError(t, err)
		assert.Empty(t, keys)
	})

	t.Run("canceled context returns error", func(t *testing.T) {
		kv := NewMemoryKVClient()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := kv.List(ctx, "")
		require.Error(t, err)
	})
}

func TestMemoryKVClientScan(t *testing.T) {
	t.Run("scans keys with prefix", func(t *testing.T) {
		kv := NewMemoryKVClient()
		ctx := context.Background()

		require.NoError(t, kv.Put(ctx, "ns/a", []byte("1")))
		require.NoError(t, kv.Put(ctx, "ns/b", []byte("2")))
		require.NoError(t, kv.Put(ctx, "other/c", []byte("3")))

		result, err := kv.Scan(ctx, "ns/")
		require.NoError(t, err)
		assert.Len(t, result, 2)
		assert.Equal(t, []byte("1"), result["ns/a"])
		assert.Equal(t, []byte("2"), result["ns/b"])
	})

	t.Run("returns copies of values", func(t *testing.T) {
		kv := NewMemoryKVClient()
		ctx := context.Background()

		require.NoError(t, kv.Put(ctx, "key", []byte("value")))

		result, err := kv.Scan(ctx, "")
		require.NoError(t, err)

		// Mutate returned value.
		result["key"][0] = 'X'

		got, err := kv.Get(ctx, "key")
		require.NoError(t, err)
		assert.Equal(t, []byte("value"), got)
	})

	t.Run("canceled context returns error", func(t *testing.T) {
		kv := NewMemoryKVClient()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := kv.Scan(ctx, "")
		require.Error(t, err)
	})
}

func TestMemoryKVClientExists(t *testing.T) {
	t.Run("returns true for existing key", func(t *testing.T) {
		kv := NewMemoryKVClient()
		ctx := context.Background()

		require.NoError(t, kv.Put(ctx, "key1", []byte("value1")))

		exists, err := kv.Exists(ctx, "key1")
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("returns false for missing key", func(t *testing.T) {
		kv := NewMemoryKVClient()
		ctx := context.Background()

		exists, err := kv.Exists(ctx, "nonexistent")
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("canceled context returns error", func(t *testing.T) {
		kv := NewMemoryKVClient()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := kv.Exists(ctx, "key")
		require.Error(t, err)
	})
}

func TestMemoryKVClientConcurrentAccess(t *testing.T) {
	kv := NewMemoryKVClient()
	ctx := context.Background()
	const goroutines = 50

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Concurrent writers.
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			key := "key-" + string(rune('a'+idx%26))
			_ = kv.Put(ctx, key, []byte("val"))
		}(i)
	}

	// Concurrent readers.
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			key := "key-" + string(rune('a'+idx%26))
			_, _ = kv.Get(ctx, key)
		}(i)
	}

	wg.Wait()
}

func TestMemoryKVClientOverwrite(t *testing.T) {
	kv := NewMemoryKVClient()
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "key", []byte("v1")))
	require.NoError(t, kv.Put(ctx, "key", []byte("v2")))

	got, err := kv.Get(ctx, "key")
	require.NoError(t, err)
	assert.Equal(t, []byte("v2"), got)
}

// Compile-time interface compliance check.
var _ db.KVClient = (*MemoryKVClient)(nil)
