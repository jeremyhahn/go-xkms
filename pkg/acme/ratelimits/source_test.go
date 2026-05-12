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

package ratelimits

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMemorySourceGet(t *testing.T) {
	t.Run("returns bucket not found for non-existent key", func(t *testing.T) {
		source := NewInMemorySource()

		_, err := source.Get(context.Background(), "nonexistent")

		assert.ErrorIs(t, err, errors.ErrBucketNotFound)
	})

	t.Run("returns stored value", func(t *testing.T) {
		source := NewInMemorySource()
		now := time.Now()
		source.BatchSet(context.Background(), map[string]time.Time{"key1": now})

		got, err := source.Get(context.Background(), "key1")

		require.NoError(t, err)
		assert.Equal(t, now, got)
	})

	t.Run("returns bucket not found for expired entry", func(t *testing.T) {
		source := NewInMemorySource()
		now := time.Now()

		// Set with TTL in the past
		source.buckets.Store("key1", bucketEntry{
			tat: now,
			ttl: now.Add(-time.Hour),
		})

		_, err := source.Get(context.Background(), "key1")

		assert.ErrorIs(t, err, errors.ErrBucketNotFound)
	})
}

func TestInMemorySourceBatchGet(t *testing.T) {
	t.Run("returns empty map for empty keys", func(t *testing.T) {
		source := NewInMemorySource()

		got, err := source.BatchGet(context.Background(), nil)

		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("returns only existing keys", func(t *testing.T) {
		source := NewInMemorySource()
		now := time.Now()
		source.BatchSet(context.Background(), map[string]time.Time{
			"key1": now,
			"key2": now.Add(time.Hour),
		})

		got, err := source.BatchGet(context.Background(), []string{"key1", "key3"})

		require.NoError(t, err)
		assert.Len(t, got, 1)
		assert.Equal(t, now, got["key1"])
	})

	t.Run("filters expired entries", func(t *testing.T) {
		source := NewInMemorySource()
		now := time.Now()

		source.buckets.Store("key1", bucketEntry{tat: now, ttl: now.Add(time.Hour)})
		source.buckets.Store("key2", bucketEntry{tat: now, ttl: now.Add(-time.Hour)})

		got, err := source.BatchGet(context.Background(), []string{"key1", "key2"})

		require.NoError(t, err)
		assert.Len(t, got, 1)
		assert.Contains(t, got, "key1")
	})
}

func TestInMemorySourceBatchSet(t *testing.T) {
	t.Run("sets multiple keys", func(t *testing.T) {
		source := NewInMemorySource()
		now := time.Now()
		buckets := map[string]time.Time{
			"key1": now,
			"key2": now.Add(time.Hour),
		}

		err := source.BatchSet(context.Background(), buckets)

		require.NoError(t, err)
		assert.Equal(t, int64(2), source.Count())

		got1, _ := source.Get(context.Background(), "key1")
		got2, _ := source.Get(context.Background(), "key2")
		assert.Equal(t, now, got1)
		assert.Equal(t, now.Add(time.Hour), got2)
	})

	t.Run("overwrites existing keys", func(t *testing.T) {
		source := NewInMemorySource()
		now := time.Now()

		source.BatchSet(context.Background(), map[string]time.Time{"key1": now})
		source.BatchSet(context.Background(), map[string]time.Time{"key1": now.Add(time.Hour)})

		got, _ := source.Get(context.Background(), "key1")
		assert.Equal(t, now.Add(time.Hour), got)
		assert.Equal(t, int64(1), source.Count())
	})
}

func TestInMemorySourceBatchSetNotExisting(t *testing.T) {
	t.Run("sets only non-existent keys", func(t *testing.T) {
		source := NewInMemorySource()
		now := time.Now()

		source.BatchSet(context.Background(), map[string]time.Time{"key1": now})

		exists, err := source.BatchSetNotExisting(context.Background(), map[string]time.Time{
			"key1": now.Add(time.Hour),
			"key2": now.Add(time.Hour * 2),
		})

		require.NoError(t, err)
		assert.True(t, exists["key1"])
		assert.False(t, exists["key2"])

		// key1 should still have original value
		got1, _ := source.Get(context.Background(), "key1")
		assert.Equal(t, now, got1)

		// key2 should have new value
		got2, _ := source.Get(context.Background(), "key2")
		assert.Equal(t, now.Add(time.Hour*2), got2)
	})

	t.Run("tracks count correctly", func(t *testing.T) {
		source := NewInMemorySource()
		now := time.Now()

		source.BatchSetNotExisting(context.Background(), map[string]time.Time{"key1": now})
		assert.Equal(t, int64(1), source.Count())

		source.BatchSetNotExisting(context.Background(), map[string]time.Time{
			"key1": now,
			"key2": now,
		})
		assert.Equal(t, int64(2), source.Count())
	})
}

func TestInMemorySourceBatchIncrement(t *testing.T) {
	t.Run("increments existing buckets", func(t *testing.T) {
		source := NewInMemorySource()
		now := time.Now()

		source.BatchSet(context.Background(), map[string]time.Time{"key1": now})

		err := source.BatchIncrement(context.Background(), map[string]increment{
			"key1": {cost: time.Hour, ttl: time.Hour},
		})

		require.NoError(t, err)
		got, _ := source.Get(context.Background(), "key1")
		assert.Equal(t, now.Add(time.Hour), got)
	})

	t.Run("skips non-existent buckets", func(t *testing.T) {
		source := NewInMemorySource()

		err := source.BatchIncrement(context.Background(), map[string]increment{
			"nonexistent": {cost: time.Hour, ttl: time.Hour},
		})

		require.NoError(t, err)
		assert.Equal(t, int64(0), source.Count())
	})

	t.Run("handles negative increment (refund)", func(t *testing.T) {
		source := NewInMemorySource()
		now := time.Now()

		source.BatchSet(context.Background(), map[string]time.Time{"key1": now.Add(time.Hour)})

		err := source.BatchIncrement(context.Background(), map[string]increment{
			"key1": {cost: -30 * time.Minute, ttl: time.Hour},
		})

		require.NoError(t, err)
		got, _ := source.Get(context.Background(), "key1")
		assert.Equal(t, now.Add(30*time.Minute), got)
	})
}

func TestInMemorySourceBatchDelete(t *testing.T) {
	t.Run("deletes existing keys", func(t *testing.T) {
		source := NewInMemorySource()
		now := time.Now()

		source.BatchSet(context.Background(), map[string]time.Time{
			"key1": now,
			"key2": now,
			"key3": now,
		})

		err := source.BatchDelete(context.Background(), []string{"key1", "key2"})

		require.NoError(t, err)
		assert.Equal(t, int64(1), source.Count())

		_, err = source.Get(context.Background(), "key1")
		assert.ErrorIs(t, err, errors.ErrBucketNotFound)

		_, err = source.Get(context.Background(), "key3")
		require.NoError(t, err)
	})

	t.Run("ignores non-existent keys", func(t *testing.T) {
		source := NewInMemorySource()

		err := source.BatchDelete(context.Background(), []string{"nonexistent"})

		require.NoError(t, err)
	})
}

func TestInMemorySourceCleanup(t *testing.T) {
	t.Run("removes expired entries", func(t *testing.T) {
		source := NewInMemorySource()
		now := time.Now()

		source.buckets.Store("fresh", bucketEntry{tat: now, ttl: now.Add(time.Hour)})
		source.buckets.Store("expired", bucketEntry{tat: now, ttl: now.Add(-time.Hour)})
		source.count.Store(2)

		removed := source.Cleanup()

		assert.Equal(t, 1, removed)
		assert.Equal(t, int64(1), source.Count())

		_, err := source.Get(context.Background(), "fresh")
		require.NoError(t, err)

		_, err = source.Get(context.Background(), "expired")
		assert.ErrorIs(t, err, errors.ErrBucketNotFound)
	})

	t.Run("handles entries without TTL", func(t *testing.T) {
		source := NewInMemorySource()
		now := time.Now()

		source.buckets.Store("noTTL", bucketEntry{tat: now})
		source.count.Store(1)

		removed := source.Cleanup()

		assert.Equal(t, 0, removed)
		assert.Equal(t, int64(1), source.Count())
	})
}

func TestInMemorySourceConcurrency(t *testing.T) {
	t.Run("handles concurrent operations", func(t *testing.T) {
		source := NewInMemorySource()
		now := time.Now()
		ctx := context.Background()

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				key := string(rune('a' + i%26))
				source.BatchSet(ctx, map[string]time.Time{key: now.Add(time.Duration(i) * time.Minute)})
				source.Get(ctx, key)
				source.BatchIncrement(ctx, map[string]increment{key: {cost: time.Second}})
			}(i)
		}
		wg.Wait()

		// No panic means test passed
	})

	t.Run("BatchIncrement handles concurrent updates", func(t *testing.T) {
		source := NewInMemorySource()
		now := time.Now()
		ctx := context.Background()

		source.BatchSet(ctx, map[string]time.Time{"key": now})

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				source.BatchIncrement(ctx, map[string]increment{
					"key": {cost: time.Millisecond, ttl: time.Hour},
				})
			}()
		}
		wg.Wait()

		got, err := source.Get(ctx, "key")
		require.NoError(t, err)
		assert.True(t, got.After(now))
	})
}

func TestInMemorySourceCleanupRoutine(t *testing.T) {
	t.Run("runs cleanup periodically", func(t *testing.T) {
		source := NewInMemorySource()
		now := time.Now()

		source.buckets.Store("expired", bucketEntry{tat: now, ttl: now.Add(-time.Hour)})
		source.count.Store(1)

		cancel := source.StartCleanupRoutine(10 * time.Millisecond)
		defer cancel()

		// Wait for cleanup to run
		time.Sleep(50 * time.Millisecond)

		_, err := source.Get(context.Background(), "expired")
		assert.ErrorIs(t, err, errors.ErrBucketNotFound)
	})

	t.Run("stops on cancel", func(t *testing.T) {
		source := NewInMemorySource()
		cancel := source.StartCleanupRoutine(10 * time.Millisecond)
		cancel()
		// No deadlock means test passed
	})
}
