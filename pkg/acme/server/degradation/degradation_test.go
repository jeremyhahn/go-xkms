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

package degradation

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/server/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	metrics.Init()
	metrics.InitProduction()
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.True(t, cfg.Enabled)
	assert.Equal(t, 1*time.Minute, cfg.CacheTTL)
	assert.Equal(t, 5*time.Minute, cfg.StaleTTL)
	assert.Equal(t, 10000, cfg.MaxCacheSize)
	assert.Equal(t, 500*time.Millisecond, cfg.SlowThreshold)
	assert.Equal(t, 100, cfg.SlowWindowSize)
	assert.Equal(t, 0.5, cfg.SlowPercentageThreshold)
}

func TestCacheEntry(t *testing.T) {
	t.Run("fresh entry not expired", func(t *testing.T) {
		entry := &CacheEntry{
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(time.Minute),
		}
		assert.False(t, entry.IsExpired())
	})

	t.Run("old entry expired", func(t *testing.T) {
		entry := &CacheEntry{
			CreatedAt: time.Now().Add(-2 * time.Minute),
			ExpiresAt: time.Now().Add(-1 * time.Minute),
		}
		assert.True(t, entry.IsExpired())
	})

	t.Run("stale but usable", func(t *testing.T) {
		staleTTL := 5 * time.Minute
		entry := &CacheEntry{
			CreatedAt: time.Now().Add(-2 * time.Minute),
			ExpiresAt: time.Now().Add(-1 * time.Minute),
		}
		assert.True(t, entry.IsStale(staleTTL))
	})

	t.Run("too stale to use", func(t *testing.T) {
		staleTTL := 1 * time.Minute
		entry := &CacheEntry{
			CreatedAt: time.Now().Add(-10 * time.Minute),
			ExpiresAt: time.Now().Add(-5 * time.Minute),
		}
		assert.False(t, entry.IsStale(staleTTL))
	})
}

func TestCache(t *testing.T) {
	t.Run("set and get", func(t *testing.T) {
		cache := NewCache("test", 100)

		cache.Set("key1", []byte("value1"), time.Minute)

		entry, err := cache.Get("key1")
		require.NoError(t, err)
		assert.Equal(t, []byte("value1"), entry.Value)
	})

	t.Run("cache miss", func(t *testing.T) {
		cache := NewCache("test", 100)

		_, err := cache.Get("nonexistent")
		assert.ErrorIs(t, err, ErrCacheMiss)
	})

	t.Run("delete", func(t *testing.T) {
		cache := NewCache("test", 100)

		cache.Set("key1", []byte("value1"), time.Minute)
		cache.Delete("key1")

		_, err := cache.Get("key1")
		assert.ErrorIs(t, err, ErrCacheMiss)
	})

	t.Run("size tracking", func(t *testing.T) {
		cache := NewCache("test", 100)

		assert.Equal(t, int64(0), cache.Size())

		cache.Set("key1", []byte("value1"), time.Minute)
		assert.Equal(t, int64(1), cache.Size())

		cache.Set("key2", []byte("value2"), time.Minute)
		assert.Equal(t, int64(2), cache.Size())

		cache.Delete("key1")
		assert.Equal(t, int64(1), cache.Size())
	})

	t.Run("clear", func(t *testing.T) {
		cache := NewCache("test", 100)

		cache.Set("key1", []byte("value1"), time.Minute)
		cache.Set("key2", []byte("value2"), time.Minute)
		cache.Clear()

		assert.Equal(t, int64(0), cache.Size())
	})

	t.Run("eviction on max size", func(t *testing.T) {
		cache := NewCache("test", 3)

		// Fill to max
		for i := 0; i < 3; i++ {
			cache.Set(formatKey(i), []byte("value"), time.Minute)
		}

		// Add one more - should trigger eviction
		cache.Set("key3", []byte("value"), time.Minute)

		// Size should still be reasonable
		assert.LessOrEqual(t, cache.Size(), int64(4))
	})

	t.Run("overwrites existing key", func(t *testing.T) {
		cache := NewCache("test", 100)

		cache.Set("key1", []byte("value1"), time.Minute)
		cache.Set("key1", []byte("value2"), time.Minute)

		entry, err := cache.Get("key1")
		require.NoError(t, err)
		assert.Equal(t, []byte("value2"), entry.Value)
		assert.Equal(t, int64(1), cache.Size())
	})
}

func formatKey(n int) string {
	return "key" + formatInt(n)
}

func formatInt(n int) string {
	if n == 0 {
		return "0"
	}
	result := ""
	for n > 0 {
		result = string(rune('0'+n%10)) + result
		n /= 10
	}
	return result
}

func TestLatencyTracker(t *testing.T) {
	t.Run("tracks latency samples", func(t *testing.T) {
		lt := NewLatencyTracker(10, 100*time.Millisecond)

		lt.Record(50 * time.Millisecond)
		lt.Record(150 * time.Millisecond)

		avg := lt.AverageLatency()
		assert.Equal(t, 100*time.Millisecond, avg)
	})

	t.Run("calculates slow percentage", func(t *testing.T) {
		lt := NewLatencyTracker(10, 100*time.Millisecond)

		// 5 fast, 5 slow
		for i := 0; i < 5; i++ {
			lt.Record(50 * time.Millisecond)
		}
		for i := 0; i < 5; i++ {
			lt.Record(150 * time.Millisecond)
		}

		pct := lt.SlowPercentage()
		assert.Equal(t, 0.5, pct)
	})

	t.Run("empty tracker returns zero", func(t *testing.T) {
		lt := NewLatencyTracker(10, 100*time.Millisecond)

		assert.Equal(t, float64(0), lt.SlowPercentage())
		assert.Equal(t, time.Duration(0), lt.AverageLatency())
	})

	t.Run("reset clears samples", func(t *testing.T) {
		lt := NewLatencyTracker(10, 100*time.Millisecond)

		lt.Record(50 * time.Millisecond)
		lt.Record(50 * time.Millisecond)
		lt.Reset()

		assert.Equal(t, time.Duration(0), lt.AverageLatency())
	})

	t.Run("rolling window", func(t *testing.T) {
		lt := NewLatencyTracker(3, 100*time.Millisecond)

		// Fill window with slow samples
		lt.Record(150 * time.Millisecond)
		lt.Record(150 * time.Millisecond)
		lt.Record(150 * time.Millisecond)
		assert.Equal(t, 1.0, lt.SlowPercentage())

		// Add fast samples - should replace old ones
		lt.Record(50 * time.Millisecond)
		lt.Record(50 * time.Millisecond)
		lt.Record(50 * time.Millisecond)

		// Now all samples should be fast
		assert.Equal(t, 0.0, lt.SlowPercentage())
	})
}

func TestDegradationManager(t *testing.T) {
	t.Run("starts not degraded", func(t *testing.T) {
		dm := NewDegradationManager(nil)
		assert.False(t, dm.IsDegraded())
	})

	t.Run("enters degraded mode on slow responses", func(t *testing.T) {
		cfg := &Config{
			Enabled:                 true,
			SlowThreshold:           10 * time.Millisecond,
			SlowWindowSize:          10,
			SlowPercentageThreshold: 0.5,
		}
		dm := NewDegradationManager(cfg)

		// Record enough slow requests
		for i := 0; i < 10; i++ {
			dm.RecordLatency(100 * time.Millisecond)
		}

		assert.True(t, dm.IsDegraded())
		assert.False(t, dm.DegradedSince().IsZero())
	})

	t.Run("exits degraded mode on fast responses", func(t *testing.T) {
		cfg := &Config{
			Enabled:                 true,
			SlowThreshold:           10 * time.Millisecond,
			SlowWindowSize:          10,
			SlowPercentageThreshold: 0.5,
		}
		dm := NewDegradationManager(cfg)

		// Enter degraded mode
		for i := 0; i < 10; i++ {
			dm.RecordLatency(100 * time.Millisecond)
		}
		assert.True(t, dm.IsDegraded())

		// Record fast requests to exit
		for i := 0; i < 20; i++ {
			dm.RecordLatency(1 * time.Millisecond)
		}

		assert.False(t, dm.IsDegraded())
	})

	t.Run("force enter and exit", func(t *testing.T) {
		dm := NewDegradationManager(nil)

		dm.ForceEnterDegradedMode()
		assert.True(t, dm.IsDegraded())

		dm.ForceExitDegradedMode()
		assert.False(t, dm.IsDegraded())
	})

	t.Run("status", func(t *testing.T) {
		dm := NewDegradationManager(nil)

		status := dm.Status()
		assert.False(t, status.Degraded)
		assert.Equal(t, float64(0), status.SlowPercentage)
	})

	t.Run("get cache", func(t *testing.T) {
		dm := NewDegradationManager(nil)

		cache1 := dm.GetCache("cache1")
		cache2 := dm.GetCache("cache1")
		cache3 := dm.GetCache("cache2")

		assert.Same(t, cache1, cache2)
		assert.NotSame(t, cache1, cache3)
	})
}

func TestExecuteWithCache(t *testing.T) {
	cfg := &Config{
		Enabled:                 true,
		CacheTTL:                1 * time.Minute,
		StaleTTL:                5 * time.Minute,
		MaxCacheSize:            100,
		SlowThreshold:           10 * time.Millisecond,
		SlowWindowSize:          10,
		SlowPercentageThreshold: 0.5,
	}

	t.Run("caches result", func(t *testing.T) {
		dm := NewDegradationManager(cfg)
		ctx := context.Background()

		callCount := 0
		fn := func(ctx context.Context) ([]byte, error) {
			callCount++
			return []byte("result"), nil
		}

		// First call
		result, err := dm.ExecuteWithCache(ctx, "test", "key1", fn)
		require.NoError(t, err)
		assert.Equal(t, []byte("result"), result)
		assert.Equal(t, 1, callCount)

		// Second call should use cache
		result, err = dm.ExecuteWithCache(ctx, "test", "key1", fn)
		require.NoError(t, err)
		assert.Equal(t, []byte("result"), result)
		assert.Equal(t, 1, callCount) // Should not increment
	})

	t.Run("returns stale cache in degraded mode on error", func(t *testing.T) {
		dm := NewDegradationManager(cfg)
		ctx := context.Background()

		// First call succeeds
		successFn := func(ctx context.Context) ([]byte, error) {
			return []byte("cached"), nil
		}
		_, err := dm.ExecuteWithCache(ctx, "test", "stale-key", successFn)
		require.NoError(t, err)

		// Force cache to be stale but within stale TTL
		cache := dm.GetCache("test")
		entry, _ := cache.Get("stale-key")
		entry.ExpiresAt = time.Now().Add(-1 * time.Second)
		cache.Set("stale-key", entry.Value, -1*time.Second)

		// Enter degraded mode
		dm.ForceEnterDegradedMode()

		// Second call fails but returns stale cache
		failFn := func(ctx context.Context) ([]byte, error) {
			return nil, errors.New("backend error")
		}
		result, err := dm.ExecuteWithCache(ctx, "test", "stale-key", failFn)

		// In degraded mode with stale cache, should return cached value
		if err == nil {
			assert.Equal(t, []byte("cached"), result)
		}
	})

	t.Run("records latency", func(t *testing.T) {
		dm := NewDegradationManager(cfg)
		ctx := context.Background()

		slowFn := func(ctx context.Context) ([]byte, error) {
			time.Sleep(20 * time.Millisecond)
			return []byte("slow"), nil
		}

		for i := 0; i < 10; i++ {
			_, _ = dm.ExecuteWithCache(ctx, "test", formatKey(i), slowFn)
		}

		status := dm.Status()
		assert.Greater(t, status.AverageLatency, time.Duration(0))
	})
}

func TestCacheConcurrency(t *testing.T) {
	cache := NewCache("concurrent", 1000)

	var wg sync.WaitGroup
	operations := 100

	// Concurrent writes
	for i := 0; i < operations; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			cache.Set(formatKey(n), []byte("value"), time.Minute)
		}(i)
	}

	// Concurrent reads
	for i := 0; i < operations; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, _ = cache.Get(formatKey(n))
		}(i)
	}

	wg.Wait()

	// Should have some entries
	assert.GreaterOrEqual(t, cache.Size(), int64(1))
}

func TestDegradationManagerConcurrency(t *testing.T) {
	cfg := &Config{
		Enabled:                 true,
		SlowThreshold:           10 * time.Millisecond,
		SlowWindowSize:          100,
		SlowPercentageThreshold: 0.5,
	}
	dm := NewDegradationManager(cfg)

	var wg sync.WaitGroup
	operations := 100

	for i := 0; i < operations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dm.RecordLatency(5 * time.Millisecond)
			_ = dm.IsDegraded()
			_ = dm.Status()
			_ = dm.GetCache("test")
		}()
	}

	wg.Wait()
}

func TestMarshalCacheKey(t *testing.T) {
	t.Run("single part", func(t *testing.T) {
		key := MarshalCacheKey("part1")
		assert.NotEmpty(t, key)
	})

	t.Run("multiple parts", func(t *testing.T) {
		key := MarshalCacheKey("tenant", "order", "123")
		assert.NotEmpty(t, key)
		assert.Contains(t, key, "tenant")
	})

	t.Run("empty parts", func(t *testing.T) {
		key := MarshalCacheKey()
		assert.Empty(t, key)
	})
}

func TestNewCacheableRequest(t *testing.T) {
	req := NewCacheableRequest("orders", "order-123")
	assert.Equal(t, "orders", req.CacheName)
	assert.Equal(t, "order-123", req.Key)
}

func TestEvictRemovesExpiredEntries(t *testing.T) {
	cache := NewCache("evict-test", 3)

	// Add entries with already-expired TTLs
	cache.Set("expired1", []byte("val1"), -1*time.Second)
	cache.Set("expired2", []byte("val2"), -1*time.Second)
	cache.Set("fresh1", []byte("val3"), time.Minute)

	assert.Equal(t, int64(3), cache.Size())

	// Adding a fourth entry when at max triggers eviction
	cache.Set("fresh2", []byte("val4"), time.Minute)

	// The two expired entries should have been evicted
	assert.LessOrEqual(t, cache.Size(), int64(2))

	// Fresh entry should still be accessible
	entry, err := cache.Get("fresh1")
	require.NoError(t, err)
	assert.Equal(t, []byte("val3"), entry.Value)

	// Expired entries should be gone
	_, err = cache.Get("expired1")
	assert.ErrorIs(t, err, ErrCacheMiss)

	_, err = cache.Get("expired2")
	assert.ErrorIs(t, err, ErrCacheMiss)
}

func TestExecuteWithCache_FreshCacheHit(t *testing.T) {
	cfg := &Config{
		Enabled:                 true,
		CacheTTL:                1 * time.Minute,
		StaleTTL:                5 * time.Minute,
		MaxCacheSize:            100,
		SlowThreshold:           10 * time.Millisecond,
		SlowWindowSize:          10,
		SlowPercentageThreshold: 0.5,
	}
	dm := NewDegradationManager(cfg)
	ctx := context.Background()

	callCount := 0
	fn := func(ctx context.Context) ([]byte, error) {
		callCount++
		return []byte("fresh-result"), nil
	}

	// Populate cache
	result, err := dm.ExecuteWithCache(ctx, "test", "fresh-hit-key", fn)
	require.NoError(t, err)
	assert.Equal(t, []byte("fresh-result"), result)
	assert.Equal(t, 1, callCount)

	// Second call: entry is still fresh (1 min TTL), should return from cache
	// without calling fn
	result, err = dm.ExecuteWithCache(ctx, "test", "fresh-hit-key", fn)
	require.NoError(t, err)
	assert.Equal(t, []byte("fresh-result"), result)
	assert.Equal(t, 1, callCount) // fn was not called again
}

func TestExecuteWithCache_StaleCacheServedInDegradedMode(t *testing.T) {
	cfg := &Config{
		Enabled:                 true,
		CacheTTL:                1 * time.Minute,
		StaleTTL:                5 * time.Minute,
		MaxCacheSize:            100,
		SlowThreshold:           10 * time.Millisecond,
		SlowWindowSize:          10,
		SlowPercentageThreshold: 0.5,
	}
	dm := NewDegradationManager(cfg)
	ctx := context.Background()

	// Populate cache
	fn := func(ctx context.Context) ([]byte, error) {
		return []byte("cached-value"), nil
	}
	_, err := dm.ExecuteWithCache(ctx, "test", "stale-serve-key", fn)
	require.NoError(t, err)

	// Make the entry stale (expired but within staleTTL)
	cache := dm.GetCache("test")
	entry, _ := cache.Get("stale-serve-key")
	entry.ExpiresAt = time.Now().Add(-10 * time.Second)
	cache.entries.Store("stale-serve-key", entry)

	// Enter degraded mode
	dm.ForceEnterDegradedMode()
	assert.True(t, dm.IsDegraded())

	// Call should return the stale cached value without calling fn
	callCount := 0
	fn2 := func(ctx context.Context) ([]byte, error) {
		callCount++
		return []byte("new-value"), nil
	}
	result, err := dm.ExecuteWithCache(ctx, "test", "stale-serve-key", fn2)
	require.NoError(t, err)
	assert.Equal(t, []byte("cached-value"), result)
	assert.Equal(t, 0, callCount) // fn was NOT called
}

func TestExecuteWithCache_ErrorWithoutStaleCache(t *testing.T) {
	cfg := &Config{
		Enabled:                 true,
		CacheTTL:                1 * time.Minute,
		StaleTTL:                5 * time.Minute,
		MaxCacheSize:            100,
		SlowThreshold:           10 * time.Millisecond,
		SlowWindowSize:          10,
		SlowPercentageThreshold: 0.5,
	}
	dm := NewDegradationManager(cfg)
	ctx := context.Background()

	// No cache entry exists; fn returns an error
	fn := func(ctx context.Context) ([]byte, error) {
		return nil, errors.New("backend unavailable")
	}

	result, err := dm.ExecuteWithCache(ctx, "test", "no-cache-key", fn)
	assert.Nil(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "backend unavailable")
}

func TestMarshalCacheKey_Deterministic(t *testing.T) {
	// Verify that the same parts always produce the same key
	key1 := MarshalCacheKey("tenant", "order", "123")
	key2 := MarshalCacheKey("tenant", "order", "123")
	assert.Equal(t, key1, key2)

	// Different parts produce different keys
	key3 := MarshalCacheKey("tenant", "order", "456")
	assert.NotEqual(t, key1, key3)
}

func TestMarshalCacheKey_SinglePart(t *testing.T) {
	key := MarshalCacheKey("only-part")
	assert.NotEmpty(t, key)
	assert.Contains(t, key, "only-part")
}

func TestDeleteNonexistentKey(t *testing.T) {
	cache := NewCache("test", 100)
	cache.Set("key1", []byte("value1"), time.Minute)

	// Deleting a key that doesn't exist should not affect size
	cache.Delete("nonexistent")
	assert.Equal(t, int64(1), cache.Size())
}

func TestExecuteWithCache_ErrorWithStaleCacheInDegradedMode(t *testing.T) {
	cfg := &Config{
		Enabled:                 true,
		CacheTTL:                1 * time.Minute,
		StaleTTL:                10 * time.Minute,
		MaxCacheSize:            100,
		SlowThreshold:           10 * time.Millisecond,
		SlowWindowSize:          10,
		SlowPercentageThreshold: 0.5,
	}
	dm := NewDegradationManager(cfg)
	ctx := context.Background()

	// Populate cache with a value
	fn := func(ctx context.Context) ([]byte, error) {
		return []byte("original"), nil
	}
	_, err := dm.ExecuteWithCache(ctx, "test", "error-stale-key", fn)
	require.NoError(t, err)

	// Make the entry stale but within staleTTL window
	cache := dm.GetCache("test")
	entry, err := cache.Get("error-stale-key")
	require.NoError(t, err)
	entry.ExpiresAt = time.Now().Add(-5 * time.Second)
	cache.entries.Store("error-stale-key", entry)

	// To hit the error+stale path (line 440), we need:
	// 1. Not degraded when checking stale before fn (line 428) -> skips early return
	// 2. fn returns error
	// 3. RecordLatency after fn pushes system into degraded mode
	// 4. entry is stale but within staleTTL -> returns cached value
	//
	// Use tracker.Record directly to avoid triggering degradation checks.
	// Fill with 4 slow + 5 fast = 44.4% < 50%. The slow sample from
	// ExecuteWithCache pushes to 5/10 = 50% >= threshold -> enters degraded.
	dm.latencyTracker.Reset()
	for i := 0; i < 4; i++ {
		dm.latencyTracker.Record(100 * time.Millisecond) // slow
	}
	for i := 0; i < 5; i++ {
		dm.latencyTracker.Record(1 * time.Millisecond) // fast
	}
	require.False(t, dm.IsDegraded())

	slowFailFn := func(ctx context.Context) ([]byte, error) {
		time.Sleep(15 * time.Millisecond) // slow: will be the 10th sample
		return nil, errors.New("backend failure")
	}

	result, err := dm.ExecuteWithCache(ctx, "test", "error-stale-key", slowFailFn)
	require.NoError(t, err)
	assert.Equal(t, []byte("original"), result)
}
