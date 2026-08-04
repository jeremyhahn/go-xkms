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

// Package degradation provides graceful degradation capabilities for the ACME server.
// When backends become slow or unavailable, the server can serve cached responses
// and continue operating in a degraded mode.
package degradation

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/server/metrics"
)

// Error types for degradation package.
var (
	// ErrCacheMiss is returned when no cached value exists.
	ErrCacheMiss = errors.New("degradation: cache miss")

	// ErrCacheExpired is returned when the cached value has expired.
	ErrCacheExpired = errors.New("degradation: cache expired")

	// ErrDegradationActive is returned when degradation mode is active
	// and the request cannot be served from cache.
	ErrDegradationActive = errors.New("degradation: degradation mode active, cannot serve request")
)

// Config contains configuration for graceful degradation.
type Config struct {
	// Enabled indicates whether graceful degradation is enabled.
	Enabled bool

	// CacheTTL is how long cached responses are considered fresh.
	CacheTTL time.Duration

	// StaleTTL is how long stale cached responses can be served in degraded mode.
	StaleTTL time.Duration

	// MaxCacheSize is the maximum number of entries in the cache.
	MaxCacheSize int

	// SlowThreshold is the latency threshold for considering a backend slow.
	SlowThreshold time.Duration

	// SlowWindowSize is the number of requests to track for slow detection.
	SlowWindowSize int

	// SlowPercentageThreshold is the percentage of slow requests to trigger degradation.
	SlowPercentageThreshold float64

	// Logger for degradation events.
	Logger *slog.Logger
}

// DefaultConfig returns the default degradation configuration.
func DefaultConfig() *Config {
	return &Config{
		Enabled:                 true,
		CacheTTL:                1 * time.Minute,
		StaleTTL:                5 * time.Minute,
		MaxCacheSize:            10000,
		SlowThreshold:           500 * time.Millisecond,
		SlowWindowSize:          100,
		SlowPercentageThreshold: 0.5,
		Logger:                  slog.Default(),
	}
}

// CacheEntry represents a cached response.
type CacheEntry struct {
	Key       string
	Value     []byte
	CreatedAt time.Time
	ExpiresAt time.Time
}

// IsExpired checks if the entry has expired.
func (e *CacheEntry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// IsStale checks if the entry is stale but still usable in degraded mode.
func (e *CacheEntry) IsStale(staleTTL time.Duration) bool {
	return time.Now().After(e.ExpiresAt) && time.Now().Before(e.ExpiresAt.Add(staleTTL))
}

// Cache is a simple in-memory cache with LRU eviction.
type Cache struct {
	entries    sync.Map // map[string]*CacheEntry
	entryCount atomic.Int64
	maxSize    int
	name       string
	mu         sync.Mutex // For eviction operations
}

// NewCache creates a new cache with the given name and max size.
func NewCache(name string, maxSize int) *Cache {
	return &Cache{
		maxSize: maxSize,
		name:    name,
	}
}

// Get retrieves a value from the cache.
func (c *Cache) Get(key string) (*CacheEntry, error) {
	value, ok := c.entries.Load(key)
	if !ok {
		metrics.RecordCacheMiss(c.name)
		return nil, ErrCacheMiss
	}

	entry := value.(*CacheEntry)
	metrics.RecordCacheHit(c.name)
	return entry, nil
}

// Set stores a value in the cache.
func (c *Cache) Set(key string, value []byte, ttl time.Duration) {
	// Check if we need to evict
	if c.entryCount.Load() >= int64(c.maxSize) {
		c.evict()
	}

	entry := &CacheEntry{
		Key:       key,
		Value:     value,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(ttl),
	}

	_, loaded := c.entries.LoadOrStore(key, entry)
	if !loaded {
		c.entryCount.Add(1)
	} else {
		c.entries.Store(key, entry)
	}

	metrics.SetCacheSize(c.name, float64(c.entryCount.Load()))
}

// Delete removes a value from the cache.
func (c *Cache) Delete(key string) {
	if _, loaded := c.entries.LoadAndDelete(key); loaded {
		c.entryCount.Add(-1)
		metrics.SetCacheSize(c.name, float64(c.entryCount.Load()))
	}
}

// evict removes expired entries and oldest entries if needed.
func (c *Cache) evict() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var expiredKeys []string

	// First, remove expired entries
	c.entries.Range(func(key, value any) bool {
		entry := value.(*CacheEntry)
		if now.After(entry.ExpiresAt) {
			expiredKeys = append(expiredKeys, key.(string))
		}
		return true
	})

	for _, key := range expiredKeys {
		if _, loaded := c.entries.LoadAndDelete(key); loaded {
			c.entryCount.Add(-1)
		}
	}

	metrics.SetCacheSize(c.name, float64(c.entryCount.Load()))
}

// Size returns the current number of entries in the cache.
func (c *Cache) Size() int64 {
	return c.entryCount.Load()
}

// Clear removes all entries from the cache.
func (c *Cache) Clear() {
	c.entries.Range(func(key, value any) bool {
		c.entries.Delete(key)
		return true
	})
	c.entryCount.Store(0)
	metrics.SetCacheSize(c.name, 0)
}

// LatencyTracker tracks request latencies for slow detection.
type LatencyTracker struct {
	samples    []time.Duration
	index      int
	count      int
	windowSize int
	threshold  time.Duration
	mu         sync.Mutex
}

// NewLatencyTracker creates a new latency tracker.
func NewLatencyTracker(windowSize int, threshold time.Duration) *LatencyTracker {
	return &LatencyTracker{
		samples:    make([]time.Duration, windowSize),
		windowSize: windowSize,
		threshold:  threshold,
	}
}

// Record records a latency sample.
func (lt *LatencyTracker) Record(latency time.Duration) {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	lt.samples[lt.index] = latency
	lt.index = (lt.index + 1) % lt.windowSize
	if lt.count < lt.windowSize {
		lt.count++
	}
}

// SlowPercentage returns the percentage of samples above the threshold.
func (lt *LatencyTracker) SlowPercentage() float64 {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	if lt.count == 0 {
		return 0
	}

	slowCount := 0
	for i := 0; i < lt.count; i++ {
		if lt.samples[i] >= lt.threshold {
			slowCount++
		}
	}

	return float64(slowCount) / float64(lt.count)
}

// AverageLatency returns the average latency of recorded samples.
func (lt *LatencyTracker) AverageLatency() time.Duration {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	if lt.count == 0 {
		return 0
	}

	var total time.Duration
	for i := 0; i < lt.count; i++ {
		total += lt.samples[i]
	}

	return total / time.Duration(lt.count)
}

// Reset clears all recorded samples.
func (lt *LatencyTracker) Reset() {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	lt.samples = make([]time.Duration, lt.windowSize)
	lt.index = 0
	lt.count = 0
}

// DegradationManager manages graceful degradation for the ACME server.
type DegradationManager struct {
	config         *Config
	caches         sync.Map // map[string]*Cache
	latencyTracker *LatencyTracker
	degraded       atomic.Bool
	degradedSince  atomic.Int64
}

// NewDegradationManager creates a new degradation manager.
func NewDegradationManager(config *Config) *DegradationManager {
	if config == nil {
		config = DefaultConfig()
	}

	return &DegradationManager{
		config: config,
		latencyTracker: NewLatencyTracker(
			config.SlowWindowSize,
			config.SlowThreshold,
		),
	}
}

// GetCache returns the cache for the given name, creating it if necessary.
func (dm *DegradationManager) GetCache(name string) *Cache {
	if cache, ok := dm.caches.Load(name); ok {
		return cache.(*Cache)
	}

	cache := NewCache(name, dm.config.MaxCacheSize)
	actual, _ := dm.caches.LoadOrStore(name, cache)
	return actual.(*Cache)
}

// RecordLatency records a request latency and checks for degradation triggers.
func (dm *DegradationManager) RecordLatency(latency time.Duration) {
	dm.latencyTracker.Record(latency)

	slowPct := dm.latencyTracker.SlowPercentage()
	if slowPct >= dm.config.SlowPercentageThreshold {
		dm.enterDegradedMode()
	} else if dm.IsDegraded() && slowPct < dm.config.SlowPercentageThreshold/2 {
		// Recover when slow percentage drops below half the threshold
		dm.exitDegradedMode()
	}
}

// IsDegraded returns whether the service is in degraded mode.
func (dm *DegradationManager) IsDegraded() bool {
	return dm.degraded.Load()
}

// DegradedSince returns when degraded mode was entered.
func (dm *DegradationManager) DegradedSince() time.Time {
	ts := dm.degradedSince.Load()
	if ts == 0 {
		return time.Time{}
	}
	return time.Unix(0, ts)
}

// enterDegradedMode enters degraded mode.
func (dm *DegradationManager) enterDegradedMode() {
	if dm.degraded.CompareAndSwap(false, true) {
		dm.degradedSince.Store(time.Now().UnixNano())
		metrics.SetDegradationActive(true)

		if dm.config.Logger != nil {
			dm.config.Logger.Warn("entering degraded mode",
				slog.Float64("slow_percentage", dm.latencyTracker.SlowPercentage()),
				slog.Duration("avg_latency", dm.latencyTracker.AverageLatency()),
			)
		}
	}
}

// exitDegradedMode exits degraded mode.
func (dm *DegradationManager) exitDegradedMode() {
	if dm.degraded.CompareAndSwap(true, false) {
		degradedDuration := time.Since(dm.DegradedSince())
		dm.degradedSince.Store(0)
		metrics.SetDegradationActive(false)

		if dm.config.Logger != nil {
			dm.config.Logger.Info("exiting degraded mode",
				slog.Duration("degraded_duration", degradedDuration),
				slog.Float64("slow_percentage", dm.latencyTracker.SlowPercentage()),
			)
		}
	}
}

// ForceEnterDegradedMode manually enters degraded mode.
func (dm *DegradationManager) ForceEnterDegradedMode() {
	dm.enterDegradedMode()
}

// ForceExitDegradedMode manually exits degraded mode.
func (dm *DegradationManager) ForceExitDegradedMode() {
	dm.exitDegradedMode()
}

// Status returns the current degradation status.
func (dm *DegradationManager) Status() DegradationStatus {
	return DegradationStatus{
		Degraded:       dm.IsDegraded(),
		DegradedSince:  dm.DegradedSince(),
		SlowPercentage: dm.latencyTracker.SlowPercentage(),
		AverageLatency: dm.latencyTracker.AverageLatency(),
	}
}

// DegradationStatus represents the current degradation status.
type DegradationStatus struct {
	Degraded       bool          `json:"degraded"`
	DegradedSince  time.Time     `json:"degraded_since,omitempty"`
	SlowPercentage float64       `json:"slow_percentage"`
	AverageLatency time.Duration `json:"average_latency"`
}

// ExecuteWithCache executes a function with caching support.
// If degraded and cache hit, returns cached value.
// If not degraded, executes function and caches result.
type ExecuteFunc func(ctx context.Context) ([]byte, error)

// ExecuteWithCache executes a function with caching and degradation support.
func (dm *DegradationManager) ExecuteWithCache(
	ctx context.Context,
	cacheName, key string,
	fn ExecuteFunc,
) ([]byte, error) {
	cache := dm.GetCache(cacheName)
	start := time.Now()

	// Try to get from cache first
	entry, err := cache.Get(key)
	if err == nil {
		// Cache hit
		if !entry.IsExpired() {
			// Fresh cache entry
			return entry.Value, nil
		}

		// Stale entry - check if we can serve it in degraded mode
		if dm.IsDegraded() && entry.IsStale(dm.config.StaleTTL) {
			return entry.Value, nil
		}
	}

	// Execute the function
	result, err := fn(ctx)
	latency := time.Since(start)
	dm.RecordLatency(latency)

	if err != nil {
		// If we have a stale entry and in degraded mode, return it
		if entry != nil && dm.IsDegraded() && entry.IsStale(dm.config.StaleTTL) {
			return entry.Value, nil
		}
		return nil, err
	}

	// Cache the result
	cache.Set(key, result, dm.config.CacheTTL)

	return result, nil
}

// CacheableRequest represents a request that can be cached.
type CacheableRequest struct {
	CacheName string
	Key       string
	TTL       time.Duration
}

// NewCacheableRequest creates a new cacheable request.
func NewCacheableRequest(cacheName, key string) *CacheableRequest {
	return &CacheableRequest{
		CacheName: cacheName,
		Key:       key,
	}
}

// MarshalCacheKey creates a cache key from multiple parts.
func MarshalCacheKey(parts ...string) string {
	if len(parts) == 0 {
		return ""
	}

	data, err := json.Marshal(parts)
	if err != nil {
		// Fallback to simple concatenation
		key := ""
		for _, part := range parts {
			if key != "" {
				key += ":"
			}
			key += part
		}
		return key
	}

	return string(data)
}
