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

package metrics

import (
	"context"
	"runtime"
	"time"
)

// ResourceCollector periodically collects and updates resource metrics
// such as goroutine count, memory usage, and GC statistics.
type ResourceCollector struct {
	ctx      context.Context
	cancel   context.CancelFunc
	interval time.Duration
	started  time.Time
}

// NewResourceCollector creates a new resource collector that updates metrics
// at the specified interval.
//
// Parameters:
//   - ctx: Parent context for lifecycle management
//   - interval: How often to collect metrics (recommended: 10-60 seconds)
//
// Example:
//
//	collector := metrics.NewResourceCollector(ctx, 30*time.Second)
//	go collector.Start()
//	defer collector.Stop()
func NewResourceCollector(ctx context.Context, interval time.Duration) *ResourceCollector {
	collectorCtx, cancel := context.WithCancel(ctx)
	return &ResourceCollector{
		ctx:      collectorCtx,
		cancel:   cancel,
		interval: interval,
		started:  time.Now(),
	}
}

// Start begins collecting resource metrics at the configured interval.
// This method blocks and should typically be run in a goroutine.
//
// It will continue collecting metrics until Stop() is called or the parent context is cancelled.
func (rc *ResourceCollector) Start() {
	ticker := time.NewTicker(rc.interval)
	defer ticker.Stop()

	// Collect initial metrics immediately
	rc.collect()

	for {
		select {
		case <-rc.ctx.Done():
			return
		case <-ticker.C:
			rc.collect()
		}
	}
}

// Stop halts the resource collector gracefully.
func (rc *ResourceCollector) Stop() {
	rc.cancel()
}

// collect gathers and updates all resource metrics.
func (rc *ResourceCollector) collect() {
	if !IsEnabled() {
		return
	}

	// Collect goroutine count
	Goroutines.Set(float64(runtime.NumGoroutine()))

	// Collect memory statistics
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	MemoryAllocBytes.Set(float64(memStats.Alloc))
	MemorySysBytes.Set(float64(memStats.Sys))

	// Calculate total GC pause time in seconds
	gcPauseTotal := float64(memStats.PauseTotalNs) / 1e9
	GCPauseTotalSeconds.Set(gcPauseTotal)

	// Update server uptime
	uptime := time.Since(rc.started).Seconds()
	ServerUptime.Set(uptime)
}

// CollectOnce performs a single collection of resource metrics.
// This is useful for immediate metric updates outside of the periodic collection.
func CollectOnce() {
	if !IsEnabled() {
		return
	}

	Goroutines.Set(float64(runtime.NumGoroutine()))

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	MemoryAllocBytes.Set(float64(memStats.Alloc))
	MemorySysBytes.Set(float64(memStats.Sys))

	gcPauseTotal := float64(memStats.PauseTotalNs) / 1e9
	GCPauseTotalSeconds.Set(gcPauseTotal)
}

// StartResourceCollector is a convenience function that creates and starts a resource collector.
// It returns the collector instance for optional lifecycle management.
//
// Parameters:
//   - ctx: Context for lifecycle management
//   - interval: Collection interval (recommended: 10-60 seconds)
//
// Example:
//
//	collector := metrics.StartResourceCollector(ctx, 30*time.Second)
//	// Collector runs in background, stops when ctx is cancelled
func StartResourceCollector(ctx context.Context, interval time.Duration) *ResourceCollector {
	collector := NewResourceCollector(ctx, interval)
	go collector.Start()
	return collector
}
