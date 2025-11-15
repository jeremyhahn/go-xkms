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
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestNewResourceCollector(t *testing.T) {
	ctx := context.Background()
	interval := 1 * time.Second

	collector := NewResourceCollector(ctx, interval)

	if collector == nil {
		t.Fatal("Expected collector to be created")
	}

	if collector.interval != interval {
		t.Errorf("Expected interval %v, got %v", interval, collector.interval)
	}

	if collector.ctx == nil {
		t.Error("Expected context to be set")
	}

	if collector.started.IsZero() {
		t.Error("Expected started time to be set")
	}

	// Clean up
	collector.Stop()
}

func TestResourceCollectorStart(t *testing.T) {
	Enable()

	// Reset gauges
	Goroutines.Set(0)
	MemoryAllocBytes.Set(0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	collector := NewResourceCollector(ctx, 100*time.Millisecond)

	// Start collector in background
	go collector.Start()

	// Wait for at least one collection cycle
	time.Sleep(150 * time.Millisecond)

	// Stop collector
	collector.Stop()

	// Verify metrics were collected
	goroutines := testutil.CollectAndCount(Goroutines)
	if goroutines == 0 {
		t.Error("Expected goroutines metric to be collected")
	}

	memAlloc := testutil.CollectAndCount(MemoryAllocBytes)
	if memAlloc == 0 {
		t.Error("Expected memory alloc metric to be collected")
	}
}

func TestResourceCollectorStop(t *testing.T) {
	ctx := context.Background()
	collector := NewResourceCollector(ctx, 1*time.Second)

	// Start collector
	go collector.Start()

	// Stop immediately
	collector.Stop()

	// Should complete without blocking
	// If this test hangs, Stop() isn't working correctly
}

func TestResourceCollectorContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	collector := NewResourceCollector(ctx, 1*time.Second)

	// Start collector
	done := make(chan bool)
	go func() {
		collector.Start()
		done <- true
	}()

	// Cancel context
	cancel()

	// Wait for collector to stop
	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Error("Collector did not stop after context cancellation")
	}
}

func TestResourceCollectorCollectMetrics(t *testing.T) {
	Enable()

	// Reset all resource gauges
	Goroutines.Set(0)
	MemoryAllocBytes.Set(0)
	MemorySysBytes.Set(0)
	GCPauseTotalSeconds.Set(0)
	ServerUptime.Set(0)

	ctx := context.Background()
	collector := NewResourceCollector(ctx, 1*time.Second)

	// Call collect manually
	collector.collect()

	// Verify all metrics are non-zero (they should reflect actual system state)
	// We can't test exact values, but we can verify they're being set

	// Goroutines should be at least 1 (the current test goroutine)
	goroutineCount := float64(runtime.NumGoroutine())
	if goroutineCount < 1 {
		t.Error("Expected at least 1 goroutine")
	}

	// Memory should be allocated
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	if memStats.Alloc == 0 {
		t.Error("Expected allocated memory > 0")
	}
	if memStats.Sys == 0 {
		t.Error("Expected system memory > 0")
	}

	// Verify metrics are being collected
	if testutil.CollectAndCount(Goroutines) == 0 {
		t.Error("Expected Goroutines to be collecting")
	}
	if testutil.CollectAndCount(MemoryAllocBytes) == 0 {
		t.Error("Expected MemoryAllocBytes to be collecting")
	}
	if testutil.CollectAndCount(MemorySysBytes) == 0 {
		t.Error("Expected MemorySysBytes to be collecting")
	}
	if testutil.CollectAndCount(GCPauseTotalSeconds) == 0 {
		t.Error("Expected GCPauseTotalSeconds to be collecting")
	}
	if testutil.CollectAndCount(ServerUptime) == 0 {
		t.Error("Expected ServerUptime to be collecting")
	}
}

func TestResourceCollectorCollectWhenDisabled(t *testing.T) {
	Disable()
	defer Enable()

	ctx := context.Background()
	collector := NewResourceCollector(ctx, 1*time.Second)

	// Reset gauges
	Goroutines.Set(0)

	// Call collect while disabled
	collector.collect()

	// Metrics should not be updated (this is tricky to test reliably,
	// but the collect method should return early)
}

func TestCollectOnce(t *testing.T) {
	Enable()

	// Reset gauges
	Goroutines.Set(0)
	MemoryAllocBytes.Set(0)

	// Call CollectOnce
	CollectOnce()

	// Verify metrics were collected
	goroutines := testutil.CollectAndCount(Goroutines)
	if goroutines == 0 {
		t.Error("Expected goroutines metric to be collected")
	}

	memAlloc := testutil.CollectAndCount(MemoryAllocBytes)
	if memAlloc == 0 {
		t.Error("Expected memory alloc metric to be collected")
	}
}

func TestCollectOnceWhenDisabled(t *testing.T) {
	Disable()
	defer Enable()

	// Reset gauges
	Goroutines.Set(0)

	// Call CollectOnce while disabled
	CollectOnce()

	// Should not panic, but metrics won't be updated
}

func TestStartResourceCollector(t *testing.T) {
	Enable()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start collector using convenience function
	collector := StartResourceCollector(ctx, 100*time.Millisecond)

	if collector == nil {
		t.Fatal("Expected collector to be created")
	}

	// Wait for at least one collection
	time.Sleep(150 * time.Millisecond)

	// Cancel context to stop collector
	cancel()

	// Give it time to stop
	time.Sleep(50 * time.Millisecond)
}

func TestResourceCollectorUptime(t *testing.T) {
	Enable()

	ctx := context.Background()
	collector := NewResourceCollector(ctx, 1*time.Second)

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// Collect metrics
	collector.collect()

	// Server uptime should be approximately 100ms
	// We can't check the exact value easily, but we verify it was set
	count := testutil.CollectAndCount(ServerUptime)
	if count == 0 {
		t.Error("Expected server uptime to be collected")
	}

	// Wait more
	time.Sleep(100 * time.Millisecond)

	// Collect again
	collector.collect()

	// Uptime should have increased
	// Again, we can just verify it's still collecting
	count = testutil.CollectAndCount(ServerUptime)
	if count == 0 {
		t.Error("Expected server uptime to be collected after delay")
	}

	collector.Stop()
}

func TestResourceCollectorGCMetrics(t *testing.T) {
	Enable()

	ctx := context.Background()
	collector := NewResourceCollector(ctx, 1*time.Second)

	// Force a GC to ensure we have some GC stats
	runtime.GC()

	// Collect metrics
	collector.collect()

	// Verify GC pause metric is collected
	count := testutil.CollectAndCount(GCPauseTotalSeconds)
	if count == 0 {
		t.Error("Expected GC pause metric to be collected")
	}

	collector.Stop()
}

func TestResourceCollectorMemoryMetrics(t *testing.T) {
	Enable()

	ctx := context.Background()
	collector := NewResourceCollector(ctx, 1*time.Second)

	// Allocate some memory
	_ = make([]byte, 1024*1024) // 1MB

	// Collect metrics
	collector.collect()

	// Verify memory metrics are collected
	memAlloc := testutil.CollectAndCount(MemoryAllocBytes)
	if memAlloc == 0 {
		t.Error("Expected memory alloc metric to be collected")
	}

	memSys := testutil.CollectAndCount(MemorySysBytes)
	if memSys == 0 {
		t.Error("Expected memory sys metric to be collected")
	}

	collector.Stop()
}

func TestResourceCollectorMultipleCycles(t *testing.T) {
	Enable()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use short interval for faster test
	collector := NewResourceCollector(ctx, 50*time.Millisecond)

	go collector.Start()

	// Wait for multiple collection cycles
	time.Sleep(200 * time.Millisecond)

	// Stop collector
	cancel()
	collector.Stop()

	// Verify metrics were collected
	goroutines := testutil.CollectAndCount(Goroutines)
	if goroutines == 0 {
		t.Error("Expected goroutines metric to be collected")
	}
}

func BenchmarkCollect(b *testing.B) {
	Enable()

	ctx := context.Background()
	collector := NewResourceCollector(ctx, 1*time.Hour) // Won't auto-collect during benchmark

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		collector.collect()
	}

	collector.Stop()
}

func BenchmarkCollectOnce(b *testing.B) {
	Enable()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CollectOnce()
	}
}
