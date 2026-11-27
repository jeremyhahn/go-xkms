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

package circuitbreaker

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fastTripConfig returns a *Config that opens on the first failure and
// never resets during a test's runtime, so tests can drive a target's
// breaker open deterministically.
func fastTripConfig(name string) *Config {
	return &Config{Name: name, MaxFailures: 1, ResetTimeout: time.Hour}
}

// TestManager_TargetBreaker_SameTargetReturnsSameBreaker verifies that two
// calls for the same group and target return the identical breaker
// instance, so state (and therefore admission decisions) is shared across
// calls for that target.
func TestManager_TargetBreaker_SameTargetReturnsSameBreaker(t *testing.T) {
	mgr := NewManager()
	cfg := TargetConfig{Group: "http01", NewConfig: fastTripConfig}

	cb1 := mgr.TargetBreaker(cfg, "example.com")
	cb2 := mgr.TargetBreaker(cfg, "example.com")

	assert.Same(t, cb1, cb2)
	assert.Equal(t, "http01:example.com", cb1.Name())
}

// TestManager_TargetBreaker_BoundedByCapacity verifies that a flood of
// distinct targets never grows the table past cfg.Capacity: the table stays
// bounded regardless of how many distinct hosts an attacker-controlled
// authzValue has named.
func TestManager_TargetBreaker_BoundedByCapacity(t *testing.T) {
	mgr := NewManager()
	cfg := TargetConfig{Group: "http01", NewConfig: fastTripConfig, Capacity: 10}

	for i := 0; i < 1000; i++ {
		mgr.TargetBreaker(cfg, fmt.Sprintf("target-%d.example.com", i))
	}

	status := mgr.TargetGroupStatuses()["http01"]
	assert.Equal(t, 10, status.Capacity)
	assert.Equal(t, 10, status.Tracked, "table must never exceed its configured capacity")
}

// TestManager_TargetBreaker_EvictsLeastRecentlyUsed verifies the eviction
// policy directly: once a group is at capacity, the least recently touched
// target is evicted first, and re-touching a target protects it from
// eviction.
func TestManager_TargetBreaker_EvictsLeastRecentlyUsed(t *testing.T) {
	mgr := NewManager()
	cfg := TargetConfig{Group: "http01", NewConfig: fastTripConfig, Capacity: 2}

	first := mgr.TargetBreaker(cfg, "first.example.com")
	mgr.TargetBreaker(cfg, "second.example.com")

	// Touch "first" again so "second" becomes the least recently used.
	mgr.TargetBreaker(cfg, "first.example.com")

	// Adding a third target must evict "second", not "first".
	mgr.TargetBreaker(cfg, "third.example.com")

	status := mgr.TargetGroupStatuses()["http01"]
	assert.Equal(t, 2, status.Tracked)

	// "first" must still be the same breaker instance (never evicted);
	// "second" must have been replaced with a fresh breaker on next access.
	assert.Same(t, first, mgr.TargetBreaker(cfg, "first.example.com"))
}

// TestManager_TargetBreaker_IdleTTLEvictsStaleTargets verifies that a target
// idle for longer than cfg.IdleTTL is evicted independent of capacity, so a
// server that ran a validation for a target once does not hold that
// target's breaker forever.
func TestManager_TargetBreaker_IdleTTLEvictsStaleTargets(t *testing.T) {
	mgr := NewManager()
	cfg := TargetConfig{
		Group:     "http01",
		NewConfig: fastTripConfig,
		Capacity:  100,
		IdleTTL:   10 * time.Millisecond,
	}

	first := mgr.TargetBreaker(cfg, "stale.example.com")
	time.Sleep(20 * time.Millisecond)

	// A lookup for a different target prunes expired entries as a side
	// effect; "stale.example.com" has been idle longer than IdleTTL.
	mgr.TargetBreaker(cfg, "fresh.example.com")

	status := mgr.TargetGroupStatuses()["http01"]
	assert.Equal(t, 1, status.Tracked, "the stale target must have been evicted")

	// Looking it up again creates a brand new breaker, not the original.
	recreated := mgr.TargetBreaker(cfg, "stale.example.com")
	assert.NotSame(t, first, recreated)
}

// TestManager_TargetBreaker_ZeroCapacityAndTTLUseDefaults verifies the
// documented fallback for a TargetConfig left at its zero Capacity/IdleTTL:
// DefaultTargetCapacity and DefaultTargetIdleTTL, not zero (which would
// otherwise evict every entry immediately).
func TestManager_TargetBreaker_ZeroCapacityAndTTLUseDefaults(t *testing.T) {
	mgr := NewManager()
	cfg := TargetConfig{Group: "http01", NewConfig: fastTripConfig}

	mgr.TargetBreaker(cfg, "example.com")

	status := mgr.TargetGroupStatuses()["http01"]
	assert.Equal(t, DefaultTargetCapacity, status.Capacity)
	assert.Equal(t, 1, status.Tracked, "an entry created under the default TTL must not be evicted immediately")
}

// TestManager_TargetGroupStatuses_ReportsBoundedSummary verifies that
// TargetGroupStatuses reports accurate Closed/Open counts and caps TopOpen
// at TargetGroupTopOpenLimit even when far more than that many targets are
// open, so the summary itself cannot grow with attacker-chosen input.
func TestManager_TargetGroupStatuses_ReportsBoundedSummary(t *testing.T) {
	mgr := NewManager()
	cfg := TargetConfig{Group: "http01", NewConfig: fastTripConfig, Capacity: 100}

	const openCount = TargetGroupTopOpenLimit + 15
	for i := 0; i < openCount; i++ {
		mgr.TargetBreaker(cfg, fmt.Sprintf("open-%d.example.com", i)).Trip()
	}
	for i := 0; i < 3; i++ {
		mgr.TargetBreaker(cfg, fmt.Sprintf("closed-%d.example.com", i))
	}

	status := mgr.TargetGroupStatuses()["http01"]
	assert.Equal(t, openCount+3, status.Tracked)
	assert.Equal(t, openCount, status.Open)
	assert.Equal(t, 3, status.Closed)
	assert.Zero(t, status.HalfOpen)
	assert.Len(t, status.TopOpen, TargetGroupTopOpenLimit, "TopOpen must stay bounded regardless of how many targets are open")
}

// TestManager_TargetBreaker_ConcurrentAccessIsRaceFree drives many
// goroutines through TargetBreaker (some sharing targets, some distinct) and
// TargetGroupStatuses concurrently. It asserts no panics/deadlocks and that
// the table stays within its configured capacity; run with -race, its real
// purpose is proving there is no data race in targetTable's LRU/TTL
// bookkeeping.
func TestManager_TargetBreaker_ConcurrentAccessIsRaceFree(t *testing.T) {
	mgr := NewManager()
	cfg := TargetConfig{Group: "http01", NewConfig: fastTripConfig, Capacity: 50}

	const goroutines = 64
	const iterations = 200
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				target := fmt.Sprintf("target-%d.example.com", (g*iterations+i)%97)
				cb := mgr.TargetBreaker(cfg, target)
				if i%10 == 0 {
					cb.Trip()
				}
				_ = mgr.TargetGroupStatuses()
			}
		}(g)
	}
	wg.Wait()

	status := mgr.TargetGroupStatuses()["http01"]
	assert.LessOrEqual(t, status.Tracked, 50, "table must never exceed its configured capacity under concurrent load")
}

// TestManager_TargetBreaker_NamedManagerBreakersUnaffected verifies the
// separation this feature relies on: target breakers do not appear in the
// Manager's flat named registry (List/Status/Get), so a flood of distinct
// targets cannot evict or crowd out a small set of operator-named breakers
// (e.g. "storage", "kms").
func TestManager_TargetBreaker_NamedManagerBreakersUnaffected(t *testing.T) {
	mgr := NewManager()
	mgr.Get("storage")

	cfg := TargetConfig{Group: "http01", NewConfig: fastTripConfig, Capacity: 10}
	for i := 0; i < 100; i++ {
		mgr.TargetBreaker(cfg, fmt.Sprintf("target-%d.example.com", i))
	}

	list := mgr.List()
	require.Len(t, list, 1, "only the named breaker must appear in the flat registry")
	assert.Equal(t, "storage", list[0].Name())
}
