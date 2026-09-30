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
	"container/list"
	"sync"
	"time"
)

// Default bounds for a per-target breaker group, applied whenever a
// TargetConfig leaves Capacity or IdleTTL at its zero value.
const (
	// DefaultTargetCapacity is the maximum number of distinct targets a
	// per-target breaker group tracks at once.
	DefaultTargetCapacity = 1000

	// DefaultTargetIdleTTL evicts a target that has not been used for at
	// least this long, independent of Capacity.
	DefaultTargetIdleTTL = 10 * time.Minute
)

// TargetGroupTopOpenLimit bounds how many open targets TargetGroupStatus.TopOpen
// names. A group can hold up to a group's configured Capacity targets; this
// keeps /acme/health bounded regardless of Capacity or how many of those
// targets happen to be open at once.
const TargetGroupTopOpenLimit = 10

// TargetConfig configures one bounded group of per-target circuit breakers:
// breakers keyed not by a name an operator chose, but by whatever host or
// zone a caller's validation last named -- so a target seen for the first
// time gets its own breaker on demand, and a flood of distinct targets
// cannot grow the group without bound.
//
// This is what closes go-xkms#1189/#1190: a single breaker shared by every
// account's http-01 (or dns-01) validation let one account whose target
// always failed trip the breaker for everybody. A TargetConfig group gives
// every target its own breaker, so a failing target stalls only itself.
type TargetConfig struct {
	// Group names this set for logging/metrics and prefixes every breaker's
	// reported Name ("Group:target"). Required.
	Group string

	// NewConfig builds the *Config for a target seen for the first time,
	// named name (Group + ":" + target). Required.
	NewConfig func(name string) *Config

	// Capacity bounds the number of distinct targets tracked at once for
	// this group. The least recently used target is evicted first when a
	// new target would exceed it. Zero selects DefaultTargetCapacity.
	Capacity int

	// IdleTTL evicts a target that has not been used for at least this
	// long, independent of Capacity. Zero selects DefaultTargetIdleTTL.
	IdleTTL time.Duration
}

// resolveCapacity returns cfg.Capacity, substituting DefaultTargetCapacity
// when it is not positive.
func (cfg TargetConfig) resolveCapacity() int {
	if cfg.Capacity > 0 {
		return cfg.Capacity
	}
	return DefaultTargetCapacity
}

// resolveIdleTTL returns cfg.IdleTTL, substituting DefaultTargetIdleTTL when
// it is not positive.
func (cfg TargetConfig) resolveIdleTTL() time.Duration {
	if cfg.IdleTTL > 0 {
		return cfg.IdleTTL
	}
	return DefaultTargetIdleTTL
}

// TargetGroupStatus summarizes one bounded group of per-target breakers for
// reporting (see Manager.TargetGroupStatuses). It never grows with the
// number of distinct targets a group has ever tracked: Tracked/Closed/
// HalfOpen/Open are counts bounded by the group's Capacity, and TopOpen lists
// at most TargetGroupTopOpenLimit of the currently open targets by name --
// the operationally useful detail (which hosts are failing right now)
// without listing every target the group happens to be holding.
type TargetGroupStatus struct {
	// Capacity is the group's configured maximum number of tracked targets.
	Capacity int `json:"capacity"`

	// Tracked is the number of targets currently held in the group's bounded
	// table (at most Capacity).
	Tracked int `json:"tracked"`

	// Closed is the number of tracked targets whose breaker is closed.
	Closed int `json:"closed"`

	// HalfOpen is the number of tracked targets whose breaker is half-open.
	HalfOpen int `json:"half_open"`

	// Open is the number of tracked targets whose breaker is open.
	Open int `json:"open"`

	// TopOpen names up to TargetGroupTopOpenLimit of the currently open
	// targets. Empty when Open is zero.
	TopOpen []string `json:"top_open,omitempty"`
}

// targetEntry is one target's breaker plus the bookkeeping targetTable needs
// for LRU/TTL eviction.
type targetEntry struct {
	target   string
	breaker  *CircuitBreaker
	lastUsed time.Time
}

// targetTable is a bounded, LRU-ordered table of per-target circuit
// breakers for a single TargetConfig group.
//
// The eviction list is ordered by recency of use, most-recently-used at the
// front. Because every touch (creation or lookup) moves an entry to the
// front, the entry at the back is simultaneously the least recently used
// and the longest idle -- so a single list serves both Capacity eviction
// (trim the back) and IdleTTL eviction (prune from the back while stale),
// with neither needing its own bookkeeping.
type targetTable struct {
	mu       sync.Mutex
	cfg      TargetConfig
	capacity int
	ttl      time.Duration
	order    *list.List // *targetEntry, front = most recently used
	elements map[string]*list.Element
}

// newTargetTable creates an empty bounded table for cfg.
func newTargetTable(cfg TargetConfig) *targetTable {
	return &targetTable{
		cfg:      cfg,
		capacity: cfg.resolveCapacity(),
		ttl:      cfg.resolveIdleTTL(),
		order:    list.New(),
		elements: make(map[string]*list.Element),
	}
}

// get returns the breaker for target, creating it via cfg.NewConfig if this
// is the first time target has been seen (or if it was since evicted).
// Every call prunes idle-expired entries and marks target as most recently
// used, so a busy target is never evicted ahead of an idle one regardless of
// insertion order.
func (t *targetTable) get(target string) *CircuitBreaker {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	t.pruneExpiredLocked(now)

	if el, ok := t.elements[target]; ok {
		entry := el.Value.(*targetEntry)
		entry.lastUsed = now
		t.order.MoveToFront(el)
		return entry.breaker
	}

	name := t.cfg.Group + ":" + target
	entry := &targetEntry{
		target:   target,
		breaker:  New(t.cfg.NewConfig(name)),
		lastUsed: now,
	}
	el := t.order.PushFront(entry)
	t.elements[target] = el

	if t.order.Len() > t.capacity {
		t.evictBackLocked()
	}

	return entry.breaker
}

// pruneExpiredLocked evicts every entry idle for at least t.ttl, walking
// from the back of the list (oldest first) and stopping at the first entry
// that is still fresh -- everything ahead of it in the list was touched more
// recently and so cannot be expired either. t.mu must be held.
func (t *targetTable) pruneExpiredLocked(now time.Time) {
	for {
		back := t.order.Back()
		if back == nil {
			return
		}
		entry := back.Value.(*targetEntry)
		if now.Sub(entry.lastUsed) < t.ttl {
			return
		}
		t.order.Remove(back)
		delete(t.elements, entry.target)
	}
}

// evictBackLocked removes the single least-recently-used entry. t.mu must be
// held, and the list must be non-empty.
func (t *targetTable) evictBackLocked() {
	back := t.order.Back()
	if back == nil {
		return
	}
	t.order.Remove(back)
	delete(t.elements, back.Value.(*targetEntry).target)
}

// status summarizes the table's current contents. t.mu is taken for the
// duration of the scan; the scan itself is bounded by t.capacity, which is
// what keeps this -- and therefore /acme/health -- bounded regardless of how
// many distinct targets have been seen over the table's lifetime.
func (t *targetTable) status() TargetGroupStatus {
	t.mu.Lock()
	defer t.mu.Unlock()

	status := TargetGroupStatus{
		Capacity: t.capacity,
		Tracked:  t.order.Len(),
	}
	for el := t.order.Front(); el != nil; el = el.Next() {
		entry := el.Value.(*targetEntry)
		switch entry.breaker.State() {
		case StateClosed:
			status.Closed++
		case StateHalfOpen:
			status.HalfOpen++
		case StateOpen:
			status.Open++
			if len(status.TopOpen) < TargetGroupTopOpenLimit {
				status.TopOpen = append(status.TopOpen, entry.target)
			}
		}
	}
	return status
}

// TargetBreaker returns the circuit breaker for target within cfg's group,
// creating the group's bounded table and/or the breaker for target as
// needed. Concurrent calls for the same group share one table; concurrent
// calls for the same target within that table share one breaker.
//
// The breaker this returns is intentionally NOT stored in m's flat name
// registry (Get/GetOrCreate/List/Status): those exist for a small, fixed set
// of named dependencies (http01, dns01, ct, kms, storage) an operator
// configures once, and listing every target a group has ever tracked would
// make List/Status/HealthHandler grow with attacker-chosen input. Use
// TargetGroupStatuses for bounded reporting on target breakers instead.
func (m *Manager) TargetBreaker(cfg TargetConfig, target string) *CircuitBreaker {
	return m.targetTable(cfg).get(target)
}

// RegisterTargetGroup ensures cfg's group has a (possibly empty) bounded
// table, so the group is visible in TargetGroupStatuses immediately -- e.g.
// at startup, before any target has been validated -- rather than only after
// the first call to TargetBreaker for that group.
func (m *Manager) RegisterTargetGroup(cfg TargetConfig) {
	m.targetTable(cfg)
}

// targetTable returns cfg.Group's bounded table, creating it from cfg on
// first use. The config that wins a race to create the table is whichever
// caller's LoadOrStore lands first, matching GetOrCreate's "first registered
// config wins" rule for named breakers.
func (m *Manager) targetTable(cfg TargetConfig) *targetTable {
	if table, ok := m.targets.Load(cfg.Group); ok {
		return table.(*targetTable)
	}
	actual, _ := m.targets.LoadOrStore(cfg.Group, newTargetTable(cfg))
	return actual.(*targetTable)
}

// TargetGroupStatuses returns a bounded summary of every per-target breaker
// group registered on m (via TargetBreaker or RegisterTargetGroup), keyed by
// group name. Unlike List/Status, this never grows with the number of
// distinct targets seen -- see TargetGroupStatus.
func (m *Manager) TargetGroupStatuses() map[string]TargetGroupStatus {
	statuses := make(map[string]TargetGroupStatus)
	m.targets.Range(func(key, value any) bool {
		statuses[key.(string)] = value.(*targetTable).status()
		return true
	})
	return statuses
}
