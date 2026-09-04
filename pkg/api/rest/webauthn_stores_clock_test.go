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

package rest

import (
	"sync"
	"testing"
	"time"
)

// fakeClock is a manually advanced time source for the session-expiry tests.
//
// It is safe for concurrent use: the store reads the clock under its own lock,
// and the cleanup goroutine may read it while a test advances it.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// newFakeClock starts at a fixed, arbitrary instant. Only deltas matter, but it
// is deliberately not the zero Time so that a bug reading an unset timestamp
// shows up as a wild duration rather than a plausible one.
func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

// Now returns the current fake time.
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward by d.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// waitFor polls cond until it reports true, failing the test if it never does.
//
// It replaces "sleep long enough that the background cleanup has probably run".
// A fixed sleep asserts the goroutine was scheduled inside a window nothing
// promises; polling asserts the EVENT. The deadline is deliberately generous so
// that it is a hang detector rather than a second coin flip.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()

	const (
		deadline = 30 * time.Second
		interval = 2 * time.Millisecond
	)

	start := time.Now()
	for time.Since(start) < deadline {
		if cond() {
			return
		}
		time.Sleep(interval)
	}
	t.Fatalf("timed out after %s waiting for %s", deadline, what)
}
