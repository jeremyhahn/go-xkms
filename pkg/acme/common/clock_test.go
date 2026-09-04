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

package common

import (
	"sync"
	"time"
)

// fakeClock is a manually advanced time source for the nonce TTL tests.
//
// It exists because the tests it serves were asserting on the scheduler rather
// than on the code: time.Sleep guarantees a MINIMUM duration and no maximum, so
// "sleep 80ms, then assert the 100ms TTL has not elapsed" is an assertion that
// the machine stayed idle. Under -race on a runner building three branches at
// once it does not, and go-xkms#243 records the cost -- these tests reddened
// three PRs that do not touch this package.
//
// Advancing a counter instead makes the same assertions exact and removes every
// sleep, so the tests are both deterministic and faster.
//
// It is safe for concurrent use: NonceStore reads the clock under its own
// mutex, but a test may advance it from another goroutine.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// newFakeClock starts at a fixed, arbitrary instant. The absolute value is
// irrelevant -- only the deltas matter -- but it is deliberately not the zero
// Time, so that a bug reading an unset timestamp shows up as a wild duration
// rather than as a plausible-looking one.
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

// newTestNonceStore returns a store whose time source is the returned clock, so
// a test advances time rather than waiting for it.
func newTestNonceStore(ttl time.Duration) (*NonceStore, *fakeClock) {
	clock := newFakeClock()
	return NewNonceStore(ttl, WithClock(clock.Now)), clock
}
