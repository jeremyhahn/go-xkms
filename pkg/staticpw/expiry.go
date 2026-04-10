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

package staticpw

import (
	"sync"
	"time"
)

// ExpiryChecker periodically checks for expired password entries and
// deletes them, invoking the onExpiry callback for each expired entry.
type ExpiryChecker struct {
	store    Store
	interval time.Duration
	onExpiry func(pw *StaticPassword)
	done     chan struct{}
	stopped  chan struct{}
	stopOnce sync.Once
}

// NewExpiryChecker creates a new ExpiryChecker that periodically scans the
// store for expired entries. The onExpiry callback is called for each
// expired entry before it is deleted.
func NewExpiryChecker(store Store, interval time.Duration, onExpiry func(pw *StaticPassword)) *ExpiryChecker {
	return &ExpiryChecker{
		store:    store,
		interval: interval,
		onExpiry: onExpiry,
		done:     make(chan struct{}),
		stopped:  make(chan struct{}),
	}
}

// Start begins the background expiry checking loop. It runs a ticker
// at the configured interval and calls CheckExpired on each tick.
func (c *ExpiryChecker) Start() {
	go func() {
		defer close(c.stopped)

		ticker := time.NewTicker(c.interval)
		defer ticker.Stop()

		for {
			select {
			case <-c.done:
				return
			case <-ticker.C:
				_, _ = c.CheckExpired()
			}
		}
	}()
}

// Stop signals the background goroutine to exit and waits for it to finish.
// Stop is safe to call multiple times; subsequent calls are no-ops.
func (c *ExpiryChecker) Stop() {
	c.stopOnce.Do(func() {
		close(c.done)
	})
	<-c.stopped
}

// CheckExpired scans all entries and deletes those whose ExpiresAt has passed.
// The onExpiry callback is invoked for each expired entry. Returns the list
// of deleted entries.
func (c *ExpiryChecker) CheckExpired() ([]*StaticPassword, error) {
	passwords, err := c.store.List()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	expired := make([]*StaticPassword, 0)

	for _, pw := range passwords {
		if pw.ExpiresAt.IsZero() {
			continue
		}
		if pw.ExpiresAt.Before(now) {
			if delErr := c.store.Delete(pw.ID); delErr != nil {
				return expired, delErr
			}
			if c.onExpiry != nil {
				c.onExpiry(pw)
			}
			expired = append(expired, pw)
		}
	}

	return expired, nil
}
