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

package webauthn

import (
	"context"
	"time"
)

// DefaultSessionSweepInterval is how often a service owner sweeps expired
// ceremony sessions. It is half the default session TTL, so an abandoned
// ceremony is held for at most about one and a half TTLs.
const DefaultSessionSweepInterval = time.Minute

// SweepSessions removes expired sessions from store every interval until ctx
// is done, then returns. It blocks, so the caller runs it on a goroutine
// whose lifetime it owns — cancelling ctx and waiting for the return is how
// that goroutine is stopped without a leak.
//
// A store that does not implement SessionCleaner expires sessions itself;
// SweepSessions then returns immediately. A non-positive interval selects
// DefaultSessionSweepInterval.
func SweepSessions(ctx context.Context, store SessionStore, interval time.Duration) {
	cleaner, ok := store.(SessionCleaner)
	if !ok {
		return
	}
	if interval <= 0 {
		interval = DefaultSessionSweepInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cleaner.Cleanup()
		}
	}
}

// SweepSessions sweeps the service's session store every interval until ctx
// is done. See the package-level SweepSessions.
func (s *Service) SweepSessions(ctx context.Context, interval time.Duration) {
	SweepSessions(ctx, s.sessions, interval)
}
