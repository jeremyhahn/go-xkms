// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package server

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestNoiseStopDrained pins the decision that licenses freeing the Noise
// bootstrap key's protected pages.
//
// Both halves are load-bearing and each was, at some point, the whole
// condition on one of the two paths that stop this server:
//
//   - The context alone: upstream Stop returns immediately with
//     ErrServerNotStarted when it does not consider itself started, and that
//     fast return leaves the deadline unexpired. Read as "drained", it frees a
//     key whose handshake workers may still be running. This was the surviving
//     reading on the startup-teardown path.
//   - The error alone: upstream Stop returns nil whether its workers drained
//     or its own deadline expired. Read as "drained", it frees the key of a
//     server that timed out.
//
// Drop either conjunct and one of the rows below turns green when it must not.
func TestNoiseStopDrained(t *testing.T) {
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()

	live, cancelLive := context.WithTimeout(context.Background(), time.Minute)
	defer cancelLive()

	tests := []struct {
		name    string
		stopErr error
		ctx     context.Context
		drained bool
	}{
		{
			name:    "stop returned nil inside its deadline",
			stopErr: nil,
			ctx:     live,
			drained: true,
		},
		{
			name:    "stop returned early without waiting",
			stopErr: errors.New("noise: server not started"),
			ctx:     live,
			drained: false,
		},
		{
			name:    "stop swallowed its own expired deadline",
			stopErr: nil,
			ctx:     expired,
			drained: false,
		},
		{
			name:    "stop failed and the deadline expired",
			stopErr: errors.New("noise: server not started"),
			ctx:     expired,
			drained: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := noiseStopDrained(tc.stopErr, tc.ctx); got != tc.drained {
				t.Fatalf("noiseStopDrained(%v, deadline expired=%v) = %v, want %v — "+
					"a wrong answer here either frees protected pages a handshake "+
					"is still reading, or retains a key that was safe to wipe",
					tc.stopErr, tc.ctx.Err() != nil, got, tc.drained)
			}
		})
	}
}
