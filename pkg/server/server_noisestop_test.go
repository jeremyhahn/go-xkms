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

package server

import (
	"errors"
	"testing"

	noiseboot "github.com/jeremyhahn/go-truststrap/pkg/noiseproto/bootstrap"
)

// TestNoiseStopDrained pins the decision that licenses freeing the Noise
// bootstrap key's protected pages against the Stop contract of the pinned
// go-truststrap (v0.4.0-alpha, go-truststrap#13): nil is returned only after
// the run's WaitGroup has emptied, and every other outcome is a non-nil
// sentinel. The error is the whole decision.
//
// The rows name the sentinels upstream actually returns, so a future pin that
// renames or removes one turns this red instead of silently changing what a
// retained or destroyed key means. The last row is the one the previous
// decision got wrong: it also read the caller's context, and a server that
// drained as the deadline expired was retained and reported incomplete
// (go-xkms#83).
func TestNoiseStopDrained(t *testing.T) {
	tests := []struct {
		name    string
		stopErr error
		drained bool
	}{
		{
			name:    "stop returned nil: the drain completed",
			stopErr: nil,
			drained: true,
		},
		{
			name:    "stop returned ErrShutdownIncomplete: the caller's deadline expired first",
			stopErr: noiseboot.ErrShutdownIncomplete,
			drained: false,
		},
		{
			name:    "stop returned ErrServerNotStarted: nothing was waited for",
			stopErr: noiseboot.ErrServerNotStarted,
			drained: false,
		},
		{
			name:    "stop failed for any other reason",
			stopErr: errors.New("noise: listener close failed"),
			drained: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := noiseStopDrained(tc.stopErr); got != tc.drained {
				t.Fatalf("noiseStopDrained(%v) = %v, want %v — a wrong answer here "+
					"either frees protected pages a handshake is still reading, or "+
					"retains a key that was safe to wipe",
					tc.stopErr, got, tc.drained)
			}
		})
	}
}
