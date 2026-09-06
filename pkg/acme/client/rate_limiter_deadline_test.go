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

package client

import (
	"context"
	"math"
	"testing"
	"time"
)

// newDeadlineTestLimiter returns a limiter whose token bucket never blocks, so
// every assertion below is about the retry-after deadline and nothing else.
func newDeadlineTestLimiter(maxWait time.Duration) *RateLimiter {
	return NewRateLimiter(&RateLimiterConfig{
		Enabled:           true,
		RequestsPerSecond: 1000,
		BurstSize:         1000,
		MaxWaitTime:       maxWait,
		RetryAfterHeader:  true,
	})
}

// TestRateLimiter_Wait_HonoursSubSecondRetryAfter is the regression test for the
// truncation defect: the deadline used to be stored via Time.Unix(), so a
// sub-second Retry-After collapsed to a whole-second boundary and Wait could
// return before the instant the server asked for.
//
// The assertion is the property itself — Wait must not return before the
// deadline the caller asked for — rather than a wall-clock boundary. The two
// durations are deliberately chosen so that no phase within the current second
// lets second-granularity storage satisfy both: passing the shorter one
// requires the call to land in the last 120ms of a second, and passing the
// longer one then leaves at most 120ms of wait against a required 320ms.
func TestRateLimiter_Wait_HonoursSubSecondRetryAfter(t *testing.T) {
	for _, retryAfter := range []time.Duration{120 * time.Millisecond, 320 * time.Millisecond} {
		t.Run(retryAfter.String(), func(t *testing.T) {
			rl := newDeadlineTestLimiter(5 * time.Second)

			before := time.Now()
			rl.SetRetryAfter(retryAfter)
			// The real deadline is at or after this instant, because
			// SetRetryAfter reads the clock at or after `before`.
			deadline := before.Add(retryAfter)

			if err := rl.Wait(context.Background()); err != nil {
				t.Fatalf("Wait() returned %v, want nil", err)
			}

			if resumed := time.Now(); resumed.Before(deadline) {
				t.Errorf("Wait() resumed %v before the server deadline", deadline.Sub(resumed))
			}

			if rl.retryUntil.Load() != 0 {
				t.Error("expected the expired retry-after deadline to be cleared")
			}
		})
	}
}

// TestRateLimiter_Wait_HonoursExtendedDeadline covers a second 429 arriving
// while Wait is already parked: the newer, later deadline must win. Wait used
// to sleep once and then unconditionally clear the field, so it resumed on the
// original deadline and discarded the extension.
func TestRateLimiter_Wait_HonoursExtendedDeadline(t *testing.T) {
	rl := newDeadlineTestLimiter(5 * time.Second)

	const initial = 200 * time.Millisecond
	const extended = 400 * time.Millisecond

	before := time.Now()
	rl.SetRetryAfter(initial)

	// Extend the deadline while Wait is parked on the first one.
	extend := time.AfterFunc(50*time.Millisecond, func() {
		rl.SetRetryAfterTime(before.Add(extended))
	})
	defer extend.Stop()

	if err := rl.Wait(context.Background()); err != nil {
		t.Fatalf("Wait() returned %v, want nil", err)
	}

	if resumed := time.Now(); resumed.Before(before.Add(extended)) {
		t.Errorf("Wait() resumed %v before the extended deadline",
			before.Add(extended).Sub(resumed))
	}
}

// TestRateLimiter_Wait_ContextCancelledDuringRetryAfter is the failure path:
// a context that expires first must surface its own error, not a silent
// early resume.
func TestRateLimiter_Wait_ContextCancelledDuringRetryAfter(t *testing.T) {
	rl := newDeadlineTestLimiter(5 * time.Second)
	rl.SetRetryAfter(2 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	if err := rl.Wait(ctx); err != context.DeadlineExceeded {
		t.Errorf("Wait() returned %v, want context.DeadlineExceeded", err)
	}

	if rl.retryUntil.Load() == 0 {
		t.Error("expected the retry-after deadline to survive a cancelled Wait")
	}
}

// TestRateLimiter_Wait_SubSecondRetryAfterExceedsMaxWait is the failure path for
// a deadline the caller is unwilling to wait out.
func TestRateLimiter_Wait_SubSecondRetryAfterExceedsMaxWait(t *testing.T) {
	rl := newDeadlineTestLimiter(10 * time.Millisecond)
	rl.SetRetryAfter(500 * time.Millisecond)

	if err := rl.Wait(context.Background()); err != ErrRateLimitExceeded {
		t.Errorf("Wait() returned %v, want ErrRateLimitExceeded", err)
	}
}

// TestRateLimiter_Allow_SubSecondRetryAfter covers both Allow branches around a
// sub-second deadline: refused while it is in effect, admitted once it passes.
func TestRateLimiter_Allow_SubSecondRetryAfter(t *testing.T) {
	t.Run("refuses during an active sub-second deadline", func(t *testing.T) {
		rl := newDeadlineTestLimiter(time.Second)
		rl.SetRetryAfter(300 * time.Millisecond)

		if rl.Allow() {
			t.Error("Allow() admitted a request inside the retry-after period")
		}
		if rl.retryUntil.Load() == 0 {
			t.Error("expected an active deadline to be left in place")
		}
	})

	t.Run("admits and clears once the deadline has passed", func(t *testing.T) {
		rl := newDeadlineTestLimiter(time.Second)
		rl.retryUntil.Store(time.Now().Add(-time.Nanosecond).UnixNano())

		if !rl.Allow() {
			t.Error("Allow() refused a request after the retry-after period ended")
		}
		if rl.retryUntil.Load() != 0 {
			t.Error("expected the expired deadline to be cleared")
		}
	})
}

// TestRateLimiter_Stats_IsBlockedSubSecond checks that Stats reports a
// sub-second block, which second-granularity storage could not represent.
func TestRateLimiter_Stats_IsBlockedSubSecond(t *testing.T) {
	rl := newDeadlineTestLimiter(time.Second)

	if stats := rl.Stats(); stats.IsBlocked {
		t.Error("Stats() reported blocked with no retry-after set")
	}

	rl.SetRetryAfter(300 * time.Millisecond)

	if stats := rl.Stats(); !stats.IsBlocked {
		t.Error("Stats() reported not blocked inside a sub-second retry-after period")
	}
}

// TestRateLimiter_StoreRetryDeadline covers the nanosecond round trip and the
// clamp that keeps an unrepresentable deadline from wrapping to a negative
// value, which would read back as "not blocked".
func TestRateLimiter_StoreRetryDeadline(t *testing.T) {
	t.Run("preserves nanosecond precision", func(t *testing.T) {
		rl := newDeadlineTestLimiter(time.Second)
		until := time.Now().Add(1500 * time.Millisecond)

		rl.storeRetryDeadline(until)

		if got := rl.retryUntil.Load(); got != until.UnixNano() {
			t.Errorf("stored deadline = %d, want %d", got, until.UnixNano())
		}
	})

	t.Run("clamps a deadline past the representable range", func(t *testing.T) {
		rl := newDeadlineTestLimiter(time.Second)

		rl.storeRetryDeadline(maxRetryDeadline.Add(365 * 24 * time.Hour))

		got := rl.retryUntil.Load()
		if got != math.MaxInt64 {
			t.Errorf("clamped deadline = %d, want %d", got, int64(math.MaxInt64))
		}
		if rl.Allow() {
			t.Error("Allow() admitted a request against a clamped far-future deadline")
		}
	})
}

// TestRateLimiter_SetRetryAfter_Rejected covers the setter failure paths: a
// non-positive duration, a deadline already in the past, and a limiter
// configured to ignore Retry-After entirely.
func TestRateLimiter_SetRetryAfter_Rejected(t *testing.T) {
	t.Run("non-positive duration", func(t *testing.T) {
		rl := newDeadlineTestLimiter(time.Second)

		rl.SetRetryAfter(0)
		rl.SetRetryAfter(-time.Second)

		if rl.retryUntil.Load() != 0 {
			t.Error("expected no deadline from a non-positive duration")
		}
	})

	t.Run("past deadline", func(t *testing.T) {
		rl := newDeadlineTestLimiter(time.Second)

		rl.SetRetryAfterTime(time.Now().Add(-time.Millisecond))

		if rl.retryUntil.Load() != 0 {
			t.Error("expected no deadline from a past instant")
		}
	})

	t.Run("Retry-After handling disabled", func(t *testing.T) {
		rl := NewRateLimiter(&RateLimiterConfig{
			Enabled:          true,
			BurstSize:        100,
			MaxWaitTime:      time.Second,
			RetryAfterHeader: false,
		})

		rl.SetRetryAfter(300 * time.Millisecond)
		rl.SetRetryAfterTime(time.Now().Add(300 * time.Millisecond))

		if rl.retryUntil.Load() != 0 {
			t.Error("expected no deadline when Retry-After handling is disabled")
		}
		if !rl.Allow() {
			t.Error("Allow() refused a request with Retry-After handling disabled")
		}
	})
}
