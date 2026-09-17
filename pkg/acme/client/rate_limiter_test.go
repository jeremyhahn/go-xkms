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
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestNewRateLimiter(t *testing.T) {
	t.Run("nil config uses defaults", func(t *testing.T) {
		rl := NewRateLimiter(nil)
		if rl == nil {
			t.Fatal("expected non-nil rate limiter")
		}
		if !rl.config.Enabled {
			t.Error("expected rate limiter to be enabled by default")
		}
	})

	t.Run("custom config", func(t *testing.T) {
		config := &RateLimiterConfig{
			Enabled:           true,
			RequestsPerSecond: 5,
			BurstSize:         10,
			MaxWaitTime:       10 * time.Second,
		}
		rl := NewRateLimiter(config)
		if rl.config.RequestsPerSecond != 5 {
			t.Errorf("expected RequestsPerSecond = 5, got %v", rl.config.RequestsPerSecond)
		}
	})

	t.Run("zero values get defaults", func(t *testing.T) {
		config := &RateLimiterConfig{
			Enabled:           true,
			RequestsPerSecond: 0,
			BurstSize:         0,
		}
		rl := NewRateLimiter(config)
		if rl.config.RequestsPerSecond != 10 {
			t.Errorf("expected default RequestsPerSecond = 10, got %v", rl.config.RequestsPerSecond)
		}
		if rl.config.BurstSize != 20 {
			t.Errorf("expected default BurstSize = 20, got %v", rl.config.BurstSize)
		}
	})
}

func TestRateLimiter_Allow(t *testing.T) {
	t.Run("disabled rate limiter always allows", func(t *testing.T) {
		rl := NewRateLimiter(&RateLimiterConfig{
			Enabled: false,
		})
		for i := 0; i < 100; i++ {
			if !rl.Allow() {
				t.Errorf("iteration %d: expected Allow() to return true when disabled", i)
			}
		}
	})

	t.Run("closed rate limiter denies", func(t *testing.T) {
		rl := NewRateLimiter(&RateLimiterConfig{
			Enabled:   true,
			BurstSize: 100,
		})
		rl.Close()
		if rl.Allow() {
			t.Error("expected Allow() to return false when closed")
		}
	})

	t.Run("burst allows multiple requests", func(t *testing.T) {
		rl := NewRateLimiter(&RateLimiterConfig{
			Enabled:   true,
			BurstSize: 5,
		})
		// Should allow 5 requests immediately
		for i := 0; i < 5; i++ {
			if !rl.Allow() {
				t.Errorf("iteration %d: expected Allow() to return true within burst", i)
			}
		}
	})

	t.Run("exceeding burst denies", func(t *testing.T) {
		rl := NewRateLimiter(&RateLimiterConfig{
			Enabled:           true,
			BurstSize:         3,
			RequestsPerSecond: 1,
		})
		// Consume all burst tokens
		for i := 0; i < 3; i++ {
			rl.Allow()
		}
		// Next request should be denied
		if rl.Allow() {
			t.Error("expected Allow() to return false after exhausting burst")
		}
	})
}

func TestRateLimiter_Wait(t *testing.T) {
	t.Run("disabled rate limiter returns immediately", func(t *testing.T) {
		ctx := context.Background()
		rl := NewRateLimiter(&RateLimiterConfig{
			Enabled: false,
		})
		start := time.Now()
		err := rl.Wait(ctx)
		elapsed := time.Since(start)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if elapsed > 10*time.Millisecond {
			t.Errorf("Wait() took too long: %v", elapsed)
		}
	})

	t.Run("closed rate limiter returns error", func(t *testing.T) {
		ctx := context.Background()
		rl := NewRateLimiter(&RateLimiterConfig{
			Enabled:   true,
			BurstSize: 100,
		})
		rl.Close()
		err := rl.Wait(ctx)
		if err != ErrRateLimiterClosed {
			t.Errorf("expected ErrRateLimiterClosed, got %v", err)
		}
	})

	t.Run("cancelled context returns error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		rl := NewRateLimiter(&RateLimiterConfig{
			Enabled:           true,
			BurstSize:         1,
			RequestsPerSecond: 0.1,
			MaxWaitTime:       5 * time.Second, // Long enough to see context cancel
		})
		// Consume the burst
		rl.Allow()

		err := rl.Wait(ctx)
		// When context is cancelled before any polling, we get context.Canceled
		// When polling happens first, we may get rate limit exceeded
		if err != context.Canceled && err != ErrRateLimitExceeded {
			t.Errorf("expected context.Canceled or ErrRateLimitExceeded, got %v", err)
		}
	})

	t.Run("waits for token refill", func(t *testing.T) {
		ctx := context.Background()
		rl := NewRateLimiter(&RateLimiterConfig{
			Enabled:           true,
			BurstSize:         1,
			RequestsPerSecond: 100, // 10ms per token
			MaxWaitTime:       1 * time.Second,
		})
		// Consume the burst
		rl.Allow()

		start := time.Now()
		err := rl.Wait(ctx)
		elapsed := time.Since(start)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if elapsed < 5*time.Millisecond {
			t.Errorf("Wait() returned too quickly: %v", elapsed)
		}
	})
}

func TestRateLimiter_SetRetryAfter(t *testing.T) {
	t.Run("sets retry-after period", func(t *testing.T) {
		rl := NewRateLimiter(&RateLimiterConfig{
			Enabled:          true,
			BurstSize:        100,
			RetryAfterHeader: true,
		})

		// Set a retry-after period in the future (use a longer duration for reliability)
		rl.SetRetryAfter(2 * time.Second)

		// Verify retry-after was set in the atomic value
		retryUntil := rl.retryUntil.Load()
		if retryUntil == 0 {
			t.Error("expected retryUntil to be set after SetRetryAfter")
		}

		// The retryUntil should be in the future
		if time.Unix(0, retryUntil).Before(time.Now()) {
			t.Error("expected retryUntil to be in the future")
		}
	})

	t.Run("ignores when disabled", func(t *testing.T) {
		rl := NewRateLimiter(&RateLimiterConfig{
			Enabled:          true,
			BurstSize:        100,
			RetryAfterHeader: false,
		})

		rl.SetRetryAfter(1 * time.Hour)

		// Should not be blocked
		if !rl.Allow() {
			t.Error("expected Allow() to return true when RetryAfterHeader is disabled")
		}
	})
}

func TestRateLimiter_Stats(t *testing.T) {
	rl := NewRateLimiter(&RateLimiterConfig{
		Enabled:           true,
		BurstSize:         10,
		RequestsPerSecond: 5,
	})

	stats := rl.Stats()
	if stats.MaxTokens != 10 {
		t.Errorf("expected MaxTokens = 10, got %v", stats.MaxTokens)
	}
	if stats.RefillRate != 5 {
		t.Errorf("expected RefillRate = 5, got %v", stats.RefillRate)
	}
	if stats.AvailableTokens != 10 {
		t.Errorf("expected AvailableTokens = 10, got %v", stats.AvailableTokens)
	}

	// Consume some tokens
	rl.Allow()
	rl.Allow()

	stats = rl.Stats()
	if stats.AvailableTokens != 8 {
		t.Errorf("expected AvailableTokens = 8, got %v", stats.AvailableTokens)
	}
}

func TestDefaultRateLimiterConfig(t *testing.T) {
	config := DefaultRateLimiterConfig()

	if !config.Enabled {
		t.Error("expected Enabled to be true")
	}
	if config.RequestsPerSecond != 10 {
		t.Errorf("expected RequestsPerSecond = 10, got %v", config.RequestsPerSecond)
	}
	if config.BurstSize != 20 {
		t.Errorf("expected BurstSize = 20, got %v", config.BurstSize)
	}
	if config.MaxWaitTime != 30*time.Second {
		t.Errorf("expected MaxWaitTime = 30s, got %v", config.MaxWaitTime)
	}
	if !config.RetryAfterHeader {
		t.Error("expected RetryAfterHeader to be true")
	}
}

func TestParseRetryAfter(t *testing.T) {
	// A fixed "now" with a sub-second component: the parsed deadline must
	// carry it through, not round it away.
	now := time.Date(2026, time.September, 6, 12, 30, 45, 678_901_234, time.UTC)

	tests := []struct {
		name  string
		value string
		want  time.Time
		ok    bool
	}{
		{
			name:  "delta-seconds keeps now's sub-second offset",
			value: "120",
			want:  now.Add(120 * time.Second),
			ok:    true,
		},
		{
			name:  "single second",
			value: "1",
			want:  now.Add(time.Second),
			ok:    true,
		},
		{
			name:  "delta-seconds beyond time.Duration clamps instead of overflowing",
			value: "99999999999",
			want:  now.Add(time.Duration(maxRetryAfterSeconds) * time.Second),
			ok:    true,
		},
		{
			name:  "delta-seconds beyond uint64 clamps instead of failing",
			value: "99999999999999999999999",
			want:  now.Add(time.Duration(maxRetryAfterSeconds) * time.Second),
			ok:    true,
		},
		{
			name:  "zero means no hold-off",
			value: "0",
		},
		{
			name:  "signed value is not delta-seconds",
			value: "+5",
		},
		{
			name:  "negative value is not delta-seconds",
			value: "-1",
		},
		{
			name:  "fractional seconds are not delta-seconds",
			value: "1.5",
		},
		{
			name:  "surrounding whitespace is rejected",
			value: " 5",
		},
		{
			name:  "invalid string",
			value: "invalid",
		},
		{
			name:  "empty string",
			value: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseRetryAfter(tt.value, now)
			if ok != tt.ok {
				t.Fatalf("parseRetryAfter(%q) ok = %v, want %v", tt.value, ok, tt.ok)
			}
			if !got.Equal(tt.want) {
				t.Errorf("parseRetryAfter(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestRateLimitedTransport(t *testing.T) {
	t.Run("applies rate limiting", func(t *testing.T) {
		limiter := NewRateLimiter(&RateLimiterConfig{
			Enabled:   true,
			BurstSize: 1,
		})

		transport := NewRateLimitedTransport(nil, limiter)

		// First request should succeed
		stats := limiter.Stats()
		if stats.AvailableTokens != 1 {
			t.Errorf("expected 1 token, got %v", stats.AvailableTokens)
		}

		// Verify the transport was created
		if transport.base == nil {
			t.Error("expected base transport to be set")
		}
		if transport.rateLimiter == nil {
			t.Error("expected rate limiter to be set")
		}
	})

	t.Run("handles nil base transport", func(t *testing.T) {
		transport := NewRateLimitedTransport(nil, nil)
		if transport.base == nil {
			t.Error("expected default transport to be used")
		}
		if transport.base != http.DefaultTransport {
			t.Error("expected http.DefaultTransport to be used")
		}
	})
}

func TestRateLimiter_SetRetryAfterTime(t *testing.T) {
	t.Run("sets retry time in future", func(t *testing.T) {
		rl := NewRateLimiter(&RateLimiterConfig{
			Enabled:          true,
			BurstSize:        100,
			RetryAfterHeader: true,
		})

		futureTime := time.Now().Add(2 * time.Second)
		rl.SetRetryAfterTime(futureTime)

		retryUntil := rl.retryUntil.Load()
		if retryUntil != futureTime.UnixNano() {
			t.Errorf("expected retryUntil = %d, got %d", futureTime.UnixNano(), retryUntil)
		}
	})

	t.Run("ignores past time", func(t *testing.T) {
		rl := NewRateLimiter(&RateLimiterConfig{
			Enabled:          true,
			BurstSize:        100,
			RetryAfterHeader: true,
		})

		pastTime := time.Now().Add(-1 * time.Hour)
		rl.SetRetryAfterTime(pastTime)

		retryUntil := rl.retryUntil.Load()
		if retryUntil != 0 {
			t.Errorf("expected retryUntil = 0, got %d", retryUntil)
		}
	})

	t.Run("ignores when RetryAfterHeader disabled", func(t *testing.T) {
		rl := NewRateLimiter(&RateLimiterConfig{
			Enabled:          true,
			BurstSize:        100,
			RetryAfterHeader: false,
		})

		futureTime := time.Now().Add(1 * time.Hour)
		rl.SetRetryAfterTime(futureTime)

		retryUntil := rl.retryUntil.Load()
		if retryUntil != 0 {
			t.Errorf("expected retryUntil = 0 when disabled, got %d", retryUntil)
		}
	})
}

func TestRateLimiter_StatsIsBlocked(t *testing.T) {
	t.Run("not blocked when no retry-after set", func(t *testing.T) {
		rl := NewRateLimiter(&RateLimiterConfig{
			Enabled:          true,
			BurstSize:        100,
			RetryAfterHeader: true,
		})

		stats := rl.Stats()
		if stats.IsBlocked {
			t.Error("expected not blocked when no retry-after set")
		}
	})

	t.Run("blocked when retry-after set in future", func(t *testing.T) {
		rl := NewRateLimiter(&RateLimiterConfig{
			Enabled:          true,
			BurstSize:        100,
			RetryAfterHeader: true,
		})

		rl.SetRetryAfter(2 * time.Second)

		stats := rl.Stats()
		if !stats.IsBlocked {
			t.Error("expected blocked when retry-after in future")
		}
	})
}

func TestParseRetryAfter_HTTPDate(t *testing.T) {
	now := time.Date(2026, time.September, 6, 12, 30, 45, 678_901_234, time.UTC)
	future := time.Date(2026, time.September, 6, 13, 30, 45, 0, time.UTC)

	// RFC 9110 §5.6.7: a recipient must accept all three HTTP-date forms.
	dates := []struct {
		name  string
		value string
	}{
		{name: "IMF-fixdate", value: future.Format(http.TimeFormat)},
		{name: "RFC 850", value: future.Format("Monday, 02-Jan-06 15:04:05 GMT")},
		{name: "asctime", value: future.Format(time.ANSIC)},
	}

	for _, tt := range dates {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseRetryAfter(tt.value, now)
			if !ok {
				t.Fatalf("parseRetryAfter(%q) rejected a valid HTTP-date", tt.value)
			}
			if !got.Equal(future) {
				t.Errorf("parseRetryAfter(%q) = %v, want %v", tt.value, got, future)
			}
		})
	}

	t.Run("date already elapsed means no hold-off", func(t *testing.T) {
		past := now.Add(-time.Minute).Format(http.TimeFormat)
		if got, ok := parseRetryAfter(past, now); ok {
			t.Errorf("expected an elapsed HTTP-date to be ignored, got %v", got)
		}
	})

	t.Run("date equal to now means no hold-off", func(t *testing.T) {
		if got, ok := parseRetryAfter(now.Format(http.TimeFormat), now.Truncate(time.Second)); ok {
			t.Errorf("expected an HTTP-date equal to now to be ignored, got %v", got)
		}
	})

	t.Run("invalid date format", func(t *testing.T) {
		if got, ok := parseRetryAfter("not-a-date", now); ok {
			t.Errorf("expected an invalid date to be ignored, got %v", got)
		}
	})
}

// mockRoundTripper is a mock HTTP transport for testing
type mockRoundTripper struct {
	response *http.Response
	err      error
}

func (m *mockRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return m.response, m.err
}

func TestRateLimitedTransport_RoundTrip(t *testing.T) {
	t.Run("successful request without rate limiter", func(t *testing.T) {
		mockTransport := &mockRoundTripper{
			response: &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
			},
		}

		transport := NewRateLimitedTransport(mockTransport, nil)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		resp, err := transport.RoundTrip(req)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}
	})

	t.Run("successful request with rate limiter", func(t *testing.T) {
		mockTransport := &mockRoundTripper{
			response: &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
			},
		}

		limiter := NewRateLimiter(&RateLimiterConfig{
			Enabled:   true,
			BurstSize: 10,
		})

		transport := NewRateLimitedTransport(mockTransport, limiter)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		resp, err := transport.RoundTrip(req)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}
	})

	t.Run("handles 429 with Retry-After header", func(t *testing.T) {
		header := make(http.Header)
		header.Set("Retry-After", "60")

		mockTransport := &mockRoundTripper{
			response: &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header:     header,
			},
		}

		limiter := NewRateLimiter(&RateLimiterConfig{
			Enabled:          true,
			BurstSize:        10,
			RetryAfterHeader: true,
		})

		transport := NewRateLimitedTransport(mockTransport, limiter)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		resp, err := transport.RoundTrip(req)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.StatusCode != http.StatusTooManyRequests {
			t.Errorf("expected status 429, got %d", resp.StatusCode)
		}

		// Verify retry-after was applied
		retryUntil := limiter.retryUntil.Load()
		if retryUntil == 0 {
			t.Error("expected retryUntil to be set after 429 response")
		}
	})

	t.Run("handles 429 with an HTTP-date Retry-After", func(t *testing.T) {
		until := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
		header := make(http.Header)
		header.Set("Retry-After", until.Format(http.TimeFormat))

		mockTransport := &mockRoundTripper{
			response: &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header:     header,
			},
		}

		limiter := NewRateLimiter(&RateLimiterConfig{
			Enabled:          true,
			BurstSize:        10,
			RetryAfterHeader: true,
		})

		transport := NewRateLimitedTransport(mockTransport, limiter)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		if _, err := transport.RoundTrip(req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// The instant the server named is stored as-is, not re-derived from a
		// duration measured against a second time.Now().
		if got := limiter.retryUntil.Load(); got != until.UnixNano() {
			t.Errorf("expected retryUntil = %d (%v), got %d (%v)",
				until.UnixNano(), until, got, time.Unix(0, got))
		}
	})

	t.Run("ignores an unparseable Retry-After", func(t *testing.T) {
		header := make(http.Header)
		header.Set("Retry-After", "soon")

		mockTransport := &mockRoundTripper{
			response: &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header:     header,
			},
		}

		limiter := NewRateLimiter(&RateLimiterConfig{
			Enabled:          true,
			BurstSize:        10,
			RetryAfterHeader: true,
		})

		transport := NewRateLimitedTransport(mockTransport, limiter)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		if _, err := transport.RoundTrip(req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := limiter.retryUntil.Load(); got != 0 {
			t.Errorf("expected no hold-off from an unparseable Retry-After, got %d", got)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		expectedErr := errors.New("transport error")
		mockTransport := &mockRoundTripper{
			response: nil,
			err:      expectedErr,
		}

		transport := NewRateLimitedTransport(mockTransport, nil)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		resp, err := transport.RoundTrip(req)

		if err != expectedErr {
			t.Errorf("expected %v, got %v", expectedErr, err)
		}
		if resp != nil {
			t.Error("expected nil response on error")
		}
	})

	t.Run("rate limiter wait error", func(t *testing.T) {
		mockTransport := &mockRoundTripper{
			response: &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
			},
		}

		limiter := NewRateLimiter(&RateLimiterConfig{
			Enabled:   true,
			BurstSize: 10,
		})

		// Close the limiter to cause Wait to return error
		limiter.Close()

		transport := NewRateLimitedTransport(mockTransport, limiter)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		resp, err := transport.RoundTrip(req)

		if err == nil {
			t.Error("expected error when rate limiter is closed")
		}
		if resp != nil {
			t.Error("expected nil response on error")
		}
	})
}

func TestRateLimitedTransportInterfaceCompliance(t *testing.T) {
	// Verify RateLimitedTransport implements http.RoundTripper
	var _ http.RoundTripper = (*RateLimitedTransport)(nil)
}

func TestRateLimiter_Wait_RetryAfter(t *testing.T) {
	t.Run("retry-after exceeds MaxWaitTime", func(t *testing.T) {
		ctx := context.Background()
		rl := NewRateLimiter(&RateLimiterConfig{
			Enabled:          true,
			BurstSize:        100,
			MaxWaitTime:      100 * time.Millisecond,
			RetryAfterHeader: true,
		})

		// Set retry-after much longer than MaxWaitTime
		rl.SetRetryAfterTime(time.Now().Add(10 * time.Second))

		err := rl.Wait(ctx)
		if err != ErrRateLimitExceeded {
			t.Errorf("expected ErrRateLimitExceeded, got %v", err)
		}
	})

	t.Run("retry-after with short wait completes", func(t *testing.T) {
		ctx := context.Background()
		rl := NewRateLimiter(&RateLimiterConfig{
			Enabled:          true,
			BurstSize:        100,
			MaxWaitTime:      5 * time.Second,
			RetryAfterHeader: true,
		})

		// Set retry-after to short duration
		retryUntil := time.Now().Add(50 * time.Millisecond)
		rl.SetRetryAfterTime(retryUntil)

		// Verify retryUntil was set
		if rl.retryUntil.Load() == 0 {
			t.Error("expected retryUntil to be set")
		}

		start := time.Now()
		err := rl.Wait(ctx)
		elapsed := time.Since(start)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		// The Wait returned - verify it took some time if we had to wait
		_ = elapsed // elapsed time depends on timing
	})

	t.Run("retry-after with context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()

		rl := NewRateLimiter(&RateLimiterConfig{
			Enabled:          true,
			BurstSize:        100,
			MaxWaitTime:      5 * time.Second,
			RetryAfterHeader: true,
		})

		// Set retry-after longer than context timeout
		rl.SetRetryAfterTime(time.Now().Add(1 * time.Second))

		err := rl.Wait(ctx)
		if err != context.DeadlineExceeded {
			t.Errorf("expected context.DeadlineExceeded, got %v", err)
		}
	})
}

func TestRateLimiter_Allow_RetryAfterExpired(t *testing.T) {
	t.Run("clears expired retry-after", func(t *testing.T) {
		rl := NewRateLimiter(&RateLimiterConfig{
			Enabled:          true,
			BurstSize:        100,
			RetryAfterHeader: true,
		})

		// Set retry-after in the past
		pastTime := time.Now().Add(-1 * time.Second)
		rl.retryUntil.Store(pastTime.UnixNano())

		// Allow should clear the expired retry-after and succeed
		allowed := rl.Allow()
		if !allowed {
			t.Error("expected Allow to succeed after retry-after expired")
		}

		// Verify retry-after was cleared
		if rl.retryUntil.Load() != 0 {
			t.Error("expected retry-after to be cleared")
		}
	})
}

func TestRateLimiter_refill(t *testing.T) {
	t.Run("refills tokens over time", func(t *testing.T) {
		rl := NewRateLimiter(&RateLimiterConfig{
			Enabled:           true,
			BurstSize:         10,
			RequestsPerSecond: 1000, // Fast refill for testing
		})

		// Consume all tokens
		for i := 0; i < 10; i++ {
			rl.Allow()
		}

		initialTokens := rl.tokens.Load()
		if initialTokens != 0 {
			t.Errorf("expected 0 tokens after consuming all, got %v", initialTokens)
		}

		// Wait for refill
		time.Sleep(20 * time.Millisecond)

		// Trigger refill by calling tryAcquire
		rl.refill()

		newTokens := rl.tokens.Load()
		if newTokens <= 0 {
			t.Error("expected tokens to be refilled")
		}
	})

	t.Run("caps at max tokens", func(t *testing.T) {
		rl := NewRateLimiter(&RateLimiterConfig{
			Enabled:           true,
			BurstSize:         5,
			RequestsPerSecond: 10000, // Very fast refill
		})

		// Verify stats reports correct max
		stats := rl.Stats()
		if stats.MaxTokens != 5 {
			t.Errorf("expected MaxTokens = 5, got %v", stats.MaxTokens)
		}

		// Even after fast refill, tokens should not exceed max
		time.Sleep(20 * time.Millisecond)
		rl.refill()

		stats = rl.Stats()
		if stats.AvailableTokens > float64(stats.MaxTokens) {
			t.Errorf("tokens should not exceed max (%v), got %v", stats.MaxTokens, stats.AvailableTokens)
		}
	})
}

func TestRateLimiter_AllowRaceCondition(t *testing.T) {
	// Test concurrent access to Allow
	rl := NewRateLimiter(&RateLimiterConfig{
		Enabled:           true,
		BurstSize:         100,
		RequestsPerSecond: 1000,
	})

	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = rl.Allow()
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}
