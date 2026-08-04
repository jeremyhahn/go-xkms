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
	"sync/atomic"
	"time"
)

// Rate limiter error types
var (
	// ErrRateLimitExceeded indicates the rate limit has been exceeded
	ErrRateLimitExceeded = errors.New("acme-client: rate limit exceeded")

	// ErrRateLimiterClosed indicates the rate limiter has been closed
	ErrRateLimiterClosed = errors.New("acme-client: rate limiter closed")
)

// RateLimiterConfig configures the client-side rate limiter
type RateLimiterConfig struct {
	// Enabled enables client-side rate limiting
	Enabled bool

	// RequestsPerSecond is the maximum number of requests per second
	// Default: 10
	RequestsPerSecond float64

	// BurstSize is the maximum number of requests that can be made in a burst
	// Default: 20
	BurstSize int

	// MaxWaitTime is the maximum time to wait when rate limited
	// If exceeded, returns ErrRateLimitExceeded
	// Default: 30s
	MaxWaitTime time.Duration

	// RetryAfterHeader determines whether to respect Retry-After headers
	// from the server. Default: true
	RetryAfterHeader bool
}

// DefaultRateLimiterConfig returns sensible default rate limiter settings
func DefaultRateLimiterConfig() *RateLimiterConfig {
	return &RateLimiterConfig{
		Enabled:           true,
		RequestsPerSecond: 10,
		BurstSize:         20,
		MaxWaitTime:       30 * time.Second,
		RetryAfterHeader:  true,
	}
}

// RateLimiter implements a token bucket rate limiter for the ACME client
type RateLimiter struct {
	config     *RateLimiterConfig
	tokens     atomic.Int64 // Available tokens * 1000 (for precision)
	maxTokens  int64        // Maximum tokens * 1000
	refillRate int64        // Tokens to add per millisecond * 1000
	lastRefill atomic.Int64 // Last refill time in nanoseconds
	closed     atomic.Bool
	retryUntil atomic.Int64 // Unix time until retry is blocked
}

// NewRateLimiter creates a new rate limiter with the given configuration
func NewRateLimiter(config *RateLimiterConfig) *RateLimiter {
	if config == nil {
		config = DefaultRateLimiterConfig()
	}

	if config.RequestsPerSecond <= 0 {
		config.RequestsPerSecond = 10
	}
	if config.BurstSize <= 0 {
		config.BurstSize = 20
	}

	// Use scaled integers for atomic operations
	// We multiply by 1000 for precision
	maxTokens := int64(config.BurstSize) * 1000
	refillRate := int64(config.RequestsPerSecond * 1000 / 1000) // Per millisecond

	rl := &RateLimiter{
		config:     config,
		maxTokens:  maxTokens,
		refillRate: refillRate,
	}

	rl.tokens.Store(maxTokens) // Start with full bucket
	rl.lastRefill.Store(time.Now().UnixNano())

	return rl
}

// Wait blocks until a request can be made or the context is cancelled.
// Returns nil when a token is acquired, or an error if rate limited.
func (rl *RateLimiter) Wait(ctx context.Context) error {
	if !rl.config.Enabled {
		return nil
	}

	if rl.closed.Load() {
		return ErrRateLimiterClosed
	}

	// Check if we're in a retry-after period
	if retryUntil := rl.retryUntil.Load(); retryUntil > 0 {
		waitUntil := time.Unix(retryUntil, 0)
		if time.Now().Before(waitUntil) {
			waitDuration := time.Until(waitUntil)
			if waitDuration > rl.config.MaxWaitTime {
				return ErrRateLimitExceeded
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(waitDuration):
				rl.retryUntil.Store(0)
			}
		}
	}

	deadline := time.Now().Add(rl.config.MaxWaitTime)

	for {
		if rl.tryAcquire() {
			return nil
		}

		// Check if we've exceeded max wait time
		if time.Now().After(deadline) {
			return ErrRateLimitExceeded
		}

		// Wait for token refill (check every 10ms)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// Allow returns true if a request can be made without waiting.
// If true is returned, a token is consumed.
func (rl *RateLimiter) Allow() bool {
	if !rl.config.Enabled {
		return true
	}

	if rl.closed.Load() {
		return false
	}

	// Check retry-after period
	if retryUntil := rl.retryUntil.Load(); retryUntil > 0 {
		if time.Now().Before(time.Unix(retryUntil, 0)) {
			return false
		}
		rl.retryUntil.Store(0)
	}

	return rl.tryAcquire()
}

// tryAcquire attempts to acquire a token without waiting
func (rl *RateLimiter) tryAcquire() bool {
	rl.refill()

	for {
		current := rl.tokens.Load()
		if current < 1000 { // Less than 1 token
			return false
		}

		// Try to decrement
		if rl.tokens.CompareAndSwap(current, current-1000) {
			return true
		}
	}
}

// refill adds tokens based on elapsed time
func (rl *RateLimiter) refill() {
	now := time.Now().UnixNano()
	last := rl.lastRefill.Load()

	// Calculate elapsed milliseconds
	elapsedMs := (now - last) / 1000000

	if elapsedMs <= 0 {
		return
	}

	// Try to update lastRefill atomically
	if !rl.lastRefill.CompareAndSwap(last, now) {
		return // Another goroutine updated it
	}

	// Calculate tokens to add
	tokensToAdd := elapsedMs * rl.refillRate

	for {
		current := rl.tokens.Load()
		newTokens := current + tokensToAdd
		if newTokens > rl.maxTokens {
			newTokens = rl.maxTokens
		}

		if rl.tokens.CompareAndSwap(current, newTokens) {
			break
		}
	}
}

// SetRetryAfter sets a retry-after period from server response.
// During this period, all requests will wait.
func (rl *RateLimiter) SetRetryAfter(duration time.Duration) {
	if !rl.config.RetryAfterHeader || duration <= 0 {
		return
	}

	retryUntil := time.Now().Add(duration).Unix()
	rl.retryUntil.Store(retryUntil)
}

// SetRetryAfterTime sets a retry-after period to a specific time
func (rl *RateLimiter) SetRetryAfterTime(until time.Time) {
	if !rl.config.RetryAfterHeader || until.Before(time.Now()) {
		return
	}

	rl.retryUntil.Store(until.Unix())
}

// Close closes the rate limiter
func (rl *RateLimiter) Close() {
	rl.closed.Store(true)
}

// Stats returns current rate limiter statistics
func (rl *RateLimiter) Stats() *RateLimiterStats {
	rl.refill()

	return &RateLimiterStats{
		AvailableTokens: float64(rl.tokens.Load()) / 1000,
		MaxTokens:       float64(rl.maxTokens) / 1000,
		RefillRate:      rl.config.RequestsPerSecond,
		IsBlocked:       rl.retryUntil.Load() > 0 && time.Now().Before(time.Unix(rl.retryUntil.Load(), 0)),
	}
}

// RateLimiterStats contains rate limiter statistics
type RateLimiterStats struct {
	// AvailableTokens is the current number of available tokens
	AvailableTokens float64

	// MaxTokens is the maximum number of tokens (burst size)
	MaxTokens float64

	// RefillRate is the token refill rate per second
	RefillRate float64

	// IsBlocked indicates if we're in a retry-after period
	IsBlocked bool
}

// RateLimitedTransport wraps an http.RoundTripper with rate limiting
type RateLimitedTransport struct {
	base        http.RoundTripper
	rateLimiter *RateLimiter
}

// NewRateLimitedTransport creates a new rate-limited HTTP transport
func NewRateLimitedTransport(base http.RoundTripper, limiter *RateLimiter) *RateLimitedTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &RateLimitedTransport{
		base:        base,
		rateLimiter: limiter,
	}
}

// RoundTrip implements http.RoundTripper with rate limiting
func (t *RateLimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.rateLimiter != nil {
		if err := t.rateLimiter.Wait(req.Context()); err != nil {
			return nil, err
		}
	}

	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// Handle Retry-After header
	if t.rateLimiter != nil && resp.StatusCode == http.StatusTooManyRequests {
		if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
			if duration := parseRetryAfter(retryAfter); duration > 0 {
				t.rateLimiter.SetRetryAfter(duration)
			}
		}
	}

	return resp, nil
}

// parseRetryAfter parses a Retry-After header value
func parseRetryAfter(value string) time.Duration {
	// Try to parse as seconds
	if seconds := parseInt(value); seconds > 0 {
		return time.Duration(seconds) * time.Second
	}

	// Try to parse as HTTP-date
	if t, err := time.Parse(time.RFC1123, value); err == nil {
		return time.Until(t)
	}

	return 0
}

// parseInt parses an integer from a string, returning 0 on error
func parseInt(s string) int {
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
