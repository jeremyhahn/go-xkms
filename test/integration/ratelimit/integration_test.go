// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build integration

package ratelimit

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/ratelimit"
	"github.com/stretchr/testify/assert"
)

// TestRateLimiterBasicIntegration tests basic rate limiting functionality
func TestRateLimiterBasicIntegration(t *testing.T) {
	config := &ratelimit.Config{
		Enabled:           true,
		RequestsPerMinute: 60, // 1 request per second
		Burst:             5,
	}

	limiter := ratelimit.New(config)
	defer limiter.Stop()

	clientID := "test-client"

	// First 5 requests should succeed (burst)
	for i := 0; i < 5; i++ {
		allowed := limiter.Allow(clientID)
		assert.True(t, allowed, "Request %d should be allowed (burst)", i+1)
	}

	// 6th request should be rate limited
	allowed := limiter.Allow(clientID)
	assert.False(t, allowed, "Request 6 should be rate limited")

	// Wait for tokens to refill
	time.Sleep(1100 * time.Millisecond)

	// Should allow another request
	allowed = limiter.Allow(clientID)
	assert.True(t, allowed, "Request should be allowed after waiting")
}

// TestRateLimiterDisabledIntegration tests disabled rate limiter
func TestRateLimiterDisabledIntegration(t *testing.T) {
	config := &ratelimit.Config{
		Enabled:           false,
		RequestsPerMinute: 60,
	}

	limiter := ratelimit.New(config)
	defer limiter.Stop()

	clientID := "test-client"

	// All requests should be allowed when disabled
	for i := 0; i < 100; i++ {
		allowed := limiter.Allow(clientID)
		assert.True(t, allowed, "All requests should be allowed when disabled")
	}
}

// TestRateLimiterMultipleClientsIntegration tests per-client rate limiting
func TestRateLimiterMultipleClientsIntegration(t *testing.T) {
	config := &ratelimit.Config{
		Enabled:           true,
		RequestsPerMinute: 60,
		Burst:             2,
	}

	limiter := ratelimit.New(config)
	defer limiter.Stop()

	// Each client should have independent rate limits
	client1 := "client-1"
	client2 := "client-2"

	// Client 1: Use up burst
	assert.True(t, limiter.Allow(client1))
	assert.True(t, limiter.Allow(client1))
	assert.False(t, limiter.Allow(client1), "Client 1 should be rate limited")

	// Client 2: Should still have full burst available
	assert.True(t, limiter.Allow(client2))
	assert.True(t, limiter.Allow(client2))
	assert.False(t, limiter.Allow(client2), "Client 2 should be rate limited")
}

// TestRateLimiterWaitIntegration tests Allow behavior over time
func TestRateLimiterWaitIntegration(t *testing.T) {
	config := &ratelimit.Config{
		Enabled:           true,
		RequestsPerMinute: 120, // 2 requests per second
		Burst:             1,
	}

	limiter := ratelimit.New(config)
	defer limiter.Stop()

	clientID := "wait-client"

	// First request succeeds immediately
	assert.True(t, limiter.Allow(clientID), "First request should be allowed")

	// Second request should be rate limited
	assert.False(t, limiter.Allow(clientID), "Second request should be rate limited")

	// Wait for token refill (500ms at 2 req/sec rate)
	time.Sleep(600 * time.Millisecond)

	// Should allow another request after waiting
	assert.True(t, limiter.Allow(clientID), "Request after wait should be allowed")
}

// TestRateLimiterStatsIntegration tests statistics reporting
func TestRateLimiterStatsIntegration(t *testing.T) {
	config := &ratelimit.Config{
		Enabled:           true,
		RequestsPerMinute: 60,
		Burst:             5,
	}

	limiter := ratelimit.New(config)
	defer limiter.Stop()

	// Make requests from multiple clients
	for i := 0; i < 10; i++ {
		clientID := fmt.Sprintf("client-%d", i)
		limiter.Allow(clientID)
	}

	// Get stats
	stats := limiter.Stats()

	assert.True(t, stats["enabled"].(bool), "Should be enabled")
	assert.Equal(t, 10, stats["active_clients"], "Should have 10 active clients")
	assert.Equal(t, 60.0, stats["rate_per_min"], "Rate should be 60/min")
	assert.Equal(t, 5, stats["burst"], "Burst should be 5")
}

// TestRateLimiterCleanupIntegration tests idle client cleanup
func TestRateLimiterCleanupIntegration(t *testing.T) {
	config := &ratelimit.Config{
		Enabled:           true,
		RequestsPerMinute: 60,
		CleanupInterval:   100 * time.Millisecond,
		MaxIdle:           200 * time.Millisecond,
	}

	limiter := ratelimit.New(config)
	defer limiter.Stop()

	// Make request from client
	clientID := "transient-client"
	limiter.Allow(clientID)

	// Verify client exists
	stats := limiter.Stats()
	assert.Equal(t, 1, stats["active_clients"], "Should have 1 active client")

	// Wait for cleanup
	time.Sleep(400 * time.Millisecond)

	// Client should be cleaned up
	stats = limiter.Stats()
	assert.Equal(t, 0, stats["active_clients"], "Idle client should be cleaned up")
}

// TestRateLimiterMiddlewareIntegration tests HTTP middleware
func TestRateLimiterMiddlewareIntegration(t *testing.T) {
	config := &ratelimit.Config{
		Enabled:           true,
		RequestsPerMinute: 120, // 2 requests per second
		Burst:             2,
	}

	limiter := ratelimit.New(config)
	defer limiter.Stop()

	// Create test handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "success")
	})

	// Wrap with rate limit middleware
	rateLimitedHandler := ratelimit.Middleware(limiter)(handler)

	t.Run("AllowedRequests", func(t *testing.T) {
		// First 2 requests should succeed (burst)
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.1.100:12345"
			w := httptest.NewRecorder()

			rateLimitedHandler.ServeHTTP(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			assert.Equal(t, http.StatusOK, resp.StatusCode, "Request %d should succeed", i+1)
		}
	})

	t.Run("RateLimitedRequest", func(t *testing.T) {
		// 3rd request should be rate limited
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.100:12345"
		w := httptest.NewRecorder()

		rateLimitedHandler.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode, "Should be rate limited")
	})
}

// TestRateLimiterXForwardedForIntegration tests X-Forwarded-For header handling
func TestRateLimiterXForwardedForIntegration(t *testing.T) {
	config := &ratelimit.Config{
		Enabled:           true,
		RequestsPerMinute: 60,
		Burst:             1,
	}

	limiter := ratelimit.New(config)
	defer limiter.Stop()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rateLimitedHandler := ratelimit.Middleware(limiter)(handler)

	// Request with X-Forwarded-For header
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()

	rateLimitedHandler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Second request should be rate limited (uses same client IP from header)
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")
	req.RemoteAddr = "192.168.1.1:12345"
	w = httptest.NewRecorder()

	rateLimitedHandler.ServeHTTP(w, req)

	resp = w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
}

// TestRateLimiterXRealIPIntegration tests X-Real-IP header handling
func TestRateLimiterXRealIPIntegration(t *testing.T) {
	config := &ratelimit.Config{
		Enabled:           true,
		RequestsPerMinute: 60,
		Burst:             1,
	}

	limiter := ratelimit.New(config)
	defer limiter.Stop()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rateLimitedHandler := ratelimit.Middleware(limiter)(handler)

	// Request with X-Real-IP header
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "10.0.0.5")
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()

	rateLimitedHandler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Second request should be rate limited
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "10.0.0.5")
	req.RemoteAddr = "192.168.1.1:12345"
	w = httptest.NewRecorder()

	rateLimitedHandler.ServeHTTP(w, req)

	resp = w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
}

// TestRateLimiterConcurrentIntegration tests concurrent requests
func TestRateLimiterConcurrentIntegration(t *testing.T) {
	config := &ratelimit.Config{
		Enabled:           true,
		RequestsPerMinute: 600, // 10 requests per second
		Burst:             50,
	}

	limiter := ratelimit.New(config)
	defer limiter.Stop()

	numClients := 10
	requestsPerClient := 10
	var allowed atomic.Int32
	var denied atomic.Int32
	var wg sync.WaitGroup

	// Launch concurrent requests from multiple clients
	wg.Add(numClients)
	for i := 0; i < numClients; i++ {
		clientID := fmt.Sprintf("client-%d", i)
		go func(cid string) {
			defer wg.Done()
			for j := 0; j < requestsPerClient; j++ {
				if limiter.Allow(cid) {
					allowed.Add(1)
				} else {
					denied.Add(1)
				}
			}
		}(clientID)
	}

	wg.Wait()

	totalRequests := numClients * requestsPerClient
	allowedCount := int(allowed.Load())
	deniedCount := int(denied.Load())

	assert.Equal(t, totalRequests, allowedCount+deniedCount,
		"All requests should be counted")
	assert.Greater(t, allowedCount, 0, "Some requests should be allowed")

	t.Logf("Allowed: %d, Denied: %d, Total: %d", allowedCount, deniedCount, totalRequests)
}

// TestRateLimiterBurstSizesIntegration tests different burst sizes
func TestRateLimiterBurstSizesIntegration(t *testing.T) {
	testCases := []struct {
		name  string
		burst int
	}{
		{"SmallBurst", 1},
		{"MediumBurst", 10},
		{"LargeBurst", 100},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &ratelimit.Config{
				Enabled:           true,
				RequestsPerMinute: 60,
				Burst:             tc.burst,
			}

			limiter := ratelimit.New(config)
			defer limiter.Stop()

			clientID := "burst-test-client"

			// Should allow exactly burst number of requests
			for i := 0; i < tc.burst; i++ {
				allowed := limiter.Allow(clientID)
				assert.True(t, allowed, "Request %d should be allowed", i+1)
			}

			// Next request should be rate limited
			allowed := limiter.Allow(clientID)
			assert.False(t, allowed, "Request after burst should be rate limited")
		})
	}
}

// TestRateLimiterDefaultsIntegration tests default configuration values
func TestRateLimiterDefaultsIntegration(t *testing.T) {
	t.Run("NilConfig", func(t *testing.T) {
		limiter := ratelimit.New(nil)
		defer limiter.Stop()

		stats := limiter.Stats()
		assert.False(t, stats["enabled"].(bool), "Should be disabled by default")
	})

	t.Run("EmptyConfig", func(t *testing.T) {
		config := &ratelimit.Config{}
		limiter := ratelimit.New(config)
		defer limiter.Stop()

		stats := limiter.Stats()
		assert.False(t, stats["enabled"].(bool), "Should be disabled with empty config")
	})

	t.Run("DefaultBurst", func(t *testing.T) {
		config := &ratelimit.Config{
			Enabled:           true,
			RequestsPerMinute: 120,
			// Burst not set
		}

		limiter := ratelimit.New(config)
		defer limiter.Stop()

		stats := limiter.Stats()
		assert.Equal(t, 120, stats["burst"], "Burst should default to RequestsPerMinute")
	})
}

// TestRateLimiterHighLoadIntegration tests behavior under high load
func TestRateLimiterHighLoadIntegration(t *testing.T) {
	config := &ratelimit.Config{
		Enabled:           true,
		RequestsPerMinute: 6000, // 100 requests per second
		Burst:             100,
	}

	limiter := ratelimit.New(config)
	defer limiter.Stop()

	numClients := 100
	requestsPerClient := 50
	var wg sync.WaitGroup
	var totalAllowed atomic.Int32

	start := time.Now()

	// Launch high-volume concurrent requests
	wg.Add(numClients)
	for i := 0; i < numClients; i++ {
		clientID := fmt.Sprintf("high-load-client-%d", i)
		go func(cid string) {
			defer wg.Done()
			for j := 0; j < requestsPerClient; j++ {
				if limiter.Allow(cid) {
					totalAllowed.Add(1)
				}
			}
		}(clientID)
	}

	wg.Wait()
	elapsed := time.Since(start)

	allowed := int(totalAllowed.Load())
	t.Logf("Processed %d requests in %v (%d allowed)", numClients*requestsPerClient, elapsed, allowed)

	// Verify performance
	assert.Less(t, elapsed, 5*time.Second, "Should handle high load efficiently")
	assert.Greater(t, allowed, 0, "Should allow some requests")
}

// TestRateLimiterTimeBasedRefillIntegration tests token refill over time
func TestRateLimiterTimeBasedRefillIntegration(t *testing.T) {
	config := &ratelimit.Config{
		Enabled:           true,
		RequestsPerMinute: 60, // 1 request per second
		Burst:             1,
	}

	limiter := ratelimit.New(config)
	defer limiter.Stop()

	clientID := "time-test-client"

	// Use the initial token
	assert.True(t, limiter.Allow(clientID))

	// Should be rate limited
	assert.False(t, limiter.Allow(clientID))

	// Wait for 1 token to refill
	time.Sleep(1100 * time.Millisecond)

	// Should allow 1 request
	assert.True(t, limiter.Allow(clientID))

	// Should be rate limited again
	assert.False(t, limiter.Allow(clientID))
}

// TestRateLimiterRealWorldHTTPServerIntegration simulates a real HTTP server
func TestRateLimiterRealWorldHTTPServerIntegration(t *testing.T) {
	config := &ratelimit.Config{
		Enabled:           true,
		RequestsPerMinute: 120, // 2 requests per second
		Burst:             5,
		CleanupInterval:   1 * time.Second,
		MaxIdle:           5 * time.Second,
	}

	limiter := ratelimit.New(config)
	defer limiter.Stop()

	// Create HTTP server with rate limiting
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"status":"ok"}`)
	})

	server := httptest.NewServer(ratelimit.Middleware(limiter)(handler))
	defer server.Close()

	// Simulate multiple clients making requests
	numClients := 3
	requestsPerClient := 10
	var wg sync.WaitGroup
	var successCount atomic.Int32
	var rateLimitedCount atomic.Int32

	wg.Add(numClients)
	for i := 0; i < numClients; i++ {
		clientIP := fmt.Sprintf("10.0.0.%d", i+1)
		go func(ip string) {
			defer wg.Done()

			client := &http.Client{Timeout: 5 * time.Second}
			for j := 0; j < requestsPerClient; j++ {
				req, _ := http.NewRequest("GET", server.URL, nil)
				req.Header.Set("X-Forwarded-For", ip)

				resp, err := client.Do(req)
				if err != nil {
					continue
				}

				if resp.StatusCode == http.StatusOK {
					successCount.Add(1)
				} else if resp.StatusCode == http.StatusTooManyRequests {
					rateLimitedCount.Add(1)
				}

				resp.Body.Close()
				time.Sleep(100 * time.Millisecond)
			}
		}(clientIP)
	}

	wg.Wait()

	success := int(successCount.Load())
	rateLimited := int(rateLimitedCount.Load())

	t.Logf("Success: %d, Rate Limited: %d", success, rateLimited)

	assert.Greater(t, success, 0, "Should have successful requests")
	// Some requests may be rate limited depending on timing
}

// TestRateLimiterStopCleanupIntegration tests cleanup worker shutdown
func TestRateLimiterStopCleanupIntegration(t *testing.T) {
	config := &ratelimit.Config{
		Enabled:           true,
		RequestsPerMinute: 60,
		CleanupInterval:   100 * time.Millisecond,
	}

	limiter := ratelimit.New(config)

	// Make some requests
	limiter.Allow("client-1")
	limiter.Allow("client-2")

	// Stop cleanup
	limiter.Stop()

	// Wait a bit to ensure cleanup worker has stopped
	time.Sleep(300 * time.Millisecond)

	// Should not panic or error
	stats := limiter.Stats()
	assert.NotNil(t, stats)
}

// TestRateLimiterZeroRequestsPerMinuteIntegration tests edge case
func TestRateLimiterZeroRequestsPerMinuteIntegration(t *testing.T) {
	config := &ratelimit.Config{
		Enabled:           true,
		RequestsPerMinute: 0, // Edge case: no requests allowed
		Burst:             0,
	}

	limiter := ratelimit.New(config)
	defer limiter.Stop()

	// All requests should be denied
	for i := 0; i < 10; i++ {
		allowed := limiter.Allow("client")
		assert.False(t, allowed, "Should deny all requests with 0 rate")
	}
}
