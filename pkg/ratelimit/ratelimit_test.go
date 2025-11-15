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

package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	config := &Config{
		Enabled:           true,
		RequestsPerMinute: 60,
		Burst:             10,
	}

	limiter := New(config)
	if limiter == nil {
		t.Fatal("Expected limiter to be created")
	}

	if !limiter.enabled {
		t.Error("Expected limiter to be enabled")
	}

	stats := limiter.Stats()
	if stats["enabled"] != true {
		t.Error("Expected enabled to be true in stats")
	}

	limiter.Stop()
}

func TestAllow(t *testing.T) {
	config := &Config{
		Enabled:           true,
		RequestsPerMinute: 60, // 1 per second
		Burst:             5,
	}

	limiter := New(config)
	defer limiter.Stop()

	clientID := "test-client"

	// First 5 requests should succeed (burst)
	for i := 0; i < 5; i++ {
		if !limiter.Allow(clientID) {
			t.Errorf("Request %d should be allowed (burst)", i+1)
		}
	}

	// Next request should be denied (burst exhausted)
	if limiter.Allow(clientID) {
		t.Error("Request should be denied after burst exhausted")
	}

	// Wait for 1 second, 1 token should be available
	time.Sleep(1 * time.Second)
	if !limiter.Allow(clientID) {
		t.Error("Request should be allowed after waiting")
	}
}

func TestDisabledLimiter(t *testing.T) {
	config := &Config{
		Enabled:           false,
		RequestsPerMinute: 1,
	}

	limiter := New(config)

	clientID := "test-client"

	// All requests should be allowed when disabled
	for i := 0; i < 100; i++ {
		if !limiter.Allow(clientID) {
			t.Error("Disabled limiter should allow all requests")
		}
	}
}

func TestPerClientLimiting(t *testing.T) {
	config := &Config{
		Enabled:           true,
		RequestsPerMinute: 60,
		Burst:             1,
	}

	limiter := New(config)
	defer limiter.Stop()

	client1 := "client-1"
	client2 := "client-2"

	// Exhaust client1's burst
	if !limiter.Allow(client1) {
		t.Error("First request for client1 should be allowed")
	}
	if limiter.Allow(client1) {
		t.Error("Second request for client1 should be denied")
	}

	// Client2 should still have budget
	if !limiter.Allow(client2) {
		t.Error("First request for client2 should be allowed")
	}
}

func TestCleanup(t *testing.T) {
	config := &Config{
		Enabled:           true,
		RequestsPerMinute: 60,
		CleanupInterval:   100 * time.Millisecond,
		MaxIdle:           200 * time.Millisecond,
	}

	limiter := New(config)
	defer limiter.Stop()

	// Create a limiter entry
	limiter.Allow("test-client")

	// Check it exists
	limiter.mu.RLock()
	if len(limiter.limiters) != 1 {
		t.Errorf("Expected 1 limiter, got %d", len(limiter.limiters))
	}
	limiter.mu.RUnlock()

	// Wait for cleanup
	time.Sleep(400 * time.Millisecond)

	// Check it was cleaned up
	limiter.mu.RLock()
	if len(limiter.limiters) != 0 {
		t.Errorf("Expected 0 limiters after cleanup, got %d", len(limiter.limiters))
	}
	limiter.mu.RUnlock()
}

func TestMiddleware(t *testing.T) {
	config := &Config{
		Enabled:           true,
		RequestsPerMinute: 60,
		Burst:             2,
	}

	limiter := New(config)
	defer limiter.Stop()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := Middleware(limiter)
	wrappedHandler := middleware(handler)

	// First 2 requests should succeed
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		rr := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Request %d: expected status 200, got %d", i+1, rr.Code)
		}
	}

	// Third request should be rate limited
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	rr := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", rr.Code)
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		expected   string
	}{
		{
			name:       "X-Forwarded-For",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.1, 198.51.100.1"},
			remoteAddr: "192.168.1.1:1234",
			expected:   "203.0.113.1",
		},
		{
			name:       "X-Real-IP",
			headers:    map[string]string{"X-Real-IP": "203.0.113.1"},
			remoteAddr: "192.168.1.1:1234",
			expected:   "203.0.113.1",
		},
		{
			name:       "RemoteAddr fallback",
			headers:    map[string]string{},
			remoteAddr: "192.168.1.1:1234",
			expected:   "192.168.1.1:1234",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			ip := getClientIP(req)
			if ip != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, ip)
			}
		})
	}
}

func TestStats(t *testing.T) {
	config := &Config{
		Enabled:           true,
		RequestsPerMinute: 120,
		Burst:             10,
	}

	limiter := New(config)
	defer limiter.Stop()

	// Add some clients
	limiter.Allow("client-1")
	limiter.Allow("client-2")

	stats := limiter.Stats()

	if stats["enabled"] != true {
		t.Error("Expected enabled to be true")
	}

	if stats["active_clients"] != 2 {
		t.Errorf("Expected 2 active clients, got %v", stats["active_clients"])
	}

	if stats["rate_per_min"] != 120.0 {
		t.Errorf("Expected rate_per_min 120, got %v", stats["rate_per_min"])
	}

	if stats["burst"] != 10 {
		t.Errorf("Expected burst 10, got %v", stats["burst"])
	}
}
