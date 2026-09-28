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
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/stretchr/testify/require"
)

func TestDefaultRateLimitConfig(t *testing.T) {
	config := DefaultRateLimitConfig()

	if config == nil {
		t.Fatal("Expected non-nil config")
	}

	// Verify NewAccountRate
	if config.NewAccountRate == nil {
		t.Error("Expected NewAccountRate to be set")
	} else {
		if config.NewAccountRate.MaxRequests != 10 {
			t.Errorf("Expected NewAccountRate MaxRequests to be 10, got %d", config.NewAccountRate.MaxRequests)
		}
		if config.NewAccountRate.Interval != time.Hour {
			t.Errorf("Expected NewAccountRate Interval to be 1 hour, got %v", config.NewAccountRate.Interval)
		}
	}

	// Verify NewOrderRate
	if config.NewOrderRate == nil {
		t.Error("Expected NewOrderRate to be set")
	} else {
		if config.NewOrderRate.MaxRequests != 300 {
			t.Errorf("Expected NewOrderRate MaxRequests to be 300, got %d", config.NewOrderRate.MaxRequests)
		}
		if config.NewOrderRate.Interval != 3*time.Hour {
			t.Errorf("Expected NewOrderRate Interval to be 3 hours, got %v", config.NewOrderRate.Interval)
		}
	}

	// Verify CertificateRate
	if config.CertificateRate == nil {
		t.Error("Expected CertificateRate to be set")
	} else {
		if config.CertificateRate.MaxRequests != 50 {
			t.Errorf("Expected CertificateRate MaxRequests to be 50, got %d", config.CertificateRate.MaxRequests)
		}
		if config.CertificateRate.Interval != 3*time.Hour {
			t.Errorf("Expected CertificateRate Interval to be 3 hours, got %v", config.CertificateRate.Interval)
		}
	}

	// Verify OverallRequestRate
	if config.OverallRequestRate == nil {
		t.Error("Expected OverallRequestRate to be set")
	} else {
		if config.OverallRequestRate.MaxRequests != 20 {
			t.Errorf("Expected OverallRequestRate MaxRequests to be 20, got %d", config.OverallRequestRate.MaxRequests)
		}
		if config.OverallRequestRate.Interval != time.Second {
			t.Errorf("Expected OverallRequestRate Interval to be 1 second, got %v", config.OverallRequestRate.Interval)
		}
	}

	// Verify FailedValidationRate
	if config.FailedValidationRate == nil {
		t.Error("Expected FailedValidationRate to be set")
	} else {
		if config.FailedValidationRate.MaxRequests != 5 {
			t.Errorf("Expected FailedValidationRate MaxRequests to be 5, got %d", config.FailedValidationRate.MaxRequests)
		}
		if config.FailedValidationRate.Interval != time.Hour {
			t.Errorf("Expected FailedValidationRate Interval to be 1 hour, got %v", config.FailedValidationRate.Interval)
		}
	}
}

func TestNewRateLimiter(t *testing.T) {
	maxRequests := 10
	interval := time.Minute

	rl := NewRateLimiter(maxRequests, interval)

	if rl.MaxRequests != maxRequests {
		t.Errorf("Expected MaxRequests to be %d, got %d", maxRequests, rl.MaxRequests)
	}
	if rl.Interval != interval {
		t.Errorf("Expected Interval to be %v, got %v", interval, rl.Interval)
	}
	if rl.Len() != 0 {
		t.Errorf("Expected a new limiter to track no clients, got %d", rl.Len())
	}
	if !rl.Allow("client") {
		t.Error("Expected the first request from a new client to be allowed")
	}
}

func TestRateLimiter_AllowsRequestsWithinLimit(t *testing.T) {
	rl := NewRateLimiter(3, time.Second)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	middleware := rl.MiddlewareFunc(func(r *http.Request) string {
		return "test-client"
	})

	wrappedHandler := middleware(handler)

	// Make 3 requests - all should succeed
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: Expected status 200, got %d", i+1, w.Code)
		}
	}
}

func TestRateLimiter_BlocksRequestsOverLimit(t *testing.T) {
	rl := NewRateLimiter(2, time.Second)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	middleware := rl.MiddlewareFunc(func(r *http.Request) string {
		return "test-client"
	})

	wrappedHandler := middleware(handler)

	// Make 2 successful requests
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: Expected status 200, got %d", i+1, w.Code)
		}
	}

	// 3rd request should be rate limited
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", w.Code)
	}

	retryAfter := w.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Error("Expected Retry-After header to be set")
	}
}

func TestRateLimiter_DifferentClientsIndependent(t *testing.T) {
	rl := NewRateLimiter(1, time.Second)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := rl.MiddlewareFunc(func(r *http.Request) string {
		return r.Header.Get("X-Client-ID")
	})

	wrappedHandler := middleware(handler)

	// Client 1 makes a request
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req1.Header.Set("X-Client-ID", "client1")
	w1 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Errorf("Client 1: Expected status 200, got %d", w1.Code)
	}

	// Client 2 makes a request (should succeed independently)
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.Header.Set("X-Client-ID", "client2")
	w2 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("Client 2: Expected status 200, got %d", w2.Code)
	}
}

func TestRateLimiter_RFC8555_CompliantErrorResponse(t *testing.T) {
	rl := NewRateLimiter(1, 60*time.Second) // 1 request per 60 seconds

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := rl.MiddlewareFunc(func(r *http.Request) string {
		return "test-client"
	})

	wrappedHandler := middleware(handler)

	// First request succeeds
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	w1 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("First request failed: %d", w1.Code)
	}

	// Second request should be rate limited
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	w2 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w2, req2)

	// Verify HTTP status code
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", w2.Code)
	}

	// Verify Retry-After header is an integer (seconds)
	retryAfter := w2.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Fatal("Expected Retry-After header to be set")
	}

	// Verify it's a valid integer
	seconds, err := strconv.Atoi(retryAfter)
	if err != nil {
		t.Errorf("Retry-After header should be an integer, got: %s", retryAfter)
	}

	// Verify the seconds value is correct (60 seconds)
	if seconds != 60 {
		t.Errorf("Expected Retry-After to be 60 seconds, got %d", seconds)
	}

	// Verify Content-Type is application/problem+json
	contentType := w2.Header().Get("Content-Type")
	if contentType != "application/problem+json" {
		t.Errorf("Expected Content-Type to be application/problem+json, got %s", contentType)
	}

	// Verify ACME error response structure
	var acmeError entities.Error
	if err := json.NewDecoder(w2.Body).Decode(&acmeError); err != nil {
		t.Fatalf("Failed to decode ACME error response: %v", err)
	}

	// Verify error type is rateLimited per RFC 8555
	expectedType := "urn:ietf:params:acme:error:rateLimited"
	if acmeError.Type != expectedType {
		t.Errorf("Expected error type %s, got %s", expectedType, acmeError.Type)
	}

	// Verify detail message exists
	if acmeError.Detail == "" {
		t.Error("Expected non-empty detail message")
	}

	// Verify detail message mentions retry time
	if !strings.Contains(acmeError.Detail, "60 seconds") {
		t.Errorf("Expected detail to mention retry time, got: %s", acmeError.Detail)
	}
}

func TestRateLimiter_RetryAfterHeaderIsInteger(t *testing.T) {
	testCases := []struct {
		name     string
		interval time.Duration
		expected string
	}{
		{
			name:     "1 second interval",
			interval: time.Second,
			expected: "1",
		},
		{
			name:     "60 seconds interval",
			interval: 60 * time.Second,
			expected: "60",
		},
		{
			name:     "1 hour interval",
			interval: time.Hour,
			expected: "3600",
		},
		{
			name:     "3 hours interval",
			interval: 3 * time.Hour,
			expected: "10800",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rl := NewRateLimiter(1, tc.interval)

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			middleware := rl.MiddlewareFunc(func(r *http.Request) string {
				return "test-client"
			})

			wrappedHandler := middleware(handler)

			// First request succeeds
			req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
			w1 := httptest.NewRecorder()
			wrappedHandler.ServeHTTP(w1, req1)

			// Second request should be rate limited
			req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
			w2 := httptest.NewRecorder()
			wrappedHandler.ServeHTTP(w2, req2)

			retryAfter := w2.Header().Get("Retry-After")
			if retryAfter != tc.expected {
				t.Errorf("Expected Retry-After to be %s, got %s", tc.expected, retryAfter)
			}

			// Verify it's NOT a Go duration string
			if strings.Contains(retryAfter, "h") || strings.Contains(retryAfter, "m") || strings.Contains(retryAfter, "s") {
				t.Errorf("Retry-After should be integer seconds, not Go duration string: %s", retryAfter)
			}
		})
	}
}

// TestClientID_IgnoresUnverifiedKID verifies ClientID never keys on a JWS
// "kid" it has not seen verified, and never consumes the request body: a
// body naming an arbitrary account still maps to the client IP.
func TestClientID_IgnoresUnverifiedKID(t *testing.T) {
	jwsPayload := `{"protected":"eyJhbGciOiJFUzI1NiIsImtpZCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vYWNtZS9hY2N0LzEifQ","payload":"","signature":"test"}`

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(jwsPayload))
	req.RemoteAddr = "192.0.2.10:4444"

	if got := ClientID(req); got != "192.0.2.10" {
		t.Errorf("Expected the client IP for an unverified kid, got %q", got)
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("Failed to read body after ClientID call: %v", err)
	}
	if string(body) != jwsPayload {
		t.Error("ClientID must not consume the request body")
	}
}

// TestClientID_UsesVerifiedAccountID verifies ClientID keys on the account
// a verifying middleware recorded with WithVerifiedAccountID.
func TestClientID_UsesVerifiedAccountID(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.RemoteAddr = "192.0.2.10:4444"
	req = req.WithContext(WithVerifiedAccountID(req.Context(), 4242))

	if got := ClientID(req); got != "4242" {
		t.Errorf("Expected the verified account ID, got %q", got)
	}
}

func TestClientID_WithInvalidBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString("invalid-jws"))
	req.RemoteAddr = "192.168.1.1:1234"

	clientID := ClientID(req)

	// Should fall back to extracted IP from RemoteAddr for invalid JWS
	expectedIP := "192.168.1.1"
	if clientID != expectedIP {
		t.Errorf("Expected client ID to be %s, got %s", expectedIP, clientID)
	}
}

func TestClientID_WithEmptyBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(""))
	req.RemoteAddr = "192.168.1.2:5678"

	clientID := ClientID(req)

	// Should fall back to extracted IP from RemoteAddr for empty body
	expectedIP := "192.168.1.2"
	if clientID != expectedIP {
		t.Errorf("Expected client ID to be %s, got %s", expectedIP, clientID)
	}
}

func TestClientID_FallbackUsesProxyHeaders(t *testing.T) {
	// Save and restore TrustedProxies
	oldTrustedProxies := TrustedProxies
	defer func() { TrustedProxies = oldTrustedProxies }()

	// Set up trusted proxies for these tests
	TrustedProxies = []string{"10.0.0.1"}

	t.Run("FallbackToXForwardedFor", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString("invalid-jws"))
		req.RemoteAddr = "10.0.0.1:1234"
		req.Header.Set("X-Forwarded-For", "203.0.113.50")

		clientID := ClientID(req)

		// Should fall back to X-Forwarded-For IP when JWS is invalid and proxy is trusted
		if clientID != "203.0.113.50" {
			t.Errorf("Expected client ID to be 203.0.113.50, got %s", clientID)
		}
	})

	t.Run("FallbackToXRealIP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(""))
		req.RemoteAddr = "10.0.0.1:1234"
		req.Header.Set("X-Real-IP", "198.51.100.25")

		clientID := ClientID(req)

		// Should fall back to X-Real-IP when body is empty and proxy is trusted
		if clientID != "198.51.100.25" {
			t.Errorf("Expected client ID to be 198.51.100.25, got %s", clientID)
		}
	})

	t.Run("FallbackPreservesProxyPrecedence", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString("not-a-jws"))
		req.RemoteAddr = "10.0.0.1:1234"
		req.Header.Set("X-Forwarded-For", "203.0.113.50")
		req.Header.Set("X-Real-IP", "198.51.100.25")

		clientID := ClientID(req)

		// X-Forwarded-For should take precedence over X-Real-IP when proxy is trusted
		if clientID != "203.0.113.50" {
			t.Errorf("Expected X-Forwarded-For to take precedence, got %s", clientID)
		}
	})
}

func TestClientIP(t *testing.T) {
	// Save and restore TrustedProxies
	oldTrustedProxies := TrustedProxies
	defer func() { TrustedProxies = oldTrustedProxies }()

	// Set up trusted proxies for these tests - include common test IPs
	TrustedProxies = []string{"10.0.0.1", "::1"}

	t.Run("FallbackToRemoteAddr", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.100:12345"

		clientIP := ClientIP(req)

		// Untrusted proxy - should return extracted IP from RemoteAddr (no port)
		expectedIP := "192.168.1.100"
		if clientIP != expectedIP {
			t.Errorf("Expected client IP to be %s, got %s", expectedIP, clientIP)
		}
	})

	t.Run("XForwardedFor_SingleIP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("X-Forwarded-For", "203.0.113.50")

		clientIP := ClientIP(req)

		// Trusted proxy - should use X-Forwarded-For
		if clientIP != "203.0.113.50" {
			t.Errorf("Expected client IP to be 203.0.113.50, got %s", clientIP)
		}
	})

	t.Run("XForwardedFor_MultipleIPs", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("X-Forwarded-For", "203.0.113.50, 70.41.3.18, 150.172.238.178")

		clientIP := ClientIP(req)

		// Should return the first IP (original client)
		if clientIP != "203.0.113.50" {
			t.Errorf("Expected client IP to be 203.0.113.50, got %s", clientIP)
		}
	})

	t.Run("XForwardedFor_WithWhitespace", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("X-Forwarded-For", "  203.0.113.50  ,  70.41.3.18  ")

		clientIP := ClientIP(req)

		if clientIP != "203.0.113.50" {
			t.Errorf("Expected client IP to be 203.0.113.50, got %s", clientIP)
		}
	})

	t.Run("XRealIP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("X-Real-IP", "198.51.100.25")

		clientIP := ClientIP(req)

		if clientIP != "198.51.100.25" {
			t.Errorf("Expected client IP to be 198.51.100.25, got %s", clientIP)
		}
	})

	t.Run("XRealIP_WithWhitespace", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("X-Real-IP", "  198.51.100.25  ")

		clientIP := ClientIP(req)

		if clientIP != "198.51.100.25" {
			t.Errorf("Expected client IP to be 198.51.100.25, got %s", clientIP)
		}
	})

	t.Run("XForwardedFor_PrecedenceOverXRealIP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("X-Forwarded-For", "203.0.113.50")
		req.Header.Set("X-Real-IP", "198.51.100.25")

		clientIP := ClientIP(req)

		// X-Forwarded-For should take precedence when proxy is trusted
		if clientIP != "203.0.113.50" {
			t.Errorf("Expected X-Forwarded-For to take precedence, got %s", clientIP)
		}
	})

	t.Run("EmptyXForwardedFor_FallsBackToXRealIP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("X-Forwarded-For", "")
		req.Header.Set("X-Real-IP", "198.51.100.25")

		clientIP := ClientIP(req)

		if clientIP != "198.51.100.25" {
			t.Errorf("Expected fallback to X-Real-IP, got %s", clientIP)
		}
	})

	t.Run("EmptyHeaders_FallsBackToRemoteAddr", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("X-Forwarded-For", "")
		req.Header.Set("X-Real-IP", "")

		clientIP := ClientIP(req)

		// Even trusted proxy with empty headers falls back to extracted IP from RemoteAddr
		expectedIP := "10.0.0.1"
		if clientIP != expectedIP {
			t.Errorf("Expected fallback to RemoteAddr, got %s", clientIP)
		}
	})

	t.Run("IPv6_XForwardedFor", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "[::1]:12345"
		req.Header.Set("X-Forwarded-For", "2001:db8::1, 2001:db8::2")

		clientIP := ClientIP(req)

		if clientIP != "2001:db8::1" {
			t.Errorf("Expected IPv6 address 2001:db8::1, got %s", clientIP)
		}
	})

	t.Run("IPv6_XRealIP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "[::1]:12345"
		req.Header.Set("X-Real-IP", "2001:db8::1")

		clientIP := ClientIP(req)

		if clientIP != "2001:db8::1" {
			t.Errorf("Expected IPv6 address 2001:db8::1, got %s", clientIP)
		}
	})
}

func TestRateLimiter_TokenRefill(t *testing.T) {
	rl := NewRateLimiter(2, 100*time.Millisecond)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := rl.MiddlewareFunc(func(r *http.Request) string {
		return "test-client"
	})

	wrappedHandler := middleware(handler)

	// Use all tokens
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Initial request %d failed", i+1)
		}
	}

	// Next request should be rate limited
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Error("Expected rate limit to be exceeded")
	}

	// Wait for token refill
	time.Sleep(150 * time.Millisecond)

	// Should succeed after refill
	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	w = httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected success after token refill, got %d", w.Code)
	}
}

func TestNewAccountRateLimiter_WithConfig(t *testing.T) {
	config := &RateLimit{
		MaxRequests: 5,
		Interval:    time.Minute,
	}

	middleware := NewAccountRateLimiter(config)

	if middleware == nil {
		t.Fatal("Expected non-nil middleware")
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := middleware(handler)

	// Make requests up to the limit
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/acme/new-account", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: Expected status 200, got %d", i+1, w.Code)
		}
	}

	// Next request should be rate limited
	req := httptest.NewRequest(http.MethodPost, "/acme/new-account", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	w := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", w.Code)
	}
}

func TestNewAccountRateLimiter_WithNilConfig(t *testing.T) {
	middleware := NewAccountRateLimiter(nil)

	if middleware == nil {
		t.Fatal("Expected non-nil middleware")
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := middleware(handler)

	// Should allow unlimited requests
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest(http.MethodPost, "/acme/new-account", nil)
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: Expected status 200, got %d", i+1, w.Code)
		}
	}
}

func TestNewOrderRateLimiter(t *testing.T) {
	config := &RateLimit{
		MaxRequests: 3,
		Interval:    time.Second,
	}

	middleware := NewOrderRateLimiter(config)

	if middleware == nil {
		t.Fatal("Expected non-nil middleware")
	}

	// Test with ClientID (account-based rate limiting)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := middleware(handler)

	// Make requests - should use ClientID for tracking
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/acme/new-order", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: Expected status 200, got %d", i+1, w.Code)
		}
	}

	// Next request should be rate limited
	req := httptest.NewRequest(http.MethodPost, "/acme/new-order", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	w := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", w.Code)
	}
}

func TestCertificateRateLimiter(t *testing.T) {
	config := &RateLimit{
		MaxRequests: 2,
		Interval:    time.Second,
	}

	middleware := CertificateRateLimiter(config)

	if middleware == nil {
		t.Fatal("Expected non-nil middleware")
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := middleware(handler)

	// Make requests up to limit
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/acme/cert/123", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: Expected status 200, got %d", i+1, w.Code)
		}
	}

	// Next request should be rate limited
	req := httptest.NewRequest(http.MethodGet, "/acme/cert/123", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	w := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", w.Code)
	}
}

func TestOverallRateLimiter(t *testing.T) {
	config := &RateLimit{
		MaxRequests: 10,
		Interval:    time.Second,
	}

	middleware := OverallRateLimiter(config)

	if middleware == nil {
		t.Fatal("Expected non-nil middleware")
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := middleware(handler)

	// Make requests up to limit
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: Expected status 200, got %d", i+1, w.Code)
		}
	}

	// Next request should be rate limited
	req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	w := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", w.Code)
	}
}

func TestFailedValidationRateLimiter(t *testing.T) {
	config := &RateLimit{
		MaxRequests: 3,
		Interval:    time.Minute,
	}

	middleware := FailedValidationRateLimiter(config)

	if middleware == nil {
		t.Fatal("Expected non-nil middleware")
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := middleware(handler)

	// Make failed validation attempts up to limit
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/acme/challenge/123", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: Expected status 200, got %d", i+1, w.Code)
		}
	}

	// Next request should be rate limited
	req := httptest.NewRequest(http.MethodPost, "/acme/challenge/123", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	w := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", w.Code)
	}
}

func TestRateLimiter_PerIPIsolation(t *testing.T) {
	config := &RateLimit{
		MaxRequests: 2,
		Interval:    time.Second,
	}

	middleware := NewAccountRateLimiter(config)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := middleware(handler)

	// IP 1 makes 2 requests (uses all tokens)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/acme/new-account", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("IP1 Request %d: Expected status 200, got %d", i+1, w.Code)
		}
	}

	// IP 1's next request should be rate limited
	req1 := httptest.NewRequest(http.MethodPost, "/acme/new-account", nil)
	req1.RemoteAddr = "192.168.1.1:1234"
	w1 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w1, req1)

	if w1.Code != http.StatusTooManyRequests {
		t.Errorf("IP1: Expected status 429, got %d", w1.Code)
	}

	// IP 2 should still be able to make requests (independent limit)
	req2 := httptest.NewRequest(http.MethodPost, "/acme/new-account", nil)
	req2.RemoteAddr = "192.168.1.2:5678"
	w2 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("IP2: Expected status 200, got %d", w2.Code)
	}
}

func TestRateLimiter_PerAccountIsolation(t *testing.T) {
	config := &RateLimit{
		MaxRequests: 1,
		Interval:    time.Second,
	}

	middleware := NewOrderRateLimiter(config)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := middleware(handler)

	// Account 1 makes a request (without JWS, falls back to IP)
	req1 := httptest.NewRequest(http.MethodPost, "/acme/new-order", nil)
	req1.RemoteAddr = "192.168.1.1:1234"
	w1 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Errorf("Account1: Expected status 200, got %d", w1.Code)
	}

	// Account 1's next request should be rate limited
	req2 := httptest.NewRequest(http.MethodPost, "/acme/new-order", nil)
	req2.RemoteAddr = "192.168.1.1:1234"
	w2 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("Account1: Expected status 429, got %d", w2.Code)
	}

	// Different account (different IP) should still be able to make requests
	req3 := httptest.NewRequest(http.MethodPost, "/acme/new-order", nil)
	req3.RemoteAddr = "192.168.1.2:5678"
	w3 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w3, req3)

	if w3.Code != http.StatusOK {
		t.Errorf("Account2: Expected status 200, got %d", w3.Code)
	}
}

// Tests consolidated from rate_limiter_nil_config_test.go

// TestNewOrderRateLimiter_NilConfig tests that nil config returns pass-through middleware
func TestNewOrderRateLimiter_NilConfig(t *testing.T) {
	middleware := NewOrderRateLimiter(nil)

	if middleware == nil {
		t.Fatal("Expected non-nil middleware")
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	wrappedHandler := middleware(handler)

	// Should pass through without rate limiting
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest(http.MethodPost, "/acme/new-order", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: Expected status 200, got %d", i+1, w.Code)
		}
	}
}

// TestCertificateRateLimiter_NilConfig tests that nil config returns pass-through middleware
func TestCertificateRateLimiter_NilConfig(t *testing.T) {
	middleware := CertificateRateLimiter(nil)

	if middleware == nil {
		t.Fatal("Expected non-nil middleware")
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	wrappedHandler := middleware(handler)

	// Should pass through without rate limiting
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest(http.MethodPost, "/acme/cert", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: Expected status 200, got %d", i+1, w.Code)
		}
	}
}

// TestOverallRateLimiter_NilConfig tests that nil config returns pass-through middleware
func TestOverallRateLimiter_NilConfig(t *testing.T) {
	middleware := OverallRateLimiter(nil)

	if middleware == nil {
		t.Fatal("Expected non-nil middleware")
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	wrappedHandler := middleware(handler)

	// Should pass through without rate limiting
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: Expected status 200, got %d", i+1, w.Code)
		}
	}
}

// TestFailedValidationRateLimiter_NilConfig tests that nil config returns pass-through middleware
func TestFailedValidationRateLimiter_NilConfig(t *testing.T) {
	middleware := FailedValidationRateLimiter(nil)

	if middleware == nil {
		t.Fatal("Expected non-nil middleware")
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	wrappedHandler := middleware(handler)

	// Should pass through without rate limiting
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest(http.MethodPost, "/acme/challenge", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: Expected status 200, got %d", i+1, w.Code)
		}
	}
}

// TestClientID_EmptyXForwardedFor tests ClientID with empty X-Forwarded-For header
func TestClientID_EmptyXForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	req.Header.Set("X-Forwarded-For", "")

	clientID := ClientID(req)

	// Should fall back to extracted IP from RemoteAddr (IP not in TrustedProxies)
	expectedIP := "192.168.1.100"
	if clientID != expectedIP {
		t.Errorf("Expected client ID to be %s, got %s", expectedIP, clientID)
	}
}

// TestClientIP_EmptyXForwardedFor tests ClientIP with empty X-Forwarded-For header
func TestClientIP_EmptyXForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	req.Header.Set("X-Forwarded-For", "")

	clientIP := ClientIP(req)

	// Should fall back to extracted IP from RemoteAddr (IP not in TrustedProxies)
	expectedIP := "192.168.1.100"
	if clientIP != expectedIP {
		t.Errorf("Expected client IP to be %s, got %s", expectedIP, clientIP)
	}
}

// Tests consolidated from final_91_coverage_test.go

// TestWriteRateLimitError_DirectCall tests the writeRateLimitError function directly.
// This ensures we cover the JSON encoding path and error handling.
func TestWriteRateLimitError_DirectCall(t *testing.T) {
	limiter := NewRateLimiter(10, time.Minute)

	recorder := httptest.NewRecorder()
	limiter.writeRateLimitError(recorder)

	// Verify HTTP status code
	require.Equal(t, http.StatusTooManyRequests, recorder.Code)

	// Verify Retry-After header (should be seconds as integer)
	retryAfter := recorder.Header().Get("Retry-After")
	require.Equal(t, "60", retryAfter)

	// Verify Content-Type header
	contentType := recorder.Header().Get("Content-Type")
	require.Equal(t, "application/problem+json", contentType)

	// Verify body contains ACME error
	body := recorder.Body.String()
	require.Contains(t, body, "rateLimited")
	require.Contains(t, body, "Rate limit exceeded")
}

// TestWriteRateLimitError_VariousIntervals tests with different intervals.
func TestWriteRateLimitError_VariousIntervals(t *testing.T) {
	tests := []struct {
		name            string
		interval        time.Duration
		expectedSeconds string
	}{
		{"one_second", time.Second, "1"},
		{"one_minute", time.Minute, "60"},
		{"one_hour", time.Hour, "3600"},
		{"30_seconds", 30 * time.Second, "30"},
		{"5_minutes", 5 * time.Minute, "300"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			limiter := NewRateLimiter(10, tc.interval)
			recorder := httptest.NewRecorder()
			limiter.writeRateLimitError(recorder)

			require.Equal(t, http.StatusTooManyRequests, recorder.Code)
			require.Equal(t, tc.expectedSeconds, recorder.Header().Get("Retry-After"))
		})
	}
}

// TestRateLimiter_MiddlewareExhaustion tests rate limiter when tokens are exhausted.
func TestRateLimiter_MiddlewareExhaustion(t *testing.T) {
	limiter := NewRateLimiter(2, time.Hour)
	middleware := limiter.MiddlewareFunc(func(r *http.Request) string {
		return "test-client"
	})

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request - should succeed
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	require.Equal(t, http.StatusOK, rec1.Code)

	// Second request - should succeed
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	require.Equal(t, http.StatusOK, rec2.Code)

	// Third request - should be rate limited
	req3 := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)
	require.Equal(t, http.StatusTooManyRequests, rec3.Code)
	require.Equal(t, "3600", rec3.Header().Get("Retry-After"))
}

// TestWriteJSONError tests the writeJSONError helper function.
func TestWriteJSONError(t *testing.T) {
	recorder := httptest.NewRecorder()

	err := writeJSONError(recorder, nil)
	require.NoError(t, err)
}

// TestClientID_WithEmptyBodyDirect tests ClientID with empty request body.
func TestClientID_WithEmptyBodyDirect(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"

	clientID := ClientID(req)
	// ClientID extracts IP from RemoteAddr (strips port)
	require.Equal(t, "192.168.1.100", clientID)
}

// TestClientIP_Direct tests ClientIP function.
func TestClientIP_Direct(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "10.0.0.1:54321"

	ip := ClientIP(req)
	// ClientIP extracts IP from RemoteAddr (strips port)
	require.Equal(t, "10.0.0.1", ip)
}

// TestNilConfigRateLimiters tests all rate limiter constructors with nil config.
func TestNilConfigRateLimiters(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("NewAccountRateLimiter_nil", func(t *testing.T) {
		middleware := NewAccountRateLimiter(nil)
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("NewOrderRateLimiter_nil", func(t *testing.T) {
		middleware := NewOrderRateLimiter(nil)
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("CertificateRateLimiter_nil", func(t *testing.T) {
		middleware := CertificateRateLimiter(nil)
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("OverallRateLimiter_nil", func(t *testing.T) {
		middleware := OverallRateLimiter(nil)
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("FailedValidationRateLimiter_nil", func(t *testing.T) {
		middleware := FailedValidationRateLimiter(nil)
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
	})
}
