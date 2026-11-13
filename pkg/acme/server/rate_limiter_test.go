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
	"github.com/jeremyhahn/go-xkms/pkg/ratelimit"
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

func TestClientIP(t *testing.T) {
	// Save and restore TrustedProxies
	oldTrustedProxies := TrustedProxies
	defer func() { TrustedProxies = oldTrustedProxies }()

	// Set up trusted proxies for these tests - include common test IPs
	TrustedProxies = mustTrustedProxies(t, "10.0.0.1", "::1")

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

		// Only the hop the trusted proxy appended (the rightmost) is
		// believed; entries to its left were supplied by the client.
		if clientIP != "150.172.238.178" {
			t.Errorf("Expected client IP to be 150.172.238.178, got %s", clientIP)
		}
	})

	t.Run("XForwardedFor_WithWhitespace", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("X-Forwarded-For", "  203.0.113.50  ,  70.41.3.18  ")

		clientIP := ClientIP(req)

		if clientIP != "70.41.3.18" {
			t.Errorf("Expected client IP to be 70.41.3.18, got %s", clientIP)
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

		if clientIP != "2001:db8::2" {
			t.Errorf("Expected IPv6 address 2001:db8::2, got %s", clientIP)
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

	// Built directly rather than through a per-category constructor: the
	// tenant-aware new-order/certificate/failed-validation limiters are the
	// only production callers of rateLimitClientIDKey today, and they are
	// exercised end to end elsewhere (tenant_rate_limiter_test.go). This test
	// isolates the ClientID-keying behavior itself.
	limiter := NewRateLimiter(config.MaxRequests, config.Interval)
	middleware := limiter.MiddlewareFunc(rateLimitClientIDKey)

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

// Tests consolidated from final_91_coverage_test.go

// mustTrustedProxies parses a trusted-proxy list for a test.
func mustTrustedProxies(t *testing.T, entries ...string) *ratelimit.TrustedProxies {
	t.Helper()
	proxies, err := ratelimit.ParseTrustedProxies(entries)
	if err != nil {
		t.Fatalf("ParseTrustedProxies(%v): %v", entries, err)
	}
	return proxies
}
