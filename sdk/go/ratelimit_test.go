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

package xkms

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestIPRateLimitSurface proves the SDK limiter is the canonical one: it
// refuses a client over its burst with 429, believes X-Forwarded-For only
// from a trusted proxy, and buckets IPv6 clients on their /64.
func TestIPRateLimitSurface(t *testing.T) {
	limiter := NewIPRateLimiter(&IPRateLimitConfig{Enabled: true, RequestsPerMinute: 60, Burst: 1})
	defer limiter.Stop()
	proxies, err := ParseTrustedProxies([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	h := IPRateLimitMiddleware(limiter, proxies)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	serve := func(remote, forwarded string) int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = remote
		if forwarded != "" {
			req.Header.Set("X-Forwarded-For", forwarded)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if got := serve("10.1.1.1:1000", "203.0.113.5"); got != http.StatusNoContent {
		t.Fatalf("first request = %d", got)
	}
	// Same forwarded client through another trusted proxy: same bucket.
	if got := serve("10.2.2.2:1000", "203.0.113.5"); got != http.StatusTooManyRequests {
		t.Fatalf("second request from the forwarded client = %d, want 429", got)
	}
	// An untrusted peer's X-Forwarded-For is ignored: it buckets on itself.
	if got := serve("198.51.100.9:1000", "203.0.113.5"); got != http.StatusNoContent {
		t.Fatalf("untrusted peer = %d", got)
	}

	if IPRateLimitKey("2001:db8:1:2::1") != IPRateLimitKey("2001:db8:1:2::ffff") {
		t.Fatal("IPv6 clients in one /64 must share a key")
	}
	if IPRateLimitDefaultMaxClients <= 0 || IPRateLimitUnaryServerInterceptor(limiter) == nil || IPRateLimitStreamServerInterceptor(limiter) == nil {
		t.Fatal("limiter surface incomplete")
	}
}

func TestIPRateLimitSurface_InvalidProxy(t *testing.T) {
	var invalid *InvalidTrustedProxyError
	if _, err := ParseTrustedProxies([]string{"not-a-network"}); !errors.As(err, &invalid) {
		t.Fatalf("err = %v, want *InvalidTrustedProxyError", err)
	}
	if (&IPRateLimitCapacityError{Limit: 3}).Error() == "" {
		t.Fatal("capacity error has no message")
	}
}
