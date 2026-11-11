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

package ratelimit

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

func mustProxies(t *testing.T, entries ...string) *TrustedProxies {
	t.Helper()
	p, err := ParseTrustedProxies(entries)
	if err != nil {
		t.Fatalf("ParseTrustedProxies(%v): %v", entries, err)
	}
	return p
}

func TestParseTrustedProxies(t *testing.T) {
	p := mustProxies(t, "10.0.0.1", " 192.168.0.0/16 ", "2001:db8::/32", "::ffff:172.16.0.9")
	for addr, want := range map[string]bool{
		"10.0.0.1":     true,
		"10.0.0.2":     false,
		"192.168.44.3": true,
		"2001:db8::7":  true,
		"2001:db9::7":  false,
		"172.16.0.9":   true,
	} {
		if got := p.Contains(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Contains(%s) = %v, want %v", addr, got, want)
		}
	}

	empty, err := ParseTrustedProxies(nil)
	if err != nil || empty != nil {
		t.Fatalf("ParseTrustedProxies(nil) = %v, %v; want nil, nil", empty, err)
	}
}

func TestParseTrustedProxies_RejectsMalformedEntry(t *testing.T) {
	for _, entry := range []string{"proxy.example.com", "10.0.0.0/33", "", "10.0.0.1:80"} {
		_, err := ParseTrustedProxies([]string{"10.0.0.1", entry})
		var invalid *InvalidTrustedProxyError
		if !errors.As(err, &invalid) || invalid.Entry != entry {
			t.Errorf("ParseTrustedProxies(%q) error = %v, want *InvalidTrustedProxyError", entry, err)
			continue
		}
		if !strings.Contains(err.Error(), `"`+entry+`"`) {
			t.Errorf("InvalidTrustedProxyError message %q does not name the entry", err.Error())
		}
	}
}

func TestTrustedProxies_NilTrustsNothing(t *testing.T) {
	var p *TrustedProxies
	if p.Contains(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("nil TrustedProxies must trust no address")
	}
}

func TestClientIP(t *testing.T) {
	proxies := mustProxies(t, "10.0.0.1", "10.0.1.0/24", "::1")
	tests := []struct {
		name       string
		proxies    *TrustedProxies
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{name: "peer port is dropped", remoteAddr: "192.0.2.7:51234", want: "192.0.2.7"},
		{name: "ipv6 peer port is dropped", remoteAddr: "[2001:db8::5]:443", want: "2001:db8::5"},
		{name: "portless peer kept", remoteAddr: "192.0.2.7", want: "192.0.2.7"},
		{
			name:       "untrusted peer XFF ignored",
			proxies:    proxies,
			remoteAddr: "192.0.2.7:1",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.9", "X-Real-IP": "203.0.113.10"},
			want:       "192.0.2.7",
		},
		{
			name:       "nil proxies ignore XFF",
			remoteAddr: "10.0.0.1:1",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.9"},
			want:       "10.0.0.1",
		},
		{
			name:       "trusted peer single hop",
			proxies:    proxies,
			remoteAddr: "10.0.0.1:1",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.9"},
			want:       "203.0.113.9",
		},
		{
			name:       "client-forged hops left of the proxy-appended entry are ignored",
			proxies:    proxies,
			remoteAddr: "10.0.0.1:1",
			headers:    map[string]string{"X-Forwarded-For": "198.51.100.66, 203.0.113.9"},
			want:       "203.0.113.9",
		},
		{
			name:       "chained trusted proxies are skipped",
			proxies:    proxies,
			remoteAddr: "10.0.0.1:1",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.9, 10.0.1.20"},
			want:       "203.0.113.9",
		},
		{
			name:       "malformed XFF falls back to X-Real-IP",
			proxies:    proxies,
			remoteAddr: "10.0.0.1:1",
			headers:    map[string]string{"X-Forwarded-For": "not-an-ip", "X-Real-IP": " 198.51.100.25 "},
			want:       "198.51.100.25",
		},
		{
			name:       "only trusted hops falls back to peer",
			proxies:    proxies,
			remoteAddr: "10.0.0.1:1",
			headers:    map[string]string{"X-Forwarded-For": "10.0.1.3"},
			want:       "10.0.0.1",
		},
		{
			name:       "malformed X-Real-IP falls back to peer",
			proxies:    proxies,
			remoteAddr: "[::1]:1",
			headers:    map[string]string{"X-Real-IP": strings.Repeat("a", 4096)},
			want:       "::1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			if got := tt.proxies.ClientIP(req); got != tt.want {
				t.Errorf("ClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

// serveFrom sends one request through h from remoteAddr with the given
// X-Forwarded-For value and returns the status code.
func serveFrom(h http.Handler, remoteAddr, xff string) int {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

func newMiddlewareUnderTest(t *testing.T, proxies *TrustedProxies) http.Handler {
	t.Helper()
	limiter := New(&Config{Enabled: true, RequestsPerMinute: 1, Burst: 1})
	t.Cleanup(limiter.Stop)
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return Middleware(limiter, proxies)(ok)
}

func TestMiddleware_RotatedXFFFromUntrustedPeerSharesBucket(t *testing.T) {
	h := newMiddlewareUnderTest(t, mustProxies(t, "10.0.0.1"))
	if code := serveFrom(h, "192.0.2.7:1000", "203.0.113.1"); code != http.StatusOK {
		t.Fatalf("first request = %d, want 200", code)
	}
	for i := 2; i < 6; i++ {
		if code := serveFrom(h, "192.0.2.7:1000", "203.0.113."+strconv.Itoa(i)); code != http.StatusTooManyRequests {
			t.Fatalf("rotated XFF #%d = %d, want 429", i, code)
		}
	}
}

func TestMiddleware_NewConnectionFromSameIPSharesBucket(t *testing.T) {
	h := newMiddlewareUnderTest(t, nil)
	if code := serveFrom(h, "192.0.2.7:1000", ""); code != http.StatusOK {
		t.Fatalf("first connection = %d, want 200", code)
	}
	if code := serveFrom(h, "192.0.2.7:1001", ""); code != http.StatusTooManyRequests {
		t.Fatalf("second connection from same IP = %d, want 429", code)
	}
	if code := serveFrom(h, "192.0.2.8:1000", ""); code != http.StatusOK {
		t.Fatalf("different IP = %d, want 200", code)
	}
}

func TestMiddleware_TrustedProxySelectsClient(t *testing.T) {
	h := newMiddlewareUnderTest(t, mustProxies(t, "10.0.0.0/8"))
	if code := serveFrom(h, "10.0.0.1:1000", "203.0.113.1"); code != http.StatusOK {
		t.Fatalf("client A = %d, want 200", code)
	}
	if code := serveFrom(h, "10.0.0.1:1000", "203.0.113.1"); code != http.StatusTooManyRequests {
		t.Fatalf("client A again = %d, want 429", code)
	}
	// A different client behind the same proxy gets its own bucket.
	if code := serveFrom(h, "10.0.0.1:1001", "203.0.113.2"); code != http.StatusOK {
		t.Fatalf("client B via same proxy = %d, want 200", code)
	}
}

func TestLimiter_MaxClientsRefusesNewClients(t *testing.T) {
	limiter := New(&Config{Enabled: true, RequestsPerMinute: 600, Burst: 10, MaxClients: 2})
	t.Cleanup(limiter.Stop)

	if !limiter.Allow("a") || !limiter.Allow("b") {
		t.Fatal("clients within the cap must be admitted")
	}
	if limiter.Allow("c") {
		t.Fatal("a new client beyond the cap must be refused")
	}
	var capErr *CapacityError
	if err := limiter.Wait(context.Background(), "c"); !errors.As(err, &capErr) || capErr.Limit != 2 {
		t.Fatalf("Wait beyond the cap = %v, want *CapacityError{Limit: 2}", err)
	}
	if !strings.Contains(capErr.Error(), "2") {
		t.Fatalf("CapacityError message %q does not name the limit", capErr.Error())
	}
	if !limiter.Allow("a") {
		t.Fatal("an already-tracked client must be unaffected by the cap")
	}
	if got := limiter.Stats()["active_clients"]; got != 2 {
		t.Fatalf("active_clients = %v, want 2", got)
	}

	// Once idle clients are cleaned up, new clients are admitted again.
	limiter.maxIdle = 0
	limiter.cleanup()
	if !limiter.Allow("c") {
		t.Fatal("a new client must be admitted after cleanup frees capacity")
	}
}

func TestRateLimitKey(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want string
	}{
		{name: "ipv4 keys on the exact address", ip: "203.0.113.9", want: "203.0.113.9"},
		{name: "another ipv4 keys on its own exact address", ip: "203.0.113.10", want: "203.0.113.10"},
		{name: "ipv6 keys on its /64", ip: "2001:db8:1::1", want: "2001:db8:1::/64"},
		{name: "a different address in the same /64 shares the key", ip: "2001:db8:1::ffff", want: "2001:db8:1::/64"},
		{name: "a different /64 gets a different key", ip: "2001:db8:2::1", want: "2001:db8:2::/64"},
		{name: "ipv4-mapped ipv6 keys as ipv4", ip: "::ffff:203.0.113.9", want: "203.0.113.9"},
		{name: "a non-IP value (e.g. a JWS KID) passes through unchanged", ip: "https://acme.example/acct/1", want: "https://acme.example/acct/1"},
		{name: "empty string passes through unchanged", ip: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RateLimitKey(tt.ip); got != tt.want {
				t.Errorf("RateLimitKey(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

func TestRateLimitKey_IPv6AddressesInSameSlash64ShareABucket(t *testing.T) {
	a := RateLimitKey("2001:db8:abcd:1::1")
	b := RateLimitKey("2001:db8:abcd:1::2")
	if a != b {
		t.Fatalf("two addresses in the same /64 must share a rate-limit key: %q != %q", a, b)
	}

	c := RateLimitKey("2001:db8:abcd:2::1")
	if a == c {
		t.Fatalf("addresses in different /64s must not share a rate-limit key: both resolved to %q", a)
	}
}
