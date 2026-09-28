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

package audit

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/ratelimit"
)

// TestClientIP verifies that an audit record names the client that actually
// made the request rather than a reverse proxy standing in front of the CA,
// and that a forwarding header from an untrusted peer is never believed
// (go-xkms#1179).
func TestClientIP(t *testing.T) {
	tests := []struct {
		name    string
		proxies []string
		headers map[string]string
		remote  string
		want    string
	}{
		{name: "falls back to the peer address, port dropped", remote: "198.51.100.4:52344", want: "198.51.100.4"},
		{
			name:    "an untrusted peer's X-Forwarded-For is ignored",
			headers: map[string]string{"X-Forwarded-For": "203.0.113.7", "X-Real-IP": "10.0.0.1"},
			remote:  "10.0.0.1:9999",
			want:    "10.0.0.1",
		},
		{
			name:    "an untrusted peer's X-Real-IP is ignored",
			headers: map[string]string{"X-Real-IP": "203.0.113.8"},
			remote:  "10.0.0.1:9999",
			want:    "10.0.0.1",
		},
		{
			name:    "a trusted peer's X-Forwarded-For is believed",
			proxies: []string{"10.0.0.1"},
			headers: map[string]string{"X-Forwarded-For": "203.0.113.7", "X-Real-IP": "203.0.113.8"},
			remote:  "10.0.0.1:9999",
			want:    "203.0.113.7",
		},
		{
			name:    "a trusted peer's X-Real-IP is believed absent X-Forwarded-For",
			proxies: []string{"10.0.0.1"},
			headers: map[string]string{"X-Real-IP": "203.0.113.8"},
			remote:  "10.0.0.1:9999",
			want:    "203.0.113.8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxies, err := ratelimit.ParseTrustedProxies(tt.proxies)
			if err != nil {
				t.Fatalf("ParseTrustedProxies(%v): %v", tt.proxies, err)
			}
			old := trustedProxies
			SetTrustedProxies(proxies)
			defer func() { trustedProxies = old }()

			req := httptest.NewRequest("POST", "/acme/revoke-cert", nil)
			req.RemoteAddr = tt.remote
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			if got := ClientIP(req); got != tt.want {
				t.Fatalf("ClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestRequestContext verifies that the attributes stamped onto audit events
// are carried on the context handlers pass to the Log helpers.
func TestRequestContext(t *testing.T) {
	t.Run("uses the client's correlation ID", func(t *testing.T) {
		proxies, err := ratelimit.ParseTrustedProxies([]string{"198.51.100.4"})
		if err != nil {
			t.Fatalf("ParseTrustedProxies: %v", err)
		}
		old := trustedProxies
		SetTrustedProxies(proxies)
		defer func() { trustedProxies = old }()

		req := httptest.NewRequest("POST", "/acme/new-account", nil)
		req.RemoteAddr = "198.51.100.4:52344"
		req.Header.Set("X-Request-ID", "client-correlation-id")
		req.Header.Set("X-Forwarded-For", "203.0.113.7")
		req.Header.Set("User-Agent", "acme-client/2.1")

		ctx := RequestContext(context.Background(), req)

		if got := extractRequestID(ctx); got != "client-correlation-id" {
			t.Fatalf("request ID = %q", got)
		}
		if got := extractSourceIP(ctx); got != "203.0.113.7" {
			t.Fatalf("source IP = %q", got)
		}
		if got := extractUserAgent(ctx); got != "acme-client/2.1" {
			t.Fatalf("user agent = %q", got)
		}
	})

	t.Run("generates a correlation ID when the client sent none", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/acme/new-account", nil)
		req.RemoteAddr = "198.51.100.4:52344"

		ctx := RequestContext(context.Background(), req)

		requestID := extractRequestID(ctx)
		if requestID == "" {
			t.Fatal("every audited request must be correlatable")
		}
		if !strings.HasPrefix(requestID, "req-") {
			t.Fatalf("generated request ID = %q, want a req- prefix", requestID)
		}
		if got := extractSourceIP(ctx); got != "198.51.100.4" {
			t.Fatalf("source IP = %q", got)
		}
		if got := extractUserAgent(ctx); got != "" {
			t.Fatalf("user agent = %q, want empty", got)
		}
	})

	t.Run("preserves values already on the context", func(t *testing.T) {
		type key string
		req := httptest.NewRequest("POST", "/acme/new-account", nil)

		parent := context.WithValue(context.Background(), key("carried"), "value")
		ctx := RequestContext(parent, req)

		if got := ctx.Value(key("carried")); got != "value" {
			t.Fatalf("parent context value lost: %v", got)
		}
	})
}
