// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/stretchr/testify/require"
)

// TestNewClientRateLimiterMiddleware_AllowsWithinLimit verifies that
// NewClientRateLimiterMiddleware — the single construction path shared by
// the standalone TrustedCA and xkmsd's embedded ACME listener — admits
// requests from a single client up to the configured cap and serves them
// through to the wrapped handler.
func TestNewClientRateLimiterMiddleware_AllowsWithinLimit(t *testing.T) {
	recorder := &recordingRateLimitAuditLogger{}
	mw := NewClientRateLimiterMiddleware(2, time.Minute, recorder)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/acme/new-order", nil)
		req.RemoteAddr = "203.0.113.5:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		require.Equalf(t, http.StatusOK, rec.Code, "request %d within the cap should pass", i+1)
	}
	require.Empty(t, recorder.events, "no request within the cap should be audited as throttled")
}

// TestNewClientRateLimiterMiddleware_BlocksOverLimit verifies that a
// request exceeding the configured cap is refused with the RFC 8555
// Section 6.6 rateLimited problem document (HTTP 429, Retry-After header,
// urn:ietf:params:acme:error:rateLimited body) and that the throttle is
// recorded through the wired audit logger — the "requests carry a tenant"
// scope is not implemented (see docs/acme-issuance/engineering.md), so this
// exercises the per-client cap that is wired.
func TestNewClientRateLimiterMiddleware_BlocksOverLimit(t *testing.T) {
	recorder := &recordingRateLimitAuditLogger{}
	mw := NewClientRateLimiterMiddleware(1, time.Minute, recorder)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request consumes the only token.
	req1 := httptest.NewRequest(http.MethodPost, "/acme/new-account", nil)
	req1.RemoteAddr = "203.0.113.9:1234"
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	require.Equal(t, http.StatusOK, rec1.Code)

	// Second request from the same client is throttled.
	req2 := httptest.NewRequest(http.MethodPost, "/acme/new-account", nil)
	req2.RemoteAddr = "203.0.113.9:1234"
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	require.Equal(t, http.StatusTooManyRequests, rec2.Code)
	require.Equal(t, "application/problem+json", rec2.Header().Get("Content-Type"))
	require.Equal(t, "60", rec2.Header().Get("Retry-After"))

	var acmeErr entities.Error
	require.NoError(t, json.Unmarshal(rec2.Body.Bytes(), &acmeErr))
	require.Equal(t, "urn:ietf:params:acme:error:rateLimited", acmeErr.Type)

	require.Len(t, recorder.events, 1, "the throttled request must be audited")
}

// TestNewClientRateLimiterMiddleware_ZeroMaxRequests verifies the error/edge
// path: a misconfigured zero request cap fails closed (every request is
// throttled) rather than being silently treated as "unlimited". This is the
// admission-control property go-xkms#882 requires: an ACME endpoint must
// never accept unbounded traffic, even under a degenerate configuration.
func TestNewClientRateLimiterMiddleware_ZeroMaxRequests(t *testing.T) {
	mw := NewClientRateLimiterMiddleware(0, time.Minute, nil)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/acme/new-order", nil)
	req.RemoteAddr = "198.51.100.7:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusTooManyRequests, rec.Code)
}
