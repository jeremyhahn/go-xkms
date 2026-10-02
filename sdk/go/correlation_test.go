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
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCorrelationSurface proves the SDK middleware is the transports' own:
// an inbound ID reaches the handler's context and is echoed to the client,
// and a request without one is given a fresh ID.
func TestCorrelationSurface(t *testing.T) {
	var seen string
	h := CorrelationMiddleware()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = CorrelationIDFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(CorrelationRequestIDHeader, "req-7")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if seen != "req-7" || rec.Header().Get(CorrelationIDHeader) != "req-7" {
		t.Fatalf("inbound ID: handler %q, response %q", seen, rec.Header().Get(CorrelationIDHeader))
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if seen == "" || seen == "req-7" || rec.Header().Get(CorrelationIDHeader) != seen {
		t.Fatalf("generated ID: handler %q, response %q", seen, rec.Header().Get(CorrelationIDHeader))
	}

	ctx := WithCorrelationID(context.Background(), "c-1")
	first, second := NewCorrelationID(), NewCorrelationID()
	if CorrelationIDOrNew(ctx) != "c-1" || CorrelationIDOrNew(context.Background()) == "" || first == second {
		t.Fatal("context helpers do not match the canonical package")
	}
	if CorrelationUnaryServerInterceptor(nil) == nil || CorrelationStreamServerInterceptor(nil) == nil {
		t.Fatal("interceptor constructors returned nil")
	}
}
