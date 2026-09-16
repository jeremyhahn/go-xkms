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

package guard

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// recordingDeny captures the arguments the guard passed to a DenyFunc, so
// tests can confirm the caller's own error envelope is invoked rather than
// one hard-coded by the guard.
func recordingDeny(status *int, err *error) DenyFunc {
	return func(w http.ResponseWriter, r *http.Request, s int, e error) {
		*status = s
		*err = e
		w.WriteHeader(s)
	}
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestGuard_MiddlewareNetworkSameOriginAccepted(t *testing.T) {
	g := New(slog.Default(), func(http.ResponseWriter, *http.Request, int, error) {})
	handler := g.Middleware(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "ca.example.com"
	req.Header.Set("Origin", "https://ca.example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for a same-origin caller, got %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://ca.example.com" {
		t.Errorf("expected the origin echoed, got %q", got)
	}
}

func TestGuard_MiddlewareNetworkCrossOriginRejected(t *testing.T) {
	var status int
	var denyErr error
	g := New(slog.Default(), recordingDeny(&status, &denyErr))
	handler := g.Middleware(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "ca.example.com"
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if status != http.StatusForbidden {
		t.Fatalf("expected deny to be called with 403, got %d", status)
	}
	forbidden, ok := denyErr.(*ErrForbiddenOrigin)
	if !ok {
		t.Fatalf("expected *ErrForbiddenOrigin, got %T", denyErr)
	}
	if forbidden.Origin != "https://evil.example.com" {
		t.Errorf("expected the rejected origin recorded, got %q", forbidden.Origin)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("a rejected origin must not be granted CORS access, got %q", got)
	}
}

func TestGuard_MiddlewareInProcessAcceptsOpaqueOrigin(t *testing.T) {
	g := New(slog.Default(), func(http.ResponseWriter, *http.Request, int, error) {}, WithInProcessTransport())
	handler := g.Middleware(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "null")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 in-process for an opaque origin, got %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != AnyOrigin {
		t.Errorf("expected the wildcard origin in-process, got %q", got)
	}
}

func TestGuard_MiddlewareAnswersPreflight(t *testing.T) {
	g := New(slog.Default(), func(http.ResponseWriter, *http.Request, int, error) {})
	handler := g.Middleware(okHandler())

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Host = "ca.example.com"
	req.Header.Set("Origin", "https://ca.example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for a preflight, got %d", rec.Code)
	}
}

func TestGuard_MiddlewareNoOriginSkipsCORSHeaders(t *testing.T) {
	g := New(slog.Default(), func(http.ResponseWriter, *http.Request, int, error) {})
	handler := g.Middleware(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for a request without an Origin header, got %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("a request with no Origin needs no CORS header, got %q", got)
	}
}

func TestGuard_AllowOriginRejectsUnparsableOrEmptyOrigin(t *testing.T) {
	g := New(slog.Default(), func(http.ResponseWriter, *http.Request, int, error) {})

	if _, ok := g.AllowOrigin("://not a url", "ca.example.com"); ok {
		t.Error("an unparsable origin must not be allowed on a network listener")
	}
	if _, ok := g.AllowOrigin("", "ca.example.com"); ok {
		t.Error("an empty origin must not be allowed on a network listener")
	}
}

func TestGuard_AllowOriginInProcessAcceptsAnything(t *testing.T) {
	g := New(slog.Default(), func(http.ResponseWriter, *http.Request, int, error) {}, WithInProcessTransport())

	allow, ok := g.AllowOrigin("://not a url", "ca.example.com")
	if !ok || allow != AnyOrigin {
		t.Errorf("expected the wildcard for any origin in-process, got %q, %v", allow, ok)
	}
}

func TestErrForbiddenOrigin_Error(t *testing.T) {
	e := &ErrForbiddenOrigin{Origin: "https://evil.example.com"}
	if got := e.Error(); got == "" {
		t.Fatal("expected a non-empty message")
	} else if got != "gui/guard: forbidden origin: https://evil.example.com" {
		t.Errorf("unexpected message: %q", got)
	}
}
