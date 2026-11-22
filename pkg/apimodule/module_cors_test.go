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

package apimodule

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

const corsTestOrigin = "https://localhost:18444"

// newGatedSurface builds the module's HTTP surface on a live chi router the
// way the unified server does: Handle routes sit behind an auth gate that
// refuses every request (401, as an unauthenticated preflight sees it) and
// HandlePublic / HandleOptional routes serve the handler directly.
func newGatedSurface(t *testing.T, opts ...Option) *httptest.Server {
	t.Helper()
	mux := chi.NewRouter()
	gate := func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
	r := qrdbsdk.NewModuleHTTPRegistrar(mux,
		func(method, pattern string, _ qrdbsdk.Permission, _ http.HandlerFunc) {
			mux.MethodFunc(method, pattern, gate)
		},
		func(method, pattern string, h http.HandlerFunc) {
			mux.MethodFunc(method, pattern, h)
		},
		func(method, pattern string, h http.HandlerFunc) {
			mux.MethodFunc(method, pattern, h)
		})
	m, err := NewModule(func() *xkms.XKMSService { return nil }, opts...)
	if err != nil {
		t.Fatalf("NewModule: %v", err)
	}
	m.RegisterHTTP(r)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// corsWebAuthnPath returns a concrete public webauthn POST route the
// browser ceremony calls cross-origin.
func corsWebAuthnPath(t *testing.T) string {
	t.Helper()
	for _, spec := range rest.Routes() {
		if spec.Method == http.MethodPost && spec.Auth == rest.RouteAuthPublic &&
			strings.Contains(spec.Pattern, "webauthn") && !strings.Contains(spec.Pattern, "{") {
			return spec.Pattern
		}
	}
	t.Fatal("no public webauthn POST route")
	return ""
}

func corsDo(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	_ = resp.Body.Close()
	return resp
}

func preflight(t *testing.T, srv *httptest.Server, path, origin string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodOptions, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	req.Header.Set("Access-Control-Request-Headers", "content-type,x-session-id")
	return corsDo(t, req)
}

func corsPost(t *testing.T, srv *httptest.Server, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", corsTestOrigin)
	req.Header.Set("Content-Type", "application/json")
	return corsDo(t, req)
}

func corsEnabled() Option {
	return WithCORS(&rest.CORSOptions{
		AllowedOrigins:   []string{corsTestOrigin},
		AllowCredentials: true,
	})
}

// TestRegisterHTTP_CORSPreflightAllowedOrigin pins #2329: a preflight from an
// allowed origin is answered before the auth gate with the configured policy.
func TestRegisterHTTP_CORSPreflightAllowedOrigin(t *testing.T) {
	srv := newGatedSurface(t, corsEnabled())
	path := corsWebAuthnPath(t)

	resp := preflight(t, srv, path, corsTestOrigin)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		t.Fatalf("preflight status = %d, want 2xx", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != corsTestOrigin {
		t.Fatalf("Allow-Origin = %q, want %q", got, corsTestOrigin)
	}
	if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("Allow-Credentials = %q, want true", got)
	}
	allowed := strings.ToLower(resp.Header.Get("Access-Control-Allow-Headers"))
	if !strings.Contains(allowed, "x-session-id") {
		t.Fatalf("Allow-Headers = %q, want x-session-id", allowed)
	}

	// An authenticated route's preflight is answered before the auth gate too.
	for _, spec := range rest.Routes() {
		if spec.Auth == rest.RouteAuthPermission && !strings.Contains(spec.Pattern, "{") && !rest.IsHostRoute(spec) {
			resp := preflight(t, srv, spec.Pattern, corsTestOrigin)
			if resp.StatusCode == http.StatusUnauthorized || resp.Header.Get("Access-Control-Allow-Origin") != corsTestOrigin {
				t.Fatalf("preflight %s = %d (Allow-Origin %q), want answered before auth",
					spec.Pattern, resp.StatusCode, resp.Header.Get("Access-Control-Allow-Origin"))
			}
			break
		}
	}
}

// TestRegisterHTTP_CORSPreflightRefusedOrigin: another origin gets no CORS
// headers.
func TestRegisterHTTP_CORSPreflightRefusedOrigin(t *testing.T) {
	srv := newGatedSurface(t, corsEnabled())
	resp := preflight(t, srv, corsWebAuthnPath(t), "https://evil.example")
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Allow-Origin = %q for a refused origin, want none", got)
	}
}

// TestRegisterHTTP_CORSActualRequest: the cross-origin POST itself carries
// Allow-Origin and Expose-Headers.
func TestRegisterHTTP_CORSActualRequest(t *testing.T) {
	srv := newGatedSurface(t, corsEnabled())
	resp := corsPost(t, srv, corsWebAuthnPath(t))
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != corsTestOrigin {
		t.Fatalf("Allow-Origin = %q, want %q (status %d)", got, corsTestOrigin, resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Expose-Headers"); got == "" {
		t.Fatal("Expose-Headers missing on the cross-origin response")
	}
}

// TestRegisterHTTP_CORSDisabled: without a policy no CORS headers appear.
func TestRegisterHTTP_CORSDisabled(t *testing.T) {
	srv := newGatedSurface(t)
	path := corsWebAuthnPath(t)
	for _, resp := range []*http.Response{
		preflight(t, srv, path, corsTestOrigin),
		corsPost(t, srv, path),
	} {
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("Allow-Origin = %q with CORS disabled, want none", got)
		}
	}
}
