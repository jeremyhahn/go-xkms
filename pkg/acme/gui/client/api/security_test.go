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

package api

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/gui/guard"
)

// serveHost is the address a network deployment of the router
// ("trusted-acme-client serve") is reached at in these tests.
const serveHost = "acme.example.com:8443"

// serveOrigin is the origin of a browser that loaded the UI from serveHost.
const serveOrigin = "https://" + serveHost

// networkRouter builds the router the way "trusted-acme-client serve" does:
// on a real listener, with the default guard.
func networkRouter(t *testing.T) http.Handler {
	t.Helper()
	h := newHandlersFor(nil, nil, nil)
	return NewRouter(nil, h.service, slog.Default())
}

// inProcessRouter builds the router the way the desktop application does:
// mounted behind the Wails AssetServer handler, with no listener under it.
func inProcessRouter(t *testing.T) http.Handler {
	t.Helper()
	h := newHandlersFor(nil, nil, nil)
	return NewRouter(nil, h.service, slog.Default(), WithInProcessTransport())
}

// apiRequest builds a request addressed to the network deployment's host.
func apiRequest(method, path string, body []byte) *http.Request {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req.Host = serveHost
	return req
}

func serve(handler http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// apiRoutes is every route the API exposes. The device routes are listed
// because the guard must cover them too, regardless of what the handlers
// behind them currently return.
var apiRoutes = []struct {
	method string
	path   string
	body   []byte
}{
	{http.MethodPost, "/api/v1/account/register", []byte(`{}`)},
	{http.MethodGet, "/api/v1/accounts", nil},
	{http.MethodPost, "/api/v1/accounts", []byte(`{}`)},
	{http.MethodGet, "/api/v1/accounts/acc", nil},
	{http.MethodDelete, "/api/v1/accounts/acc", nil},
	{http.MethodPost, "/api/v1/certificate/request", []byte(`{}`)},
	{http.MethodPost, "/api/v1/certificate/renew", []byte(`{}`)},
	{http.MethodPost, "/api/v1/certificate/revoke", []byte(`{}`)},
	{http.MethodGet, "/api/v1/certificates", nil},
	{http.MethodGet, "/api/v1/certificates/web", nil},
	{http.MethodPost, "/api/v1/certificates/web/deploy", nil},
	{http.MethodPost, "/api/v1/device/enroll", []byte(`{}`)},
	{http.MethodPost, "/api/v1/device/attest", []byte(`{}`)},
}

// =============================================================================
// Network deployment: same-origin enforcement
// =============================================================================

// TestNetworkRouter_EveryRouteIsMounted uses OPTIONS, which the guard answers
// for any matched route, to separate "the route exists" from whatever the
// handler behind it makes of the request.
func TestNetworkRouter_EveryRouteIsMounted(t *testing.T) {
	router := networkRouter(t)
	for _, rt := range apiRoutes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			rec := serve(router, apiRequest(http.MethodOptions, rt.path, nil))
			if rec.Code != http.StatusNoContent {
				t.Fatalf("route not registered, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestNetworkRouter_NoRouteRequiresCredentials(t *testing.T) {
	router := networkRouter(t)
	for _, rt := range apiRoutes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			rec := serve(router, apiRequest(rt.method, rt.path, rt.body))
			if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
				t.Fatalf("a same-origin caller was rejected with %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestNetworkRouter_CrossOriginRejected(t *testing.T) {
	router := networkRouter(t)
	origins := []string{
		"https://evil.example.com",
		"http://evil.example.com",
		"null",
		"https://acme.example.com:9443",
		"wails://wails",
	}
	for _, origin := range origins {
		t.Run(origin, func(t *testing.T) {
			req := apiRequest(http.MethodPost, "/api/v1/certificate/request", []byte(`{}`))
			req.Header.Set("Origin", origin)
			rec := serve(router, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected 403 for Origin %q, got %d: %s", origin, rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
				t.Errorf("a rejected origin must not be granted CORS access, got %q", got)
			}
			if !strings.Contains(rec.Body.String(), "forbidden origin") {
				t.Errorf("expected the forbidden-origin envelope, got %s", rec.Body.String())
			}
		})
	}
}

func TestNetworkRouter_SameOriginAccepted(t *testing.T) {
	req := apiRequest(http.MethodGet, "/api/v1/accounts", nil)
	req.Header.Set("Origin", serveOrigin)
	rec := serve(networkRouter(t), req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for the same origin, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != serveOrigin {
		t.Errorf("expected the origin to be echoed, got %q", got)
	}
	if got := rec.Header().Get("Vary"); !strings.Contains(got, "Origin") {
		t.Errorf("expected Vary: Origin, got %q", got)
	}
}

func TestNetworkRouter_NoWildcardCORS(t *testing.T) {
	req := apiRequest(http.MethodGet, "/api/v1/accounts", nil)
	req.Header.Set("Origin", serveOrigin)
	rec := serve(networkRouter(t), req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got == guard.AnyOrigin {
		t.Error("a network deployment must not send the wildcard CORS header")
	}
}

// TestNetworkRouter_AnyHostAccepted records that the Host allow list is gone:
// it existed to defend a loopback listener against DNS rebinding, and the
// desktop application has no listener left to rebind to. The host a network
// deployment answers on is the operator's, not this router's, business.
func TestNetworkRouter_AnyHostAccepted(t *testing.T) {
	router := networkRouter(t)
	for _, host := range []string{"127.0.0.1:8443", "acme.internal", "attacker.example.com"} {
		t.Run(host, func(t *testing.T) {
			req := apiRequest(http.MethodGet, "/api/v1/accounts", nil)
			req.Host = host
			if rec := serve(router, req); rec.Code != http.StatusOK {
				t.Errorf("expected 200 for Host %q, got %d: %s", host, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestNetworkRouter_PreflightFromSameOrigin(t *testing.T) {
	req := apiRequest(http.MethodOptions, "/api/v1/accounts", nil)
	req.Header.Set("Origin", serveOrigin)
	rec := serve(networkRouter(t), req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for a preflight, got %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "Content-Type") {
		t.Errorf("a preflight must allow the Content-Type header, got %q", got)
	}
}

func TestNetworkRouter_PreflightFromForeignOriginRejected(t *testing.T) {
	req := apiRequest(http.MethodOptions, "/api/v1/accounts", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	if rec := serve(networkRouter(t), req); rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for a foreign preflight, got %d", rec.Code)
	}
}

// =============================================================================
// In-process deployment: no listener, no origin to enforce
// =============================================================================

func TestInProcessRouter_EveryRouteIsMounted(t *testing.T) {
	router := inProcessRouter(t)
	for _, rt := range apiRoutes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			rec := serve(router, apiRequest(http.MethodOptions, rt.path, nil))
			if rec.Code != http.StatusNoContent {
				t.Fatalf("route not registered, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestInProcessRouter_NoRouteChallengesTheWebview(t *testing.T) {
	router := inProcessRouter(t)
	for _, rt := range apiRoutes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			rec := serve(router, apiRequest(rt.method, rt.path, rt.body))
			if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
				t.Fatalf("the webview's own request was rejected with %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestInProcessRouter_EveryWebviewOriginAccepted covers the reason the origin
// check is dropped in-process: a webview presents an origin of its own scheme,
// which differs per platform and may be opaque, and every one of them is the
// application's own user interface. Accepting them costs nothing because no
// socket exists for anything else to arrive on.
func TestInProcessRouter_EveryWebviewOriginAccepted(t *testing.T) {
	router := inProcessRouter(t)
	origins := []string{
		"wails://wails",
		"wails://wails.localhost",
		"http://wails.localhost",
		"https://wails.localhost",
		"null",
		"https://evil.example.com",
	}
	for _, origin := range origins {
		t.Run(origin, func(t *testing.T) {
			req := apiRequest(http.MethodGet, "/api/v1/accounts", nil)
			req.Header.Set("Origin", origin)
			rec := serve(router, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200 for Origin %q, got %d: %s", origin, rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != guard.AnyOrigin {
				t.Errorf("expected the wildcard CORS header so an opaque origin can read the response, got %q", got)
			}
		})
	}
}

func TestInProcessRouter_PreflightAnswered(t *testing.T) {
	req := apiRequest(http.MethodOptions, "/api/v1/accounts", nil)
	req.Header.Set("Origin", "wails://wails")
	rec := serve(inProcessRouter(t), req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for a preflight, got %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, http.MethodPut) {
		t.Errorf("a preflight must allow the methods the frontend uses, got %q", got)
	}
}

func TestInProcessRouter_RequestWithoutOriginServed(t *testing.T) {
	rec := serve(inProcessRouter(t), apiRequest(http.MethodGet, "/api/v1/accounts", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 without an Origin header, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("a request with no Origin needs no CORS header, got %q", got)
	}
}

// =============================================================================
// Error types
// =============================================================================

func TestErrForbiddenOrigin_Error(t *testing.T) {
	e := &ErrForbiddenOrigin{Origin: "https://evil.example.com"}
	if !strings.Contains(e.Error(), "https://evil.example.com") {
		t.Errorf("expected the origin in the message: %q", e.Error())
	}
}

func TestGuard_AllowOriginRejectsUnparsableOrigin(t *testing.T) {
	g := guard.New(slog.Default(), denyOrigin)
	if _, ok := g.AllowOrigin("://not a url", serveHost); ok {
		t.Error("an unparsable origin must not be allowed on a network listener")
	}
	if _, ok := g.AllowOrigin("", serveHost); ok {
		t.Error("an empty origin must not be allowed on a network listener")
	}
}
