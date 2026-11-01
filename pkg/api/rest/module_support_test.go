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

package rest

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// newBindRouteServer builds a server whose authenticator rejects everything,
// so the single-pass authentication semantics are observable.
func newBindRouteServer(t *testing.T) *Server {
	t.Helper()
	s, err := NewServer(&Config{
		Authenticator: rejectingAuthenticator{},
		Backends:      map[string]xkms.Backend{"test": newMockKeyStore()},
		Logger:        testLogger(),
	})
	require.NoError(t, err)
	return s
}

// findRoute returns the first table route matching method+pattern.
func findRoute(t *testing.T, method, pattern string) RouteSpec {
	t.Helper()
	for _, spec := range Routes() {
		if spec.Method == method && spec.Pattern == pattern {
			return spec
		}
	}
	t.Fatalf("route %s %s not in table", method, pattern)
	return RouteSpec{}
}

// TestBindRoute_AuthenticationIsUpstream proves the P1 contract: BindRoute
// itself applies NO authentication — go-qrdb's middleware owns it on the
// unified server (its mTLS chain first, then the module's AuthenticateHTTP
// fallback), so the bound handler serves a request whose identity was bound
// upstream and never consults the local authenticator inline.
func TestBindRoute_AuthenticationIsUpstream(t *testing.T) {
	s := newBindRouteServer(t)
	h := s.BindRoute(findRoute(t, "GET", "/api/v1/keys"))

	// Upstream-authenticated: served with the identity from the context.
	req := httptest.NewRequest("GET", "/api/v1/keys", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), &auth.Identity{
		Subject:  "upstream-user",
		TenantID: "system",
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code,
		"upstream-authenticated request must be served")
}

// TestServer_AuthenticateHTTP_FallbackContract proves the module fallback
// seam: the rejecting authenticator fails closed (no identity, an error),
// and a nil authenticator is a typed error rather than an open door.
func TestServer_AuthenticateHTTP_FallbackContract(t *testing.T) {
	s := newBindRouteServer(t)
	id, err := s.AuthenticateHTTP(httptest.NewRequest("GET", "/api/v1/keys", nil))
	assert.Error(t, err, "the rejecting authenticator must fail closed")
	assert.Nil(t, id)

	s.authenticator = nil
	id, err = s.AuthenticateHTTP(httptest.NewRequest("GET", "/api/v1/keys", nil))
	assert.ErrorIs(t, err, ErrAuthenticatorRequired)
	assert.Nil(t, id)
}

// TestBindRoute_PublicRouteSkipsAuthentication proves public routes bind
// without any authentication middleware.
func TestBindRoute_PublicRouteSkipsAuthentication(t *testing.T) {
	s := newBindRouteServer(t)
	h := s.BindRoute(findRoute(t, "GET", "/health"))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/health", nil))
	assert.Equal(t, http.StatusOK, w.Code)
}

// corsTestOrigin is the second relying-party origin the WebAuthn browser
// suite serves its cross-origin page from
// (test/integration/webauthn-browser/config.yaml).
const corsTestOrigin = "https://localhost:18444"

// newCORSBindRouteServer is newBindRouteServer with corsTestOrigin
// allow-listed.
func newCORSBindRouteServer(t *testing.T) *Server {
	t.Helper()
	s, err := NewServer(&Config{
		Authenticator: rejectingAuthenticator{},
		Backends:      map[string]xkms.Backend{"test": newMockKeyStore()},
		Logger:        testLogger(),
		CORS:          &CORSOptions{AllowedOrigins: []string{corsTestOrigin}},
	})
	require.NoError(t, err)
	return s
}

// newPreflight builds a browser's CORS preflight for a WebAuthn ceremony
// POST from origin.
func newPreflight(path, origin string) *http.Request {
	req := httptest.NewRequest(http.MethodOptions, path, nil)
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	req.Header.Set("Access-Control-Request-Headers", "content-type,x-session-id")
	return req
}

// TestBindPreflight_AllowsConfiguredOriginOnRegistrationRoutes proves a
// preflight from an allow-listed origin on the registration ceremony routes
// is answered with that origin allowed and the ceremony's session header
// permitted, as the legacy router answered it.
func TestBindPreflight_AllowsConfiguredOriginOnRegistrationRoutes(t *testing.T) {
	h := newCORSBindRouteServer(t).BindPreflight()
	for _, path := range []string{
		"/api/v1/webauthn/registration/begin",
		"/api/v1/webauthn/registration/finish",
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, newPreflight(path, corsTestOrigin))

		assert.Equal(t, http.StatusNoContent, w.Code, path)
		assert.Equal(t, corsTestOrigin, w.Header().Get("Access-Control-Allow-Origin"), path)
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), http.MethodPost, path)
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Headers"), "X-Session-Id", path)
	}
}

// TestBindPreflight_RefusesUnlistedOrigin proves a preflight from an origin
// the policy does not list, and any preflight without a policy, is refused
// and carries no Access-Control-Allow-Origin.
func TestBindPreflight_RefusesUnlistedOrigin(t *testing.T) {
	for name, tc := range map[string]struct {
		server *Server
		origin string
	}{
		"unlisted origin": {newCORSBindRouteServer(t), "https://evil.example"},
		"no cors policy":  {newBindRouteServer(t), corsTestOrigin},
	} {
		w := httptest.NewRecorder()
		tc.server.BindPreflight().ServeHTTP(w, newPreflight("/api/v1/webauthn/registration/begin", tc.origin))

		assert.Equal(t, http.StatusForbidden, w.Code, name)
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"), name)
		assert.Contains(t, w.Body.String(), ErrCORSPreflightRefused.Error(), name)
	}
}

// TestBindRoute_AppliesCORSPolicy proves a bound route's response to an
// allow-listed origin carries the policy's headers -- the browser reads the
// ceremony's X-Session-Id only when it is exposed -- and a response to an
// unlisted origin carries none.
func TestBindRoute_AppliesCORSPolicy(t *testing.T) {
	h := newCORSBindRouteServer(t).BindRoute(findRoute(t, "GET", "/health"))

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/health", nil)
	req.Header.Set("Origin", corsTestOrigin)
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, corsTestOrigin, w.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, w.Header().Get("Access-Control-Expose-Headers"), "X-Session-Id")

	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/health", nil)
	req.Header.Set("Origin", "https://evil.example")
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}
