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
