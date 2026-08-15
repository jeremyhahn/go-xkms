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

// TestBindRoute_UpstreamIdentitySkipsLocalAuthentication proves the
// single-pass authentication contract of the unified server: a request
// already carrying an identity (authenticated upstream by qrdb's
// middleware) is admitted without consulting xkms's authenticator, while an
// anonymous request still faces it.
func TestBindRoute_UpstreamIdentitySkipsLocalAuthentication(t *testing.T) {
	s := newBindRouteServer(t)
	h := s.BindRoute(findRoute(t, "GET", "/api/v1/keys"))

	// Anonymous: the rejecting authenticator denies.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/keys", nil))
	assert.Equal(t, http.StatusUnauthorized, w.Code,
		"anonymous request must face the local authenticator")

	// Upstream-authenticated: admitted without the local authenticator.
	req := httptest.NewRequest("GET", "/api/v1/keys", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), &auth.Identity{
		Subject:  "upstream-user",
		TenantID: "system",
	}))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code,
		"upstream-authenticated request must bypass the local authenticator")
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
