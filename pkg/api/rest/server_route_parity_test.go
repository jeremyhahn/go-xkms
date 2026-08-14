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
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// collectRoutes walks the server's chi router and returns the sorted
// "METHOD pattern" set it serves.
func collectRoutes(t *testing.T, s *Server) []string {
	t.Helper()

	mux, ok := s.server.Handler.(*chi.Mux)
	require.True(t, ok, "server handler is not a *chi.Mux")

	var routes []string
	err := chi.Walk(mux, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		routes = append(routes, method+" "+route)
		return nil
	})
	require.NoError(t, err)

	sort.Strings(routes)
	return routes
}

// TestRouteParity_RBACAndNonRBACArmsMatch proves the RBAC and non-RBAC
// registration arms in setupRouter expose the identical route set. A route
// present in only one arm silently appears or disappears when the operator
// toggles auth.enable_rbac — exactly the class of bug where
// POST /keys/{id}/encrypt-asym existed only without RBAC.
func TestRouteParity_RBACAndNonRBACArmsMatch(t *testing.T) {
	ks := newMockKeyStore()

	newCfg := func() *Config {
		return &Config{
			Authenticator: auth.NewNoOpAuthenticator(),
			Backends:      map[string]xkms.Backend{"test": ks},
			Logger:        testLogger(),
			SSHClient:     newMockSSHClient(),
		}
	}

	plain, err := NewServer(newCfg())
	require.NoError(t, err)

	rbacCfg := newCfg()
	rbacCfg.EnableRBAC = true
	rbacCfg.RBACAuthorizer = auth.NewAuthorizer(denyingRBACClient{})
	rbac, err := NewServer(rbacCfg)
	require.NoError(t, err)

	assert.Equal(t, collectRoutes(t, plain), collectRoutes(t, rbac),
		"RBAC and non-RBAC arms must register the identical route set")
}

// rejectingAuthenticator refuses every request, standing in for a production
// authenticator with no credentials presented.
type rejectingAuthenticator struct{}

func (rejectingAuthenticator) AuthenticateHTTP(*http.Request) (*auth.Identity, error) {
	return nil, auth.ErrAuthenticationFailed
}

func (rejectingAuthenticator) AuthenticateGRPC(context.Context, metadata.MD) (*auth.Identity, error) {
	return nil, auth.ErrAuthenticationFailed
}

func (rejectingAuthenticator) Name() string { return "rejecting" }

// TestSSHRoutes_RequireAuthentication is the regression test for the SSH
// route mount: /xkms/v1/ssh/* previously registered at the router root with
// no middleware, so key generation and signing were reachable anonymously.
func TestSSHRoutes_RequireAuthentication(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Authenticator: rejectingAuthenticator{},
		Backends:      map[string]xkms.Backend{"test": ks},
		Logger:        testLogger(),
		SSHClient:     newMockSSHClient(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	paths := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/xkms/v1/ssh/keys"},
		{http.MethodPost, "/xkms/v1/ssh/keys"},
		{http.MethodPost, "/xkms/v1/ssh/keys/host/root/id/sign"},
		{http.MethodGet, "/xkms/v1/ssh/known-hosts"},
		{http.MethodGet, "/xkms/v1/ssh/authorized-keys"},
		{http.MethodPost, "/xkms/v1/ssh/authorized-keys/emit"},
	}

	for _, p := range paths {
		req := httptest.NewRequest(p.method, p.path, nil)
		w := httptest.NewRecorder()

		server.server.Handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code,
			"%s %s must require authentication", p.method, p.path)
	}
}

// TestSSHRoutes_AuthenticatedAccess proves the authenticated path still
// reaches the SSH handlers after the middleware wrap.
func TestSSHRoutes_AuthenticatedAccess(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Authenticator: auth.NewNoOpAuthenticator(),
		Backends:      map[string]xkms.Backend{"test": ks},
		Logger:        testLogger(),
		SSHClient:     newMockSSHClient(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/xkms/v1/ssh/keys", nil)
	w := httptest.NewRecorder()

	server.server.Handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code,
		"authenticated request must reach the SSH list handler")
}

// TestNoSSHConsoleRoute is the regression test for the decision that xkmsd
// never terminates an SSH session. The vault stores SSH keys and signs
// authentication challenges with them; the SSH connection itself belongs to
// the client (xkey). A console route here would let any authenticated caller
// make the appliance dial an arbitrary host and proxy an interactive shell
// through it — server-side request forgery, a network pivot, and remote code
// execution against the target, from the one host that must offer none of
// them. If a console mount is ever reintroduced, this test fails.
func TestNoSSHConsoleRoute(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Authenticator: auth.NewNoOpAuthenticator(),
		Backends:      map[string]xkms.Backend{"test": ks},
		Logger:        testLogger(),
		SSHClient:     newMockSSHClient(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	mux, ok := server.server.Handler.(chi.Router)
	require.True(t, ok, "REST handler must be a chi router")

	werr := chi.Walk(mux, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		assert.NotContains(t, strings.ToLower(route), "console",
			"%s %s: xkmsd must not serve an SSH console route", method, route)
		return nil
	})
	require.NoError(t, werr)
}

// capturingPlatformStore records the secret name each operation received,
// proving the router's URL parameter placeholder reaches the handlers.
type capturingPlatformStore struct {
	lastName string
}

func (c *capturingPlatformStore) Put(_ context.Context, name string, _ []byte) error {
	c.lastName = name
	return nil
}

func (c *capturingPlatformStore) Get(_ context.Context, name string) ([]byte, error) {
	c.lastName = name
	return []byte("value"), nil
}

func (c *capturingPlatformStore) Delete(_ context.Context, name string) error {
	c.lastName = name
	return nil
}

func (c *capturingPlatformStore) Exists(_ context.Context, name string) (bool, error) {
	c.lastName = name
	return true, nil
}

func (c *capturingPlatformStore) List(context.Context) ([]string, error) { return nil, nil }

func (c *capturingPlatformStore) Reseal(_ context.Context, name string) error {
	c.lastName = name
	return nil
}

// TestPlatformSecretRoutes_URLParamReachesHandler is the regression test for
// the {key}-vs-{name} placeholder mismatch: the routes registered {key} while
// the handlers read chi.URLParam(r, "name"), handing every keyed platform
// secret operation an empty name.
func TestPlatformSecretRoutes_URLParamReachesHandler(t *testing.T) {
	store := &capturingPlatformStore{}

	cfg := &Config{
		Authenticator: auth.NewNoOpAuthenticator(),
		Backends:      map[string]xkms.Backend{"test": newMockKeyStore()},
		Logger:        testLogger(),
		PlatformStore: store,
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/platform/secrets/my-secret"},
		{http.MethodDelete, "/api/v1/platform/secrets/my-secret"},
		{http.MethodPost, "/api/v1/platform/secrets/my-secret/reseal"},
	} {
		store.lastName = ""
		req := httptest.NewRequest(tc.method, tc.path, nil)
		w := httptest.NewRecorder()

		server.server.Handler.ServeHTTP(w, req)

		assert.Equal(t, "my-secret", store.lastName,
			"%s %s must deliver the URL secret name to the handler (status %d)",
			tc.method, tc.path, w.Code)
	}
}
