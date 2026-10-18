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
	"testing"
	"testing/fstest"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testAdminRoutes is a small admin route table covering both mount points
// and both permission shapes (resource:action and a cross-scope grant).
var testAdminRoutes = []AdminRoute{
	{Method: http.MethodGet, Path: "/admin/certificates", Permission: "certs:list"},
	{Method: http.MethodPost, Path: "/admin/certificates/{serial}/revoke", Permission: "certs:revoke"},
	{Method: http.MethodPost, Path: "/api/v1/tenants", Permission: qrdbsdk.PermissionTenantsCreateCross},
	{Method: http.MethodGet, Path: "/api/v1/tenants/{id}", Permission: qrdbsdk.PermissionTenantsReadCross, SelfPermission: "tenants:read"},
}

// TestNewAdminModule_NilRouterResolver proves construction fails closed
// without a router resolver: an admin module that could never reach the
// admin API would otherwise register routes with no way to ever serve them.
func TestNewAdminModule_NilRouterResolver(t *testing.T) {
	m, err := NewAdminModule(nil, testAdminRoutes)
	assert.Nil(t, m)
	target := &NilAdminRouterResolverError{}
	assert.ErrorAs(t, err, &target)
}

// TestNewAdminModule_NoRoutes proves construction fails closed without at
// least one API route: an admin module with no routes would register
// nothing at all — a silently dead surface.
func TestNewAdminModule_NoRoutes(t *testing.T) {
	for name, routes := range map[string][]AdminRoute{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			m, err := NewAdminModule(func() http.Handler { return nil }, routes)
			assert.Nil(t, m)
			target := &NoAdminRoutesError{}
			assert.ErrorAs(t, err, &target)
		})
	}
}

// TestAdminModule_Name proves the module identifies itself distinctly from
// the crypto-plane Module ("xkms"), so qrdb's duplicate-module detection and
// an operator reading the module registry can tell the two capability
// planes apart.
func TestAdminModule_Name(t *testing.T) {
	m, err := NewAdminModule(func() http.Handler { return nil }, testAdminRoutes)
	require.NoError(t, err)
	assert.Equal(t, "xkms-admin", m.Name())
	assert.NotEqual(t, ModuleName, m.Name())
}

// TestAdminModule_RegisterHTTP_EachRouteOwnPermission proves every admin
// route is registered exactly as given, never public, under its own
// permission — so qrdb's chain authorizes each route before the admin
// handlers run — except a route gated by the tenant it reaches, which is
// registered identity-gated for the admin router to authorize, and that
// nothing else on the API plane is registered.
func TestAdminModule_RegisterHTTP_EachRouteOwnPermission(t *testing.T) {
	m, err := NewAdminModule(func() http.Handler { return nil }, testAdminRoutes)
	require.NoError(t, err)

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)

	got := map[string]captured{} // "method pattern" -> registration
	for _, r := range *recs {
		got[r.method+" "+r.pattern] = r
	}
	require.Len(t, got, len(testAdminRoutes), "only the given routes may register")

	for _, rt := range testAdminRoutes {
		rec, ok := got[rt.Method+" "+rt.Path]
		if assert.True(t, ok, "missing registration for %s %s", rt.Method, rt.Path) {
			assert.False(t, rec.public, "%s %s must not be registered public", rt.Method, rt.Path)
			want := rt.Permission
			if rt.SelfPermission != "" {
				want = qrdbsdk.PermissionIdentityGated
			}
			assert.Equal(t, want, rec.perm, "%s %s must carry its own permission", rt.Method, rt.Path)
		}
	}
}

// TestNewAdminModule_ClonesRoutes proves the module keeps its own copy of
// the route table, so a caller mutating its slice after construction cannot
// change what is registered or the permission it is registered under.
func TestNewAdminModule_ClonesRoutes(t *testing.T) {
	routes := []AdminRoute{{Method: http.MethodGet, Path: "/admin/audit", Permission: "audit:read"}}
	m, err := NewAdminModule(func() http.Handler { return nil }, routes)
	require.NoError(t, err)
	routes[0].Permission = "audit:write"

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)

	require.Len(t, *recs, 1)
	assert.Equal(t, qrdbsdk.Permission("audit:read"), (*recs)[0].perm)
}

// TestAdminModule_RegisterHTTP_NoUIByDefault proves the admin SPA is not
// mounted unless WithAdminWebUI is supplied.
func TestAdminModule_RegisterHTTP_NoUIByDefault(t *testing.T) {
	m, err := NewAdminModule(func() http.Handler { return nil }, testAdminRoutes)
	require.NoError(t, err)

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)

	for _, r := range *recs {
		assert.NotContains(t, r.pattern, "/ui", "no UI route should register without WithAdminWebUI")
	}
}

// TestAdminModule_RegisterHTTP_UIOnItsOwnPrefix proves the admin SPA, when
// configured, is registered on its own prefix — never the crypto-plane
// module's "/ui" — and serves the underlying fs.FS content.
func TestAdminModule_RegisterHTTP_UIOnItsOwnPrefix(t *testing.T) {
	const uiPrefix = "/admin-ui"
	fsys := fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<html>admin ui</html>")},
	}
	m, err := NewAdminModule(func() http.Handler { return nil }, testAdminRoutes,
		WithAdminWebUI(uiPrefix, fsys, false))
	require.NoError(t, err)
	require.NotEqual(t, "/ui", uiPrefix)

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)

	var uiHandler http.HandlerFunc
	found := false
	for _, r := range *recs {
		if r.method == http.MethodGet && r.pattern == uiPrefix+"/*" {
			uiHandler = r.handler
			found = true
		}
		assert.NotEqual(t, "/ui", r.pattern, "admin module must never register the crypto module's /ui prefix")
		assert.NotEqual(t, "/ui/*", r.pattern)
	}
	require.True(t, found, "expected %s/* to be registered", uiPrefix)

	req := httptest.NewRequest(http.MethodGet, uiPrefix+"/", nil)
	w := httptest.NewRecorder()
	uiHandler(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "admin ui")
}

// TestAdminModule_RegisterHTTP_RedirectRoot proves that, when
// WithAdminWebUI's redirectRoot is set, GET / is registered as a public
// 302 redirect to the admin UI's own prefix.
func TestAdminModule_RegisterHTTP_RedirectRoot(t *testing.T) {
	const uiPrefix = "/admin-ui"
	fsys := fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<html>admin ui</html>")},
	}
	m, err := NewAdminModule(func() http.Handler { return nil }, testAdminRoutes,
		WithAdminWebUI(uiPrefix, fsys, true))
	require.NoError(t, err)

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)

	var rootHandler http.HandlerFunc
	for _, r := range *recs {
		if r.method == http.MethodGet && r.pattern == "/" {
			rootHandler = r.handler
		}
	}
	require.NotNil(t, rootHandler, "GET / must be registered when redirectRoot is set")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	rootHandler(w, req)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, uiPrefix, w.Header().Get("Location"))
}

// TestAdminModule_LazyAPIHandler_ComposingServer503 proves an admin API
// request answers 503 while the resolver has not yet published a router
// (the host is still composing the ACME CA/storage/qrdb TenantService the
// admin service is built from), and forwards to the resolved handler once
// it has.
func TestAdminModule_LazyAPIHandler_ComposingServer503(t *testing.T) {
	var resolved http.Handler
	m, err := NewAdminModule(func() http.Handler { return resolved }, testAdminRoutes)
	require.NoError(t, err)

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)

	var h http.HandlerFunc
	for _, r := range *recs {
		if r.method == http.MethodGet && r.pattern == "/admin/certificates" {
			h = r.handler
		}
	}
	require.NotNil(t, h)

	// Composing: resolver returns nil.
	req := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	w := httptest.NewRecorder()
	h(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	// Resolved: forwards to the real handler.
	served := false
	resolved = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served = true
		w.WriteHeader(http.StatusOK)
	})
	req = httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	w = httptest.NewRecorder()
	h(w, req)
	assert.True(t, served)
	assert.Equal(t, http.StatusOK, w.Code)
}
