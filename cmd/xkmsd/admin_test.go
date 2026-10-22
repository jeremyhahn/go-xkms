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

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
)

// capturedModuleRoute records one qrdbsdk.ModuleHTTPRegistrar registration,
// mirroring pkg/apimodule's own test helper (unexported there, so cmd/xkmsd
// keeps a small copy rather than reaching into another package's test file).
type capturedModuleRoute struct {
	method, pattern string
	perm            qrdbsdk.Permission
	public          bool
	handler         http.HandlerFunc
}

func newCaptureModuleRegistrar() (*qrdbsdk.ModuleHTTPRegistrar, *[]capturedModuleRoute) {
	var recs []capturedModuleRoute
	r := qrdbsdk.NewModuleHTTPRegistrar(chi.NewRouter(),
		func(method, pattern string, perm qrdbsdk.Permission, h http.HandlerFunc) {
			recs = append(recs, capturedModuleRoute{method: method, pattern: pattern, perm: perm, handler: h})
		},
		func(method, pattern string, h http.HandlerFunc) {
			recs = append(recs, capturedModuleRoute{method: method, pattern: pattern, public: true, handler: h})
		},
		func(string, string, http.HandlerFunc) {})
	return r, &recs
}

// TestAdminModule_LazyResolverBranches exercises newAdminModule's resolver
// closure directly through the registered handler (rather than only
// checking route patterns, as TestAdminModule_ReachableOnUnifiedListener
// does): before adminRouterState is published, every request answers 503
// (AdminModule's documented "server still composing" behavior); once
// finalizeAdminModule publishes a router, the same handler reaches it.
func TestAdminModule_LazyResolverBranches(t *testing.T) {
	original := adminRouterState.Load()
	t.Cleanup(func() { adminRouterState.Store(original) })
	adminRouterState.Store(nil)

	m, err := newAdminModule()
	require.NoError(t, err)

	reg, recs := newCaptureModuleRegistrar()
	m.RegisterHTTP(reg)

	var adminHandler http.HandlerFunc
	for _, r := range *recs {
		if r.method == http.MethodGet && r.pattern == "/admin/status" {
			adminHandler = r.handler
			break
		}
	}
	require.NotNil(t, adminHandler, "expected a captured handler for GET /admin/status")

	rec := httptest.NewRecorder()
	adminHandler(rec, httptest.NewRequest(http.MethodGet, "/admin/status", nil))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"unpublished adminRouterState must answer 503, not panic or 200")

	published := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	adminRouterState.Store(&published)

	rec2 := httptest.NewRecorder()
	adminHandler(rec2, httptest.NewRequest(http.MethodGet, "/admin/status", nil))
	assert.Equal(t, http.StatusTeapot, rec2.Code,
		"once published, the resolver must reach the stored router")
}

// TestAdminModule_ReachableOnUnifiedListener proves the ACME admin
// ServiceModule constructed by newAdminModule registers every ACME admin
// route, under that route's own permission and never public, plus the SPA
// prefix (adminUIPrefix), when mounted on the unified server's module
// registrar — the same registrar pkg/server/qrdb_node.go feeds every
// registered qrdbsdk.WithModule module, including this one via
// server.WithExtraModules.
func TestAdminModule_ReachableOnUnifiedListener(t *testing.T) {
	m, err := newAdminModule()
	require.NoError(t, err)

	reg, recs := newCaptureModuleRegistrar()
	m.RegisterHTTP(reg)

	got := map[string]capturedModuleRoute{} // "method pattern" -> registration
	for _, r := range *recs {
		got[r.method+" "+r.pattern] = r
	}

	routes := admin.Routes()
	require.NotEmpty(t, routes)
	for _, rt := range routes {
		rec, ok := got[rt.Method+" "+rt.Path]
		if assert.True(t, ok, "expected %s %s registered on the unified listener", rt.Method, rt.Path) {
			assert.False(t, rec.public, "%s %s must not be registered public", rt.Method, rt.Path)
			// A tenant lifecycle route's permission depends on the tenant it
			// reaches, so the listener only authenticates it and the admin
			// router's gate authorizes it.
			want := rt.Permission
			if rt.SelfPermission != "" {
				want = qrdbsdk.PermissionIdentityGated
			}
			assert.Equal(t, want, rec.perm, "%s %s must carry its own permission", rt.Method, rt.Path)
		}
	}
	assert.True(t, got[http.MethodGet+" "+adminUIPrefix+"/*"].handler != nil,
		"expected admin SPA prefix %s/* registered on the unified listener", adminUIPrefix)
	assert.NotEqual(t, "/ui", adminUIPrefix, "admin SPA must not share the crypto module's /ui prefix")
}

// TestAdminModule_AbsentFromACMEListener proves the ACME protocol router
// (buildACMERouter, bound to xkmsd's dedicated public ACME HTTPS listener in
// startACMEServer) carries none of the admin surface's routes: a request for
// any admin API or SPA prefix against the ACME router is unmatched (404),
// never dispatched to an ACME RFC 8555 handler or the admin surface.
func TestAdminModule_AbsentFromACMEListener(t *testing.T) {
	svc := &stubRestService{}
	acmeRouter := buildACMERouter(svc, "/acme", nil, nil)
	ts := httptest.NewServer(acmeRouter)
	t.Cleanup(ts.Close)

	paths := []string{adminUIPrefix, adminUIPrefix + "/index.html"}
	for _, rt := range admin.Routes() {
		paths = append(paths, pathVariable.ReplaceAllString(rt.Path, "absent"))
	}
	for _, p := range paths {
		resp, err := http.Get(ts.URL + p)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode,
			"ACME listener must not serve admin path %s", p)
	}

	// Sanity check the ACME router itself still works, so a 404 above means
	// "route absent" and not "router broken".
	resp, err := http.Get(ts.URL + "/acme/directory")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
