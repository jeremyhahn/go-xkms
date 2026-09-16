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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewAdminModule_NilRouterResolver proves construction fails closed
// without a router resolver: an admin module that could never reach the
// admin API would otherwise register routes with no way to ever serve them.
func TestNewAdminModule_NilRouterResolver(t *testing.T) {
	m, err := NewAdminModule(nil, []string{"/admin"})
	assert.Nil(t, m)
	target := &NilAdminRouterResolverError{}
	assert.ErrorAs(t, err, &target)
}

// TestNewAdminModule_NoPrefixes proves construction fails closed without at
// least one API path prefix: an admin module with no prefixes would
// register no routes at all — a silently dead surface.
func TestNewAdminModule_NoPrefixes(t *testing.T) {
	m, err := NewAdminModule(func() http.Handler { return nil }, nil)
	assert.Nil(t, m)
	target := &NilAdminAPIPrefixesError{}
	assert.ErrorAs(t, err, &target)
}

// TestAdminModule_Name proves the module identifies itself distinctly from
// the crypto-plane Module ("xkms"), so qrdb's duplicate-module detection and
// an operator reading the module registry can tell the two capability
// planes apart.
func TestAdminModule_Name(t *testing.T) {
	m, err := NewAdminModule(func() http.Handler { return nil }, []string{"/admin"})
	require.NoError(t, err)
	assert.Equal(t, "xkms-admin", m.Name())
	assert.NotEqual(t, ModuleName, m.Name())
}

// TestAdminModule_RegisterHTTP_PublicForEveryPrefixAndMethod proves every
// configured API prefix is registered as a PUBLIC route (at the qrdb
// module-registration layer) for every method the admin route tables use,
// both at the bare prefix and its wildcard. Public registration here is
// deliberate: pkg/acme/admin's Handlers/TenantHandlers authenticate and
// authorize every request themselves (admin.AuthHandler + PermissionGate,
// both backed by the same qrdb RBAC service other transports use) — see
// AdminRouterResolver's doc comment. This test proves the module does not
// additionally gate these routes at the qrdb layer, which would require an
// identity qrdb's own authenticators cannot produce for this credential.
func TestAdminModule_RegisterHTTP_PublicForEveryPrefixAndMethod(t *testing.T) {
	prefixes := []string{"/admin", "/api/v1/tenants"}
	m, err := NewAdminModule(func() http.Handler { return nil }, prefixes)
	require.NoError(t, err)

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)

	got := map[string]bool{} // "method pattern" -> public
	for _, r := range *recs {
		got[r.method+" "+r.pattern] = r.public
	}

	for _, prefix := range prefixes {
		for _, method := range adminAPIMethods {
			for _, pattern := range []string{prefix, prefix + "/*"} {
				public, ok := got[method+" "+pattern]
				if assert.True(t, ok, "missing registration for %s %s", method, pattern) {
					assert.True(t, public, "%s %s must be registered public (admin package self-authenticates)", method, pattern)
				}
			}
		}
	}
}

// TestAdminModule_RegisterHTTP_NoUIByDefault proves the admin SPA is not
// mounted unless WithAdminWebUI is supplied.
func TestAdminModule_RegisterHTTP_NoUIByDefault(t *testing.T) {
	m, err := NewAdminModule(func() http.Handler { return nil }, []string{"/admin"})
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
	m, err := NewAdminModule(func() http.Handler { return nil }, []string{"/admin"},
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

// TestAdminModule_LazyAPIHandler_ComposingServer503 proves an admin API
// request answers 503 while the resolver has not yet published a router
// (the host is still composing the ACME CA/storage/qrdb TenantService the
// admin service is built from), and forwards to the resolved handler once
// it has.
func TestAdminModule_LazyAPIHandler_ComposingServer503(t *testing.T) {
	var resolved http.Handler
	m, err := NewAdminModule(func() http.Handler { return resolved }, []string{"/admin"})
	require.NoError(t, err)

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)

	var h http.HandlerFunc
	for _, r := range *recs {
		if r.method == http.MethodGet && r.pattern == "/admin/*" {
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
