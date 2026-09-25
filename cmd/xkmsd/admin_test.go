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
)

// capturedModuleRoute records one qrdbsdk.ModuleHTTPRegistrar registration,
// mirroring pkg/apimodule's own test helper (unexported there, so cmd/xkmsd
// keeps a small copy rather than reaching into another package's test file).
type capturedModuleRoute struct {
	method, pattern string
	public          bool
}

func newCaptureModuleRegistrar() (*qrdbsdk.ModuleHTTPRegistrar, *[]capturedModuleRoute) {
	var recs []capturedModuleRoute
	r := qrdbsdk.NewModuleHTTPRegistrar(chi.NewRouter(),
		func(method, pattern string, perm qrdbsdk.Permission, h http.HandlerFunc) {
			recs = append(recs, capturedModuleRoute{method: method, pattern: pattern})
		},
		func(method, pattern string, h http.HandlerFunc) {
			recs = append(recs, capturedModuleRoute{method: method, pattern: pattern, public: true})
		})
	return r, &recs
}

// TestAdminModule_ReachableOnUnifiedListener proves the ACME admin
// ServiceModule constructed by newAdminModule registers its API prefixes
// ("/admin", "/api/v1/tenants") and SPA prefix (adminUIPrefix) when mounted
// on the unified server's module registrar — the same registrar
// pkg/server/qrdb_node.go feeds every registered qrdbsdk.WithModule module,
// including this one via server.WithExtraModules.
func TestAdminModule_ReachableOnUnifiedListener(t *testing.T) {
	m, err := newAdminModule()
	require.NoError(t, err)

	reg, recs := newCaptureModuleRegistrar()
	m.RegisterHTTP(reg)

	patterns := map[string]bool{}
	for _, r := range *recs {
		patterns[r.pattern] = true
	}

	for _, prefix := range adminAPIPrefixes {
		assert.True(t, patterns[prefix+"/*"], "expected %s/* registered on the unified listener", prefix)
	}
	assert.True(t, patterns[adminUIPrefix+"/*"], "expected admin SPA prefix %s/* registered on the unified listener", adminUIPrefix)
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

	paths := append([]string{adminUIPrefix, adminUIPrefix + "/index.html"}, adminAPIPrefixes...)
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
