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
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// captured records one registrar registration.
type captured struct {
	method, pattern string
	perm            qrdbsdk.Permission
	public          bool
	handler         http.HandlerFunc
}

// newCaptureRegistrar builds a real qrdb HTTPRegistrar whose route/public
// sinks record into the returned slice.
func newCaptureRegistrar() (*qrdbsdk.ModuleHTTPRegistrar, *[]captured) {
	var recs []captured
	r := qrdbsdk.NewModuleHTTPRegistrar(chi.NewRouter(),
		func(method, pattern string, perm qrdbsdk.Permission, h http.HandlerFunc) {
			recs = append(recs, captured{method: method, pattern: pattern, perm: perm, handler: h})
		},
		func(method, pattern string, h http.HandlerFunc) {
			recs = append(recs, captured{method: method, pattern: pattern, public: true, handler: h})
		})
	return r, &recs
}

func newModuleRESTServer(t *testing.T) *rest.Server {
	t.Helper()
	srv, err := rest.NewServer(&rest.Config{
		Authenticator: auth.NewNoOpAuthenticator(),
		Backends:      map[string]xkms.Backend{"test": xkmsmocks.NewMockKeyStore()},
	})
	require.NoError(t, err)
	return srv
}

// TestRegisterHTTP_FullSurface proves the module registers the complete
// route table, deduplicated, with the correct permission class per route.
func TestRegisterHTTP_FullSurface(t *testing.T) {
	srv := newModuleRESTServer(t)
	m, err := NewModule(func() *xkms.XKMSService { return nil },
		WithRESTServer(func() *rest.Server { return srv }))
	require.NoError(t, err)

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)

	// Expected: one registration per distinct method+pattern in the table.
	type key struct{ m, p string }
	want := map[key]rest.RouteSpec{}
	var wantOrder int
	for _, spec := range rest.Routes() {
		k := key{spec.Method, spec.Pattern}
		if _, dup := want[k]; !dup {
			want[k] = spec
			wantOrder++
		}
	}
	require.Len(t, *recs, wantOrder, "one registration per distinct route")

	got := map[key]captured{}
	for _, rec := range *recs {
		got[key{rec.method, rec.pattern}] = rec
	}
	for k, spec := range want {
		rec, ok := got[k]
		require.True(t, ok, "route %s %s not registered", k.m, k.p)
		switch spec.Auth {
		case rest.RouteAuthPublic:
			assert.True(t, rec.public, "%s %s must register public", k.m, k.p)
		case rest.RouteAuthSession:
			assert.Equal(t, qrdbsdk.Permission("identity:gated"), rec.perm,
				"%s %s must register identity-gated", k.m, k.p)
		default:
			assert.False(t, rec.public)
			assert.Equal(t, qrdbsdk.Permission(spec.Resource+":"+spec.Action), rec.perm,
				"%s %s permission", k.m, k.p)
		}
	}
}

// TestRegisterHTTP_NoResolver proves a module constructed without a REST
// resolver registers no HTTP routes (BaseModule semantics preserved).
func TestRegisterHTTP_NoResolver(t *testing.T) {
	m, err := NewModule(func() *xkms.XKMSService { return nil })
	require.NoError(t, err)

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)
	assert.Empty(t, *recs)
}

// TestRegisterHTTP_LazyBinding proves module routes answer 503 while the
// REST surface is unresolved and serve normally once it resolves — without
// re-registration.
func TestRegisterHTTP_LazyBinding(t *testing.T) {
	var srv atomic.Pointer[rest.Server]
	m, err := NewModule(func() *xkms.XKMSService { return nil },
		WithRESTServer(func() *rest.Server { return srv.Load() }))
	require.NoError(t, err)

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)

	var health http.HandlerFunc
	for _, rec := range *recs {
		if rec.method == "GET" && rec.pattern == "/health" {
			health = rec.handler
		}
	}
	require.NotNil(t, health, "GET /health must be registered")

	// Unresolved: 503.
	w := httptest.NewRecorder()
	health(w, httptest.NewRequest("GET", "/health", nil))
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	// Resolved: served by the real handler.
	srv.Store(newModuleRESTServer(t))
	w = httptest.NewRecorder()
	health(w, httptest.NewRequest("GET", "/health", nil))
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestRegisterHTTP_VariantRoutesRegisterOnce proves availability variants
// (the CA bundle endpoint's full-CA and bootstrap-only forms) collapse into
// a single registration.
func TestRegisterHTTP_VariantRoutesRegisterOnce(t *testing.T) {
	srv := newModuleRESTServer(t)
	m, err := NewModule(func() *xkms.XKMSService { return nil },
		WithRESTServer(func() *rest.Server { return srv }))
	require.NoError(t, err)

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)

	n := 0
	for _, rec := range *recs {
		if rec.method == "GET" && rec.pattern == "/api/v1/ca/bundle" {
			n++
		}
	}
	assert.Equal(t, 1, n, "variant routes must register exactly once")
}
