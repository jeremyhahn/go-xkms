//go:build codec_json

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

package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// newAuthorizedRouter builds a router with the admin and tenant routes
// registered as the unified server mounts them: no per-route gate but on
// the tenant lifecycle routes, with authMiddleware (nil to inject the
// identity directly) in front.
func newAuthorizedRouter(authMiddleware AuthHandler) (*mux.Router, *qrdbRoleRBAC) {
	gate, client := newQRDBGate()
	router := mux.NewRouter()
	NewHandlers(newAuthzMockService(), discardLogger()).RegisterAuthorizedRoutes(router, authMiddleware, gate)
	NewTenantHandlers(newAuthzMockTenantService(), discardLogger()).RegisterAuthorizedRoutes(router, authMiddleware, gate)
	return router, client
}

// authorizedRouter returns newAuthorizedRouter's router alone.
func authorizedRouter(authMiddleware AuthHandler) *mux.Router {
	router, _ := newAuthorizedRouter(authMiddleware)
	return router
}

// servedRoutes walks router and returns every method and path template it
// serves, in registration order. The subrouter mount points carry no method
// and are skipped.
func servedRoutes(t *testing.T, router *mux.Router) []Route {
	t.Helper()

	var served []Route
	err := router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		methods, err := route.GetMethods()
		if err != nil {
			return nil
		}
		path, err := route.GetPathTemplate()
		if err != nil {
			return err
		}
		for _, method := range methods {
			served = append(served, Route{Method: method, Path: path})
		}
		return nil
	})
	require.NoError(t, err)
	return served
}

// routeKeys drops the permissions from routes, leaving what a router walk
// can observe.
func routeKeys(routes []Route) []Route {
	keys := make([]Route, 0, len(routes))
	for _, rt := range routes {
		keys = append(keys, Route{Method: rt.Method, Path: rt.Path})
	}
	return keys
}

func TestRoutes_MatchWhatBothRegistrationsServe(t *testing.T) {
	want := routeKeys(Routes())
	require.NotEmpty(t, want)

	gated, _ := newAdminRouter(t)
	assert.Equal(t, want, servedRoutes(t, gated), "RegisterRoutes must serve exactly Routes()")
	assert.Equal(t, want, servedRoutes(t, authorizedRouter(nil)),
		"RegisterAuthorizedRoutes must serve exactly Routes()")
}

func TestRoutes_EveryRouteCarriesAPermission(t *testing.T) {
	seen := make(map[Route]bool)
	for _, rt := range Routes() {
		assert.NotEmpty(t, rt.Permission, "route %s %s has no permission", rt.Method, rt.Path)

		key := Route{Method: rt.Method, Path: rt.Path}
		assert.False(t, seen[key], "route %s %s is declared twice", rt.Method, rt.Path)
		seen[key] = true
	}
}

func TestRegisterAuthorizedRoutes_ServesWithoutGate(t *testing.T) {
	tc := adminRouteCases[0]

	gated, _ := newAdminRouter(t)
	rec := httptest.NewRecorder()
	gated.ServeHTTP(rec, requestWithRoles(tc, unprivilegedRole))
	require.Equal(t, http.StatusForbidden, rec.Code, "the gated router must refuse a caller without the grant")

	rec = httptest.NewRecorder()
	authorizedRouter(nil).ServeHTTP(rec, requestWithRoles(tc, unprivilegedRole))
	assert.Equal(t, http.StatusOK, rec.Code, "the authorized router must leave authorization to its host")
}

func TestRegisterAuthorizedRoutes_UnknownPathIsNotFound(t *testing.T) {
	rec := httptest.NewRecorder()
	authorizedRouter(nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/does-not-exist", nil))

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestRegisterAuthorizedRoutes_UnauthenticatedCallerRejected(t *testing.T) {
	router := authorizedRouter(newTestAuthMiddlewareInvalid())

	for _, path := range []string{"/admin/certificates", "/api/v1/tenants"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

		assert.Equal(t, http.StatusUnauthorized, rec.Code,
			"%s must still run the authentication middleware without a gate", path)
	}
}

// TestRoutes_TenantLifecycleRoutesCarrySelfPermission pins which routes a
// host must mount identity-gated: exactly the tenant lifecycle routes that
// name or list the caller's own tenant, each with its self-scoped grant.
func TestRoutes_TenantLifecycleRoutesCarrySelfPermission(t *testing.T) {
	want := map[string]qrdbsdk.Permission{
		"GET /api/v1/tenants":             "tenants:list",
		"GET /api/v1/tenants/{id}":        "tenants:read",
		"PUT /api/v1/tenants/{id}":        "tenants:update",
		"DELETE /api/v1/tenants/{id}":     "tenants:delete",
		"PUT /api/v1/tenants/{id}/status": "tenants:update",
	}
	got := make(map[string]qrdbsdk.Permission)
	for _, rt := range Routes() {
		if rt.SelfPermission != "" {
			got[rt.Method+" "+rt.Path] = rt.SelfPermission
		}
	}
	assert.Equal(t, want, got)
}

// TestRegisterAuthorizedRoutes_GatesTenantLifecycleRoutes proves the routes
// a host mounts identity-gated are still authorized by the tenant they
// reach: the self-scoped grant within the caller's own tenant, and beyond it
// a refusal that reads as a missing tenant (go-xkms#1225).
func TestRegisterAuthorizedRoutes_GatesTenantLifecycleRoutes(t *testing.T) {
	own := routeCase{name: "get own tenant", method: http.MethodGet, path: "/api/v1/tenants/t1"}
	router, client := newAuthorizedRouter(nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, requestWithRoles(own, qrdbsdk.RoleNameAuditor))
	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, []string{"tenants:read"}, client.requests())

	foreign := routeCase{name: "get foreign tenant", method: http.MethodGet, path: "/api/v1/tenants/t2"}
	router, client = newAuthorizedRouter(nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, requestWithRoles(foreign, qrdbsdk.RoleNameAdmin))
	assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "Tenant not found")
	assert.Equal(t, []string{"tenants:read:cross"}, client.requests())
}
