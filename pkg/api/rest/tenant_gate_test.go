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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tenantLifecycleSpec returns the route table's spec for one of the
// /api/v1/tenants lifecycle routes, so the gate tests exercise the
// permissions the server actually mounts.
func tenantLifecycleSpec(t *testing.T, method, pattern string) RouteSpec {
	t.Helper()
	for _, spec := range Routes() {
		if spec.Method == method && spec.Pattern == pattern {
			require.Equal(t, RouteAuthTenant, spec.Auth, "%s %s", method, pattern)
			return spec
		}
	}
	require.Failf(t, "route missing from the table", "%s %s", method, pattern)
	return RouteSpec{}
}

// serveTenantGate mounts spec behind gate on a chi router and serves one
// request as identity (nil for an unauthenticated request).
func serveTenantGate(gate *TenantGate, spec RouteSpec, identity *auth.Identity, path string) *httptest.ResponseRecorder {
	router := chi.NewRouter()
	router.With(gate.Require(spec)).Method(spec.Method, spec.Pattern, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(spec.Method, path, nil)
	if identity != nil {
		req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// TestTenantGate_AsksForTheReachPermission proves each lifecycle route asks
// the authorizer for the permission its reach selects: a caller confined to
// its own tenant needs tenants:<action> for itself or the collection, and
// the cross permission for anything else; a system-tenant caller always
// needs the cross permission. Granted, the request reaches the handler.
func TestTenantGate_AsksForTheReachPermission(t *testing.T) {
	system := &auth.Identity{Subject: "so", TenantID: qrdbsdk.SystemTenantID}
	tenantA := &auth.Identity{Subject: "tenant-user", TenantID: "tenant-a"}
	cross := func(p qrdbsdk.Permission) [2]string {
		return [2]string{qrdbsdk.PermissionResource(p), qrdbsdk.PermissionAction(p)}
	}

	cases := []struct {
		name     string
		method   string
		pattern  string
		path     string
		identity *auth.Identity
		want     [2]string
	}{
		{"system creates", http.MethodPost, "/api/v1/tenants/", "/api/v1/tenants/", system, cross(qrdbsdk.PermissionTenantsCreateCross)},
		{"tenant creates", http.MethodPost, "/api/v1/tenants/", "/api/v1/tenants/", tenantA, cross(qrdbsdk.PermissionTenantsCreateCross)},
		{"system lists", http.MethodGet, "/api/v1/tenants/", "/api/v1/tenants/", system, cross(qrdbsdk.PermissionTenantsListCross)},
		{"tenant lists", http.MethodGet, "/api/v1/tenants/", "/api/v1/tenants/", tenantA, [2]string{"tenants", "list"}},
		{"tenant reads its own", http.MethodGet, "/api/v1/tenants/{tenantID}", "/api/v1/tenants/tenant-a", tenantA, [2]string{"tenants", "read"}},
		{"tenant reads another", http.MethodGet, "/api/v1/tenants/{tenantID}", "/api/v1/tenants/tenant-b", tenantA, cross(qrdbsdk.PermissionTenantsReadCross)},
		{"system reads a tenant", http.MethodGet, "/api/v1/tenants/{tenantID}", "/api/v1/tenants/tenant-b", system, cross(qrdbsdk.PermissionTenantsReadCross)},
		{"tenant deletes its own", http.MethodDelete, "/api/v1/tenants/{tenantID}", "/api/v1/tenants/tenant-a", tenantA, [2]string{"tenants", "delete"}},
		{"system deletes a tenant", http.MethodDelete, "/api/v1/tenants/{tenantID}", "/api/v1/tenants/tenant-b", system, cross(qrdbsdk.PermissionTenantsDeleteCross)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rbac := &routeAuthzRecordingClient{allowResource: tc.want[0], allowAction: tc.want[1]}
			gate := NewTenantGate(auth.NewAuthorizer(rbac), slog.New(slog.DiscardHandler))

			rec := serveTenantGate(gate, tenantLifecycleSpec(t, tc.method, tc.pattern), tc.identity, tc.path)

			assert.Equal(t, tc.want, [2]string{rbac.gotResource, rbac.gotAction})
			assert.Equal(t, http.StatusOK, rec.Code)
		})
	}
}

// TestTenantGate_Refusals proves how the gate refuses: no identity is 401,
// no authorizer is 503, a refused caller confined to another tenant gets the
// handler's 404 (no tenant-existence oracle), and every other refusal is 403.
func TestTenantGate_Refusals(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	denying := NewTenantGate(auth.NewAuthorizer(denyingRBACClient{}), logger)
	system := &auth.Identity{Subject: "so", TenantID: qrdbsdk.SystemTenantID}
	tenantA := &auth.Identity{Subject: "tenant-user", TenantID: "tenant-a"}

	cases := []struct {
		name     string
		gate     *TenantGate
		method   string
		pattern  string
		path     string
		identity *auth.Identity
		wantCode int
	}{
		{"no identity", denying, http.MethodGet, "/api/v1/tenants/", "/api/v1/tenants/", nil, http.StatusUnauthorized},
		{"no authorizer", NewTenantGate(nil, logger), http.MethodGet, "/api/v1/tenants/", "/api/v1/tenants/", system, http.StatusServiceUnavailable},
		{"tenant refused create", denying, http.MethodPost, "/api/v1/tenants/", "/api/v1/tenants/", tenantA, http.StatusForbidden},
		{"tenant refused list", denying, http.MethodGet, "/api/v1/tenants/", "/api/v1/tenants/", tenantA, http.StatusForbidden},
		{"tenant refused its own", denying, http.MethodGet, "/api/v1/tenants/{tenantID}", "/api/v1/tenants/tenant-a", tenantA, http.StatusForbidden},
		{"tenant refused another", denying, http.MethodGet, "/api/v1/tenants/{tenantID}", "/api/v1/tenants/tenant-b", tenantA, http.StatusNotFound},
		{"tenant refused deleting another", denying, http.MethodDelete, "/api/v1/tenants/{tenantID}", "/api/v1/tenants/tenant-b", tenantA, http.StatusNotFound},
		{"system refused a tenant", denying, http.MethodDelete, "/api/v1/tenants/{tenantID}", "/api/v1/tenants/tenant-b", system, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := serveTenantGate(tc.gate, tenantLifecycleSpec(t, tc.method, tc.pattern), tc.identity, tc.path)
			assert.Equal(t, tc.wantCode, rec.Code, rec.Body.String())
		})
	}
}
