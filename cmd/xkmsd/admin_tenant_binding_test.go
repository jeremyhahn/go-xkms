// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Cross-tenant tests for the ACME admin plane as xkmsd composes it
// (go-xkms#1225), against a real embedded qrdb node with the node barrier
// engaged, so the admin service composes qrdb's real TenantServicer and the
// embedded client's real user and role services.
//
// A tenant-scoped caller holds its own tenant's Admin and SO roles -- between
// them every tenant-local grant, roles:* and users:* included -- and attempts every cross-tenant exploit the issue
// records. Each attempt must be refused exactly the way a missing resource
// is answered, and must leave the other tenant's state untouched; the
// platform (system-tenant) administrator must keep its cross-tenant reach.
//
// qrdb resolves a certificate's thumbprint through the cert index of the
// tenant the request context names (pkg/user routing: UserByCertThumbprint
// "routes on the context tenant"; qrdb's auth wiring pins a certificate to
// the tenant its OU names before the lookup). The tenant caller's requests
// therefore carry that binding, exactly as a tenant-pinned deployment
// presents them; the platform caller's carry none and resolve in the system
// tenant.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/server"
)

// tenantBindingFixture is an embedded qrdb node with the node barrier
// engaged, two prefix tenants, and the ACME admin plane composed on it.
type tenantBindingFixture struct {
	srv    *server.Server
	client *qrdbsdk.Client
	router http.Handler

	// callerA is a tenant-a user holding tenant-a's Admin and SO roles.
	callerA adminCaller
	// platform is the first-boot system-tenant administrator.
	platform adminCaller

	// userB and roleB are tenant-b's victims: a user and a custom role.
	userB *qrdbtransport.User
	roleB *qrdbtransport.Role
}

// adminCaller is a client certificate and the tenant its requests are
// pinned to ("" for the system tenant).
type adminCaller struct {
	cert     *x509.Certificate
	tenantID string
}

const (
	bindingTenantA = "tenant-a-1225"
	bindingTenantB = "tenant-b-1225"
)

func newTenantBindingFixture(t *testing.T) *tenantBindingFixture {
	t.Helper()
	original := adminRouterState.Load()
	t.Cleanup(func() { adminRouterState.Store(original) })

	cfg := newServeTestConfig(t)
	srv, err := server.New(cfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := srv.Shutdown(); err != nil {
			t.Errorf("server.Shutdown: %v", err)
		}
	})
	require.NotNil(t, srv.TenantService(), "fixture: the node barrier must compose qrdb's TenantServicer")

	require.NoError(t, finalizeAdminModule(srv, nil, slog.New(slog.NewTextHandler(io.Discard, nil))))
	published := adminRouterState.Load()
	require.NotNil(t, published)

	ctx := oracleContext(qrdbsdk.SystemTenantID)
	for _, id := range []string{bindingTenantA, bindingTenantB} {
		_, err := srv.TenantService().CreateTenant(ctx, id, id, qrdbsdk.TenantIsolationPrefix)
		require.NoError(t, err)
	}

	// CreateTenant seeds each prefix tenant's built-in roles.
	client := srv.QRDBClient()
	f := &tenantBindingFixture{srv: srv, client: client, router: *published}

	adminA := tenantRole(t, client, bindingTenantA, qrdbsdk.RoleNameAdmin)
	// qrdb refuses certificate issuance to an SO or Owner, and role management
	// is the SO's alone among the built-in roles, so the caller is an Admin
	// holding a custom role that manages roles.
	roleManagerA, err := client.Roles().CreateRole(oracleContext(bindingTenantA), &qrdbtransport.CreateRoleRequest{
		Name:        "role-manager-1225",
		TenantID:    bindingTenantA,
		Permissions: []string{"roles:create", "roles:read", "roles:update", "roles:delete", "roles:list"},
	})
	require.NoError(t, err)
	userA, err := client.Users().CreateUser(oracleContext(bindingTenantA), &qrdbtransport.CreateUserRequest{
		Username:             "admin-a-1225",
		TenantID:             bindingTenantA,
		RoleIDs:              []string{adminA.ID, roleManagerA.ID},
		WithoutEmailLoginKey: true,
	})
	require.NoError(t, err)
	f.callerA = adminCaller{cert: bindClientCert(t, client, userA), tenantID: bindingTenantA}
	f.platform = adminCaller{cert: firstBootAdminCert(t, cfg)}

	ctxB := oracleContext(bindingTenantB)
	f.userB, err = client.Users().CreateUser(ctxB, &qrdbtransport.CreateUserRequest{
		Username:             "victim-b-1225",
		Name:                 "Victim B",
		TenantID:             bindingTenantB,
		WithoutEmailLoginKey: true,
	})
	require.NoError(t, err)
	// go-qrdb lets a grantor grant only permissions it holds, and kv:get is
	// not among Admin's or SO's, so the victim role is created by a tenant-b
	// principal that also holds the built-in Operator and User roles.
	f.roleB, err = client.Roles().CreateRole(granterContext(bindingTenantB), &qrdbtransport.CreateRoleRequest{
		Name:        "victim-role-1225",
		TenantID:    bindingTenantB,
		Permissions: []string{"kv:get"},
	})
	require.NoError(t, err)
	return f
}

// tenantRole resolves a built-in role of tenantID.
func tenantRole(t *testing.T, client *qrdbsdk.Client, tenantID, name string) *qrdbtransport.Role {
	t.Helper()
	r, err := client.Roles().GetRoleByName(oracleContext(tenantID),
		&qrdbtransport.GetRoleByNameRequest{TenantID: tenantID, Name: name})
	require.NoError(t, err, "tenant %s must be seeded with the %q role", tenantID, name)
	return r
}

// granterContext is oracleContext for a principal that holds every built-in
// role of the tenant (Admin, SO, Operator, User), so it may grant the data
// permissions (kv:get and the like) go-qrdb's grant rule refuses a grantor
// that does not hold them.
func granterContext(tenantID string) context.Context {
	granter := &qrdbsdk.Identity{
		Subject:  "admin-plane-granter",
		TenantID: tenantID,
		Roles: []string{
			qrdbsdk.SystemRoleID(tenantID, qrdbsdk.RoleNameAdmin),
			qrdbsdk.SystemRoleID(tenantID, qrdbsdk.RoleNameSO),
			qrdbsdk.SystemRoleID(tenantID, qrdbsdk.RoleNameOperator),
			qrdbsdk.SystemRoleID(tenantID, qrdbsdk.RoleNameUser),
		},
	}
	return qrdbsdk.ContextWithTenant(qrdbsdk.WithIdentity(context.Background(), granter), tenantID)
}

// do dispatches one admin request presenting the caller's certificate as the
// verified mTLS peer, pinned to the caller's tenant.
func (f *tenantBindingFixture) do(t *testing.T, caller adminCaller, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, reader)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{caller.cert}}
	if caller.tenantID != "" {
		req = req.WithContext(qrdbsdk.ContextWithTenant(req.Context(), caller.tenantID))
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

// problemDetail decodes an RFC 7807 body.
func problemDetail(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var p struct {
		Detail string `json:"detail"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &p), "body: %s", rec.Body.String())
	return p.Detail
}

// TestAdminPlane_TenantCallerCannotReachAnotherTenant is the go-xkms#1225
// regression over every tenant-lifecycle, role and user route.
func TestAdminPlane_TenantCallerCannotReachAnotherTenant(t *testing.T) {
	f := newTenantBindingFixture(t)
	ctx := oracleContext(qrdbsdk.SystemTenantID)
	userBID := strconv.FormatUint(f.userB.ID, 10)

	// A genuinely missing tenant, as the tenant caller sees it: the answer
	// every cross-tenant refusal below must be indistinguishable from.
	// Reading, listing, creating and deleting tenants are the core
	// /api/v1/tenants routes, gated by rest.TenantGate (go-xkms#794); the
	// admin plane keeps updates and the per-tenant sub-resources.
	missing := f.do(t, f.callerA, http.MethodPut, "/api/v1/tenants/no-such-tenant-1225", map[string]string{"name": "pwned"})
	require.Equal(t, http.StatusNotFound, missing.Code, missing.Body.String())
	missingDetail := problemDetail(t, missing)

	foreignTenant := []struct {
		name   string
		method string
		path   string
		body   any
	}{
		{"update tenant", http.MethodPut, "/api/v1/tenants/" + bindingTenantB, map[string]string{"name": "pwned"}},
		{"update tenant status", http.MethodPut, "/api/v1/tenants/" + bindingTenantB + "/status", map[string]string{"status": "suspended"}},
		{"list roles", http.MethodGet, "/api/v1/tenants/" + bindingTenantB + "/roles", nil},
		{"create role", http.MethodPost, "/api/v1/tenants/" + bindingTenantB + "/roles", map[string]any{"name": "planted", "permissions": []string{"kv:get"}}},
		{"get role", http.MethodGet, "/api/v1/tenants/" + bindingTenantB + "/roles/" + f.roleB.ID, nil},
		{"update role", http.MethodPut, "/api/v1/tenants/" + bindingTenantB + "/roles/" + f.roleB.ID, map[string]any{"permissions": []string{"kv:get", "kv:put"}}},
		{"delete role", http.MethodDelete, "/api/v1/tenants/" + bindingTenantB + "/roles/" + f.roleB.ID, nil},
		{"list users", http.MethodGet, "/api/v1/tenants/" + bindingTenantB + "/users", nil},
		{"create user", http.MethodPost, "/api/v1/tenants/" + bindingTenantB + "/users", map[string]any{"username": "planted", "without_email_login_key": true}},
		{"get user", http.MethodGet, "/api/v1/tenants/" + bindingTenantB + "/users/" + userBID, nil},
		{"update user", http.MethodPut, "/api/v1/tenants/" + bindingTenantB + "/users/" + userBID, map[string]any{"name": "pwned"}},
		{"delete user", http.MethodDelete, "/api/v1/tenants/" + bindingTenantB + "/users/" + userBID, nil},
	}
	for _, tc := range foreignTenant {
		t.Run("foreign tenant/"+tc.name, func(t *testing.T) {
			rec := f.do(t, f.callerA, tc.method, tc.path, tc.body)
			assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
			assert.Equal(t, missingDetail, problemDetail(t, rec),
				"a refusal must read exactly like a missing tenant")
		})
	}

	// Addressing another tenant's role or user through the caller's OWN
	// tenant path is refused as that resource being absent.
	ownPath := []struct {
		name   string
		method string
		path   string
		body   any
		want   string
	}{
		{"get role", http.MethodGet, "/api/v1/tenants/" + bindingTenantA + "/roles/" + f.roleB.ID, nil, "Role not found"},
		{"update role", http.MethodPut, "/api/v1/tenants/" + bindingTenantA + "/roles/" + f.roleB.ID, map[string]any{"permissions": []string{"kv:get", "kv:put"}}, "Role not found"},
		{"delete role", http.MethodDelete, "/api/v1/tenants/" + bindingTenantA + "/roles/" + f.roleB.ID, nil, "Role not found"},
		{"get user", http.MethodGet, "/api/v1/tenants/" + bindingTenantA + "/users/" + userBID, nil, "User not found"},
		{"update user", http.MethodPut, "/api/v1/tenants/" + bindingTenantA + "/users/" + userBID, map[string]any{"name": "pwned"}, "User not found"},
		{"delete user", http.MethodDelete, "/api/v1/tenants/" + bindingTenantA + "/users/" + userBID, nil, "User not found"},
	}
	for _, tc := range ownPath {
		t.Run("own path/"+tc.name, func(t *testing.T) {
			rec := f.do(t, f.callerA, tc.method, tc.path, tc.body)
			assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
			assert.Equal(t, tc.want, problemDetail(t, rec))
		})
	}

	// Tenant B is untouched.
	_, err := f.srv.TenantService().GetTenant(ctx, bindingTenantB)
	require.NoError(t, err, "tenant-b must survive a tenant-a caller")
	ctxB := oracleContext(bindingTenantB)
	gotUser, err := f.client.Users().GetUser(ctxB, f.userB.ID)
	require.NoError(t, err, "tenant-b's user must survive a tenant-a caller")
	assert.Equal(t, "Victim B", gotUser.Name)
	gotRole, err := f.client.Roles().GetRole(ctxB, f.roleB.ID)
	require.NoError(t, err, "tenant-b's role must survive a tenant-a caller")
	assert.Equal(t, []string{"kv:get"}, gotRole.Permissions)
	roles, err := f.client.Roles().ListRoles(ctxB, &qrdbtransport.ListRolesRequest{TenantID: bindingTenantB})
	require.NoError(t, err)
	for _, r := range roles.Roles {
		assert.NotEqual(t, "planted", r.Name, "a tenant-a caller planted a role in tenant-b")
	}
	users, err := f.client.Users().ListUsers(ctxB, &qrdbtransport.ListUsersRequest{TenantID: bindingTenantB})
	require.NoError(t, err)
	for _, u := range users.Users {
		assert.NotEqual(t, "planted", u.Username, "a tenant-a caller planted a user in tenant-b")
	}
}

// TestAdminPlane_TenantCallerManagesItsOwnTenant proves the binding confines
// without disabling: the tenant caller still administers its own users.
func TestAdminPlane_TenantCallerManagesItsOwnTenant(t *testing.T) {
	f := newTenantBindingFixture(t)

	rec := f.do(t, f.callerA, http.MethodPost, "/api/v1/tenants/"+bindingTenantA+"/users",
		map[string]any{"username": "own-user-1225", "without_email_login_key": true})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var created qrdbtransport.User
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	assert.Equal(t, bindingTenantA, created.TenantID)

	id := strconv.FormatUint(created.ID, 10)
	rec = f.do(t, f.callerA, http.MethodPut, "/api/v1/tenants/"+bindingTenantA+"/users/"+id,
		map[string]any{"name": "Own User"})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	rec = f.do(t, f.callerA, http.MethodDelete, "/api/v1/tenants/"+bindingTenantA+"/users/"+id, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

// TestAdminPlane_PlatformAdminReachesEveryTenant proves the system identity
// keeps its cross-tenant reach over the tenant records the tenant caller is
// refused.
func TestAdminPlane_PlatformAdminReachesEveryTenant(t *testing.T) {
	f := newTenantBindingFixture(t)
	userBID := strconv.FormatUint(f.userB.ID, 10)

	rec := f.do(t, f.platform, http.MethodPut, "/api/v1/tenants/"+bindingTenantB,
		map[string]string{"name": "Renamed Tenant B"})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "Renamed Tenant B")

	// qrdb's strict tenant isolation keeps the platform out of a tenant's own
	// users and roles: it manages tenants, the tenant's administrators manage
	// what is inside them.
	rec = f.do(t, f.platform, http.MethodPut, "/api/v1/tenants/"+bindingTenantB+"/users/"+userBID,
		map[string]any{"name": "Renamed B"})
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	gotUser, err := f.client.Users().GetUser(oracleContext(bindingTenantB), f.userB.ID)
	require.NoError(t, err)
	assert.Equal(t, "Victim B", gotUser.Name)

	rec = f.do(t, f.platform, http.MethodDelete, "/api/v1/tenants/"+bindingTenantB+"/roles/"+f.roleB.ID, nil)
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	_, err = f.client.Roles().GetRole(oracleContext(bindingTenantB), f.roleB.ID)
	require.NoError(t, err, "the platform deleted a tenant's role")

	// Tenant-a's users are as closed to the platform as tenant-b's: tenant-b's
	// user addressed under tenant-a's path is refused, and survives.
	rec = f.do(t, f.platform, http.MethodDelete, "/api/v1/tenants/"+bindingTenantA+"/users/"+userBID, nil)
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	_, err = f.client.Users().GetUser(oracleContext(bindingTenantB), f.userB.ID)
	require.NoError(t, err, "the platform deleted a tenant's user")
}
