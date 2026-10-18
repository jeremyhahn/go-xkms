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
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// routeCase describes one ACME admin REST operation, the qrdb grant its gate is
// expected to request, and the canonical role that must and must not reach it.
type routeCase struct {
	name     string
	method   string
	path     string
	resource string
	action   string
	// allowedRole is a canonical qrdb role that holds the grant.
	allowedRole string
	// deniedRole is a canonical qrdb role that does not hold the grant.
	deniedRole string
}

// adminRouteCases covers every route registered by Handlers.RegisterRoutes.
var adminRouteCases = []routeCase{
	{"list certificates", http.MethodGet, "/admin/certificates", auth.ResourceCerts, auth.ActionList, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameUser},
	{"list expiring certificates", http.MethodGet, "/admin/certificates/expiring", auth.ResourceCerts, auth.ActionList, qrdbsdk.RoleNameAuditor, qrdbsdk.RoleNameUser},
	{"get certificate", http.MethodGet, "/admin/certificates/abc123", auth.ResourceCerts, auth.ActionRead, qrdbsdk.RoleNameAuditor, qrdbsdk.RoleNameUser},
	{"revoke certificate", http.MethodPost, "/admin/certificates/abc123/revoke", auth.ResourceCerts, auth.ActionRevoke, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameAuditor},
	{"list accounts", http.MethodGet, "/admin/accounts", auth.ResourceACMEAccounts, auth.ActionList, qrdbsdk.RoleNameOperator, qrdbsdk.RoleNameUser},
	{"get account", http.MethodGet, "/admin/accounts/1", auth.ResourceACMEAccounts, auth.ActionRead, qrdbsdk.RoleNameOperator, qrdbsdk.RoleNameUser},
	{"disable account", http.MethodDelete, "/admin/accounts/1", auth.ResourceACMEAccounts, auth.ActionDisable, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameOperator},
	{"list orders", http.MethodGet, "/admin/orders", auth.ResourceACMEOrders, auth.ActionList, qrdbsdk.RoleNameOperator, qrdbsdk.RoleNameUser},
	{"get order", http.MethodGet, "/admin/orders/1", auth.ResourceACMEOrders, auth.ActionRead, qrdbsdk.RoleNameOperator, qrdbsdk.RoleNameUser},
	{"list audit logs", http.MethodGet, "/admin/audit", auth.ResourceAudit, auth.ActionRead, qrdbsdk.RoleNameAuditor, qrdbsdk.RoleNameUser},
	{"get status", http.MethodGet, "/admin/status", auth.ResourceAdmin, auth.ActionStatus, qrdbsdk.RoleNameOperator, unprivilegedRole},
	{"get stats", http.MethodGet, "/admin/stats", auth.ResourceAdmin, auth.ActionStatus, qrdbsdk.RoleNameOperator, unprivilegedRole},
	{"get algorithms", http.MethodGet, "/admin/algorithms", auth.ResourceAdmin, auth.ActionCapabilities, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameUser},
}

// tenantRouteCases covers every route registered by
// TenantHandlers.RegisterRoutes.
var tenantRouteCases = []routeCase{
	crossRouteCase("list tenants", http.MethodGet, "/api/v1/tenants", qrdbsdk.PermissionTenantsListCross, qrdbsdk.RoleNameUser),
	crossRouteCase("create tenant", http.MethodPost, "/api/v1/tenants", qrdbsdk.PermissionTenantsCreateCross, qrdbsdk.RoleNameAuditor),
	crossRouteCase("get tenant", http.MethodGet, "/api/v1/tenants/t1", qrdbsdk.PermissionTenantsReadCross, qrdbsdk.RoleNameUser),
	crossRouteCase("update tenant", http.MethodPut, "/api/v1/tenants/t1", qrdbsdk.PermissionTenantsUpdateCross, qrdbsdk.RoleNameAuditor),
	crossRouteCase("delete tenant", http.MethodDelete, "/api/v1/tenants/t1", qrdbsdk.PermissionTenantsDeleteCross, qrdbsdk.RoleNameOperator),
	crossRouteCase("update tenant status", http.MethodPut, "/api/v1/tenants/t1/status", qrdbsdk.PermissionTenantsUpdateCross, qrdbsdk.RoleNameOperator),

	// The same lifecycle routes called by a tenant-scoped caller on its own
	// tenant need only the self-scoped grant (go-xkms#1225).
	{"list own tenant", http.MethodGet, "/api/v1/tenants", auth.ResourceTenants, auth.ActionList, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameUser},
	{"get own tenant", http.MethodGet, "/api/v1/tenants/t1", auth.ResourceTenants, auth.ActionRead, qrdbsdk.RoleNameAuditor, qrdbsdk.RoleNameUser},
	{"update own tenant", http.MethodPut, "/api/v1/tenants/t1", auth.ResourceTenants, auth.ActionUpdate, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameAuditor},
	{"delete own tenant", http.MethodDelete, "/api/v1/tenants/t1", auth.ResourceTenants, auth.ActionDelete, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameOperator},
	{"update own tenant status", http.MethodPut, "/api/v1/tenants/t1/status", auth.ResourceTenants, auth.ActionUpdate, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameOperator},

	{"create tenant root CA", http.MethodPost, "/api/v1/tenants/t1/root-ca", auth.ResourceCA, auth.ActionCreate, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameOperator},
	{"list intermediate CAs", http.MethodGet, "/api/v1/tenants/t1/intermediate-cas", auth.ResourceCA, auth.ActionList, qrdbsdk.RoleNameOperator, qrdbsdk.RoleNameUser},
	{"create intermediate CA", http.MethodPost, "/api/v1/tenants/t1/intermediate-cas", auth.ResourceCA, auth.ActionCreate, qrdbsdk.RoleNameSO, qrdbsdk.RoleNameOperator},
	{"get intermediate CA", http.MethodGet, "/api/v1/tenants/t1/intermediate-cas/ca1", auth.ResourceCA, auth.ActionRead, qrdbsdk.RoleNameAuditor, qrdbsdk.RoleNameUser},
	{"update intermediate CA status", http.MethodPut, "/api/v1/tenants/t1/intermediate-cas/ca1/status", auth.ResourceCA, auth.ActionUpdate, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameOperator},
	{"set default intermediate CA", http.MethodPut, "/api/v1/tenants/t1/default-intermediate-ca", auth.ResourceCA, auth.ActionUpdate, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameAuditor},
	{"get tenant CA status", http.MethodGet, "/api/v1/tenants/t1/ca-status", auth.ResourceCA, auth.ActionRead, qrdbsdk.RoleNameOperator, qrdbsdk.RoleNameUser},

	{"list EABs", http.MethodGet, "/api/v1/tenants/t1/eab", auth.ResourceACMEEAB, auth.ActionList, qrdbsdk.RoleNameOperator, qrdbsdk.RoleNameUser},
	{"create EAB", http.MethodPost, "/api/v1/tenants/t1/eab", auth.ResourceACMEEAB, auth.ActionCreate, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameOperator},
	{"get EAB", http.MethodGet, "/api/v1/tenants/t1/eab/kid1", auth.ResourceACMEEAB, auth.ActionRead, qrdbsdk.RoleNameAuditor, qrdbsdk.RoleNameUser},
	{"delete EAB", http.MethodDelete, "/api/v1/tenants/t1/eab/kid1", auth.ResourceACMEEAB, auth.ActionDelete, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameOperator},

	{"list roles", http.MethodGet, "/api/v1/tenants/t1/roles", auth.ResourceRoles, auth.ActionList, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameUser},
	{"create role", http.MethodPost, "/api/v1/tenants/t1/roles", auth.ResourceRoles, auth.ActionCreate, qrdbsdk.RoleNameSO, qrdbsdk.RoleNameAdmin},
	{"get role", http.MethodGet, "/api/v1/tenants/t1/roles/r1", auth.ResourceRoles, auth.ActionRead, qrdbsdk.RoleNameAuditor, qrdbsdk.RoleNameUser},
	{"update role", http.MethodPut, "/api/v1/tenants/t1/roles/r1", auth.ResourceRoles, auth.ActionUpdate, qrdbsdk.RoleNameSO, qrdbsdk.RoleNameAdmin},
	{"delete role", http.MethodDelete, "/api/v1/tenants/t1/roles/r1", auth.ResourceRoles, auth.ActionDelete, qrdbsdk.RoleNameSO, qrdbsdk.RoleNameAdmin},

	{"list users", http.MethodGet, "/api/v1/tenants/t1/users", auth.ResourceUsers, auth.ActionList, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameUser},
	{"create user", http.MethodPost, "/api/v1/tenants/t1/users", auth.ResourceUsers, auth.ActionCreate, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameAuditor},
	{"get user", http.MethodGet, "/api/v1/tenants/t1/users/u1", auth.ResourceUsers, auth.ActionRead, qrdbsdk.RoleNameAuditor, qrdbsdk.RoleNameUser},
	{"update user", http.MethodPut, "/api/v1/tenants/t1/users/u1", auth.ResourceUsers, auth.ActionUpdate, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameAuditor},
	{"delete user", http.MethodDelete, "/api/v1/tenants/t1/users/u1", auth.ResourceUsers, auth.ActionDelete, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameOperator},
}

// unprivilegedRole names a role that is not a canonical go-qrdb role and so
// holds no permission. Every canonical role carries admin:status since
// go-qrdb v0.40, so the status routes need a non-canonical caller to prove the
// gate still refuses one without the grant.
const unprivilegedRole = "unprivileged"

// newAdminRouter builds a router with the admin and tenant routes
// registered against the qrdb-backed gate. Authentication middleware is nil so
// each test injects the identity it wants directly.
func newAdminRouter(t *testing.T) (*mux.Router, *qrdbRoleRBAC) {
	t.Helper()

	gate, client := newQRDBGate()
	router := mux.NewRouter()

	NewHandlers(newAuthzMockService(), discardLogger()).RegisterRoutes(router, nil, gate)
	NewTenantHandlers(newAuthzMockTenantService(), discardLogger()).RegisterRoutes(router, nil, gate)

	return router, client
}

// requestWithRoles builds a request for the case carrying an identity with the
// given roles, scoped to the tenant the tenant routes address.
func requestWithRoles(tc routeCase, roles ...string) *http.Request {
	req := httptest.NewRequest(tc.method, tc.path, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	if len(roles) == 0 {
		return req
	}
	// The tenant routes address tenant "t1"; scoping the caller there keeps the
	// tenant-scope check out of the way so the assertion is purely about the
	// permission gate. The platform-only routes are reached from the system
	// tenant, the only tenant their grants reach from. withUser publishes both the AuthenticatedUser
	// the handlers read and the canonical identity the gate reads, exactly as
	// the auth middleware does.
	tenantID := "t1"
	if platformOnlyRoutes[tc.name] {
		tenantID = qrdbsdk.SystemTenantID
	}
	user := &AuthenticatedUser{UserID: "test-subject", TenantID: tenantID, Roles: roles}
	return req.WithContext(withUser(req.Context(), user))
}

// platformOnlyRoutes are the routes called from the system tenant: creating a
// tenant and reaching the tenant lifecycle routes across tenants, gated on
// qrdb's cross-scope tenant grants, and reading the audit trail (refused
// outside the system tenant), which records no tenant to confine it by.
var platformOnlyRoutes = map[string]bool{
	"list tenants":         true,
	"create tenant":        true,
	"get tenant":           true,
	"update tenant":        true,
	"delete tenant":        true,
	"update tenant status": true,
	"list audit logs":      true,
}

// crossRouteCase builds a routeCase for a route gated on one cross-scope qrdb
// permission, which the Admin role holds and deniedRole does not.
func crossRouteCase(name, method, path string, p qrdbsdk.Permission, deniedRole string) routeCase {
	return routeCase{
		name:        name,
		method:      method,
		path:        path,
		resource:    qrdbsdk.PermissionResource(p),
		action:      qrdbsdk.PermissionAction(p),
		allowedRole: qrdbsdk.RoleNameAdmin,
		deniedRole:  deniedRole,
	}
}

// TestACMEAdminRoutes_RequestExactPermission verifies every ACME admin REST
// route asks the qrdb authorizer for exactly the resource:action pair it
// declares, and for nothing else.
func TestACMEAdminRoutes_RequestExactPermission(t *testing.T) {
	for _, group := range [][]routeCase{adminRouteCases, tenantRouteCases} {
		for _, tc := range group {
			t.Run(tc.name, func(t *testing.T) {
				router, client := newAdminRouter(t)

				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, requestWithRoles(tc, tc.allowedRole))

				require.Equal(t, []string{tc.resource + ":" + tc.action}, client.requests(),
					"route %s %s must request exactly one permission", tc.method, tc.path)
			})
		}
	}
}

// TestACMEAdminRoutes_AllowedWithGrant verifies every route is served when the
// caller holds a canonical qrdb role carrying its grant.
func TestACMEAdminRoutes_AllowedWithGrant(t *testing.T) {
	for _, group := range [][]routeCase{adminRouteCases, tenantRouteCases} {
		for _, tc := range group {
			t.Run(tc.name, func(t *testing.T) {
				router, _ := newAdminRouter(t)

				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, requestWithRoles(tc, tc.allowedRole))

				assert.NotEqual(t, http.StatusForbidden, rec.Code,
					"role %q holds %s:%s and must not be forbidden", tc.allowedRole, tc.resource, tc.action)
				assert.NotEqual(t, http.StatusUnauthorized, rec.Code)
			})
		}
	}
}

// TestACMEAdminRoutes_DeniedWithoutGrant verifies every route is refused when
// the caller holds a canonical role that lacks its grant.
func TestACMEAdminRoutes_DeniedWithoutGrant(t *testing.T) {
	for _, group := range [][]routeCase{adminRouteCases, tenantRouteCases} {
		for _, tc := range group {
			t.Run(tc.name, func(t *testing.T) {
				router, _ := newAdminRouter(t)

				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, requestWithRoles(tc, tc.deniedRole))

				assert.Equal(t, http.StatusForbidden, rec.Code,
					"role %q lacks %s:%s and must be forbidden", tc.deniedRole, tc.resource, tc.action)
			})
		}
	}
}

// TestACMEAdminRoutes_DeniedWithoutIdentity verifies every route refuses an
// unauthenticated caller. Before the unification, thirteen of these routes
// carried no authorization decorator at all and only the authentication
// middleware stood between an anonymous caller and the data.
func TestACMEAdminRoutes_DeniedWithoutIdentity(t *testing.T) {
	for _, group := range [][]routeCase{adminRouteCases, tenantRouteCases} {
		for _, tc := range group {
			t.Run(tc.name, func(t *testing.T) {
				router, _ := newAdminRouter(t)

				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, requestWithRoles(tc))

				assert.Equal(t, http.StatusUnauthorized, rec.Code,
					"route %s %s must reject an unauthenticated caller", tc.method, tc.path)
			})
		}
	}
}

// TestACMEAdminRoutes_QRDBAdminReachesEverySurface is the regression test for
// the user-visible bug: a caller granted qrdb's canonical "admin" role must
// reach the ACME admin surface. Before the unification, "admin" in qrdb
// conferred nothing here — the ACME API ran its own super-admin / endorser /
// viewer vocabulary that shared no members with the qrdb roles.
func TestACMEAdminRoutes_QRDBAdminReachesEverySurface(t *testing.T) {
	// The routes an Admin is expected to reach. The SO-exclusive
	// role-mutation operations are deliberately excluded — qrdb reserves
	// those for the Security Officer.
	soOnly := map[string]bool{
		"create role": true, "update role": true, "delete role": true,
		"create intermediate CA": true,
	}

	for _, group := range [][]routeCase{adminRouteCases, tenantRouteCases} {
		for _, tc := range group {
			if soOnly[tc.name] {
				continue
			}
			t.Run(tc.name, func(t *testing.T) {
				router, _ := newAdminRouter(t)

				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, requestWithRoles(tc, qrdbsdk.RoleNameAdmin))

				assert.NotEqual(t, http.StatusForbidden, rec.Code,
					"the canonical qrdb admin role must reach %s %s", tc.method, tc.path)
			})
		}
	}
}

// TestACMEAdminRoutes_RevokingAdminRemovesAccess is the other half of the
// regression: taking the admin role away removes ACME admin access. An identity
// with no roles at all reaches nothing.
func TestACMEAdminRoutes_RevokingAdminRemovesAccess(t *testing.T) {
	for _, group := range [][]routeCase{adminRouteCases, tenantRouteCases} {
		for _, tc := range group {
			t.Run(tc.name, func(t *testing.T) {
				router, _ := newAdminRouter(t)

				req := httptest.NewRequest(tc.method, tc.path, strings.NewReader("{}"))
				req = req.WithContext(withUser(req.Context(),
					&AuthenticatedUser{UserID: "revoked", TenantID: "t1"}))

				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)

				assert.Equal(t, http.StatusForbidden, rec.Code,
					"an identity whose roles were revoked must not reach %s %s", tc.method, tc.path)
			})
		}
	}
}

// TestACMEAdminRoutes_UnknownPathIsNotFound verifies an unmapped path is a 404
// from the router rather than an accidentally ungated handler. It documents
// that there is no undecorated registration path on the admin surface.
func TestACMEAdminRoutes_UnknownPathIsNotFound(t *testing.T) {
	router, client := newAdminRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/does-not-exist", nil)
	req = req.WithContext(withUser(req.Context(),
		&AuthenticatedUser{UserID: "admin", TenantID: "t1", Roles: []string{qrdbsdk.RoleNameAdmin}}))

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Empty(t, client.requests(), "an unrouted path must never reach the authorizer")
}

// TestACMEAdminRoutes_TenantCallerForeignTenantIsNotFound verifies that a
// tenant-scoped caller addressing another tenant's lifecycle routes is asked
// for the cross-scope grant and, whatever it holds, is answered as for a
// missing tenant, so it cannot tell a foreign tenant from an absent one
// (go-xkms#1225).
func TestACMEAdminRoutes_TenantCallerForeignTenantIsNotFound(t *testing.T) {
	foreign := []routeCase{
		crossRouteCase("get foreign tenant", http.MethodGet, "/api/v1/tenants/t2", qrdbsdk.PermissionTenantsReadCross, ""),
		crossRouteCase("update foreign tenant", http.MethodPut, "/api/v1/tenants/t2", qrdbsdk.PermissionTenantsUpdateCross, ""),
		crossRouteCase("delete foreign tenant", http.MethodDelete, "/api/v1/tenants/t2", qrdbsdk.PermissionTenantsDeleteCross, ""),
		crossRouteCase("update foreign tenant status", http.MethodPut, "/api/v1/tenants/t2/status", qrdbsdk.PermissionTenantsUpdateCross, ""),
	}
	for _, tc := range foreign {
		for _, role := range []string{qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameUser} {
			t.Run(tc.name+"/"+role, func(t *testing.T) {
				router, client := newAdminRouter(t)

				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, requestWithRoles(tc, role))

				assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
				assert.Contains(t, rec.Body.String(), "Tenant not found")
				assert.Equal(t, []string{tc.resource + ":" + tc.action}, client.requests())
			})
		}
	}
}

// newAuthzMockService returns a Service whose every method succeeds with an
// empty, fully-populated result. The authorization tests care only about which
// requests reach a handler, so the handlers must not fail for want of data.
func newAuthzMockService() *mockService {
	page := func() *Pagination { return &Pagination{Page: 1, PerPage: 20, Total: 0} }
	return &mockService{
		listCertificatesFunc: func(context.Context, ListCertificatesRequest) ([]*CertificateInfo, *Pagination, error) {
			return []*CertificateInfo{}, page(), nil
		},
		listExpiringCertificatesFunc: func(context.Context, int, int, int) ([]*CertificateInfo, *Pagination, error) {
			return []*CertificateInfo{}, page(), nil
		},
		getCertificateFunc: func(context.Context, string) (*CertificateInfo, error) {
			return &CertificateInfo{SerialNumber: "abc123"}, nil
		},
		revokeCertificateFunc: func(context.Context, string, string) error { return nil },
		listAccountsFunc: func(context.Context, ListAccountsRequest) ([]*AccountInfo, *Pagination, error) {
			return []*AccountInfo{}, page(), nil
		},
		getAccountFunc:     func(context.Context, uint64) (*AccountInfo, error) { return &AccountInfo{ID: 1}, nil },
		disableAccountFunc: func(context.Context, uint64) error { return nil },
		listOrdersFunc: func(context.Context, ListOrdersRequest) ([]*OrderInfo, *Pagination, error) {
			return []*OrderInfo{}, page(), nil
		},
		getOrderFunc:  func(context.Context, uint64, uint64) (*OrderInfo, error) { return &OrderInfo{ID: 1}, nil },
		getStatusFunc: func(context.Context) (*CAStatus, error) { return &CAStatus{Identity: "test"}, nil },
		getStatsFunc:  func(context.Context) (*CAStats, error) { return &CAStats{}, nil },
	}
}

// newAuthzMockTenantService returns a TenantService whose list operations
// return empty, non-nil results so the handlers complete rather than panic.
func newAuthzMockTenantService() *mockTenantService {
	return &mockTenantService{
		listTenantsFunc: func(context.Context, ListTenantsRequest) ([]*TenantInfo, *Pagination, error) {
			return []*TenantInfo{}, &Pagination{Page: 1, PerPage: 20}, nil
		},
		getTenantFunc: func(_ context.Context, id string) (*TenantInfo, error) {
			return &TenantInfo{ID: id, Name: id}, nil
		},
		createTenantFunc: func(_ context.Context, req CreateTenantRequest) (*TenantInfo, error) {
			return &TenantInfo{ID: req.ID, Name: req.Name}, nil
		},
		updateTenantFunc: func(_ context.Context, id string, _ UpdateTenantRequest) (*TenantInfo, error) {
			return &TenantInfo{ID: id}, nil
		},
		listTenantEABsFunc: func(context.Context, string, ListEABRequest) ([]*EABInfo, *Pagination, error) {
			return []*EABInfo{}, &Pagination{Page: 1, PerPage: 20}, nil
		},
		listTenantIntermediateCAsFunc: func(context.Context, string) ([]*TenantIntCAInfo, error) {
			return []*TenantIntCAInfo{}, nil
		},
		getTenantCAStatusFunc: func(_ context.Context, id string) (*TenantCAStatusInfo, error) {
			return &TenantCAStatusInfo{TenantID: id}, nil
		},
		listTenantRolesFunc: func(context.Context, string, *db.ListRolesRequest) (*db.ListRolesResponse, error) {
			return &db.ListRolesResponse{Roles: []*db.Role{}}, nil
		},
		getTenantRoleFunc: func(_ context.Context, _ string, id string) (*db.Role, error) {
			return &db.Role{ID: id}, nil
		},
		createTenantRoleFunc: func(_ context.Context, _ string, req *db.CreateRoleRequest) (*db.Role, error) {
			return &db.Role{ID: "r1", Name: req.Name}, nil
		},
		updateTenantRoleFunc: func(_ context.Context, _ string, req *db.UpdateRoleRequest) (*db.Role, error) {
			return &db.Role{ID: req.ID}, nil
		},
		listTenantUsersFunc: func(context.Context, string, *db.ListUsersRequest) (*db.ListUsersResponse, error) {
			return &db.ListUsersResponse{Users: []*db.User{}}, nil
		},
		getTenantUserFunc: func(context.Context, string, string) (*db.User, error) {
			return &db.User{Username: "u1"}, nil
		},
		createTenantUserFunc: func(_ context.Context, _ string, req *db.CreateUserRequest) (*db.User, error) {
			return &db.User{Username: req.Username}, nil
		},
		updateTenantUserFunc: func(context.Context, string, *db.UpdateUserRequest) (*db.User, error) {
			return &db.User{Username: "u1"}, nil
		},
		createTenantRootCAFunc: func(context.Context, string, CreateTenantRootCARequest) (*TenantRootCAInfo, error) {
			return &TenantRootCAInfo{CommonName: "root"}, nil
		},
		createTenantIntermediateCAFunc: func(context.Context, string, CreateTenantIntermediateCARequest) (*TenantIntCAInfo, error) {
			return &TenantIntCAInfo{ID: "ca1"}, nil
		},
		getTenantIntermediateCAFunc: func(_ context.Context, _ string, id string) (*TenantIntCAInfo, error) {
			return &TenantIntCAInfo{ID: id}, nil
		},
		createTenantEABFunc: func(context.Context, string, CreateEABRequest) (*CreateEABResponse, error) {
			return &CreateEABResponse{ID: "kid1", MACKey: "k", Algorithm: "HS256"}, nil
		},
		getTenantEABFunc: func(_ context.Context, _ string, kid string) (*EABInfo, error) {
			return &EABInfo{ID: kid}, nil
		},
	}
}
