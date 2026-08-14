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
	{"list certificates", http.MethodGet, "/admin/certificates", auth.ResourceCerts, auth.ActionList, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameCustodian},
	{"list expiring certificates", http.MethodGet, "/admin/certificates/expiring", auth.ResourceCerts, auth.ActionList, qrdbsdk.RoleNameAuditor, qrdbsdk.RoleNameCustodian},
	{"get certificate", http.MethodGet, "/admin/certificates/abc123", auth.ResourceCerts, auth.ActionRead, qrdbsdk.RoleNameAuditor, qrdbsdk.RoleNameCustodian},
	{"revoke certificate", http.MethodPost, "/admin/certificates/abc123/revoke", auth.ResourceCerts, auth.ActionRevoke, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameAuditor},
	{"list accounts", http.MethodGet, "/admin/accounts", auth.ResourceACMEAccounts, auth.ActionList, qrdbsdk.RoleNameOperator, qrdbsdk.RoleNameUser},
	{"get account", http.MethodGet, "/admin/accounts/1", auth.ResourceACMEAccounts, auth.ActionRead, qrdbsdk.RoleNameOperator, qrdbsdk.RoleNameUser},
	{"disable account", http.MethodDelete, "/admin/accounts/1", auth.ResourceACMEAccounts, auth.ActionDisable, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameOperator},
	{"list orders", http.MethodGet, "/admin/orders", auth.ResourceACMEOrders, auth.ActionList, qrdbsdk.RoleNameOperator, qrdbsdk.RoleNameUser},
	{"get order", http.MethodGet, "/admin/orders/1", auth.ResourceACMEOrders, auth.ActionRead, qrdbsdk.RoleNameOperator, qrdbsdk.RoleNameUser},
	{"list audit logs", http.MethodGet, "/admin/audit", auth.ResourceAudit, auth.ActionRead, qrdbsdk.RoleNameAuditor, qrdbsdk.RoleNameUser},
	{"get status", http.MethodGet, "/admin/status", auth.ResourceAdmin, auth.ActionStatus, qrdbsdk.RoleNameOperator, qrdbsdk.RoleNameCustodian},
	{"get stats", http.MethodGet, "/admin/stats", auth.ResourceAdmin, auth.ActionStatus, qrdbsdk.RoleNameOperator, qrdbsdk.RoleNameCustodian},
	{"get algorithms", http.MethodGet, "/admin/algorithms", auth.ResourceAdmin, auth.ActionCapabilities, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameUser},
}

// tenantRouteCases covers every route registered by
// TenantHandlers.RegisterRoutes.
var tenantRouteCases = []routeCase{
	{"list tenants", http.MethodGet, "/api/v1/tenants", auth.ResourceTenants, auth.ActionList, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameUser},
	{"create tenant", http.MethodPost, "/api/v1/tenants", auth.ResourceTenants, auth.ActionCreate, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameAuditor},
	{"get tenant", http.MethodGet, "/api/v1/tenants/t1", auth.ResourceTenants, auth.ActionRead, qrdbsdk.RoleNameAuditor, qrdbsdk.RoleNameUser},
	{"update tenant", http.MethodPut, "/api/v1/tenants/t1", auth.ResourceTenants, auth.ActionUpdate, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameAuditor},
	{"delete tenant", http.MethodDelete, "/api/v1/tenants/t1", auth.ResourceTenants, auth.ActionDelete, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameOperator},
	{"update tenant status", http.MethodPut, "/api/v1/tenants/t1/status", auth.ResourceTenants, auth.ActionUpdate, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameOperator},

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

// barrierRouteCases covers every route registered by
// BarrierHandlers.RegisterRoutes.
var barrierRouteCases = []routeCase{
	{"barrier status", http.MethodGet, "/admin/barrier/status", auth.ResourceSeal, auth.ActionStatus, qrdbsdk.RoleNameOperator, qrdbsdk.RoleNameCustodian},
	{"barrier initialize", http.MethodPost, "/admin/barrier/initialize", auth.ResourceSeal, auth.ActionBootstrap, qrdbsdk.RoleNameSO, qrdbsdk.RoleNameAdmin},
	{"barrier seal", http.MethodPost, "/admin/barrier/seal", auth.ResourceSeal, auth.ActionSeal, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameUser},
	{"barrier unseal", http.MethodPost, "/admin/barrier/unseal", auth.ResourceSeal, auth.ActionUnseal, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameAuditor},
	{"shamir initialize", http.MethodPost, "/admin/barrier/shamir/initialize", auth.ResourceSeal, auth.ActionInitializeShamir, qrdbsdk.RoleNameSO, qrdbsdk.RoleNameAdmin},
	{"shamir unseal share", http.MethodPost, "/admin/barrier/shamir/unseal-share", auth.ResourceBarrier, auth.ActionUnsealShare, qrdbsdk.RoleNameCustodian, qrdbsdk.RoleNameAdmin},
	{"barrier rekey", http.MethodPost, "/admin/barrier/rekey", auth.ResourceSeal, auth.ActionRekey, qrdbsdk.RoleNameSO, qrdbsdk.RoleNameAdmin},
	{"recovery generate", http.MethodPost, "/admin/barrier/recovery/generate", auth.ResourceSeal, auth.ActionGenerateRecovery, qrdbsdk.RoleNameSO, qrdbsdk.RoleNameAdmin},
	{"recovery recover", http.MethodPost, "/admin/barrier/recovery/recover", auth.ResourceSeal, auth.ActionRecoverWithKeys, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameUser},
	{"recovery status", http.MethodGet, "/admin/barrier/recovery/status", auth.ResourceSeal, auth.ActionStatus, qrdbsdk.RoleNameOperator, qrdbsdk.RoleNameCustodian},
	{"barrier root token", http.MethodPost, "/admin/barrier/root-token", auth.ResourceSeal, auth.ActionRotateRootKey, qrdbsdk.RoleNameSO, qrdbsdk.RoleNameAdmin},
}

// newAdminRouter builds a router with the admin, tenant, and barrier routes
// registered against the qrdb-backed gate. Authentication middleware is nil so
// each test injects the identity it wants directly.
func newAdminRouter(t *testing.T) (*mux.Router, *qrdbRoleRBAC) {
	t.Helper()

	gate, client := newQRDBGate()
	router := mux.NewRouter()

	NewHandlers(newAuthzMockService(), discardLogger()).RegisterRoutes(router, nil, gate)
	NewTenantHandlers(newAuthzMockTenantService(), discardLogger()).RegisterRoutes(router, nil, gate)
	NewBarrierHandlers(newStubBarrierService(), discardLogger()).RegisterRoutes(router, nil, gate)

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
	// permission gate. withUser publishes both the AuthenticatedUser the
	// handlers read and the canonical identity the gate reads, exactly as the
	// auth middleware does.
	user := &AuthenticatedUser{UserID: "test-subject", TenantID: "t1", Roles: roles}
	return req.WithContext(withUser(req.Context(), user))
}

// TestACMEAdminRoutes_RequestExactPermission verifies every ACME admin REST
// route asks the qrdb authorizer for exactly the resource:action pair it
// declares, and for nothing else.
func TestACMEAdminRoutes_RequestExactPermission(t *testing.T) {
	for _, group := range [][]routeCase{adminRouteCases, tenantRouteCases, barrierRouteCases} {
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
	for _, group := range [][]routeCase{adminRouteCases, tenantRouteCases, barrierRouteCases} {
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
	for _, group := range [][]routeCase{adminRouteCases, tenantRouteCases, barrierRouteCases} {
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
	for _, group := range [][]routeCase{adminRouteCases, tenantRouteCases, barrierRouteCases} {
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
	// The routes an Admin is expected to reach. The SO-exclusive barrier
	// governance operations and the SO-exclusive role-mutation operations are
	// deliberately excluded — qrdb reserves those for the Security Officer.
	soOnly := map[string]bool{
		"barrier initialize": true, "shamir initialize": true, "barrier rekey": true,
		"recovery generate": true, "barrier root token": true, "shamir unseal share": true,
		"create role": true, "update role": true, "delete role": true,
		"create intermediate CA": true,
	}

	for _, group := range [][]routeCase{adminRouteCases, tenantRouteCases, barrierRouteCases} {
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
	for _, group := range [][]routeCase{adminRouteCases, tenantRouteCases, barrierRouteCases} {
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
