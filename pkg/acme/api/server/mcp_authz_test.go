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

//go:build !integration

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// newAuthzTestServer builds a MultiProtocolServer whose only wired dependency
// is the qrdb-backed gate, which is all the authorization tests exercise.
func newAuthzTestServer(t *testing.T) (*MultiProtocolServer, *qrdbRoleRBAC) {
	t.Helper()

	gate, client := newTestGate()
	s := &MultiProtocolServer{
		config: DefaultConfig(),
		logger: testLogger(),
		gate:   gate,
	}
	s.initMCPHandlers()
	return s, client
}

// mcpAuthenticatedRequest attaches a canonical platform-admin identity to an
// MCP request, standing in for the authentication middleware the /mcp route now
// carries. Every MCP method is gated, so a request with no identity is answered
// with the JSON-RPC "Unauthorized" error before the handler runs.
func mcpAuthenticatedRequest(req *http.Request) *http.Request {
	return req.WithContext(auth.WithIdentity(req.Context(), &auth.Identity{
		Subject:  "mcp-test-admin",
		TenantID: "",
		Roles:    []string{qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameSO},
	}))
}

// mcpAuthzCase pairs an MCP method with the grant it must request and with a
// canonical qrdb role that does and does not hold it.
type mcpAuthzCase struct {
	method      string
	resource    string
	action      string
	allowedRole string
	deniedRole  string
}

var mcpAuthzCases = []mcpAuthzCase{
	{"admin.getStatus", auth.ResourceAdmin, auth.ActionStatus, qrdbsdk.RoleNameOperator, unprivilegedRole},
	{"admin.getStats", auth.ResourceAdmin, auth.ActionStatus, qrdbsdk.RoleNameOperator, unprivilegedRole},

	{"admin.listCertificates", auth.ResourceCerts, auth.ActionList, qrdbsdk.RoleNameAuditor, qrdbsdk.RoleNameUser},
	{"admin.getCertificate", auth.ResourceCerts, auth.ActionRead, qrdbsdk.RoleNameAuditor, qrdbsdk.RoleNameUser},
	{"admin.revokeCertificate", auth.ResourceCerts, auth.ActionRevoke, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameAuditor},

	{"admin.listAccounts", auth.ResourceACMEAccounts, auth.ActionList, qrdbsdk.RoleNameOperator, qrdbsdk.RoleNameUser},
	{"admin.getAccount", auth.ResourceACMEAccounts, auth.ActionRead, qrdbsdk.RoleNameOperator, qrdbsdk.RoleNameUser},
	{"admin.disableAccount", auth.ResourceACMEAccounts, auth.ActionDisable, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameOperator},

	{"admin.createTenant", auth.ResourceTenants, auth.ActionCreate, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameAuditor},
	{"admin.getTenant", auth.ResourceTenants, auth.ActionRead, qrdbsdk.RoleNameAuditor, qrdbsdk.RoleNameUser},
	{"admin.updateTenant", auth.ResourceTenants, auth.ActionUpdate, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameAuditor},
	{"admin.deleteTenant", auth.ResourceTenants, auth.ActionDelete, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameOperator},
	{"admin.listTenants", auth.ResourceTenants, auth.ActionList, qrdbsdk.RoleNameAuditor, qrdbsdk.RoleNameUser},

	{"admin.createEAB", auth.ResourceACMEEAB, auth.ActionCreate, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameOperator},
	{"admin.getEAB", auth.ResourceACMEEAB, auth.ActionRead, qrdbsdk.RoleNameOperator, qrdbsdk.RoleNameUser},
	{"admin.deleteEAB", auth.ResourceACMEEAB, auth.ActionDelete, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameOperator},
	{"admin.listEABs", auth.ResourceACMEEAB, auth.ActionList, qrdbsdk.RoleNameOperator, qrdbsdk.RoleNameUser},

	{"admin.createRole", auth.ResourceRoles, auth.ActionCreate, qrdbsdk.RoleNameSO, qrdbsdk.RoleNameUser},
	{"admin.getRole", auth.ResourceRoles, auth.ActionRead, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameUser},
	{"admin.updateRole", auth.ResourceRoles, auth.ActionUpdate, qrdbsdk.RoleNameSO, qrdbsdk.RoleNameUser},
	{"admin.deleteRole", auth.ResourceRoles, auth.ActionDelete, qrdbsdk.RoleNameSO, qrdbsdk.RoleNameAdmin},
	{"admin.listRoles", auth.ResourceRoles, auth.ActionList, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameUser},

	{"admin.createUser", auth.ResourceUsers, auth.ActionCreate, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameAuditor},
	{"admin.getUser", auth.ResourceUsers, auth.ActionRead, qrdbsdk.RoleNameAuditor, qrdbsdk.RoleNameUser},
	{"admin.updateUser", auth.ResourceUsers, auth.ActionUpdate, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameAuditor},
	{"admin.deleteUser", auth.ResourceUsers, auth.ActionDelete, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameOperator},
	{"admin.listUsers", auth.ResourceUsers, auth.ActionList, qrdbsdk.RoleNameAuditor, qrdbsdk.RoleNameUser},
}

// TestMCPToolPermissions_CoversEveryDispatchableMethod verifies every method
// in the MCP dispatch table carries the permission its mirrored RPC declares,
// and that each is the exact grant the case table expects.
func TestMCPToolPermissions_CoversEveryDispatchableMethod(t *testing.T) {
	s, _ := newAuthzTestServer(t)
	perms := s.MCPToolPermissions()

	for method := range s.mcpHandlers {
		_, ok := perms[method]
		assert.True(t, ok, "dispatchable MCP method %q has no permission", method)
	}
	require.Len(t, perms, len(mcpAuthzCases))
	for _, tc := range mcpAuthzCases {
		assert.Equal(t, qrdbsdk.Permission(tc.resource+":"+tc.action), perms[tc.method], tc.method)
	}
}

// TestAuthorizeMCPMethod_RequestsExactPermission verifies each MCP method asks
// the authorizer for exactly the resource:action its table entry declares.
func TestAuthorizeMCPMethod_RequestsExactPermission(t *testing.T) {
	for _, tc := range mcpAuthzCases {
		t.Run(tc.method, func(t *testing.T) {
			s, client := newAuthzTestServer(t)

			ctx := auth.WithIdentity(context.Background(), &auth.Identity{
				Subject: "tester", TenantID: "t1", Roles: []string{tc.allowedRole},
			})

			require.NoError(t, s.authorizeMCPMethod(ctx, tc.method))
			assert.Equal(t, []string{tc.resource + ":" + tc.action}, client.requested)
		})
	}
}

// TestAuthorizeMCPMethod_DeniesWithoutGrant verifies each MCP method is refused
// when the caller's canonical role lacks its grant.
func TestAuthorizeMCPMethod_DeniesWithoutGrant(t *testing.T) {
	for _, tc := range mcpAuthzCases {
		t.Run(tc.method, func(t *testing.T) {
			s, _ := newAuthzTestServer(t)

			ctx := auth.WithIdentity(context.Background(), &auth.Identity{
				Subject: "tester", TenantID: "t1", Roles: []string{tc.deniedRole},
			})

			require.Error(t, s.authorizeMCPMethod(ctx, tc.method))
		})
	}
}

// TestAuthorizeMCPMethod_DeniesWithoutIdentity is the fail-open regression for
// the MCP surface: /mcp previously carried no authentication and no
// authorization, so every admin operation — including deleteTenant,
// revokeCertificate, and the whole user administration surface — was reachable
// by an anonymous caller.
func TestAuthorizeMCPMethod_DeniesWithoutIdentity(t *testing.T) {
	s, _ := newAuthzTestServer(t)

	for _, tc := range mcpAuthzCases {
		t.Run(tc.method, func(t *testing.T) {
			err := s.authorizeMCPMethod(context.Background(), tc.method)
			require.ErrorIs(t, err, auth.ErrUnauthenticated)
		})
	}
}

// TestAuthorizeMCPMethod_UnknownMethodFallsThrough verifies a method with no
// handler is left to the dispatcher's "method not found" answer. It reaches no
// service code, so gating it would only hide a client bug behind a 403.
func TestAuthorizeMCPMethod_UnknownMethodFallsThrough(t *testing.T) {
	s, client := newAuthzTestServer(t)

	require.NoError(t, s.authorizeMCPMethod(context.Background(), "admin.noSuchMethod"))
	assert.Empty(t, client.requested)
}

// TestAuthorizeMCPMethod_DispatchableButUnmappedIsDenied verifies the
// fail-closed path for a registration bug: a method the dispatcher can serve
// but whose mirrored RPC declares no permission is denied and is left out of
// MCPToolPermissions.
func TestAuthorizeMCPMethod_DispatchableButUnmappedIsDenied(t *testing.T) {
	s, client := newAuthzTestServer(t)
	s.mcpHandlers["admin.unmappedFuture"] = mcpMethod{
		rpc: "/trustedca.admin.v1.AdminService/UnmappedFuture",
		handle: func(ctx context.Context, params json.RawMessage) (interface{}, error) {
			return nil, nil
		},
	}

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "root", Roles: []string{qrdbsdk.RoleNameAdmin},
	})

	err := s.authorizeMCPMethod(ctx, "admin.unmappedFuture")
	require.ErrorIs(t, err, admin.ErrOperationUnmapped)
	assert.Empty(t, client.requested)
	assert.NotContains(t, s.MCPToolPermissions(), "admin.unmappedFuture")
}

// TestAuthorizeMCPMethod_NilGateDenies verifies an unwired gate fails closed.
func TestAuthorizeMCPMethod_NilGateDenies(t *testing.T) {
	s, _ := newAuthzTestServer(t)
	s.gate = nil

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "root", Roles: []string{qrdbsdk.RoleNameAdmin},
	})

	require.ErrorIs(t, s.authorizeMCPMethod(ctx, "admin.listTenants"), admin.ErrGateNotConfigured)
}

// TestAuthorizeMCPMethod_QRDBAdminReachesMCPSurface is the unification
// regression on the MCP transport: qrdb's canonical admin role reaches the ACME
// admin MCP methods an Admin should reach, and revoking it removes access.
func TestAuthorizeMCPMethod_QRDBAdminReachesMCPSurface(t *testing.T) {
	// Since go-qrdb v0.58 Admin creates and updates roles; deleting one stays
	// with the Security Officer.
	soOnly := map[string]bool{"admin.deleteRole": true}

	server, _ := newAuthzTestServer(t)
	for method := range server.MCPToolPermissions() {
		if soOnly[method] {
			continue
		}
		t.Run(method, func(t *testing.T) {
			s, _ := newAuthzTestServer(t)

			granted := auth.WithIdentity(context.Background(), &auth.Identity{
				Subject: "someone", TenantID: "t1", Roles: []string{qrdbsdk.RoleNameAdmin},
			})
			require.NoError(t, s.authorizeMCPMethod(granted, method))

			revoked := auth.WithIdentity(context.Background(), &auth.Identity{
				Subject: "someone", TenantID: "t1", Roles: nil,
			})
			require.Error(t, s.authorizeMCPMethod(revoked, method))
		})
	}
}
