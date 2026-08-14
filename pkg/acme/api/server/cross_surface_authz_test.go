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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// crossSurfaceOperations pairs the gRPC and MCP names of the same logical ACME
// admin operation. Both transports must request an identical resource:action
// pair, so a single grant means the same thing on either one.
var crossSurfaceOperations = []struct {
	operation  string
	grpcMethod string
	mcpMethod  string
}{
	{"get status", "/admin.v1.AdminService/GetStatus", "admin.getStatus"},
	{"get stats", "/admin.v1.AdminService/GetStats", "admin.getStats"},

	{"list certificates", "/admin.v1.AdminService/ListCertificates", "admin.listCertificates"},
	{"get certificate", "/admin.v1.AdminService/GetCertificate", "admin.getCertificate"},
	{"revoke certificate", "/admin.v1.AdminService/RevokeCertificate", "admin.revokeCertificate"},

	{"create tenant", "/admin.v1.AdminService/CreateTenant", "admin.createTenant"},
	{"get tenant", "/admin.v1.AdminService/GetTenant", "admin.getTenant"},
	{"update tenant", "/admin.v1.AdminService/UpdateTenant", "admin.updateTenant"},
	{"delete tenant", "/admin.v1.AdminService/DeleteTenant", "admin.deleteTenant"},
	{"list tenants", "/admin.v1.AdminService/ListTenants", "admin.listTenants"},

	{"create EAB", "/admin.v1.AdminService/CreateEAB", "admin.createEAB"},
	{"get EAB", "/admin.v1.AdminService/GetEAB", "admin.getEAB"},
	{"delete EAB", "/admin.v1.AdminService/DeleteEAB", "admin.deleteEAB"},
	{"list EABs", "/admin.v1.AdminService/ListEABs", "admin.listEABs"},

	{"create role", "/admin.v1.AdminService/CreateTenantRole", "admin.createRole"},
	{"get role", "/admin.v1.AdminService/GetTenantRole", "admin.getRole"},
	{"update role", "/admin.v1.AdminService/UpdateTenantRole", "admin.updateRole"},
	{"delete role", "/admin.v1.AdminService/DeleteTenantRole", "admin.deleteRole"},
	{"list roles", "/admin.v1.AdminService/ListTenantRoles", "admin.listRoles"},

	{"create user", "/admin.v1.AdminService/CreateTenantUser", "admin.createUser"},
	{"get user", "/admin.v1.AdminService/GetTenantUser", "admin.getUser"},
	{"update user", "/admin.v1.AdminService/UpdateTenantUser", "admin.updateUser"},
	{"delete user", "/admin.v1.AdminService/DeleteTenantUser", "admin.deleteUser"},
	{"list users", "/admin.v1.AdminService/ListTenantUsers", "admin.listUsers"},
}

// TestCrossSurface_SameOperationSamePermission verifies the gRPC and MCP tables
// agree on the grant every shared ACME admin operation requires.
func TestCrossSurface_SameOperationSamePermission(t *testing.T) {
	for _, tc := range crossSurfaceOperations {
		t.Run(tc.operation, func(t *testing.T) {
			grpcPerm, ok := MethodPermissions[tc.grpcMethod]
			require.True(t, ok, "gRPC method %s has no mapping", tc.grpcMethod)

			mcpPerm, ok := MCPMethodPermissions[tc.mcpMethod]
			require.True(t, ok, "MCP method %s has no mapping", tc.mcpMethod)

			assert.Equal(t, grpcPerm, mcpPerm,
				"%s must require the same permission on gRPC (%s:%s) and MCP (%s:%s)",
				tc.operation, grpcPerm.Resource, grpcPerm.Action, mcpPerm.Resource, mcpPerm.Action)
		})
	}
}

// TestCrossSurface_UsesCanonicalVocabulary verifies every permission either
// transport requests is drawn from the canonical go-qrdb vocabulary mirrored in
// pkg/auth. A pair that is not in this set is a locally minted permission — the
// exact failure mode this unification removed.
func TestCrossSurface_UsesCanonicalVocabulary(t *testing.T) {
	canonicalResources := map[string]bool{
		auth.ResourceCerts:        true,
		auth.ResourceTenants:      true,
		auth.ResourceRoles:        true,
		auth.ResourceUsers:        true,
		auth.ResourceAdmin:        true,
		auth.ResourceAudit:        true,
		auth.ResourceSeal:         true,
		auth.ResourceBarrier:      true,
		auth.ResourceCA:           true,
		auth.ResourceACMEAccounts: true,
		auth.ResourceACMEOrders:   true,
		auth.ResourceACMEEAB:      true,
	}
	canonicalActions := map[string]bool{
		auth.ActionCreate: true, auth.ActionRead: true, auth.ActionUpdate: true,
		auth.ActionDelete: true, auth.ActionList: true, auth.ActionRevoke: true,
		auth.ActionDisable: true, auth.ActionStatus: true, auth.ActionCapabilities: true,
	}

	for method, perm := range MethodPermissions {
		assert.True(t, canonicalResources[perm.Resource],
			"gRPC method %s requests non-canonical resource %q", method, perm.Resource)
		assert.True(t, canonicalActions[perm.Action],
			"gRPC method %s requests non-canonical action %q", method, perm.Action)
	}
	for method, perm := range MCPMethodPermissions {
		assert.True(t, canonicalResources[perm.Resource],
			"MCP method %s requests non-canonical resource %q", method, perm.Resource)
		assert.True(t, canonicalActions[perm.Action],
			"MCP method %s requests non-canonical action %q", method, perm.Action)
	}
}
