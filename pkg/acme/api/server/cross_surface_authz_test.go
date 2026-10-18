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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	adminv1 "github.com/jeremyhahn/go-xkms/api/proto/admin/v1"
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
	{"get status", adminv1.AdminService_GetStatus_FullMethodName, "admin.getStatus"},
	{"get stats", adminv1.AdminService_GetStats_FullMethodName, "admin.getStats"},

	{"list certificates", adminv1.AdminService_ListCertificates_FullMethodName, "admin.listCertificates"},
	{"get certificate", adminv1.AdminService_GetCertificate_FullMethodName, "admin.getCertificate"},
	{"revoke certificate", adminv1.AdminService_RevokeCertificate_FullMethodName, "admin.revokeCertificate"},

	{"create tenant", adminv1.AdminService_CreateTenant_FullMethodName, "admin.createTenant"},
	{"get tenant", adminv1.AdminService_GetTenant_FullMethodName, "admin.getTenant"},
	{"update tenant", adminv1.AdminService_UpdateTenant_FullMethodName, "admin.updateTenant"},
	{"delete tenant", adminv1.AdminService_DeleteTenant_FullMethodName, "admin.deleteTenant"},
	{"list tenants", adminv1.AdminService_ListTenants_FullMethodName, "admin.listTenants"},

	{"create EAB", adminv1.AdminService_CreateEAB_FullMethodName, "admin.createEAB"},
	{"get EAB", adminv1.AdminService_GetEAB_FullMethodName, "admin.getEAB"},
	{"delete EAB", adminv1.AdminService_DeleteEAB_FullMethodName, "admin.deleteEAB"},
	{"list EABs", adminv1.AdminService_ListEABs_FullMethodName, "admin.listEABs"},

	{"create role", adminv1.AdminService_CreateTenantRole_FullMethodName, "admin.createRole"},
	{"get role", adminv1.AdminService_GetTenantRole_FullMethodName, "admin.getRole"},
	{"update role", adminv1.AdminService_UpdateTenantRole_FullMethodName, "admin.updateRole"},
	{"delete role", adminv1.AdminService_DeleteTenantRole_FullMethodName, "admin.deleteRole"},
	{"list roles", adminv1.AdminService_ListTenantRoles_FullMethodName, "admin.listRoles"},

	{"create user", adminv1.AdminService_CreateTenantUser_FullMethodName, "admin.createUser"},
	{"get user", adminv1.AdminService_GetTenantUser_FullMethodName, "admin.getUser"},
	{"update user", adminv1.AdminService_UpdateTenantUser_FullMethodName, "admin.updateUser"},
	{"delete user", adminv1.AdminService_DeleteTenantUser_FullMethodName, "admin.deleteUser"},
	{"list users", adminv1.AdminService_ListTenantUsers_FullMethodName, "admin.listUsers"},

	{"list accounts", adminv1.AdminService_ListAccounts_FullMethodName, "admin.listAccounts"},
	{"get account", adminv1.AdminService_GetAccount_FullMethodName, "admin.getAccount"},
	{"disable account", adminv1.AdminService_DisableAccount_FullMethodName, "admin.disableAccount"},
}

// TestCrossSurface_SameOperationSamePermission verifies the gRPC and MCP tables
// agree on the grant every shared ACME admin operation requires.
func TestCrossSurface_SameOperationSamePermission(t *testing.T) {
	s, _ := newAuthzTestServer(t)
	mcpPerms := s.MCPToolPermissions()
	for _, tc := range crossSurfaceOperations {
		t.Run(tc.operation, func(t *testing.T) {
			grpcPerm, ok := adminRPCPermissions[tc.grpcMethod]
			require.True(t, ok, "gRPC method %s declares no permission", tc.grpcMethod)

			mcpPerm, ok := mcpPerms[tc.mcpMethod]
			require.True(t, ok, "MCP method %s has no permission", tc.mcpMethod)

			assert.Equal(t, grpcPerm, mcpPerm,
				"%s must require the same permission on gRPC (%s) and MCP (%s)",
				tc.operation, grpcPerm, mcpPerm)
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

	assertCanonical := func(surface, method string, perm qrdbsdk.Permission) {
		t.Helper()
		resource, action := qrdbsdk.PermissionResource(perm), qrdbsdk.PermissionAction(perm)
		assert.True(t, canonicalResources[resource],
			"%s method %s requests non-canonical resource %q", surface, method, resource)
		assert.True(t, canonicalActions[action],
			"%s method %s requests non-canonical action %q", surface, method, action)
	}

	for method, perm := range adminRPCPermissions {
		assertCanonical("gRPC", method, perm)
	}
	s, _ := newAuthzTestServer(t)
	for method, perm := range s.MCPToolPermissions() {
		assertCanonical("MCP", method, perm)
	}
}
