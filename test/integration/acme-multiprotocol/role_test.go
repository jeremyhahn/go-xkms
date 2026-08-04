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

//go:build integration

package multiprotocol

import (
	"context"
	"testing"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/acme/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRoleLifecycleMultiProtocol tests role CRUD operations across all protocols.
func TestRoleLifecycleMultiProtocol(t *testing.T) {
	tc := NewTestContext(t)
	defer tc.Cleanup()

	ctx := context.Background()

	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		testRoleLifecycle(t, ctx, adapter)
	})
}

func testRoleLifecycle(t *testing.T, ctx context.Context, adapter api.AdminAdapter) {
	t.Helper()

	protocol := adapter.Protocol()
	tenantID := "role-test-tenant-" + string(protocol)
	roleName := "test-role-" + string(protocol)

	// Create tenant first
	_, err := adapter.CreateTenant(ctx, &admin.CreateTenantRequest{
		ID:   tenantID,
		Name: "Role Test Tenant (" + string(protocol) + ")",
	})
	require.NoError(t, err)
	defer func() { _ = adapter.DeleteTenant(ctx, tenantID) }()

	// Create role
	role, err := adapter.CreateTenantRole(ctx, tenantID, &db.CreateRoleRequest{
		Name: roleName,
		Permissions: []string{
			"certificates:read",
			"certificates:list",
		},
	})
	require.NoError(t, err, "CreateTenantRole should succeed via %s", protocol)
	assert.Equal(t, roleName, role.Name)
	assert.Equal(t, tenantID, role.TenantID)
	assert.Len(t, role.Permissions, 2)
	assert.NotEmpty(t, role.ID)
	defer func() { _ = adapter.DeleteTenantRole(ctx, tenantID, role.ID) }()

	// Get role
	retrieved, err := adapter.GetTenantRole(ctx, tenantID, role.ID)
	require.NoError(t, err, "GetTenantRole should succeed via %s", protocol)
	assert.Equal(t, roleName, retrieved.Name)
	assert.Equal(t, role.ID, retrieved.ID)
	assert.Len(t, retrieved.Permissions, 2)

	// Update role
	updatedName := "updated-role-" + string(protocol)
	updated, err := adapter.UpdateTenantRole(ctx, tenantID, &db.UpdateRoleRequest{
		ID:   role.ID,
		Name: updatedName,
		Permissions: []string{
			"certificates:read",
			"certificates:list",
			"accounts:read",
		},
	})
	require.NoError(t, err, "UpdateTenantRole should succeed via %s", protocol)
	assert.Equal(t, updatedName, updated.Name)
	assert.Len(t, updated.Permissions, 3)

	// List roles
	listResp, err := adapter.ListTenantRoles(ctx, tenantID, &db.ListRolesRequest{
		TenantID: tenantID,
		PageSize: 10,
	})
	require.NoError(t, err, "ListTenantRoles should succeed via %s", protocol)
	require.NotNil(t, listResp)
	assert.NotEmpty(t, listResp.Roles)

	// Verify our role is in the list
	found := false
	for _, r := range listResp.Roles {
		if r.ID == role.ID {
			found = true
			break
		}
	}
	assert.True(t, found, "Created role should be in the list via %s", protocol)

	// Delete role
	err = adapter.DeleteTenantRole(ctx, tenantID, role.ID)
	require.NoError(t, err, "DeleteTenantRole should succeed via %s", protocol)

	// Verify deletion
	_, err = adapter.GetTenantRole(ctx, tenantID, role.ID)
	assert.Error(t, err, "GetTenantRole should fail after deletion via %s", protocol)
}

// TestRoleWithPermissionsMultiProtocol tests roles with various permission sets.
func TestRoleWithPermissionsMultiProtocol(t *testing.T) {
	tc := NewTestContext(t)
	defer tc.Cleanup()

	ctx := context.Background()

	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		testRoleWithPermissions(t, ctx, adapter)
	})
}

func testRoleWithPermissions(t *testing.T, ctx context.Context, adapter api.AdminAdapter) {
	t.Helper()

	protocol := adapter.Protocol()
	tenantID := "perms-role-tenant-" + string(protocol)

	// Create tenant first
	_, err := adapter.CreateTenant(ctx, &admin.CreateTenantRequest{
		ID:   tenantID,
		Name: "Permissions Role Test Tenant",
	})
	require.NoError(t, err)
	defer func() { _ = adapter.DeleteTenant(ctx, tenantID) }()

	// Create an admin role with broad permissions
	adminRole, err := adapter.CreateTenantRole(ctx, tenantID, &db.CreateRoleRequest{
		Name: "admin-role-" + string(protocol),
		Permissions: []string{
			"certificates:read",
			"certificates:write",
			"certificates:delete",
			"accounts:read",
			"accounts:write",
			"accounts:delete",
			"tenants:read",
			"tenants:write",
		},
	})
	require.NoError(t, err, "CreateTenantRole with broad permissions should succeed via %s", protocol)
	assert.Len(t, adminRole.Permissions, 8)
	defer func() { _ = adapter.DeleteTenantRole(ctx, tenantID, adminRole.ID) }()

	// Verify the role was created correctly
	retrieved, err := adapter.GetTenantRole(ctx, tenantID, adminRole.ID)
	require.NoError(t, err)
	assert.Equal(t, "admin-role-"+string(protocol), retrieved.Name)
	assert.Len(t, retrieved.Permissions, 8)

	// Create a read-only role with minimal permissions
	readOnlyRole, err := adapter.CreateTenantRole(ctx, tenantID, &db.CreateRoleRequest{
		Name: "readonly-role-" + string(protocol),
		Permissions: []string{
			"certificates:read",
			"accounts:read",
		},
	})
	require.NoError(t, err, "CreateTenantRole with minimal permissions should succeed via %s", protocol)
	assert.Len(t, readOnlyRole.Permissions, 2)
	defer func() { _ = adapter.DeleteTenantRole(ctx, tenantID, readOnlyRole.ID) }()

	// Verify read-only role
	retrievedRO, err := adapter.GetTenantRole(ctx, tenantID, readOnlyRole.ID)
	require.NoError(t, err)
	assert.Equal(t, "readonly-role-"+string(protocol), retrievedRO.Name)
	assert.Len(t, retrievedRO.Permissions, 2)
}

// TestMultipleRolesMultiProtocol tests creating and listing multiple roles.
func TestMultipleRolesMultiProtocol(t *testing.T) {
	tc := NewTestContext(t)
	defer tc.Cleanup()

	ctx := context.Background()

	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		testMultipleRoles(t, ctx, adapter)
	})
}

func testMultipleRoles(t *testing.T, ctx context.Context, adapter api.AdminAdapter) {
	t.Helper()

	protocol := adapter.Protocol()
	tenantID := "multi-role-tenant-" + string(protocol)

	// Create tenant first
	_, err := adapter.CreateTenant(ctx, &admin.CreateTenantRequest{
		ID:   tenantID,
		Name: "Multi-Role Test Tenant",
	})
	require.NoError(t, err)
	defer func() { _ = adapter.DeleteTenant(ctx, tenantID) }()

	// Create multiple roles
	roleNames := []string{
		"read-only-role-" + string(protocol),
		"admin-role-" + string(protocol),
		"audit-role-" + string(protocol),
	}

	roleIDs := make([]string, len(roleNames))
	for i, name := range roleNames {
		role, err := adapter.CreateTenantRole(ctx, tenantID, &db.CreateRoleRequest{
			Name:        name,
			Permissions: []string{"certificates:read"},
		})
		require.NoError(t, err, "CreateTenantRole for %s should succeed via %s", name, protocol)
		roleIDs[i] = role.ID
	}

	// List all roles
	listResp, err := adapter.ListTenantRoles(ctx, tenantID, &db.ListRolesRequest{
		TenantID: tenantID,
		PageSize: 100,
	})
	require.NoError(t, err, "ListTenantRoles should succeed via %s", protocol)
	require.NotNil(t, listResp)

	// Verify all roles exist
	foundCount := 0
	for _, r := range listResp.Roles {
		for _, id := range roleIDs {
			if r.ID == id {
				foundCount++
				break
			}
		}
	}
	assert.Equal(t, len(roleNames), foundCount, "All created roles should be found via %s", protocol)

	// Clean up
	for _, id := range roleIDs {
		err := adapter.DeleteTenantRole(ctx, tenantID, id)
		assert.NoError(t, err, "DeleteTenantRole for %s should succeed via %s", id, protocol)
	}
}
