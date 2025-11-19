// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package rbac_test

import (
	"context"
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/adapters/auth"
	"github.com/jeremyhahn/go-keychain/pkg/adapters/rbac"
)

// This example demonstrates how RBAC integrates with the existing auth system
func Example_rbacWithAuth() {
	ctx := context.Background()

	// Create RBAC adapter with default roles
	rbacAdapter := rbac.NewMemoryRBACAdapter(true)

	// Assign operator role to a user
	_ = rbacAdapter.AssignRole(ctx, "operations-team", rbac.RoleOperator)

	// Create an auth identity (simulating authenticated user)
	identity := &auth.Identity{
		Subject: "operations-team",
		Claims: map[string]interface{}{
			"email": "ops@example.com",
		},
		Attributes: map[string]string{
			"auth_method": "apikey",
		},
	}

	// Check if the authenticated user has permission to create keys
	createKeyPerm := rbac.NewPermission(rbac.ResourceKeys, rbac.ActionCreate)
	canCreateKeys, _ := rbacAdapter.CheckPermission(ctx, identity.Subject, createKeyPerm)

	// Check if the authenticated user has permission to manage users
	manageUsersPerm := rbac.NewPermission(rbac.ResourceUsers, rbac.ActionManage)
	canManageUsers, _ := rbacAdapter.CheckPermission(ctx, identity.Subject, manageUsersPerm)

	fmt.Printf("Subject '%s' can create keys: %v\n", identity.Subject, canCreateKeys)
	fmt.Printf("Subject '%s' can manage users: %v\n", identity.Subject, canManageUsers)

	// Output:
	// Subject 'operations-team' can create keys: true
	// Subject 'operations-team' can manage users: false
}

// This example shows multi-tenant access control
func Example_multiTenantRBAC() {
	ctx := context.Background()

	rbacAdapter := rbac.NewMemoryRBACAdapter(false)

	// Create tenant-specific roles
	tenantAAdminRole := &rbac.Role{
		Name:        "tenant-a-admin",
		Description: "Administrator for Tenant A",
		Permissions: []rbac.Permission{
			{Resource: "tenant-a:keys", Action: rbac.ActionAll},
			{Resource: "tenant-a:secrets", Action: rbac.ActionAll},
		},
		Metadata: map[string]interface{}{
			"tenant": "tenant-a",
		},
	}

	tenantBUserRole := &rbac.Role{
		Name:        "tenant-b-user",
		Description: "User for Tenant B",
		Permissions: []rbac.Permission{
			{Resource: "tenant-b:keys", Action: rbac.ActionRead},
			{Resource: "tenant-b:secrets", Action: rbac.ActionRead},
		},
		Metadata: map[string]interface{}{
			"tenant": "tenant-b",
		},
	}

	_ = rbacAdapter.CreateRole(ctx, tenantAAdminRole)
	_ = rbacAdapter.CreateRole(ctx, tenantBUserRole)

	// Assign roles to users
	_ = rbacAdapter.AssignRole(ctx, "alice@tenant-a.com", "tenant-a-admin")
	_ = rbacAdapter.AssignRole(ctx, "bob@tenant-b.com", "tenant-b-user")

	// Check tenant isolation
	aliceTenantAPerm := rbac.NewPermission("tenant-a:keys", rbac.ActionCreate)
	aliceTenantBPerm := rbac.NewPermission("tenant-b:keys", rbac.ActionCreate)

	aliceCanAccessTenantA, _ := rbacAdapter.CheckPermission(ctx, "alice@tenant-a.com", aliceTenantAPerm)
	aliceCanAccessTenantB, _ := rbacAdapter.CheckPermission(ctx, "alice@tenant-a.com", aliceTenantBPerm)

	fmt.Printf("Alice can access Tenant A: %v\n", aliceCanAccessTenantA)
	fmt.Printf("Alice can access Tenant B: %v\n", aliceCanAccessTenantB)

	// Output:
	// Alice can access Tenant A: true
	// Alice can access Tenant B: false
}

// This example demonstrates dynamic permission management
func Example_dynamicPermissionManagement() {
	ctx := context.Background()

	rbacAdapter := rbac.NewMemoryRBACAdapter(false)

	// Create a base role
	baseRole := &rbac.Role{
		Name:        "api-consumer",
		Description: "API consumer with basic permissions",
		Permissions: []rbac.Permission{
			{Resource: rbac.ResourceKeys, Action: rbac.ActionRead},
		},
	}

	_ = rbacAdapter.CreateRole(ctx, baseRole)
	_ = rbacAdapter.AssignRole(ctx, "service-account", "api-consumer")

	// Check initial permissions
	updatePerm := rbac.NewPermission(rbac.ResourceKeys, rbac.ActionUpdate)
	canUpdate, _ := rbacAdapter.CheckPermission(ctx, "service-account", updatePerm)
	fmt.Printf("Service account can update keys (before): %v\n", canUpdate)

	// Dynamically grant additional permission
	_ = rbacAdapter.GrantPermission(ctx, "api-consumer", updatePerm)

	// Check updated permissions
	canUpdate, _ = rbacAdapter.CheckPermission(ctx, "service-account", updatePerm)
	fmt.Printf("Service account can update keys (after): %v\n", canUpdate)

	// Output:
	// Service account can update keys (before): false
	// Service account can update keys (after): true
}
