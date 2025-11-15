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

	"github.com/jeremyhahn/go-keychain/pkg/adapters/rbac"
)

func ExampleMemoryRBACAdapter_basic() {
	ctx := context.Background()

	// Create adapter with default roles
	adapter := rbac.NewMemoryRBACAdapter(true)

	// Assign admin role to a user
	err := adapter.AssignRole(ctx, "alice", rbac.RoleAdmin)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Check if user has permission
	perm := rbac.NewPermission(rbac.ResourceKeys, rbac.ActionRead)
	hasPermission, err := adapter.CheckPermission(ctx, "alice", perm)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Alice has read permission on keys: %v\n", hasPermission)
	// Output: Alice has read permission on keys: true
}

func ExampleMemoryRBACAdapter_customRole() {
	ctx := context.Background()

	// Create adapter without defaults
	adapter := rbac.NewMemoryRBACAdapter(false)

	// Create a custom role
	developerRole := &rbac.Role{
		Name:        "developer",
		Description: "Developer role with key management permissions",
		Permissions: []rbac.Permission{
			{Resource: rbac.ResourceKeys, Action: rbac.ActionCreate},
			{Resource: rbac.ResourceKeys, Action: rbac.ActionRead},
			{Resource: rbac.ResourceKeys, Action: rbac.ActionList},
			{Resource: rbac.ResourceCertificates, Action: rbac.ActionRead},
		},
		Metadata: map[string]interface{}{
			"department": "engineering",
		},
	}

	err := adapter.CreateRole(ctx, developerRole)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Assign role to user
	err = adapter.AssignRole(ctx, "bob", "developer")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Check permissions
	createPerm := rbac.NewPermission(rbac.ResourceKeys, rbac.ActionCreate)
	deletePerm := rbac.NewPermission(rbac.ResourceKeys, rbac.ActionDelete)

	canCreate, _ := adapter.CheckPermission(ctx, "bob", createPerm)
	canDelete, _ := adapter.CheckPermission(ctx, "bob", deletePerm)

	fmt.Printf("Bob can create keys: %v\n", canCreate)
	fmt.Printf("Bob can delete keys: %v\n", canDelete)
	// Output:
	// Bob can create keys: true
	// Bob can delete keys: false
}

func ExampleMemoryRBACAdapter_multipleRoles() {
	ctx := context.Background()

	// Create adapter with defaults
	adapter := rbac.NewMemoryRBACAdapter(true)

	// Assign multiple roles
	adapter.AssignRole(ctx, "charlie", rbac.RoleUser)
	adapter.AssignRole(ctx, "charlie", rbac.RoleAuditor)

	// List user's permissions
	perms, err := adapter.ListPermissions(ctx, "charlie")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Charlie has %d permissions from multiple roles\n", len(perms))
	// Output: Charlie has 10 permissions from multiple roles
}

func ExampleMemoryRBACAdapter_wildcardPermissions() {
	ctx := context.Background()

	adapter := rbac.NewMemoryRBACAdapter(false)

	// Create role with wildcard permissions
	superAdminRole := &rbac.Role{
		Name:        "superadmin",
		Description: "Super administrator with full access",
		Permissions: []rbac.Permission{
			{Resource: rbac.ActionAll, Action: rbac.ActionAll},
		},
	}

	adapter.CreateRole(ctx, superAdminRole)
	adapter.AssignRole(ctx, "admin", "superadmin")

	// Check any permission
	anyPerm := rbac.NewPermission("custom-resource", "custom-action")
	hasPermission, _ := adapter.CheckPermission(ctx, "admin", anyPerm)

	fmt.Printf("Super admin has custom permission: %v\n", hasPermission)
	// Output: Super admin has custom permission: true
}
