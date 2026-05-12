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

package keyrbac_test

import (
	"context"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/keyrbac"
)

func ExampleMemoryRBACAdapter_basic() {
	ctx := context.Background()

	// Create adapter with default roles
	adapter := keyrbac.NewMemoryRBACAdapter(true)

	// Assign admin role to a user
	err := adapter.AssignRole(ctx, "alice", keyrbac.RoleAdmin)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Check if user has permission
	perm := keyrbac.NewPermission(keyrbac.ResourceKeys, keyrbac.ActionRead)
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
	adapter := keyrbac.NewMemoryRBACAdapter(false)

	// Create a custom role
	developerRole := &keyrbac.Role{
		Name:        "developer",
		Description: "Developer role with key management permissions",
		Permissions: []keyrbac.Permission{
			{Resource: keyrbac.ResourceKeys, Action: keyrbac.ActionCreate},
			{Resource: keyrbac.ResourceKeys, Action: keyrbac.ActionRead},
			{Resource: keyrbac.ResourceKeys, Action: keyrbac.ActionList},
			{Resource: keyrbac.ResourceCertificates, Action: keyrbac.ActionRead},
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
	createPerm := keyrbac.NewPermission(keyrbac.ResourceKeys, keyrbac.ActionCreate)
	deletePerm := keyrbac.NewPermission(keyrbac.ResourceKeys, keyrbac.ActionDelete)

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
	adapter := keyrbac.NewMemoryRBACAdapter(true)

	// Assign multiple roles
	_ = adapter.AssignRole(ctx, "charlie", keyrbac.RoleUser)
	_ = adapter.AssignRole(ctx, "charlie", keyrbac.RoleAuditor)

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

	adapter := keyrbac.NewMemoryRBACAdapter(false)

	// Create role with wildcard permissions
	wildcardRole := &keyrbac.Role{
		Name:        "wildcard-admin",
		Description: "Administrator with full access via wildcard permission",
		Permissions: []keyrbac.Permission{
			{Resource: keyrbac.ActionAll, Action: keyrbac.ActionAll},
		},
	}

	_ = adapter.CreateRole(ctx, wildcardRole)
	_ = adapter.AssignRole(ctx, "admin", "wildcard-admin")

	// Check any permission
	anyPerm := keyrbac.NewPermission("custom-resource", "custom-action")
	hasPermission, _ := adapter.CheckPermission(ctx, "admin", anyPerm)

	fmt.Printf("Wildcard admin has custom permission: %v\n", hasPermission)
	// Output: Wildcard admin has custom permission: true
}
