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

package rbac

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

func TestPermission_String(t *testing.T) {
	tests := []struct {
		name       string
		permission Permission
		want       string
	}{
		{
			name:       "basic permission",
			permission: Permission{Resource: "keys", Action: "read"},
			want:       "keys:read",
		},
		{
			name:       "wildcard resource",
			permission: Permission{Resource: "*", Action: "delete"},
			want:       "*:delete",
		},
		{
			name:       "wildcard action",
			permission: Permission{Resource: "secrets", Action: "*"},
			want:       "secrets:*",
		},
		{
			name:       "full wildcard",
			permission: Permission{Resource: "*", Action: "*"},
			want:       "*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.permission.String()
			if got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPermission_Matches(t *testing.T) {
	tests := []struct {
		name       string
		permission Permission
		other      Permission
		want       bool
	}{
		{
			name:       "exact match",
			permission: Permission{Resource: "keys", Action: "read"},
			other:      Permission{Resource: "keys", Action: "read"},
			want:       true,
		},
		{
			name:       "different resource",
			permission: Permission{Resource: "keys", Action: "read"},
			other:      Permission{Resource: "secrets", Action: "read"},
			want:       false,
		},
		{
			name:       "different action",
			permission: Permission{Resource: "keys", Action: "read"},
			other:      Permission{Resource: "keys", Action: "write"},
			want:       false,
		},
		{
			name:       "wildcard resource matches all",
			permission: Permission{Resource: "*", Action: "read"},
			other:      Permission{Resource: "keys", Action: "read"},
			want:       true,
		},
		{
			name:       "wildcard action matches all",
			permission: Permission{Resource: "keys", Action: "*"},
			other:      Permission{Resource: "keys", Action: "delete"},
			want:       true,
		},
		{
			name:       "full wildcard matches everything",
			permission: Permission{Resource: "*", Action: "*"},
			other:      Permission{Resource: "anything", Action: "everything"},
			want:       true,
		},
		{
			name:       "other has wildcard resource",
			permission: Permission{Resource: "keys", Action: "read"},
			other:      Permission{Resource: "*", Action: "read"},
			want:       true,
		},
		{
			name:       "other has wildcard action",
			permission: Permission{Resource: "keys", Action: "read"},
			other:      Permission{Resource: "keys", Action: "*"},
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.permission.Matches(tt.other)
			if got != tt.want {
				t.Errorf("Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRole_HasPermission(t *testing.T) {
	tests := []struct {
		name       string
		role       *Role
		permission Permission
		want       bool
	}{
		{
			name: "has permission",
			role: &Role{
				Name: "test",
				Permissions: []Permission{
					{Resource: "keys", Action: "read"},
					{Resource: "keys", Action: "write"},
				},
			},
			permission: Permission{Resource: "keys", Action: "read"},
			want:       true,
		},
		{
			name: "does not have permission",
			role: &Role{
				Name: "test",
				Permissions: []Permission{
					{Resource: "keys", Action: "read"},
				},
			},
			permission: Permission{Resource: "keys", Action: "write"},
			want:       false,
		},
		{
			name: "empty permissions",
			role: &Role{
				Name:        "test",
				Permissions: []Permission{},
			},
			permission: Permission{Resource: "keys", Action: "read"},
			want:       false,
		},
		{
			name: "wildcard permission",
			role: &Role{
				Name: "admin",
				Permissions: []Permission{
					{Resource: "*", Action: "*"},
				},
			},
			permission: Permission{Resource: "keys", Action: "delete"},
			want:       false, // HasPermission uses exact match, not wildcard match
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.role.HasPermission(tt.permission)
			if got != tt.want {
				t.Errorf("HasPermission() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewPermission(t *testing.T) {
	tests := []struct {
		name     string
		resource string
		action   string
		want     Permission
	}{
		{
			name:     "create permission",
			resource: "keys",
			action:   "read",
			want:     Permission{Resource: "keys", Action: "read"},
		},
		{
			name:     "wildcard permission",
			resource: "*",
			action:   "*",
			want:     Permission{Resource: "*", Action: "*"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewPermission(tt.resource, tt.action)
			if got.Resource != tt.want.Resource || got.Action != tt.want.Action {
				t.Errorf("NewPermission() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMemoryRBACAdapter_CreateRole(t *testing.T) {
	tests := []struct {
		name      string
		role      *Role
		wantError bool
	}{
		{
			name: "valid role",
			role: &Role{
				Name:        "custom",
				Description: "Custom role",
				Permissions: []Permission{
					{Resource: "keys", Action: "read"},
				},
			},
			wantError: false,
		},
		{
			name:      "nil role",
			role:      nil,
			wantError: true,
		},
		{
			name: "empty name",
			role: &Role{
				Name:        "",
				Description: "Invalid",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := NewMemoryRBACAdapter(false)
			ctx := context.Background()

			err := adapter.CreateRole(ctx, tt.role)

			if tt.wantError && err == nil {
				t.Error("CreateRole() expected error, got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("CreateRole() unexpected error: %v", err)
			}
		})
	}
}

func TestMemoryRBACAdapter_CreateRole_Duplicate(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	role := &Role{
		Name:        "test",
		Description: "Test role",
	}

	err := adapter.CreateRole(ctx, role)
	if err != nil {
		t.Fatalf("CreateRole() first call failed: %v", err)
	}

	err = adapter.CreateRole(ctx, role)
	if err == nil {
		t.Error("CreateRole() expected error for duplicate role, got nil")
	}
}

func TestMemoryRBACAdapter_GetRole(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	role := &Role{
		Name:        "test",
		Description: "Test role",
		Permissions: []Permission{
			{Resource: "keys", Action: "read"},
		},
		Metadata: map[string]interface{}{
			"key": "value",
		},
	}

	err := adapter.CreateRole(ctx, role)
	if err != nil {
		t.Fatalf("CreateRole() failed: %v", err)
	}

	got, err := adapter.GetRole(ctx, "test")
	if err != nil {
		t.Fatalf("GetRole() error: %v", err)
	}

	if got.Name != role.Name {
		t.Errorf("GetRole() Name = %v, want %v", got.Name, role.Name)
	}
	if got.Description != role.Description {
		t.Errorf("GetRole() Description = %v, want %v", got.Description, role.Description)
	}
	if len(got.Permissions) != len(role.Permissions) {
		t.Errorf("GetRole() Permissions length = %v, want %v", len(got.Permissions), len(role.Permissions))
	}
}

func TestMemoryRBACAdapter_GetRole_NotFound(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	_, err := adapter.GetRole(ctx, "nonexistent")
	if err == nil {
		t.Error("GetRole() expected error for nonexistent role, got nil")
	}
}

func TestMemoryRBACAdapter_UpdateRole(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	role := &Role{
		Name:        "test",
		Description: "Original",
		Permissions: []Permission{
			{Resource: "keys", Action: "read"},
		},
	}

	err := adapter.CreateRole(ctx, role)
	if err != nil {
		t.Fatalf("CreateRole() failed: %v", err)
	}

	updatedRole := &Role{
		Name:        "test",
		Description: "Updated",
		Permissions: []Permission{
			{Resource: "keys", Action: "write"},
		},
	}

	err = adapter.UpdateRole(ctx, updatedRole)
	if err != nil {
		t.Fatalf("UpdateRole() error: %v", err)
	}

	got, err := adapter.GetRole(ctx, "test")
	if err != nil {
		t.Fatalf("GetRole() error: %v", err)
	}

	if got.Description != "Updated" {
		t.Errorf("UpdateRole() Description = %v, want Updated", got.Description)
	}
}

func TestMemoryRBACAdapter_UpdateRole_NotFound(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	role := &Role{
		Name: "nonexistent",
	}

	err := adapter.UpdateRole(ctx, role)
	if err == nil {
		t.Error("UpdateRole() expected error for nonexistent role, got nil")
	}
}

func TestMemoryRBACAdapter_UpdateRole_SystemRole(t *testing.T) {
	adapter := NewMemoryRBACAdapter(true)
	ctx := context.Background()

	role := &Role{
		Name:        RoleAdmin,
		Description: "Modified",
	}

	err := adapter.UpdateRole(ctx, role)
	if err == nil {
		t.Error("UpdateRole() expected error for system role, got nil")
	}
}

func TestMemoryRBACAdapter_DeleteRole(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	role := &Role{
		Name: "test",
	}

	err := adapter.CreateRole(ctx, role)
	if err != nil {
		t.Fatalf("CreateRole() failed: %v", err)
	}

	err = adapter.DeleteRole(ctx, "test")
	if err != nil {
		t.Fatalf("DeleteRole() error: %v", err)
	}

	_, err = adapter.GetRole(ctx, "test")
	if err == nil {
		t.Error("GetRole() expected error after delete, got nil")
	}
}

func TestMemoryRBACAdapter_DeleteRole_NotFound(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	err := adapter.DeleteRole(ctx, "nonexistent")
	if err == nil {
		t.Error("DeleteRole() expected error for nonexistent role, got nil")
	}
}

func TestMemoryRBACAdapter_DeleteRole_SystemRole(t *testing.T) {
	adapter := NewMemoryRBACAdapter(true)
	ctx := context.Background()

	err := adapter.DeleteRole(ctx, RoleAdmin)
	if err == nil {
		t.Error("DeleteRole() expected error for system role, got nil")
	}
}

func TestMemoryRBACAdapter_DeleteRole_AssignedToUser(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	role := &Role{
		Name: "test",
	}

	err := adapter.CreateRole(ctx, role)
	if err != nil {
		t.Fatalf("CreateRole() failed: %v", err)
	}

	err = adapter.AssignRole(ctx, "user1", "test")
	if err != nil {
		t.Fatalf("AssignRole() failed: %v", err)
	}

	err = adapter.DeleteRole(ctx, "test")
	if err == nil {
		t.Error("DeleteRole() expected error for role assigned to user, got nil")
	}
}

func TestMemoryRBACAdapter_ListRoles(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	role1 := &Role{Name: "role1"}
	role2 := &Role{Name: "role2"}

	err := adapter.CreateRole(ctx, role1)
	if err != nil {
		t.Fatalf("CreateRole() role1 failed: %v", err)
	}

	err = adapter.CreateRole(ctx, role2)
	if err != nil {
		t.Fatalf("CreateRole() role2 failed: %v", err)
	}

	roles, err := adapter.ListRoles(ctx)
	if err != nil {
		t.Fatalf("ListRoles() error: %v", err)
	}

	if len(roles) != 2 {
		t.Errorf("ListRoles() length = %v, want 2", len(roles))
	}
}

func TestMemoryRBACAdapter_ListRoles_Empty(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	roles, err := adapter.ListRoles(ctx)
	if err != nil {
		t.Fatalf("ListRoles() error: %v", err)
	}

	if len(roles) != 0 {
		t.Errorf("ListRoles() length = %v, want 0", len(roles))
	}
}

func TestMemoryRBACAdapter_AssignRole(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	role := &Role{Name: "test"}
	err := adapter.CreateRole(ctx, role)
	if err != nil {
		t.Fatalf("CreateRole() failed: %v", err)
	}

	err = adapter.AssignRole(ctx, "user1", "test")
	if err != nil {
		t.Fatalf("AssignRole() error: %v", err)
	}

	roles, err := adapter.GetUserRoles(ctx, "user1")
	if err != nil {
		t.Fatalf("GetUserRoles() error: %v", err)
	}

	if len(roles) != 1 || roles[0] != "test" {
		t.Errorf("GetUserRoles() = %v, want [test]", roles)
	}
}

func TestMemoryRBACAdapter_AssignRole_NonexistentRole(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	err := adapter.AssignRole(ctx, "user1", "nonexistent")
	if err == nil {
		t.Error("AssignRole() expected error for nonexistent role, got nil")
	}
}

func TestMemoryRBACAdapter_RevokeRole(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	role := &Role{Name: "test"}
	err := adapter.CreateRole(ctx, role)
	if err != nil {
		t.Fatalf("CreateRole() failed: %v", err)
	}

	err = adapter.AssignRole(ctx, "user1", "test")
	if err != nil {
		t.Fatalf("AssignRole() failed: %v", err)
	}

	err = adapter.RevokeRole(ctx, "user1", "test")
	if err != nil {
		t.Fatalf("RevokeRole() error: %v", err)
	}

	roles, err := adapter.GetUserRoles(ctx, "user1")
	if err != nil {
		t.Fatalf("GetUserRoles() error: %v", err)
	}

	if len(roles) != 0 {
		t.Errorf("GetUserRoles() = %v, want []", roles)
	}
}

func TestMemoryRBACAdapter_RevokeRole_NotAssigned(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	role := &Role{Name: "test"}
	err := adapter.CreateRole(ctx, role)
	if err != nil {
		t.Fatalf("CreateRole() failed: %v", err)
	}

	err = adapter.RevokeRole(ctx, "user1", "test")
	if err == nil {
		t.Error("RevokeRole() expected error for role not assigned, got nil")
	}
}

func TestMemoryRBACAdapter_GetUserRoles_NoRoles(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	roles, err := adapter.GetUserRoles(ctx, "user1")
	if err != nil {
		t.Fatalf("GetUserRoles() error: %v", err)
	}

	if len(roles) != 0 {
		t.Errorf("GetUserRoles() = %v, want []", roles)
	}
}

func TestMemoryRBACAdapter_CheckPermission(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	role := &Role{
		Name: "test",
		Permissions: []Permission{
			{Resource: "keys", Action: "read"},
			{Resource: "keys", Action: "write"},
		},
	}

	err := adapter.CreateRole(ctx, role)
	if err != nil {
		t.Fatalf("CreateRole() failed: %v", err)
	}

	err = adapter.AssignRole(ctx, "user1", "test")
	if err != nil {
		t.Fatalf("AssignRole() failed: %v", err)
	}

	tests := []struct {
		name       string
		permission Permission
		want       bool
	}{
		{
			name:       "has permission",
			permission: Permission{Resource: "keys", Action: "read"},
			want:       true,
		},
		{
			name:       "does not have permission",
			permission: Permission{Resource: "secrets", Action: "read"},
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := adapter.CheckPermission(ctx, "user1", tt.permission)
			if err != nil {
				t.Fatalf("CheckPermission() error: %v", err)
			}
			if got != tt.want {
				t.Errorf("CheckPermission() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMemoryRBACAdapter_CheckPermission_NoRoles(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	perm := Permission{Resource: "keys", Action: "read"}
	got, err := adapter.CheckPermission(ctx, "user1", perm)
	if err != nil {
		t.Fatalf("CheckPermission() error: %v", err)
	}

	if got {
		t.Error("CheckPermission() = true, want false for user with no roles")
	}
}

func TestMemoryRBACAdapter_CheckPermission_Wildcard(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	role := &Role{
		Name: "admin",
		Permissions: []Permission{
			{Resource: "*", Action: "*"},
		},
	}

	err := adapter.CreateRole(ctx, role)
	if err != nil {
		t.Fatalf("CreateRole() failed: %v", err)
	}

	err = adapter.AssignRole(ctx, "admin1", "admin")
	if err != nil {
		t.Fatalf("AssignRole() failed: %v", err)
	}

	perm := Permission{Resource: "anything", Action: "everything"}
	got, err := adapter.CheckPermission(ctx, "admin1", perm)
	if err != nil {
		t.Fatalf("CheckPermission() error: %v", err)
	}

	if !got {
		t.Error("CheckPermission() = false, want true for wildcard permission")
	}
}

func TestMemoryRBACAdapter_ListPermissions(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	role1 := &Role{
		Name: "role1",
		Permissions: []Permission{
			{Resource: "keys", Action: "read"},
			{Resource: "keys", Action: "write"},
		},
	}

	role2 := &Role{
		Name: "role2",
		Permissions: []Permission{
			{Resource: "secrets", Action: "read"},
		},
	}

	err := adapter.CreateRole(ctx, role1)
	if err != nil {
		t.Fatalf("CreateRole() role1 failed: %v", err)
	}

	err = adapter.CreateRole(ctx, role2)
	if err != nil {
		t.Fatalf("CreateRole() role2 failed: %v", err)
	}

	err = adapter.AssignRole(ctx, "user1", "role1")
	if err != nil {
		t.Fatalf("AssignRole() role1 failed: %v", err)
	}

	err = adapter.AssignRole(ctx, "user1", "role2")
	if err != nil {
		t.Fatalf("AssignRole() role2 failed: %v", err)
	}

	perms, err := adapter.ListPermissions(ctx, "user1")
	if err != nil {
		t.Fatalf("ListPermissions() error: %v", err)
	}

	if len(perms) != 3 {
		t.Errorf("ListPermissions() length = %v, want 3", len(perms))
	}
}

func TestMemoryRBACAdapter_ListPermissions_NoRoles(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	perms, err := adapter.ListPermissions(ctx, "user1")
	if err != nil {
		t.Fatalf("ListPermissions() error: %v", err)
	}

	if len(perms) != 0 {
		t.Errorf("ListPermissions() length = %v, want 0", len(perms))
	}
}

func TestMemoryRBACAdapter_GrantPermission(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	role := &Role{
		Name:        "test",
		Permissions: []Permission{},
	}

	err := adapter.CreateRole(ctx, role)
	if err != nil {
		t.Fatalf("CreateRole() failed: %v", err)
	}

	perm := Permission{Resource: "keys", Action: "read"}
	err = adapter.GrantPermission(ctx, "test", perm)
	if err != nil {
		t.Fatalf("GrantPermission() error: %v", err)
	}

	got, err := adapter.GetRole(ctx, "test")
	if err != nil {
		t.Fatalf("GetRole() error: %v", err)
	}

	if len(got.Permissions) != 1 {
		t.Errorf("Permissions length = %v, want 1", len(got.Permissions))
	}
}

func TestMemoryRBACAdapter_GrantPermission_Duplicate(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	role := &Role{
		Name: "test",
		Permissions: []Permission{
			{Resource: "keys", Action: "read"},
		},
	}

	err := adapter.CreateRole(ctx, role)
	if err != nil {
		t.Fatalf("CreateRole() failed: %v", err)
	}

	perm := Permission{Resource: "keys", Action: "read"}
	err = adapter.GrantPermission(ctx, "test", perm)
	if err == nil {
		t.Error("GrantPermission() expected error for duplicate permission, got nil")
	}
}

func TestMemoryRBACAdapter_GrantPermission_SystemRole(t *testing.T) {
	adapter := NewMemoryRBACAdapter(true)
	ctx := context.Background()

	perm := Permission{Resource: "keys", Action: "read"}
	err := adapter.GrantPermission(ctx, RoleAdmin, perm)
	if err == nil {
		t.Error("GrantPermission() expected error for system role, got nil")
	}
}

func TestMemoryRBACAdapter_RevokePermission(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	role := &Role{
		Name: "test",
		Permissions: []Permission{
			{Resource: "keys", Action: "read"},
		},
	}

	err := adapter.CreateRole(ctx, role)
	if err != nil {
		t.Fatalf("CreateRole() failed: %v", err)
	}

	perm := Permission{Resource: "keys", Action: "read"}
	err = adapter.RevokePermission(ctx, "test", perm)
	if err != nil {
		t.Fatalf("RevokePermission() error: %v", err)
	}

	got, err := adapter.GetRole(ctx, "test")
	if err != nil {
		t.Fatalf("GetRole() error: %v", err)
	}

	if len(got.Permissions) != 0 {
		t.Errorf("Permissions length = %v, want 0", len(got.Permissions))
	}
}

func TestMemoryRBACAdapter_RevokePermission_NotFound(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	role := &Role{
		Name:        "test",
		Permissions: []Permission{},
	}

	err := adapter.CreateRole(ctx, role)
	if err != nil {
		t.Fatalf("CreateRole() failed: %v", err)
	}

	perm := Permission{Resource: "keys", Action: "read"}
	err = adapter.RevokePermission(ctx, "test", perm)
	if err == nil {
		t.Error("RevokePermission() expected error for permission not found, got nil")
	}
}

func TestMemoryRBACAdapter_RevokePermission_SystemRole(t *testing.T) {
	adapter := NewMemoryRBACAdapter(true)
	ctx := context.Background()

	perm := Permission{Resource: "keys", Action: "read"}
	err := adapter.RevokePermission(ctx, RoleAdmin, perm)
	if err == nil {
		t.Error("RevokePermission() expected error for system role, got nil")
	}
}

func TestMemoryRBACAdapter_DefaultRoles(t *testing.T) {
	adapter := NewMemoryRBACAdapter(true)
	ctx := context.Background()

	expectedRoles := []string{
		RoleAdmin,
		RoleOperator,
		RoleAuditor,
		RoleUser,
		RoleReadOnly,
		RoleGuest,
	}

	for _, roleName := range expectedRoles {
		role, err := adapter.GetRole(ctx, roleName)
		if err != nil {
			t.Errorf("GetRole(%s) error: %v", roleName, err)
			continue
		}

		if role.Name != roleName {
			t.Errorf("Role name = %v, want %v", role.Name, roleName)
		}

		if len(role.Permissions) == 0 {
			t.Errorf("Role %s has no permissions", roleName)
		}

		if isSystem, ok := role.Metadata["system"].(bool); !ok || !isSystem {
			t.Errorf("Role %s should be marked as system role", roleName)
		}
	}
}

func TestMemoryRBACAdapter_ThreadSafety(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	role := &Role{
		Name: "test",
		Permissions: []Permission{
			{Resource: "keys", Action: "read"},
		},
	}

	err := adapter.CreateRole(ctx, role)
	if err != nil {
		t.Fatalf("CreateRole() failed: %v", err)
	}

	var wg sync.WaitGroup
	numGoroutines := 100

	// Test concurrent role assignments
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			subject := fmt.Sprintf("user%d", id)
			err := adapter.AssignRole(ctx, subject, "test")
			if err != nil {
				t.Errorf("AssignRole() error: %v", err)
			}
		}(i)
	}
	wg.Wait()

	// Test concurrent permission checks
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			subject := fmt.Sprintf("user%d", id)
			perm := Permission{Resource: "keys", Action: "read"}
			_, err := adapter.CheckPermission(ctx, subject, perm)
			if err != nil {
				t.Errorf("CheckPermission() error: %v", err)
			}
		}(i)
	}
	wg.Wait()

	// Test concurrent role listing
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			_, err := adapter.ListRoles(ctx)
			if err != nil {
				t.Errorf("ListRoles() error: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestMemoryRBACAdapter_MultipleRolesPermissionCheck(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	role1 := &Role{
		Name: "role1",
		Permissions: []Permission{
			{Resource: "keys", Action: "read"},
		},
	}

	role2 := &Role{
		Name: "role2",
		Permissions: []Permission{
			{Resource: "keys", Action: "write"},
		},
	}

	err := adapter.CreateRole(ctx, role1)
	if err != nil {
		t.Fatalf("CreateRole() role1 failed: %v", err)
	}

	err = adapter.CreateRole(ctx, role2)
	if err != nil {
		t.Fatalf("CreateRole() role2 failed: %v", err)
	}

	err = adapter.AssignRole(ctx, "user1", "role1")
	if err != nil {
		t.Fatalf("AssignRole() role1 failed: %v", err)
	}

	err = adapter.AssignRole(ctx, "user1", "role2")
	if err != nil {
		t.Fatalf("AssignRole() role2 failed: %v", err)
	}

	// User should have both read and write permissions
	readPerm := Permission{Resource: "keys", Action: "read"}
	writePerm := Permission{Resource: "keys", Action: "write"}

	hasRead, err := adapter.CheckPermission(ctx, "user1", readPerm)
	if err != nil {
		t.Fatalf("CheckPermission() read error: %v", err)
	}
	if !hasRead {
		t.Error("User should have read permission from role1")
	}

	hasWrite, err := adapter.CheckPermission(ctx, "user1", writePerm)
	if err != nil {
		t.Fatalf("CheckPermission() write error: %v", err)
	}
	if !hasWrite {
		t.Error("User should have write permission from role2")
	}
}

func TestMemoryRBACAdapter_IsolationBetweenInstances(t *testing.T) {
	adapter1 := NewMemoryRBACAdapter(false)
	adapter2 := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	role := &Role{
		Name: "test",
	}

	err := adapter1.CreateRole(ctx, role)
	if err != nil {
		t.Fatalf("adapter1.CreateRole() failed: %v", err)
	}

	_, err = adapter2.GetRole(ctx, "test")
	if err == nil {
		t.Error("adapter2.GetRole() should fail for role created in adapter1")
	}
}
