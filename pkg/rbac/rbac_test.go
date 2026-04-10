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

package rbac

import (
	"context"
	"errors"
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
		wantError error
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
			wantError: nil,
		},
		{
			name:      "nil role",
			role:      nil,
			wantError: ErrNilRole,
		},
		{
			name: "empty name",
			role: &Role{
				Name:        "",
				Description: "Invalid",
			},
			wantError: ErrEmptyRoleName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := NewMemoryRBACAdapter(false)
			ctx := context.Background()

			err := adapter.CreateRole(ctx, tt.role)

			if tt.wantError != nil {
				if !errors.Is(err, tt.wantError) {
					t.Errorf("CreateRole() error = %v, want %v", err, tt.wantError)
				}
			} else if err != nil {
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
	if !errors.Is(err, ErrRoleExists) {
		t.Errorf("CreateRole() error = %v, want %v", err, ErrRoleExists)
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
	if !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("GetRole() error = %v, want %v", err, ErrRoleNotFound)
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
	if !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("UpdateRole() error = %v, want %v", err, ErrRoleNotFound)
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
	if !errors.Is(err, ErrSystemRole) {
		t.Errorf("UpdateRole() error = %v, want %v", err, ErrSystemRole)
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
	if !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("GetRole() after delete error = %v, want %v", err, ErrRoleNotFound)
	}
}

func TestMemoryRBACAdapter_DeleteRole_NotFound(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	err := adapter.DeleteRole(ctx, "nonexistent")
	if !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("DeleteRole() error = %v, want %v", err, ErrRoleNotFound)
	}
}

func TestMemoryRBACAdapter_DeleteRole_SystemRole(t *testing.T) {
	adapter := NewMemoryRBACAdapter(true)
	ctx := context.Background()

	err := adapter.DeleteRole(ctx, RoleAdmin)
	if !errors.Is(err, ErrSystemRole) {
		t.Errorf("DeleteRole() error = %v, want %v", err, ErrSystemRole)
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
	if !errors.Is(err, ErrRoleInUse) {
		t.Errorf("DeleteRole() error = %v, want %v", err, ErrRoleInUse)
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
	if !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("AssignRole() error = %v, want %v", err, ErrRoleNotFound)
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

	// Subject has no roles at all
	err = adapter.RevokeRole(ctx, "user1", "test")
	if !errors.Is(err, ErrNoRolesAssigned) {
		t.Errorf("RevokeRole() error = %v, want %v", err, ErrNoRolesAssigned)
	}
}

func TestMemoryRBACAdapter_RevokeRole_WrongRole(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	role1 := &Role{Name: "role1"}
	role2 := &Role{Name: "role2"}
	err := adapter.CreateRole(ctx, role1)
	if err != nil {
		t.Fatalf("CreateRole() failed: %v", err)
	}
	err = adapter.CreateRole(ctx, role2)
	if err != nil {
		t.Fatalf("CreateRole() failed: %v", err)
	}

	err = adapter.AssignRole(ctx, "user1", "role1")
	if err != nil {
		t.Fatalf("AssignRole() failed: %v", err)
	}

	// Subject has role1 but not role2
	err = adapter.RevokeRole(ctx, "user1", "role2")
	if !errors.Is(err, ErrRoleNotAssigned) {
		t.Errorf("RevokeRole() error = %v, want %v", err, ErrRoleNotAssigned)
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
	if !errors.Is(err, ErrPermissionExists) {
		t.Errorf("GrantPermission() error = %v, want %v", err, ErrPermissionExists)
	}
}

func TestMemoryRBACAdapter_GrantPermission_SystemRole(t *testing.T) {
	adapter := NewMemoryRBACAdapter(true)
	ctx := context.Background()

	perm := Permission{Resource: "keys", Action: "read"}
	err := adapter.GrantPermission(ctx, RoleAdmin, perm)
	if !errors.Is(err, ErrSystemRole) {
		t.Errorf("GrantPermission() error = %v, want %v", err, ErrSystemRole)
	}
}

func TestMemoryRBACAdapter_GrantPermission_NotFound(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	perm := Permission{Resource: "keys", Action: "read"}
	err := adapter.GrantPermission(ctx, "nonexistent", perm)
	if !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("GrantPermission() error = %v, want %v", err, ErrRoleNotFound)
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
	if !errors.Is(err, ErrPermissionNotFound) {
		t.Errorf("RevokePermission() error = %v, want %v", err, ErrPermissionNotFound)
	}
}

func TestMemoryRBACAdapter_RevokePermission_SystemRole(t *testing.T) {
	adapter := NewMemoryRBACAdapter(true)
	ctx := context.Background()

	perm := Permission{Resource: "keys", Action: "read"}
	err := adapter.RevokePermission(ctx, RoleAdmin, perm)
	if !errors.Is(err, ErrSystemRole) {
		t.Errorf("RevokePermission() error = %v, want %v", err, ErrSystemRole)
	}
}

func TestMemoryRBACAdapter_RevokePermission_RoleNotFound(t *testing.T) {
	adapter := NewMemoryRBACAdapter(false)
	ctx := context.Background()

	perm := Permission{Resource: "keys", Action: "read"}
	err := adapter.RevokePermission(ctx, "nonexistent", perm)
	if !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("RevokePermission() error = %v, want %v", err, ErrRoleNotFound)
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
		RoleCustodian,
		RoleSO,
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

	// Verify removed roles no longer exist
	removedRoles := []string{"readonly", "guest"}
	for _, roleName := range removedRoles {
		_, err := adapter.GetRole(ctx, roleName)
		if err == nil {
			t.Errorf("GetRole(%s) should return error for removed role", roleName)
		}
	}
}

func TestMemoryRBACAdapter_CustodianRolePermissions(t *testing.T) {
	adapter := NewMemoryRBACAdapter(true)
	ctx := context.Background()

	role, err := adapter.GetRole(ctx, RoleCustodian)
	if err != nil {
		t.Fatalf("GetRole(custodian) error: %v", err)
	}

	if role.Description != "Key custodian for ceremony participation and share management" {
		t.Errorf("Custodian description = %v, want ceremony description", role.Description)
	}

	// Check specific permissions
	expectedPerms := []Permission{
		{Resource: ResourceBarrier, Action: ActionProvideShare},
		{Resource: ResourceBarrier, Action: ActionReceiveShare},
		{Resource: ResourceBarrier, Action: ActionRead},
	}

	if len(role.Permissions) != len(expectedPerms) {
		t.Errorf("Custodian permissions count = %v, want %v", len(role.Permissions), len(expectedPerms))
	}

	for _, expected := range expectedPerms {
		if !role.HasPermission(expected) {
			t.Errorf("Custodian role missing permission: %s", expected.String())
		}
	}
}

func TestMemoryRBACAdapter_CustodianBarrierPermissionCheck(t *testing.T) {
	adapter := NewMemoryRBACAdapter(true)
	ctx := context.Background()

	err := adapter.AssignRole(ctx, "custodian-user", RoleCustodian)
	if err != nil {
		t.Fatalf("AssignRole() error: %v", err)
	}

	// Custodian should have barrier permissions
	provideShare := Permission{Resource: ResourceBarrier, Action: ActionProvideShare}
	has, err := adapter.CheckPermission(ctx, "custodian-user", provideShare)
	if err != nil {
		t.Fatalf("CheckPermission() error: %v", err)
	}
	if !has {
		t.Error("Custodian should have barrier:provide-share permission")
	}

	// Custodian should NOT have key management permissions
	keyCreate := Permission{Resource: ResourceKeys, Action: ActionCreate}
	has, err = adapter.CheckPermission(ctx, "custodian-user", keyCreate)
	if err != nil {
		t.Fatalf("CheckPermission() error: %v", err)
	}
	if has {
		t.Error("Custodian should NOT have keys:create permission")
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

func TestSODefaultPermissions(t *testing.T) {
	adapter := NewMemoryRBACAdapter(true)
	ctx := context.Background()

	role, err := adapter.GetRole(ctx, RoleSO)
	if err != nil {
		t.Fatalf("GetRole(so) error: %v", err)
	}

	if role.Description != "Security Officer for module initialization, PIN management, and tenant administration" {
		t.Errorf("SO description = %v, want expected description", role.Description)
	}

	// Verify SO has all expected resource:* permissions
	expectedWildcardPerms := []Permission{
		{Resource: ResourceInit, Action: ActionAll},
		{Resource: ResourcePIN, Action: ActionAll},
		{Resource: ResourceUsers, Action: ActionAll},
		{Resource: ResourceRoles, Action: ActionAll},
		{Resource: ResourceCertificates, Action: ActionAll},
		{Resource: ResourceBackends, Action: ActionAll},
		{Resource: ResourceBarrier, Action: ActionAll},
		{Resource: ResourceSystem, Action: ActionAll},
		{Resource: ResourceTenants, Action: ActionAll},
		{Resource: ResourceCredentials, Action: ActionAll},
	}

	for _, expected := range expectedWildcardPerms {
		if !role.HasPermission(expected) {
			t.Errorf("SO role missing permission: %s", expected.String())
		}
	}

	// Verify SO has specific key lifecycle permissions
	expectedKeyPerms := []Permission{
		{Resource: ResourceKeys, Action: ActionList},
		{Resource: ResourceKeys, Action: ActionRead},
		{Resource: ResourceKeys, Action: ActionDelete},
		{Resource: ResourceKeys, Action: ActionImport},
		{Resource: ResourceKeys, Action: ActionExport},
		{Resource: ResourceKeys, Action: ActionCreate},
	}

	for _, expected := range expectedKeyPerms {
		if !role.HasPermission(expected) {
			t.Errorf("SO role missing key lifecycle permission: %s", expected.String())
		}
	}

	// Verify SO has audit read permissions
	expectedAuditPerms := []Permission{
		{Resource: ResourceAudit, Action: ActionRead},
		{Resource: ResourceAudit, Action: ActionList},
	}

	for _, expected := range expectedAuditPerms {
		if !role.HasPermission(expected) {
			t.Errorf("SO role missing audit permission: %s", expected.String())
		}
	}

	// Verify SO is a system role
	if isSystem, ok := role.Metadata["system"].(bool); !ok || !isSystem {
		t.Error("SO role should be marked as system role")
	}
}

func TestSOCannotPerformCryptoOps(t *testing.T) {
	adapter := NewMemoryRBACAdapter(true)
	ctx := context.Background()

	role, err := adapter.GetRole(ctx, RoleSO)
	if err != nil {
		t.Fatalf("GetRole(so) error: %v", err)
	}

	// SO must NOT have keys:sign, keys:encrypt, keys:decrypt
	forbiddenPerms := []Permission{
		{Resource: ResourceKeys, Action: ActionSign},
		{Resource: ResourceKeys, Action: ActionEncrypt},
		{Resource: ResourceKeys, Action: ActionDecrypt},
	}

	for _, forbidden := range forbiddenPerms {
		if role.HasPermission(forbidden) {
			t.Errorf("SO role should NOT have permission: %s (FIPS 140-2 separation of duties violation)", forbidden.String())
		}
	}

	// Also verify SO does NOT have keys:* (wildcard) which would include crypto ops
	keysWildcard := Permission{Resource: ResourceKeys, Action: ActionAll}
	if role.HasPermission(keysWildcard) {
		t.Error("SO role should NOT have keys:* permission (would include crypto operations)")
	}

	// Double-check via CheckPermission with an SO user assigned
	err = adapter.AssignRole(ctx, "so-user", RoleSO)
	if err != nil {
		t.Fatalf("AssignRole() error: %v", err)
	}

	// SO should NOT be able to sign (no keys:sign, and no keys:* wildcard)
	signPerm := Permission{Resource: ResourceKeys, Action: ActionSign}
	has, err := adapter.CheckPermission(ctx, "so-user", signPerm)
	if err != nil {
		t.Fatalf("CheckPermission() error: %v", err)
	}
	if has {
		t.Error("SO user should NOT have keys:sign permission via CheckPermission")
	}

	// SO should NOT be able to encrypt
	encryptPerm := Permission{Resource: ResourceKeys, Action: ActionEncrypt}
	has, err = adapter.CheckPermission(ctx, "so-user", encryptPerm)
	if err != nil {
		t.Fatalf("CheckPermission() error: %v", err)
	}
	if has {
		t.Error("SO user should NOT have keys:encrypt permission via CheckPermission")
	}

	// SO should NOT be able to decrypt
	decryptPerm := Permission{Resource: ResourceKeys, Action: ActionDecrypt}
	has, err = adapter.CheckPermission(ctx, "so-user", decryptPerm)
	if err != nil {
		t.Fatalf("CheckPermission() error: %v", err)
	}
	if has {
		t.Error("SO user should NOT have keys:decrypt permission via CheckPermission")
	}
}

func TestSOCanManageKeyLifecycle(t *testing.T) {
	adapter := NewMemoryRBACAdapter(true)
	ctx := context.Background()

	err := adapter.AssignRole(ctx, "so-user", RoleSO)
	if err != nil {
		t.Fatalf("AssignRole() error: %v", err)
	}

	// SO should have key lifecycle permissions
	lifecyclePerms := []struct {
		name string
		perm Permission
	}{
		{"list keys", Permission{Resource: ResourceKeys, Action: ActionList}},
		{"read keys", Permission{Resource: ResourceKeys, Action: ActionRead}},
		{"delete keys", Permission{Resource: ResourceKeys, Action: ActionDelete}},
		{"create keys", Permission{Resource: ResourceKeys, Action: ActionCreate}},
		{"import keys", Permission{Resource: ResourceKeys, Action: ActionImport}},
		{"export keys", Permission{Resource: ResourceKeys, Action: ActionExport}},
	}

	for _, lp := range lifecyclePerms {
		t.Run(lp.name, func(t *testing.T) {
			has, err := adapter.CheckPermission(ctx, "so-user", lp.perm)
			if err != nil {
				t.Fatalf("CheckPermission() error: %v", err)
			}
			if !has {
				t.Errorf("SO user should have %s permission", lp.perm.String())
			}
		})
	}
}

func TestSOHasBarrierPermissions(t *testing.T) {
	adapter := NewMemoryRBACAdapter(true)
	ctx := context.Background()

	err := adapter.AssignRole(ctx, "so-user", RoleSO)
	if err != nil {
		t.Fatalf("AssignRole() error: %v", err)
	}

	// SO should have barrier:* which matches any barrier action
	barrierActions := []string{
		ActionSeal,
		ActionUnseal,
		ActionRead,
		ActionProvideShare,
		ActionReceiveShare,
	}

	for _, action := range barrierActions {
		t.Run("barrier:"+action, func(t *testing.T) {
			perm := Permission{Resource: ResourceBarrier, Action: action}
			has, err := adapter.CheckPermission(ctx, "so-user", perm)
			if err != nil {
				t.Fatalf("CheckPermission() error: %v", err)
			}
			if !has {
				t.Errorf("SO user should have barrier:%s permission (via barrier:*)", action)
			}
		})
	}
}

// --- New tests for ValidateRoleAssignment and separation of duties ---

func TestValidateRoleAssignment_SOOperatorConflict(t *testing.T) {
	err := ValidateRoleAssignment([]string{RoleSO}, RoleOperator)
	if !errors.Is(err, ErrConflictingRoles) {
		t.Errorf("ValidateRoleAssignment(SO+Operator) = %v, want %v", err, ErrConflictingRoles)
	}
}

func TestValidateRoleAssignment_SOUserConflict(t *testing.T) {
	err := ValidateRoleAssignment([]string{RoleSO}, RoleUser)
	if !errors.Is(err, ErrConflictingRoles) {
		t.Errorf("ValidateRoleAssignment(SO+User) = %v, want %v", err, ErrConflictingRoles)
	}
}

func TestValidateRoleAssignment_ReverseOrder(t *testing.T) {
	// Operator + SO is also a conflict (order doesn't matter)
	err := ValidateRoleAssignment([]string{RoleOperator}, RoleSO)
	if !errors.Is(err, ErrConflictingRoles) {
		t.Errorf("ValidateRoleAssignment(Operator+SO) = %v, want %v", err, ErrConflictingRoles)
	}

	// User + SO is also a conflict (order doesn't matter)
	err = ValidateRoleAssignment([]string{RoleUser}, RoleSO)
	if !errors.Is(err, ErrConflictingRoles) {
		t.Errorf("ValidateRoleAssignment(User+SO) = %v, want %v", err, ErrConflictingRoles)
	}
}

func TestValidateRoleAssignment_NoConflict(t *testing.T) {
	// Admin + Operator is allowed
	err := ValidateRoleAssignment([]string{RoleAdmin}, RoleOperator)
	if err != nil {
		t.Errorf("ValidateRoleAssignment(Admin+Operator) unexpected error: %v", err)
	}

	// Admin + User is allowed
	err = ValidateRoleAssignment([]string{RoleAdmin}, RoleUser)
	if err != nil {
		t.Errorf("ValidateRoleAssignment(Admin+User) unexpected error: %v", err)
	}

	// Custodian + Auditor is allowed
	err = ValidateRoleAssignment([]string{RoleCustodian}, RoleAuditor)
	if err != nil {
		t.Errorf("ValidateRoleAssignment(Custodian+Auditor) unexpected error: %v", err)
	}

	// SO + Custodian is allowed (custodian does ceremony, SO manages)
	err = ValidateRoleAssignment([]string{RoleSO}, RoleCustodian)
	if err != nil {
		t.Errorf("ValidateRoleAssignment(SO+Custodian) unexpected error: %v", err)
	}
}

func TestValidateRoleAssignment_Empty(t *testing.T) {
	// No existing roles - any role should be allowed
	err := ValidateRoleAssignment([]string{}, RoleSO)
	if err != nil {
		t.Errorf("ValidateRoleAssignment(empty+SO) unexpected error: %v", err)
	}

	err = ValidateRoleAssignment([]string{}, RoleOperator)
	if err != nil {
		t.Errorf("ValidateRoleAssignment(empty+Operator) unexpected error: %v", err)
	}
}

func TestValidateRoleAssignment_MultipleExistingRoles(t *testing.T) {
	// User with Admin+Operator should conflict with SO
	err := ValidateRoleAssignment([]string{RoleAdmin, RoleOperator}, RoleSO)
	if !errors.Is(err, ErrConflictingRoles) {
		t.Errorf("ValidateRoleAssignment(Admin+Operator+SO) = %v, want %v", err, ErrConflictingRoles)
	}
}

func TestMemoryRBACAdapter_AssignRole_SOOperatorConflict(t *testing.T) {
	adapter := NewMemoryRBACAdapter(true)
	ctx := context.Background()

	// Assign SO first
	err := adapter.AssignRole(ctx, "user1", RoleSO)
	if err != nil {
		t.Fatalf("AssignRole(SO) error: %v", err)
	}

	// Try to assign Operator - should fail
	err = adapter.AssignRole(ctx, "user1", RoleOperator)
	if !errors.Is(err, ErrConflictingRoles) {
		t.Errorf("AssignRole(Operator after SO) = %v, want %v", err, ErrConflictingRoles)
	}

	// Verify SO is still assigned
	roles, err := adapter.GetUserRoles(ctx, "user1")
	if err != nil {
		t.Fatalf("GetUserRoles() error: %v", err)
	}
	if len(roles) != 1 || roles[0] != RoleSO {
		t.Errorf("GetUserRoles() = %v, want [so]", roles)
	}
}

func TestMemoryRBACAdapter_AssignRole_SOUserConflict(t *testing.T) {
	adapter := NewMemoryRBACAdapter(true)
	ctx := context.Background()

	// Assign SO first
	err := adapter.AssignRole(ctx, "user1", RoleSO)
	if err != nil {
		t.Fatalf("AssignRole(SO) error: %v", err)
	}

	// Try to assign User - should fail
	err = adapter.AssignRole(ctx, "user1", RoleUser)
	if !errors.Is(err, ErrConflictingRoles) {
		t.Errorf("AssignRole(User after SO) = %v, want %v", err, ErrConflictingRoles)
	}
}

func TestMemoryRBACAdapter_AssignRole_OperatorThenSO(t *testing.T) {
	adapter := NewMemoryRBACAdapter(true)
	ctx := context.Background()

	// Assign Operator first
	err := adapter.AssignRole(ctx, "user1", RoleOperator)
	if err != nil {
		t.Fatalf("AssignRole(Operator) error: %v", err)
	}

	// Try to assign SO - should also fail (bidirectional)
	err = adapter.AssignRole(ctx, "user1", RoleSO)
	if !errors.Is(err, ErrConflictingRoles) {
		t.Errorf("AssignRole(SO after Operator) = %v, want %v", err, ErrConflictingRoles)
	}
}

func TestMemoryRBACAdapter_AssignRole_SOCustodianAllowed(t *testing.T) {
	adapter := NewMemoryRBACAdapter(true)
	ctx := context.Background()

	// Assign SO
	err := adapter.AssignRole(ctx, "user1", RoleSO)
	if err != nil {
		t.Fatalf("AssignRole(SO) error: %v", err)
	}

	// Assign Custodian - should succeed (not a conflicting pair)
	err = adapter.AssignRole(ctx, "user1", RoleCustodian)
	if err != nil {
		t.Errorf("AssignRole(Custodian after SO) unexpected error: %v", err)
	}
}

// --- Tests verifying admin role has explicit permissions instead of *:* ---

func TestAdminRoleNoWildcard(t *testing.T) {
	adapter := NewMemoryRBACAdapter(true)
	ctx := context.Background()

	role, err := adapter.GetRole(ctx, RoleAdmin)
	if err != nil {
		t.Fatalf("GetRole(admin) error: %v", err)
	}

	// Admin should NOT have *:*
	wildcardPerm := Permission{Resource: ActionAll, Action: ActionAll}
	if role.HasPermission(wildcardPerm) {
		t.Error("Admin should not have *:* wildcard permission")
	}

	// Admin SHOULD have explicit resource:* permissions
	expectedPerms := []Permission{
		{Resource: ResourceKeys, Action: ActionAll},
		{Resource: ResourceCertificates, Action: ActionAll},
		{Resource: ResourceSecrets, Action: ActionAll},
		{Resource: ResourceUsers, Action: ActionAll},
		{Resource: ResourceRoles, Action: ActionAll},
		{Resource: ResourceCredentials, Action: ActionAll},
	}

	for _, expected := range expectedPerms {
		if !role.HasPermission(expected) {
			t.Errorf("Admin role missing permission: %s", expected.String())
		}
	}

	// Admin should have specific backend and audit permissions
	specificPerms := []Permission{
		{Resource: ResourceBackends, Action: ActionRead},
		{Resource: ResourceBackends, Action: ActionList},
		{Resource: ResourceAudit, Action: ActionRead},
		{Resource: ResourceAudit, Action: ActionList},
		{Resource: ResourceBarrier, Action: ActionRead},
	}

	for _, expected := range specificPerms {
		if !role.HasPermission(expected) {
			t.Errorf("Admin role missing permission: %s", expected.String())
		}
	}
}

func TestAdminCanPerformCryptoOps(t *testing.T) {
	adapter := NewMemoryRBACAdapter(true)
	ctx := context.Background()

	err := adapter.AssignRole(ctx, "admin-user", RoleAdmin)
	if err != nil {
		t.Fatalf("AssignRole() error: %v", err)
	}

	// Admin should be able to sign (via keys:*)
	cryptoPerms := []struct {
		name string
		perm Permission
	}{
		{"sign", Permission{Resource: ResourceKeys, Action: ActionSign}},
		{"verify", Permission{Resource: ResourceKeys, Action: ActionVerify}},
		{"encrypt", Permission{Resource: ResourceKeys, Action: ActionEncrypt}},
		{"decrypt", Permission{Resource: ResourceKeys, Action: ActionDecrypt}},
		{"create", Permission{Resource: ResourceKeys, Action: ActionCreate}},
		{"delete", Permission{Resource: ResourceKeys, Action: ActionDelete}},
	}

	for _, cp := range cryptoPerms {
		t.Run(cp.name, func(t *testing.T) {
			has, err := adapter.CheckPermission(ctx, "admin-user", cp.perm)
			if err != nil {
				t.Fatalf("CheckPermission() error: %v", err)
			}
			if !has {
				t.Errorf("Admin should have %s permission (unlike SO)", cp.perm.String())
			}
		})
	}
}

func TestAdminCannotManageTenants(t *testing.T) {
	adapter := NewMemoryRBACAdapter(true)
	ctx := context.Background()

	role, err := adapter.GetRole(ctx, RoleAdmin)
	if err != nil {
		t.Fatalf("GetRole(admin) error: %v", err)
	}

	// Admin should NOT have tenant management
	tenantPerms := []Permission{
		{Resource: ResourceTenants, Action: ActionCreate},
		{Resource: ResourceTenants, Action: ActionAll},
	}

	for _, p := range tenantPerms {
		if role.HasPermission(p) {
			t.Errorf("Admin should NOT have tenant management permission: %s", p.String())
		}
	}

	// Also check via CheckPermission to verify wildcard matching doesn't grant it
	err = adapter.AssignRole(ctx, "admin-user", RoleAdmin)
	if err != nil {
		t.Fatalf("AssignRole() error: %v", err)
	}

	tenantCreate := Permission{Resource: ResourceTenants, Action: ActionCreate}
	has, err := adapter.CheckPermission(ctx, "admin-user", tenantCreate)
	if err != nil {
		t.Fatalf("CheckPermission() error: %v", err)
	}
	if has {
		t.Error("Admin should NOT have tenants:create via CheckPermission")
	}
}

func TestAdminCannotInitModule(t *testing.T) {
	adapter := NewMemoryRBACAdapter(true)
	ctx := context.Background()

	err := adapter.AssignRole(ctx, "admin-user", RoleAdmin)
	if err != nil {
		t.Fatalf("AssignRole() error: %v", err)
	}

	// Admin should NOT have init:* (SO-only)
	initPerm := Permission{Resource: ResourceInit, Action: ActionInitialize}
	has, err := adapter.CheckPermission(ctx, "admin-user", initPerm)
	if err != nil {
		t.Fatalf("CheckPermission() error: %v", err)
	}
	if has {
		t.Error("Admin should NOT have init:initialize permission (SO-only)")
	}

	// Admin should NOT have PIN management
	pinPerm := Permission{Resource: ResourcePIN, Action: ActionResetPIN}
	has, err = adapter.CheckPermission(ctx, "admin-user", pinPerm)
	if err != nil {
		t.Fatalf("CheckPermission() error: %v", err)
	}
	if has {
		t.Error("Admin should NOT have pin:reset-pin permission (SO-only)")
	}
}

func TestAdminCanManageUsersAndRoles(t *testing.T) {
	adapter := NewMemoryRBACAdapter(true)
	ctx := context.Background()

	err := adapter.AssignRole(ctx, "admin-user", RoleAdmin)
	if err != nil {
		t.Fatalf("AssignRole() error: %v", err)
	}

	// Admin should have full user and role management
	managementPerms := []struct {
		name string
		perm Permission
	}{
		{"users:create", Permission{Resource: ResourceUsers, Action: ActionCreate}},
		{"users:delete", Permission{Resource: ResourceUsers, Action: ActionDelete}},
		{"users:update", Permission{Resource: ResourceUsers, Action: ActionUpdate}},
		{"roles:create", Permission{Resource: ResourceRoles, Action: ActionCreate}},
		{"roles:delete", Permission{Resource: ResourceRoles, Action: ActionDelete}},
	}

	for _, mp := range managementPerms {
		t.Run(mp.name, func(t *testing.T) {
			has, err := adapter.CheckPermission(ctx, "admin-user", mp.perm)
			if err != nil {
				t.Fatalf("CheckPermission() error: %v", err)
			}
			if !has {
				t.Errorf("Admin should have %s permission", mp.perm.String())
			}
		})
	}
}

func TestAdminBarrierReadOnly(t *testing.T) {
	adapter := NewMemoryRBACAdapter(true)
	ctx := context.Background()

	err := adapter.AssignRole(ctx, "admin-user", RoleAdmin)
	if err != nil {
		t.Fatalf("AssignRole() error: %v", err)
	}

	// Admin can read barrier
	readPerm := Permission{Resource: ResourceBarrier, Action: ActionRead}
	has, err := adapter.CheckPermission(ctx, "admin-user", readPerm)
	if err != nil {
		t.Fatalf("CheckPermission() error: %v", err)
	}
	if !has {
		t.Error("Admin should have barrier:read permission")
	}

	// Admin should NOT be able to seal/unseal barrier (that is SO-level)
	sealPerm := Permission{Resource: ResourceBarrier, Action: ActionSeal}
	has, err = adapter.CheckPermission(ctx, "admin-user", sealPerm)
	if err != nil {
		t.Fatalf("CheckPermission() error: %v", err)
	}
	if has {
		t.Error("Admin should NOT have barrier:seal permission")
	}

	unsealPerm := Permission{Resource: ResourceBarrier, Action: ActionUnseal}
	has, err = adapter.CheckPermission(ctx, "admin-user", unsealPerm)
	if err != nil {
		t.Fatalf("CheckPermission() error: %v", err)
	}
	if has {
		t.Error("Admin should NOT have barrier:unseal permission")
	}
}
