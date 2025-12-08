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

package user

import (
	"context"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/adapters/rbac"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestRBACAdapter(t *testing.T) (*UserRBACAdapter, *FileStore, func()) {
	t.Helper()
	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	store, err := NewFileStore(backend, WithCleanupInterval(100*time.Millisecond))
	require.NoError(t, err)

	adapter := NewUserRBACAdapter(store)

	return adapter, store, func() {
		_ = store.Close()
	}
}

func TestNewUserRBACAdapter(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	store, err := NewFileStore(backend)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	adapter := NewUserRBACAdapter(store)
	assert.NotNil(t, adapter)
}

func TestUserRBACAdapter_CheckPermission(t *testing.T) {
	adapter, store, cleanup := newTestRBACAdapter(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("admin has all permissions", func(t *testing.T) {
		_, err := store.Create(ctx, "admin@example.com", "Admin", RoleAdmin)
		require.NoError(t, err)

		hasPermission, err := adapter.CheckPermission(ctx, "admin@example.com", rbac.NewPermission(rbac.ResourceKeys, rbac.ActionCreate))
		require.NoError(t, err)
		assert.True(t, hasPermission)

		hasPermission, err = adapter.CheckPermission(ctx, "admin@example.com", rbac.NewPermission(rbac.ResourceUsers, rbac.ActionDelete))
		require.NoError(t, err)
		assert.True(t, hasPermission)
	})

	t.Run("user has limited permissions", func(t *testing.T) {
		_, err := store.Create(ctx, "user@example.com", "User", RoleUser)
		require.NoError(t, err)

		// User can sign
		hasPermission, err := adapter.CheckPermission(ctx, "user@example.com", rbac.NewPermission(rbac.ResourceKeys, rbac.ActionSign))
		require.NoError(t, err)
		assert.True(t, hasPermission)

		// User can verify
		hasPermission, err = adapter.CheckPermission(ctx, "user@example.com", rbac.NewPermission(rbac.ResourceKeys, rbac.ActionVerify))
		require.NoError(t, err)
		assert.True(t, hasPermission)

		// User can encrypt
		hasPermission, err = adapter.CheckPermission(ctx, "user@example.com", rbac.NewPermission(rbac.ResourceKeys, rbac.ActionEncrypt))
		require.NoError(t, err)
		assert.True(t, hasPermission)

		// User cannot delete keys
		hasPermission, err = adapter.CheckPermission(ctx, "user@example.com", rbac.NewPermission(rbac.ResourceKeys, rbac.ActionDelete))
		require.NoError(t, err)
		assert.False(t, hasPermission)

		// User cannot read keys (only cryptographic operations)
		hasPermission, err = adapter.CheckPermission(ctx, "user@example.com", rbac.NewPermission(rbac.ResourceKeys, rbac.ActionRead))
		require.NoError(t, err)
		assert.False(t, hasPermission)
	})

	t.Run("disabled user has no permissions", func(t *testing.T) {
		user, err := store.Create(ctx, "disabled@example.com", "Disabled", RoleAdmin)
		require.NoError(t, err)

		user.Enabled = false
		err = store.Update(ctx, user)
		require.NoError(t, err)

		hasPermission, err := adapter.CheckPermission(ctx, "disabled@example.com", rbac.NewPermission(rbac.ResourceKeys, rbac.ActionRead))
		require.NoError(t, err)
		assert.False(t, hasPermission)
	})

	t.Run("nonexistent user has no permissions", func(t *testing.T) {
		hasPermission, err := adapter.CheckPermission(ctx, "nonexistent@example.com", rbac.NewPermission(rbac.ResourceKeys, rbac.ActionRead))
		require.NoError(t, err)
		assert.False(t, hasPermission)
	})
}

func TestUserRBACAdapter_AssignRole(t *testing.T) {
	adapter, store, cleanup := newTestRBACAdapter(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("assigns role successfully", func(t *testing.T) {
		_, err := store.Create(ctx, "assign@example.com", "Assign", RoleUser)
		require.NoError(t, err)

		err = adapter.AssignRole(ctx, "assign@example.com", rbac.RoleOperator)
		require.NoError(t, err)

		// Verify role was updated
		user, err := store.GetByUsername(ctx, "assign@example.com")
		require.NoError(t, err)
		assert.Equal(t, RoleOperator, user.Role)
	})

	t.Run("returns error for nonexistent user", func(t *testing.T) {
		err := adapter.AssignRole(ctx, "nonexistent@example.com", rbac.RoleAdmin)
		assert.ErrorIs(t, err, ErrUserNotFound)
	})

	t.Run("returns error for invalid role", func(t *testing.T) {
		_, err := store.Create(ctx, "assigninvalid@example.com", "User", RoleUser)
		require.NoError(t, err)

		err = adapter.AssignRole(ctx, "assigninvalid@example.com", "invalid-role")
		assert.Error(t, err)
	})
}

func TestUserRBACAdapter_RevokeRole(t *testing.T) {
	adapter, store, cleanup := newTestRBACAdapter(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("revokes role successfully", func(t *testing.T) {
		_, err := store.Create(ctx, "revoke@example.com", "Revoke", RoleOperator)
		require.NoError(t, err)

		err = adapter.RevokeRole(ctx, "revoke@example.com", rbac.RoleOperator)
		require.NoError(t, err)

		// Verify role was set to guest
		user, err := store.GetByUsername(ctx, "revoke@example.com")
		require.NoError(t, err)
		assert.Equal(t, RoleGuest, user.Role)
	})

	t.Run("returns error for nonexistent user", func(t *testing.T) {
		err := adapter.RevokeRole(ctx, "nonexistent@example.com", rbac.RoleAdmin)
		assert.ErrorIs(t, err, ErrUserNotFound)
	})

	t.Run("returns error when user doesnt have role", func(t *testing.T) {
		_, err := store.Create(ctx, "revokewrong@example.com", "User", RoleUser)
		require.NoError(t, err)

		err = adapter.RevokeRole(ctx, "revokewrong@example.com", rbac.RoleOperator)
		assert.ErrorIs(t, err, ErrInvalidRole)
	})
}

func TestUserRBACAdapter_GetUserRoles(t *testing.T) {
	adapter, store, cleanup := newTestRBACAdapter(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("returns user role", func(t *testing.T) {
		_, err := store.Create(ctx, "roles@example.com", "Roles", RoleOperator)
		require.NoError(t, err)

		roles, err := adapter.GetUserRoles(ctx, "roles@example.com")
		require.NoError(t, err)
		assert.Len(t, roles, 1)
		assert.Equal(t, string(RoleOperator), roles[0])
	})

	t.Run("returns empty for nonexistent user", func(t *testing.T) {
		roles, err := adapter.GetUserRoles(ctx, "nonexistent@example.com")
		require.NoError(t, err)
		assert.Len(t, roles, 0)
	})
}

func TestUserRBACAdapter_RoleOperations(t *testing.T) {
	adapter, _, cleanup := newTestRBACAdapter(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("CreateRole", func(t *testing.T) {
		role := &rbac.Role{
			Name:        "custom-role",
			Description: "A custom role",
			Permissions: []rbac.Permission{
				rbac.NewPermission(rbac.ResourceKeys, rbac.ActionRead),
			},
		}
		err := adapter.CreateRole(ctx, role)
		require.NoError(t, err)
	})

	t.Run("GetRole", func(t *testing.T) {
		role, err := adapter.GetRole(ctx, rbac.RoleAdmin)
		require.NoError(t, err)
		assert.Equal(t, rbac.RoleAdmin, role.Name)
	})

	t.Run("ListRoles", func(t *testing.T) {
		roles, err := adapter.ListRoles(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, roles)
	})

	t.Run("UpdateRole", func(t *testing.T) {
		role := &rbac.Role{
			Name:        "custom-role",
			Description: "Updated description",
			Permissions: []rbac.Permission{
				rbac.NewPermission(rbac.ResourceKeys, rbac.ActionRead),
				rbac.NewPermission(rbac.ResourceKeys, rbac.ActionList),
			},
		}
		err := adapter.UpdateRole(ctx, role)
		require.NoError(t, err)
	})

	t.Run("GrantPermission", func(t *testing.T) {
		err := adapter.GrantPermission(ctx, "custom-role", rbac.NewPermission(rbac.ResourceKeys, rbac.ActionSign))
		require.NoError(t, err)
	})

	t.Run("RevokePermission", func(t *testing.T) {
		err := adapter.RevokePermission(ctx, "custom-role", rbac.NewPermission(rbac.ResourceKeys, rbac.ActionSign))
		require.NoError(t, err)
	})

	t.Run("DeleteRole", func(t *testing.T) {
		err := adapter.DeleteRole(ctx, "custom-role")
		require.NoError(t, err)
	})
}

func TestUserRBACAdapter_ListPermissions(t *testing.T) {
	adapter, store, cleanup := newTestRBACAdapter(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("returns permissions for user", func(t *testing.T) {
		_, err := store.Create(ctx, "perms@example.com", "Perms", RoleAdmin)
		require.NoError(t, err)

		permissions, err := adapter.ListPermissions(ctx, "perms@example.com")
		require.NoError(t, err)
		assert.NotEmpty(t, permissions)
	})

	t.Run("returns empty for nonexistent user", func(t *testing.T) {
		permissions, err := adapter.ListPermissions(ctx, "nonexistent@example.com")
		require.NoError(t, err)
		assert.Len(t, permissions, 0)
	})
}

func TestRoleToRBAC(t *testing.T) {
	tests := []struct {
		role     Role
		expected string
	}{
		{RoleAdmin, rbac.RoleAdmin},
		{RoleOperator, rbac.RoleOperator},
		{RoleAuditor, rbac.RoleAuditor},
		{RoleUser, rbac.RoleUser},
		{RoleReadOnly, rbac.RoleReadOnly},
		{RoleGuest, rbac.RoleGuest},
		{Role("unknown"), rbac.RoleGuest},
	}

	for _, tt := range tests {
		t.Run(string(tt.role), func(t *testing.T) {
			assert.Equal(t, tt.expected, RoleToRBAC(tt.role))
		})
	}
}

func TestRBACToRole(t *testing.T) {
	tests := []struct {
		roleName string
		expected Role
	}{
		{rbac.RoleAdmin, RoleAdmin},
		{rbac.RoleOperator, RoleOperator},
		{rbac.RoleAuditor, RoleAuditor},
		{rbac.RoleUser, RoleUser},
		{rbac.RoleReadOnly, RoleReadOnly},
		{rbac.RoleGuest, RoleGuest},
		{"unknown", RoleGuest},
	}

	for _, tt := range tests {
		t.Run(tt.roleName, func(t *testing.T) {
			assert.Equal(t, tt.expected, RBACToRole(tt.roleName))
		})
	}
}

func TestUserRBACAdapter_ImplementsInterface(t *testing.T) {
	var _ rbac.RBACAdapter = (*UserRBACAdapter)(nil)
}

func TestUserRBACAdapter_CheckPermission_StorageError(t *testing.T) {
	adapter, store, cleanup := newTestRBACAdapter(t)
	defer cleanup()

	ctx := context.Background()

	// Create a user first
	_, err := store.Create(ctx, "error@example.com", "Error", RoleAdmin)
	require.NoError(t, err)

	// Close store to simulate storage error
	_ = store.Close()

	_, err = adapter.CheckPermission(ctx, "error@example.com", rbac.NewPermission(rbac.ResourceKeys, rbac.ActionRead))
	assert.Error(t, err)
}

func TestUserRBACAdapter_GetUserRoles_StorageError(t *testing.T) {
	adapter, store, cleanup := newTestRBACAdapter(t)
	defer cleanup()

	ctx := context.Background()

	// Close store to simulate storage error
	_ = store.Close()

	_, err := adapter.GetUserRoles(ctx, "error@example.com")
	assert.Error(t, err)
}

func TestUserRBACAdapter_ListPermissions_InvalidRole(t *testing.T) {
	adapter, store, cleanup := newTestRBACAdapter(t)
	defer cleanup()

	ctx := context.Background()

	// Create user with a custom invalid role (manually)
	user, err := store.Create(ctx, "invalid@example.com", "Invalid", RoleAdmin)
	require.NoError(t, err)

	// Manually set an invalid role
	user.Role = Role("nonexistent-role")
	err = store.Update(ctx, user)
	require.NoError(t, err)

	// Should return empty permissions for non-existent role
	permissions, err := adapter.ListPermissions(ctx, "invalid@example.com")
	require.NoError(t, err)
	assert.Len(t, permissions, 0)
}
