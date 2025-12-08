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

	"github.com/jeremyhahn/go-keychain/pkg/adapters/rbac"
)

// UserRBACAdapter bridges the User store with the RBAC system.
// It provides RBAC functionality using the user's role from the User store.
// The subject used for RBAC operations is the user's username.
type UserRBACAdapter struct {
	store         Store
	memoryAdapter *rbac.MemoryRBACAdapter
}

// NewUserRBACAdapter creates a new UserRBACAdapter that uses the User store
// for role information while leveraging the MemoryRBACAdapter for permission
// definitions and lookups.
func NewUserRBACAdapter(store Store) *UserRBACAdapter {
	return &UserRBACAdapter{
		store:         store,
		memoryAdapter: rbac.NewMemoryRBACAdapter(true), // Use default role definitions
	}
}

// CheckPermission verifies if a subject (username) has a specific permission.
// It looks up the user's role from the store and checks if that role has the permission.
func (a *UserRBACAdapter) CheckPermission(ctx context.Context, subject string, permission rbac.Permission) (bool, error) {
	// Look up the user by username (subject)
	user, err := a.store.GetByUsername(ctx, subject)
	if err != nil {
		if err == ErrUserNotFound {
			return false, nil // No user means no permission
		}
		return false, err
	}

	// Check if user is enabled
	if !user.Enabled {
		return false, nil
	}

	// Get the role definition and check permission
	role, err := a.memoryAdapter.GetRole(ctx, string(user.Role))
	if err != nil {
		// If role doesn't exist in RBAC system, deny access
		return false, nil
	}

	// Check if the role has the requested permission
	for _, p := range role.Permissions {
		if p.Matches(permission) {
			return true, nil
		}
	}

	return false, nil
}

// AssignRole assigns a role to a user (updates the user's role in the store).
// The subject is the username.
func (a *UserRBACAdapter) AssignRole(ctx context.Context, subject string, roleName string) error {
	// Validate role exists
	if _, err := a.memoryAdapter.GetRole(ctx, roleName); err != nil {
		return err
	}

	// Look up user
	user, err := a.store.GetByUsername(ctx, subject)
	if err != nil {
		return err
	}

	// Update role
	user.Role = Role(roleName)
	return a.store.Update(ctx, user)
}

// RevokeRole removes a role from a user (sets to guest role).
// Since each user has exactly one role, this sets them to the lowest privilege role.
func (a *UserRBACAdapter) RevokeRole(ctx context.Context, subject string, roleName string) error {
	// Look up user
	user, err := a.store.GetByUsername(ctx, subject)
	if err != nil {
		return err
	}

	// Check if user has this role
	if string(user.Role) != roleName {
		return ErrInvalidRole
	}

	// Set to guest role (lowest privilege)
	user.Role = RoleGuest
	return a.store.Update(ctx, user)
}

// GetUserRoles retrieves all roles assigned to a subject.
// Since a user has exactly one role, this returns a single-element slice.
func (a *UserRBACAdapter) GetUserRoles(ctx context.Context, subject string) ([]string, error) {
	user, err := a.store.GetByUsername(ctx, subject)
	if err != nil {
		if err == ErrUserNotFound {
			return []string{}, nil
		}
		return nil, err
	}

	return []string{string(user.Role)}, nil
}

// CreateRole creates a new role with the specified permissions.
// Delegates to the underlying memory adapter.
func (a *UserRBACAdapter) CreateRole(ctx context.Context, role *rbac.Role) error {
	return a.memoryAdapter.CreateRole(ctx, role)
}

// UpdateRole updates an existing role's permissions.
// Delegates to the underlying memory adapter.
func (a *UserRBACAdapter) UpdateRole(ctx context.Context, role *rbac.Role) error {
	return a.memoryAdapter.UpdateRole(ctx, role)
}

// DeleteRole removes a role from the system.
// Delegates to the underlying memory adapter.
func (a *UserRBACAdapter) DeleteRole(ctx context.Context, roleName string) error {
	return a.memoryAdapter.DeleteRole(ctx, roleName)
}

// GetRole retrieves a role by name.
// Delegates to the underlying memory adapter.
func (a *UserRBACAdapter) GetRole(ctx context.Context, roleName string) (*rbac.Role, error) {
	return a.memoryAdapter.GetRole(ctx, roleName)
}

// ListRoles retrieves all roles in the system.
// Delegates to the underlying memory adapter.
func (a *UserRBACAdapter) ListRoles(ctx context.Context) ([]*rbac.Role, error) {
	return a.memoryAdapter.ListRoles(ctx)
}

// ListPermissions retrieves all permissions for a specific subject.
// Looks up the user's role and returns permissions for that role.
func (a *UserRBACAdapter) ListPermissions(ctx context.Context, subject string) ([]rbac.Permission, error) {
	user, err := a.store.GetByUsername(ctx, subject)
	if err != nil {
		if err == ErrUserNotFound {
			return []rbac.Permission{}, nil
		}
		return nil, err
	}

	// Get role permissions
	role, err := a.memoryAdapter.GetRole(ctx, string(user.Role))
	if err != nil {
		return []rbac.Permission{}, nil
	}

	// Return a copy of permissions
	permissions := make([]rbac.Permission, len(role.Permissions))
	copy(permissions, role.Permissions)
	return permissions, nil
}

// GrantPermission grants a specific permission to a role.
// Delegates to the underlying memory adapter.
func (a *UserRBACAdapter) GrantPermission(ctx context.Context, roleName string, permission rbac.Permission) error {
	return a.memoryAdapter.GrantPermission(ctx, roleName, permission)
}

// RevokePermission removes a specific permission from a role.
// Delegates to the underlying memory adapter.
func (a *UserRBACAdapter) RevokePermission(ctx context.Context, roleName string, permission rbac.Permission) error {
	return a.memoryAdapter.RevokePermission(ctx, roleName, permission)
}

// Verify UserRBACAdapter implements rbac.RBACAdapter
var _ rbac.RBACAdapter = (*UserRBACAdapter)(nil)

// RoleToRBAC maps a user.Role to the corresponding RBAC role name.
func RoleToRBAC(role Role) string {
	switch role {
	case RoleAdmin:
		return rbac.RoleAdmin
	case RoleOperator:
		return rbac.RoleOperator
	case RoleAuditor:
		return rbac.RoleAuditor
	case RoleUser:
		return rbac.RoleUser
	case RoleReadOnly:
		return rbac.RoleReadOnly
	case RoleGuest:
		return rbac.RoleGuest
	default:
		return rbac.RoleGuest // Default to lowest privilege
	}
}

// RBACToRole maps an RBAC role name to the corresponding user.Role.
func RBACToRole(roleName string) Role {
	switch roleName {
	case rbac.RoleAdmin:
		return RoleAdmin
	case rbac.RoleOperator:
		return RoleOperator
	case rbac.RoleAuditor:
		return RoleAuditor
	case rbac.RoleUser:
		return RoleUser
	case rbac.RoleReadOnly:
		return RoleReadOnly
	case rbac.RoleGuest:
		return RoleGuest
	default:
		return RoleGuest
	}
}
