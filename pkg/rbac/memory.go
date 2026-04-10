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
	"sync"
)

// MemoryRBACAdapter provides an in-memory implementation of RBACAdapter.
// Suitable for development, testing, and single-instance deployments.
// For production multi-instance deployments, implement a database-backed adapter.
type MemoryRBACAdapter struct {
	// userRoles maps subject -> list of role names
	userRoles map[string]map[string]bool

	// roles maps role name -> Role
	roles map[string]*Role

	mu sync.RWMutex
}

var _ RBACAdapter = (*MemoryRBACAdapter)(nil)

// NewMemoryRBACAdapter creates a new in-memory RBAC adapter with optional predefined roles
func NewMemoryRBACAdapter(withDefaults bool) *MemoryRBACAdapter {
	adapter := &MemoryRBACAdapter{
		userRoles: make(map[string]map[string]bool),
		roles:     make(map[string]*Role),
	}

	if withDefaults {
		adapter.initializeDefaultRoles()
	}

	return adapter
}

// initializeDefaultRoles creates FIPS 140-2/3 compliant roles for separation of duties
func (m *MemoryRBACAdapter) initializeDefaultRoles() {
	// Admin role - administrative access to keys, certificates, users, and secrets within a tenant.
	// Admin has all Operator permissions plus user management, role management, audit viewing,
	// secret management, and barrier read. Admin is NOT the same as SO (no module init, PIN
	// management, or tenant management cross-tenant).
	adminRole := &Role{
		Name:        RoleAdmin,
		Description: "Administrative access to keys, certificates, users, and secrets within a tenant",
		Permissions: []Permission{
			// All key operations (including crypto - unlike SO)
			{Resource: ResourceKeys, Action: ActionAll},
			// All certificate operations
			{Resource: ResourceCertificates, Action: ActionAll},
			// Secret management
			{Resource: ResourceSecrets, Action: ActionAll},
			// User management
			{Resource: ResourceUsers, Action: ActionAll},
			// Role management
			{Resource: ResourceRoles, Action: ActionAll},
			// Backend viewing
			{Resource: ResourceBackends, Action: ActionRead},
			{Resource: ResourceBackends, Action: ActionList},
			// Audit viewing
			{Resource: ResourceAudit, Action: ActionRead},
			{Resource: ResourceAudit, Action: ActionList},
			// Barrier read (not manage)
			{Resource: ResourceBarrier, Action: ActionRead},
			// Credential management
			{Resource: ResourceCredentials, Action: ActionAll},
		},
		Metadata: map[string]interface{}{
			"system": true,
		},
	}

	// Operator role - manage keys and certificates
	operatorRole := &Role{
		Name:        RoleOperator,
		Description: "Manage keys, certificates, and cryptographic operations",
		Permissions: []Permission{
			{Resource: ResourceKeys, Action: ActionAll},
			{Resource: ResourceCertificates, Action: ActionAll},
			{Resource: ResourceSecrets, Action: ActionCreate},
			{Resource: ResourceSecrets, Action: ActionRead},
			{Resource: ResourceSecrets, Action: ActionUpdate},
			{Resource: ResourceSecrets, Action: ActionDelete},
		},
		Metadata: map[string]interface{}{
			"system": true,
		},
	}

	// Auditor role - read-only access for compliance
	auditorRole := &Role{
		Name:        RoleAuditor,
		Description: "Read-only access for audit and compliance",
		Permissions: []Permission{
			{Resource: ResourceAudit, Action: ActionRead},
			{Resource: ResourceAudit, Action: ActionList},
			{Resource: ResourceKeys, Action: ActionList},
			{Resource: ResourceCertificates, Action: ActionList},
			{Resource: ResourceUsers, Action: ActionList},
		},
		Metadata: map[string]interface{}{
			"system": true,
		},
	}

	// User role - basic cryptographic operations
	userRole := &Role{
		Name:        RoleUser,
		Description: "Basic user with cryptographic operation permissions",
		Permissions: []Permission{
			{Resource: ResourceKeys, Action: ActionSign},
			{Resource: ResourceKeys, Action: ActionVerify},
			{Resource: ResourceKeys, Action: ActionEncrypt},
			{Resource: ResourceKeys, Action: ActionDecrypt},
			{Resource: ResourceSecrets, Action: ActionRead},
		},
		Metadata: map[string]interface{}{
			"system": true,
		},
	}

	// Custodian role - key ceremony participation and share management
	custodianRole := &Role{
		Name:        RoleCustodian,
		Description: "Key custodian for ceremony participation and share management",
		Permissions: []Permission{
			{Resource: ResourceBarrier, Action: ActionProvideShare},
			{Resource: ResourceBarrier, Action: ActionReceiveShare},
			{Resource: ResourceBarrier, Action: ActionRead},
		},
		Metadata: map[string]interface{}{
			"system": true,
		},
	}

	// SO (Security Officer) role - module initialization, PIN management, CSR signing, tenant management.
	// Per FIPS 140-2 AS10.03: "Crypto Officer and User roles are mutually exclusive."
	// SO CANNOT perform cryptographic operations (sign, encrypt, decrypt).
	soRole := &Role{
		Name:        RoleSO,
		Description: "Security Officer for module initialization, PIN management, and tenant administration",
		Permissions: []Permission{
			// Module initialization
			{Resource: ResourceInit, Action: ActionAll},
			// PIN management
			{Resource: ResourcePIN, Action: ActionAll},
			// User management
			{Resource: ResourceUsers, Action: ActionAll},
			// Role management
			{Resource: ResourceRoles, Action: ActionAll},
			// Certificate management (issue, store, delete - NOT use for crypto)
			{Resource: ResourceCertificates, Action: ActionAll},
			// Key lifecycle (list, read, delete, import, export - NOT sign/encrypt/decrypt)
			{Resource: ResourceKeys, Action: ActionList},
			{Resource: ResourceKeys, Action: ActionRead},
			{Resource: ResourceKeys, Action: ActionDelete},
			{Resource: ResourceKeys, Action: ActionImport},
			{Resource: ResourceKeys, Action: ActionExport},
			{Resource: ResourceKeys, Action: ActionCreate},
			// Backend management
			{Resource: ResourceBackends, Action: ActionAll},
			// Barrier management
			{Resource: ResourceBarrier, Action: ActionAll},
			// Audit reading
			{Resource: ResourceAudit, Action: ActionRead},
			{Resource: ResourceAudit, Action: ActionList},
			// System management
			{Resource: ResourceSystem, Action: ActionAll},
			// Tenant management
			{Resource: ResourceTenants, Action: ActionAll},
			// Credential management
			{Resource: ResourceCredentials, Action: ActionAll},
		},
		Metadata: map[string]interface{}{
			"system": true,
		},
	}

	m.roles[RoleAdmin] = adminRole
	m.roles[RoleOperator] = operatorRole
	m.roles[RoleAuditor] = auditorRole
	m.roles[RoleUser] = userRole
	m.roles[RoleCustodian] = custodianRole
	m.roles[RoleSO] = soRole
}

// CheckPermission verifies if a subject has a specific permission
func (m *MemoryRBACAdapter) CheckPermission(ctx context.Context, subject string, permission Permission) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Get user's roles
	roleNames, exists := m.userRoles[subject]
	if !exists || len(roleNames) == 0 {
		return false, nil
	}

	// Check each role for the permission
	for roleName := range roleNames {
		role, exists := m.roles[roleName]
		if !exists {
			continue
		}

		// Check if any permission in the role matches
		for _, p := range role.Permissions {
			if p.Matches(permission) {
				return true, nil
			}
		}
	}

	return false, nil
}

// AssignRole assigns a role to a subject
func (m *MemoryRBACAdapter) AssignRole(ctx context.Context, subject string, roleName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Verify role exists
	if _, exists := m.roles[roleName]; !exists {
		return ErrRoleNotFound
	}

	// Get existing roles for separation of duties validation
	existingRoles := make([]string, 0)
	if roleMap, exists := m.userRoles[subject]; exists {
		for r := range roleMap {
			existingRoles = append(existingRoles, r)
		}
	}

	// Validate separation of duties (FIPS 140-3 7.4)
	if err := ValidateRoleAssignment(existingRoles, roleName); err != nil {
		return err
	}

	// Initialize user's role map if needed
	if m.userRoles[subject] == nil {
		m.userRoles[subject] = make(map[string]bool)
	}

	m.userRoles[subject][roleName] = true
	return nil
}

// RevokeRole removes a role from a subject
func (m *MemoryRBACAdapter) RevokeRole(ctx context.Context, subject string, roleName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if user has any roles
	roleMap, exists := m.userRoles[subject]
	if !exists {
		return ErrNoRolesAssigned
	}

	// Check if user has this specific role
	if !roleMap[roleName] {
		return ErrRoleNotAssigned
	}

	// Revoke role
	delete(roleMap, roleName)

	// Clean up empty map
	if len(roleMap) == 0 {
		delete(m.userRoles, subject)
	}

	return nil
}

// GetUserRoles retrieves all roles assigned to a subject
func (m *MemoryRBACAdapter) GetUserRoles(ctx context.Context, subject string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	roleMap, exists := m.userRoles[subject]
	if !exists || len(roleMap) == 0 {
		return []string{}, nil
	}

	roles := make([]string, 0, len(roleMap))
	for roleName := range roleMap {
		roles = append(roles, roleName)
	}

	return roles, nil
}

// CreateRole creates a new role
func (m *MemoryRBACAdapter) CreateRole(ctx context.Context, role *Role) error {
	if role == nil {
		return ErrNilRole
	}

	if role.Name == "" {
		return ErrEmptyRoleName
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if role already exists
	if _, exists := m.roles[role.Name]; exists {
		return ErrRoleExists
	}

	// Create a copy to prevent external modification
	newRole := &Role{
		Name:        role.Name,
		Description: role.Description,
		Permissions: make([]Permission, len(role.Permissions)),
		Metadata:    make(map[string]interface{}),
	}

	copy(newRole.Permissions, role.Permissions)
	for k, v := range role.Metadata {
		newRole.Metadata[k] = v
	}

	m.roles[role.Name] = newRole

	return nil
}

// UpdateRole updates an existing role's permissions
func (m *MemoryRBACAdapter) UpdateRole(ctx context.Context, role *Role) error {
	if role == nil {
		return ErrNilRole
	}

	if role.Name == "" {
		return ErrEmptyRoleName
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if role exists
	existingRole, exists := m.roles[role.Name]
	if !exists {
		return ErrRoleNotFound
	}

	// Don't allow updating system roles
	if isSystem, ok := existingRole.Metadata["system"].(bool); ok && isSystem {
		return ErrSystemRole
	}

	// Update the role
	updatedRole := &Role{
		Name:        role.Name,
		Description: role.Description,
		Permissions: make([]Permission, len(role.Permissions)),
		Metadata:    make(map[string]interface{}),
	}

	copy(updatedRole.Permissions, role.Permissions)
	for k, v := range role.Metadata {
		updatedRole.Metadata[k] = v
	}

	m.roles[role.Name] = updatedRole

	return nil
}

// DeleteRole removes a role from the system
func (m *MemoryRBACAdapter) DeleteRole(ctx context.Context, roleName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if role exists
	role, exists := m.roles[roleName]
	if !exists {
		return ErrRoleNotFound
	}

	// Don't allow deleting system roles
	if isSystem, ok := role.Metadata["system"].(bool); ok && isSystem {
		return ErrSystemRole
	}

	// Check if role is assigned to any users
	for _, roleMap := range m.userRoles {
		if roleMap[roleName] {
			return ErrRoleInUse
		}
	}

	// Delete the role
	delete(m.roles, roleName)

	return nil
}

// GetRole retrieves a role by name
func (m *MemoryRBACAdapter) GetRole(ctx context.Context, roleName string) (*Role, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	role, exists := m.roles[roleName]
	if !exists {
		return nil, ErrRoleNotFound
	}

	// Return a copy to prevent external modification
	roleCopy := &Role{
		Name:        role.Name,
		Description: role.Description,
		Permissions: make([]Permission, len(role.Permissions)),
		Metadata:    make(map[string]interface{}),
	}

	copy(roleCopy.Permissions, role.Permissions)
	for k, v := range role.Metadata {
		roleCopy.Metadata[k] = v
	}

	return roleCopy, nil
}

// ListRoles retrieves all roles in the system
func (m *MemoryRBACAdapter) ListRoles(ctx context.Context) ([]*Role, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	roles := make([]*Role, 0, len(m.roles))
	for _, role := range m.roles {
		// Return a copy to prevent external modification
		roleCopy := &Role{
			Name:        role.Name,
			Description: role.Description,
			Permissions: make([]Permission, len(role.Permissions)),
			Metadata:    make(map[string]interface{}),
		}

		copy(roleCopy.Permissions, role.Permissions)
		for k, v := range role.Metadata {
			roleCopy.Metadata[k] = v
		}

		roles = append(roles, roleCopy)
	}

	return roles, nil
}

// ListPermissions retrieves all permissions for a specific subject
func (m *MemoryRBACAdapter) ListPermissions(ctx context.Context, subject string) ([]Permission, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	roleMap, exists := m.userRoles[subject]
	if !exists || len(roleMap) == 0 {
		return []Permission{}, nil
	}

	// Use a map to deduplicate permissions
	permMap := make(map[string]Permission)

	// Aggregate permissions from all roles
	for roleName := range roleMap {
		role, exists := m.roles[roleName]
		if !exists {
			continue
		}

		for _, perm := range role.Permissions {
			key := perm.String()
			permMap[key] = perm
		}
	}

	// Convert map to slice
	permissions := make([]Permission, 0, len(permMap))
	for _, perm := range permMap {
		permissions = append(permissions, perm)
	}

	return permissions, nil
}

// GrantPermission grants a specific permission to a role
func (m *MemoryRBACAdapter) GrantPermission(ctx context.Context, roleName string, permission Permission) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if role exists
	role, exists := m.roles[roleName]
	if !exists {
		return ErrRoleNotFound
	}

	// Don't allow modifying system roles
	if isSystem, ok := role.Metadata["system"].(bool); ok && isSystem {
		return ErrSystemRole
	}

	// Check if permission already exists
	for _, p := range role.Permissions {
		if p.Resource == permission.Resource && p.Action == permission.Action {
			return ErrPermissionExists
		}
	}

	// Add permission
	role.Permissions = append(role.Permissions, permission)

	return nil
}

// RevokePermission removes a specific permission from a role
func (m *MemoryRBACAdapter) RevokePermission(ctx context.Context, roleName string, permission Permission) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if role exists
	role, exists := m.roles[roleName]
	if !exists {
		return ErrRoleNotFound
	}

	// Don't allow modifying system roles
	if isSystem, ok := role.Metadata["system"].(bool); ok && isSystem {
		return ErrSystemRole
	}

	// Find and remove permission
	for i, p := range role.Permissions {
		if p.Resource == permission.Resource && p.Action == permission.Action {
			role.Permissions = append(role.Permissions[:i], role.Permissions[i+1:]...)
			return nil
		}
	}

	return ErrPermissionNotFound
}
