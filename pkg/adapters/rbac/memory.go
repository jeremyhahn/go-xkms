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

// initializeDefaultRoles creates standard roles for common use cases
func (m *MemoryRBACAdapter) initializeDefaultRoles() {
	// Admin role - full access to everything
	adminRole := &Role{
		Name:        RoleAdmin,
		Description: "Full administrative access to all resources",
		Permissions: []Permission{
			{Resource: ActionAll, Action: ActionAll},
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

	// ReadOnly role - read and list only
	readOnlyRole := &Role{
		Name:        RoleReadOnly,
		Description: "Read-only access to non-sensitive information",
		Permissions: []Permission{
			{Resource: ResourceKeys, Action: ActionList},
			{Resource: ResourceCertificates, Action: ActionList},
			{Resource: ResourceCertificates, Action: ActionRead},
		},
		Metadata: map[string]interface{}{
			"system": true,
		},
	}

	// Guest role - minimal access
	guestRole := &Role{
		Name:        RoleGuest,
		Description: "Minimal guest access",
		Permissions: []Permission{
			{Resource: ResourceKeys, Action: ActionList},
		},
		Metadata: map[string]interface{}{
			"system": true,
		},
	}

	m.roles[RoleAdmin] = adminRole
	m.roles[RoleOperator] = operatorRole
	m.roles[RoleAuditor] = auditorRole
	m.roles[RoleUser] = userRole
	m.roles[RoleReadOnly] = readOnlyRole
	m.roles[RoleGuest] = guestRole
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
		return fmt.Errorf("role '%s' does not exist", roleName)
	}

	// Initialize user's role map if needed
	if m.userRoles[subject] == nil {
		m.userRoles[subject] = make(map[string]bool)
	}

	// Assign role
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
		return fmt.Errorf("subject '%s' has no roles assigned", subject)
	}

	// Check if user has this specific role
	if !roleMap[roleName] {
		return fmt.Errorf("subject '%s' does not have role '%s'", subject, roleName)
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
		return fmt.Errorf("role cannot be nil")
	}

	if role.Name == "" {
		return fmt.Errorf("role name cannot be empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if role already exists
	if _, exists := m.roles[role.Name]; exists {
		return fmt.Errorf("role '%s' already exists", role.Name)
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
		return fmt.Errorf("role cannot be nil")
	}

	if role.Name == "" {
		return fmt.Errorf("role name cannot be empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if role exists
	existingRole, exists := m.roles[role.Name]
	if !exists {
		return fmt.Errorf("role '%s' does not exist", role.Name)
	}

	// Don't allow updating system roles
	if isSystem, ok := existingRole.Metadata["system"].(bool); ok && isSystem {
		return fmt.Errorf("cannot update system role '%s'", role.Name)
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
		return fmt.Errorf("role '%s' does not exist", roleName)
	}

	// Don't allow deleting system roles
	if isSystem, ok := role.Metadata["system"].(bool); ok && isSystem {
		return fmt.Errorf("cannot delete system role '%s'", roleName)
	}

	// Check if role is assigned to any users
	for subject, roleMap := range m.userRoles {
		if roleMap[roleName] {
			return fmt.Errorf("cannot delete role '%s': still assigned to subject '%s'", roleName, subject)
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
		return nil, fmt.Errorf("role '%s' does not exist", roleName)
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
		return fmt.Errorf("role '%s' does not exist", roleName)
	}

	// Don't allow modifying system roles
	if isSystem, ok := role.Metadata["system"].(bool); ok && isSystem {
		return fmt.Errorf("cannot modify system role '%s'", roleName)
	}

	// Check if permission already exists
	for _, p := range role.Permissions {
		if p.Resource == permission.Resource && p.Action == permission.Action {
			return fmt.Errorf("permission '%s' already exists in role '%s'", permission.String(), roleName)
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
		return fmt.Errorf("role '%s' does not exist", roleName)
	}

	// Don't allow modifying system roles
	if isSystem, ok := role.Metadata["system"].(bool); ok && isSystem {
		return fmt.Errorf("cannot modify system role '%s'", roleName)
	}

	// Find and remove permission
	found := false
	for i, p := range role.Permissions {
		if p.Resource == permission.Resource && p.Action == permission.Action {
			role.Permissions = append(role.Permissions[:i], role.Permissions[i+1:]...)
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("permission '%s' not found in role '%s'", permission.String(), roleName)
	}

	return nil
}
