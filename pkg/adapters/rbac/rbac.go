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
)

// Permission represents a specific permission on a resource
type Permission struct {
	// Resource is the target of the permission (e.g., "keys", "secrets", "certificates")
	Resource string

	// Action is the operation being performed (e.g., "read", "write", "delete", "list")
	Action string
}

// String returns a string representation of the permission in resource:action format
func (p Permission) String() string {
	return fmt.Sprintf("%s:%s", p.Resource, p.Action)
}

// Role represents a named set of permissions
type Role struct {
	// Name is the unique identifier for the role
	Name string

	// Description provides context about the role's purpose
	Description string

	// Permissions is the set of permissions granted to this role
	Permissions []Permission

	// Metadata contains additional role information
	Metadata map[string]interface{}
}

// HasPermission checks if the role has a specific permission
func (r *Role) HasPermission(permission Permission) bool {
	for _, p := range r.Permissions {
		if p.Resource == permission.Resource && p.Action == permission.Action {
			return true
		}
	}
	return false
}

// RBACAdapter is the interface for Role-Based Access Control adapters.
// Applications implement this interface to integrate RBAC into their systems.
type RBACAdapter interface {
	// CheckPermission verifies if a subject has a specific permission on a resource.
	// Returns true if the subject has the permission, false otherwise.
	CheckPermission(ctx context.Context, subject string, permission Permission) (bool, error)

	// AssignRole assigns a role to a subject.
	// Returns an error if the role doesn't exist or assignment fails.
	AssignRole(ctx context.Context, subject string, roleName string) error

	// RevokeRole removes a role from a subject.
	// Returns an error if the role wasn't assigned or revocation fails.
	RevokeRole(ctx context.Context, subject string, roleName string) error

	// GetUserRoles retrieves all roles assigned to a subject.
	GetUserRoles(ctx context.Context, subject string) ([]string, error)

	// CreateRole creates a new role with the specified permissions.
	// Returns an error if the role already exists.
	CreateRole(ctx context.Context, role *Role) error

	// UpdateRole updates an existing role's permissions.
	// Returns an error if the role doesn't exist.
	UpdateRole(ctx context.Context, role *Role) error

	// DeleteRole removes a role from the system.
	// Returns an error if the role doesn't exist or is assigned to users.
	DeleteRole(ctx context.Context, roleName string) error

	// GetRole retrieves a role by name.
	// Returns an error if the role doesn't exist.
	GetRole(ctx context.Context, roleName string) (*Role, error)

	// ListRoles retrieves all roles in the system.
	ListRoles(ctx context.Context) ([]*Role, error)

	// ListPermissions retrieves all permissions for a specific subject.
	// This aggregates permissions from all roles assigned to the subject.
	ListPermissions(ctx context.Context, subject string) ([]Permission, error)

	// GrantPermission grants a specific permission to a role.
	// Returns an error if the role doesn't exist or permission already exists.
	GrantPermission(ctx context.Context, roleName string, permission Permission) error

	// RevokePermission removes a specific permission from a role.
	// Returns an error if the role doesn't exist or permission not found.
	RevokePermission(ctx context.Context, roleName string, permission Permission) error
}

// Common predefined roles
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleAuditor  = "auditor"
	RoleUser     = "user"
	RoleReadOnly = "readonly"
	RoleGuest    = "guest"
)

// Common resources
const (
	ResourceKeys         = "keys"
	ResourceSecrets      = "secrets"
	ResourceCertificates = "certificates"
	ResourceBackends     = "backends"
	ResourceUsers        = "users"
	ResourceRoles        = "roles"
	ResourceAudit        = "audit"
	ResourceSystem       = "system"
)

// Common actions
const (
	ActionCreate  = "create"
	ActionRead    = "read"
	ActionUpdate  = "update"
	ActionDelete  = "delete"
	ActionList    = "list"
	ActionSign    = "sign"
	ActionVerify  = "verify"
	ActionEncrypt = "encrypt"
	ActionDecrypt = "decrypt"
	ActionImport  = "import"
	ActionExport  = "export"
	ActionRotate  = "rotate"
	ActionManage  = "manage"
	ActionAll     = "*"
)

// NewPermission creates a new permission with the given resource and action
func NewPermission(resource, action string) Permission {
	return Permission{
		Resource: resource,
		Action:   action,
	}
}

// WildcardMatch checks if a permission matches another permission considering wildcards
func (p Permission) Matches(other Permission) bool {
	resourceMatch := p.Resource == other.Resource || p.Resource == ActionAll || other.Resource == ActionAll
	actionMatch := p.Action == other.Action || p.Action == ActionAll || other.Action == ActionAll
	return resourceMatch && actionMatch
}
