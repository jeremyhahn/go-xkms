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
)

// Typed errors for RBAC operations.
var (
	// ErrConflictingRoles is returned when assigning a role would violate
	// FIPS 140-3 separation of duties constraints.
	ErrConflictingRoles = errors.New("rbac: conflicting role assignment violates separation of duties")

	// ErrNilRole is returned when a nil role is passed to an operation.
	ErrNilRole = errors.New("rbac: role cannot be nil")

	// ErrEmptyRoleName is returned when a role with an empty name is passed.
	ErrEmptyRoleName = errors.New("rbac: role name cannot be empty")

	// ErrRoleNotFound is returned when a role does not exist.
	ErrRoleNotFound = errors.New("rbac: role not found")

	// ErrRoleExists is returned when creating a role that already exists.
	ErrRoleExists = errors.New("rbac: role already exists")

	// ErrSystemRole is returned when attempting to modify a system role.
	ErrSystemRole = errors.New("rbac: cannot modify system role")

	// ErrRoleInUse is returned when deleting a role still assigned to subjects.
	ErrRoleInUse = errors.New("rbac: role still assigned to subjects")

	// ErrPermissionExists is returned when granting a permission that already exists.
	ErrPermissionExists = errors.New("rbac: permission already exists")

	// ErrPermissionNotFound is returned when revoking a permission that does not exist.
	ErrPermissionNotFound = errors.New("rbac: permission not found")

	// ErrNoRolesAssigned is returned when revoking a role from a subject with no roles.
	ErrNoRolesAssigned = errors.New("rbac: subject has no roles assigned")

	// ErrRoleNotAssigned is returned when revoking a role that is not assigned to the subject.
	ErrRoleNotAssigned = errors.New("rbac: role not assigned to subject")
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

// Common predefined roles aligned with FIPS 140-2/3 separation of duties
const (
	RoleAdmin     = "admin"
	RoleOperator  = "operator"
	RoleAuditor   = "auditor"
	RoleUser      = "user"
	RoleCustodian = "custodian"
	RoleSO        = "so"
)

// Common resources
const (
	ResourceAll          = "*"
	ResourceKeys         = "keys"
	ResourceSecrets      = "secrets"
	ResourceCertificates = "certificates"
	ResourceBackends     = "backends"
	ResourceUsers        = "users"
	ResourceRoles        = "roles"
	ResourceAudit        = "audit"
	ResourceSystem       = "system"
	ResourceBarrier      = "barrier"
	ResourceInit         = "init"
	ResourcePIN          = "pin"
	ResourceTenants      = "tenants"
	ResourceCredentials  = "credentials"
	ResourcePasswords    = "passwords"
)

// Common actions
const (
	ActionCreate       = "create"
	ActionRead         = "read"
	ActionUpdate       = "update"
	ActionDelete       = "delete"
	ActionList         = "list"
	ActionSign         = "sign"
	ActionVerify       = "verify"
	ActionEncrypt      = "encrypt"
	ActionDecrypt      = "decrypt"
	ActionImport       = "import"
	ActionExport       = "export"
	ActionRotate       = "rotate"
	ActionManage       = "manage"
	ActionAll          = "*"
	ActionProvideShare = "provide-share"
	ActionReceiveShare = "receive-share"
	ActionSignCSR      = "sign-csr"
	ActionZeroize      = "zeroize"
	ActionResetPIN     = "reset-pin"
	ActionSeal         = "seal"
	ActionUnseal       = "unseal"
	ActionInitialize   = "initialize"
	ActionSubmit       = "submit"
)

// NewPermission creates a new permission with the given resource and action
func NewPermission(resource, action string) Permission {
	return Permission{
		Resource: resource,
		Action:   action,
	}
}

// Matches checks if a permission matches another permission considering wildcards.
// A wildcard resource (ResourceAll / "*") matches any resource. A wildcard action
// (ActionAll / "*") matches any action. A permission with both wildcards (*:*)
// matches every possible permission.
func (p Permission) Matches(other Permission) bool {
	resourceMatch := p.Resource == other.Resource || p.Resource == ResourceAll || other.Resource == ResourceAll
	actionMatch := p.Action == other.Action || p.Action == ActionAll || other.Action == ActionAll
	return resourceMatch && actionMatch
}

// ConflictingRolePairs defines role pairs that cannot be assigned to the same user.
// Per FIPS 140-3 7.4: "Crypto Officer and User roles are mutually exclusive."
var ConflictingRolePairs = [][2]string{
	{RoleSO, RoleOperator}, // SO cannot perform crypto operations
	{RoleSO, RoleUser},     // SO cannot perform crypto operations
}

// ValidateRoleAssignment checks if assigning a new role to a subject would
// violate separation of duties constraints (FIPS 140-3 7.4).
// It returns ErrConflictingRoles if the assignment would create a conflict.
func ValidateRoleAssignment(existingRoles []string, newRole string) error {
	for _, pair := range ConflictingRolePairs {
		for _, existing := range existingRoles {
			if (existing == pair[0] && newRole == pair[1]) ||
				(existing == pair[1] && newRole == pair[0]) {
				return ErrConflictingRoles
			}
		}
	}
	return nil
}
