# Role-Based Access Control (RBAC)

## Overview

The go-keychain library provides a pluggable RBAC adapter for fine-grained permission management. This allows applications to control access to keys, certificates, and other resources based on user roles and permissions.

## Architecture

The RBAC system consists of three main components:

1. **Permission** - A resource:action pair (e.g., `keys:sign`)
2. **Role** - A named collection of permissions
3. **RBACAdapter** - The interface for checking and managing permissions

## Interface

Located in `pkg/adapters/rbac/rbac.go`:

```go
type RBACAdapter interface {
    // CheckPermission verifies if a subject has a specific permission
    CheckPermission(ctx context.Context, subject string, permission Permission) (bool, error)

    // AssignRole assigns a role to a subject
    AssignRole(ctx context.Context, subject string, roleName string) error

    // RevokeRole removes a role from a subject
    RevokeRole(ctx context.Context, subject string, roleName string) error

    // GetUserRoles retrieves all roles assigned to a subject
    GetUserRoles(ctx context.Context, subject string) ([]string, error)

    // CreateRole creates a new role with the specified permissions
    CreateRole(ctx context.Context, role *Role) error

    // UpdateRole updates an existing role's permissions
    UpdateRole(ctx context.Context, role *Role) error

    // DeleteRole removes a role from the system
    DeleteRole(ctx context.Context, roleName string) error

    // GetRole retrieves a role by name
    GetRole(ctx context.Context, roleName string) (*Role, error)

    // ListRoles retrieves all roles in the system
    ListRoles(ctx context.Context) ([]*Role, error)

    // ListPermissions retrieves all permissions for a specific subject
    ListPermissions(ctx context.Context, subject string) ([]Permission, error)

    // GrantPermission grants a specific permission to a role
    GrantPermission(ctx context.Context, roleName string, permission Permission) error

    // RevokePermission removes a specific permission from a role
    RevokePermission(ctx context.Context, roleName string, permission Permission) error
}
```

## Permission Model

### Permission Structure

```go
type Permission struct {
    Resource string  // Target resource (e.g., "keys", "certificates")
    Action   string  // Operation (e.g., "read", "sign", "delete")
}
```

### Predefined Resources

| Constant | Value | Description |
|----------|-------|-------------|
| `ResourceKeys` | `keys` | Cryptographic keys |
| `ResourceSecrets` | `secrets` | Secret values |
| `ResourceCertificates` | `certificates` | X.509 certificates |
| `ResourceBackends` | `backends` | Key storage backends |
| `ResourceUsers` | `users` | User accounts |
| `ResourceRoles` | `roles` | RBAC roles |
| `ResourceAudit` | `audit` | Audit logs |
| `ResourceSystem` | `system` | System configuration |

### Predefined Actions

| Constant | Value | Description |
|----------|-------|-------------|
| `ActionCreate` | `create` | Create new resources |
| `ActionRead` | `read` | Read resource details |
| `ActionUpdate` | `update` | Modify resources |
| `ActionDelete` | `delete` | Remove resources |
| `ActionList` | `list` | List resources |
| `ActionSign` | `sign` | Sign data with keys |
| `ActionVerify` | `verify` | Verify signatures |
| `ActionEncrypt` | `encrypt` | Encrypt data |
| `ActionDecrypt` | `decrypt` | Decrypt data |
| `ActionImport` | `import` | Import keys/certs |
| `ActionExport` | `export` | Export keys/certs |
| `ActionRotate` | `rotate` | Rotate keys |
| `ActionManage` | `manage` | Full management access |
| `ActionAll` | `*` | Wildcard (all actions) |

### Wildcard Matching

Permissions support wildcards for both resource and action:

```go
// Grant all actions on keys
Permission{Resource: "keys", Action: "*"}

// Grant read on all resources
Permission{Resource: "*", Action: "read"}

// Grant everything (superadmin)
Permission{Resource: "*", Action: "*"}
```

## Default Roles

When using `NewMemoryRBACAdapter(true)`, these roles are created:

### admin
Full administrative access to all resources.
```go
Permissions: []Permission{
    {Resource: "*", Action: "*"},
}
```

### operator
Manage keys, certificates, and cryptographic operations.
```go
Permissions: []Permission{
    {Resource: "keys", Action: "*"},
    {Resource: "certificates", Action: "*"},
    {Resource: "secrets", Action: "create"},
    {Resource: "secrets", Action: "read"},
    {Resource: "secrets", Action: "update"},
    {Resource: "secrets", Action: "delete"},
}
```

### auditor
Read-only access for audit and compliance.
```go
Permissions: []Permission{
    {Resource: "audit", Action: "read"},
    {Resource: "audit", Action: "list"},
    {Resource: "keys", Action: "list"},
    {Resource: "certificates", Action: "list"},
    {Resource: "users", Action: "list"},
}
```

### user
Basic user with cryptographic operation permissions.
```go
Permissions: []Permission{
    {Resource: "keys", Action: "sign"},
    {Resource: "keys", Action: "verify"},
    {Resource: "keys", Action: "encrypt"},
    {Resource: "keys", Action: "decrypt"},
    {Resource: "secrets", Action: "read"},
}
```

### readonly
Read-only access to non-sensitive information.
```go
Permissions: []Permission{
    {Resource: "keys", Action: "list"},
    {Resource: "certificates", Action: "list"},
    {Resource: "certificates", Action: "read"},
}
```

### guest
Minimal guest access.
```go
Permissions: []Permission{
    {Resource: "keys", Action: "list"},
}
```

## Usage

### Basic Setup

```go
package main

import (
    "context"
    "github.com/jeremyhahn/go-keychain/pkg/adapters/rbac"
)

func main() {
    ctx := context.Background()

    // Create adapter with default roles
    adapter := rbac.NewMemoryRBACAdapter(true)

    // Assign a role to a user
    err := adapter.AssignRole(ctx, "alice@example.com", rbac.RoleOperator)
    if err != nil {
        panic(err)
    }

    // Check permissions
    canSign, _ := adapter.CheckPermission(ctx, "alice@example.com", rbac.Permission{
        Resource: rbac.ResourceKeys,
        Action:   rbac.ActionSign,
    })
    // canSign = true (operator has keys:*)
}
```

### Creating Custom Roles

```go
// Create a custom role for DevOps team
devOpsRole := &rbac.Role{
    Name:        "devops",
    Description: "DevOps team - manage keys and certificates",
    Permissions: []rbac.Permission{
        {Resource: rbac.ResourceKeys, Action: rbac.ActionCreate},
        {Resource: rbac.ResourceKeys, Action: rbac.ActionRotate},
        {Resource: rbac.ResourceKeys, Action: rbac.ActionList},
        {Resource: rbac.ResourceKeys, Action: rbac.ActionRead},
        {Resource: rbac.ResourceCertificates, Action: rbac.ActionAll},
        {Resource: rbac.ResourceAudit, Action: rbac.ActionRead},
    },
    Metadata: map[string]interface{}{
        "department": "engineering",
    },
}

err := adapter.CreateRole(ctx, devOpsRole)
if err != nil {
    panic(err)
}

// Assign to user
adapter.AssignRole(ctx, "bob@example.com", "devops")
```

### Multiple Roles

Users can have multiple roles. Permissions are aggregated:

```go
// Assign multiple roles
adapter.AssignRole(ctx, "charlie@example.com", rbac.RoleUser)
adapter.AssignRole(ctx, "charlie@example.com", rbac.RoleAuditor)

// Charlie now has permissions from both roles
perms, _ := adapter.ListPermissions(ctx, "charlie@example.com")
// Returns combined permissions from user + auditor roles
```

### HTTP Middleware Integration

```go
func RBACMiddleware(rbacAdapter rbac.RBACAdapter) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Get authenticated user from context
            identity := auth.GetIdentity(r.Context())
            if identity == nil {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }

            // Determine required permission from route
            permission := permissionForRoute(r.Method, r.URL.Path)

            // Check permission
            allowed, err := rbacAdapter.CheckPermission(r.Context(), identity.Subject, permission)
            if err != nil || !allowed {
                http.Error(w, "Forbidden", http.StatusForbidden)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}

func permissionForRoute(method, path string) rbac.Permission {
    switch {
    case method == "POST" && strings.HasPrefix(path, "/api/v1/keys"):
        return rbac.NewPermission(rbac.ResourceKeys, rbac.ActionCreate)
    case method == "GET" && strings.HasPrefix(path, "/api/v1/keys"):
        return rbac.NewPermission(rbac.ResourceKeys, rbac.ActionList)
    case strings.Contains(path, "/sign"):
        return rbac.NewPermission(rbac.ResourceKeys, rbac.ActionSign)
    case strings.Contains(path, "/encrypt"):
        return rbac.NewPermission(rbac.ResourceKeys, rbac.ActionEncrypt)
    case strings.Contains(path, "/decrypt"):
        return rbac.NewPermission(rbac.ResourceKeys, rbac.ActionDecrypt)
    default:
        return rbac.NewPermission(rbac.ResourceSystem, rbac.ActionRead)
    }
}
```

### Integrating with User Management

When using WebAuthn authentication with users, sync the user role to RBAC:

```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/user"
    "github.com/jeremyhahn/go-keychain/pkg/adapters/rbac"
)

// After successful WebAuthn login
func onUserLogin(ctx context.Context, u *user.User, rbacAdapter rbac.RBACAdapter) error {
    // Map user.Role to RBAC role
    return rbacAdapter.AssignRole(ctx, u.Username, user.RoleToRBAC(u.Role))
}

// Create an authorization service that combines both
type AuthzService struct {
    rbac      rbac.RBACAdapter
    userStore user.Store
}

func (s *AuthzService) CanPerform(ctx context.Context, userID []byte, perm rbac.Permission) (bool, error) {
    u, err := s.userStore.GetByID(ctx, userID)
    if err != nil {
        return false, err
    }

    if !u.Enabled {
        return false, nil
    }

    return s.rbac.CheckPermission(ctx, u.Username, perm)
}
```

The `pkg/user` package provides a `UserRBACAdapter` that wraps the user store and implements the `RBACAdapter` interface:

```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/user"
    "github.com/jeremyhahn/go-keychain/pkg/storage"
)

// Create storage backend
backend, _ := storage.NewMemoryBackend()

// Create user store
userStore, _ := user.NewFileStore(backend)

// Create RBAC adapter backed by user store
rbacAdapter := user.NewUserRBACAdapter(userStore)

// Now use rbacAdapter for permission checks
allowed, _ := rbacAdapter.CheckPermission(ctx, "alice@example.com", rbac.NewPermission(rbac.ResourceKeys, rbac.ActionSign))
```

## Implementing Custom Adapters

For production multi-instance deployments, implement a database-backed adapter:

```go
type PostgresRBACAdapter struct {
    db *sql.DB
}

func (p *PostgresRBACAdapter) CheckPermission(ctx context.Context, subject string, perm rbac.Permission) (bool, error) {
    query := `
        SELECT 1 FROM user_roles ur
        JOIN role_permissions rp ON ur.role_name = rp.role_name
        WHERE ur.subject = $1
        AND (rp.resource = $2 OR rp.resource = '*')
        AND (rp.action = $3 OR rp.action = '*')
        LIMIT 1
    `
    var exists int
    err := p.db.QueryRowContext(ctx, query, subject, perm.Resource, perm.Action).Scan(&exists)
    if err == sql.ErrNoRows {
        return false, nil
    }
    return err == nil, err
}

func (p *PostgresRBACAdapter) AssignRole(ctx context.Context, subject, roleName string) error {
    _, err := p.db.ExecContext(ctx, `
        INSERT INTO user_roles (subject, role_name, created_at)
        VALUES ($1, $2, NOW())
        ON CONFLICT (subject, role_name) DO NOTHING
    `, subject, roleName)
    return err
}

// Implement remaining interface methods...
```

## Best Practices

1. **Principle of Least Privilege** - Assign the minimum permissions needed
2. **Use Predefined Roles** - Start with built-in roles before creating custom ones
3. **Audit Role Changes** - Log all role assignments and permission changes
4. **Avoid Wildcards in Production** - Use specific permissions when possible
5. **Regular Reviews** - Periodically audit user role assignments
6. **Separation of Duties** - Don't give single users conflicting permissions
7. **Test Permissions** - Verify permission checks work as expected

## Related Documentation

- [Authentication Adapters](adapter-framework.md) - HTTP/gRPC authentication
- [User Management](../usage/user.md) - User accounts and WebAuthn
- [WebAuthn Authentication](../usage/webauthn.md) - Passwordless authentication
- [Server Architecture](server-architecture.md) - API server configuration
