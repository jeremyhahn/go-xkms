# User Management

The `pkg/user` package provides user account management with WebAuthn/FIDO2 support and role-based access control integration.

## Overview

The user management system includes:
- User account CRUD operations
- Role-based access control (RBAC) integration
- WebAuthn credential storage
- Session management with automatic cleanup
- Multiple passkeys per user

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     REST API Handlers                        │
│  (internal/rest/user_handlers.go)                           │
├─────────────────────────────────────────────────────────────┤
│                     User Store                               │
│  (pkg/user/store.go)                                        │
├─────────────────────────────────────────────────────────────┤
│  WebAuthn Adapters    │  RBAC Adapter    │  Session Store   │
│  (webauthn_adapter.go)│  (rbac.go)       │  (store.go)      │
├─────────────────────────────────────────────────────────────┤
│                   Storage Backend                            │
│  pkg/storage (Memory, File, etc.)                           │
└─────────────────────────────────────────────────────────────┘
```

## User Model

```go
type User struct {
    ID          []byte      // Unique identifier (WebAuthn user handle)
    Username    string      // Email address (normalized to lowercase)
    DisplayName string      // Human-readable display name
    Role        Role        // User role (admin, operator, user, etc.)
    Enabled     bool        // Whether the user can authenticate
    CreatedAt   time.Time   // Account creation timestamp
    UpdatedAt   time.Time   // Last modification timestamp
    Credentials []Credential // WebAuthn credentials (passkeys)
}
```

## Roles

The user package defines six roles that map to RBAC permissions:

| Role | Constant | Description |
|------|----------|-------------|
| `admin` | `RoleAdmin` | Full system access |
| `operator` | `RoleOperator` | Key and certificate management |
| `auditor` | `RoleAuditor` | Read-only audit access |
| `user` | `RoleUser` | Cryptographic operations only |
| `readonly` | `RoleReadOnly` | Read-only access |
| `guest` | `RoleGuest` | Minimal access |

### Role Permissions

```go
// Admin can do everything
admin.CanManageUsers()  // true
admin.CanManageKeys()   // true
admin.CanUseKeys()      // true

// User can only perform crypto operations
user.CanManageUsers()   // false
user.CanManageKeys()    // false
user.CanUseKeys()       // true (sign, verify, encrypt, decrypt)
```

## Usage

### Creating a User Store

```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/user"
    "github.com/jeremyhahn/go-keychain/pkg/storage"
)

// Create storage backend
backend, err := storage.NewMemoryBackend()
if err != nil {
    log.Fatal(err)
}

// Create user store with default options
store, err := user.NewFileStore(backend)
if err != nil {
    log.Fatal(err)
}
defer store.Close()

// Or with custom session cleanup interval
store, err := user.NewFileStore(backend, user.WithCleanupInterval(5*time.Minute))
```

### Creating Users

```go
ctx := context.Background()

// Create an admin user
admin, err := store.Create(ctx, "admin@example.com", "Administrator", user.RoleAdmin)
if err != nil {
    log.Fatal(err)
}

// Create a regular user
regularUser, err := store.Create(ctx, "user@example.com", "John Doe", user.RoleUser)
if err != nil {
    log.Fatal(err)
}
```

### Retrieving Users

```go
// By ID
u, err := store.GetByID(ctx, userID)

// By username (email)
u, err := store.GetByUsername(ctx, "user@example.com")

// List all users
users, err := store.List(ctx)

// Count users
count, err := store.Count(ctx)

// Check if any users exist
hasUsers, err := store.HasAnyUsers(ctx)
```

### Updating Users

```go
u, _ := store.GetByUsername(ctx, "user@example.com")

// Update role
u.Role = user.RoleOperator

// Disable user
u.Enabled = false

err := store.Update(ctx, u)
```

### Deleting Users

```go
// Delete by ID
err := store.Delete(ctx, userID)

// Note: Cannot delete the last admin user
```

## WebAuthn Integration

The user package provides WebAuthn adapters for seamless integration with the `pkg/webauthn` service.

### Creating Adapters

```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/user"
    "github.com/jeremyhahn/go-keychain/pkg/webauthn"
)

// Create user store
store, _ := user.NewFileStore(backend)

// Create WebAuthn adapters
userAdapter := user.NewWebAuthnUserAdapter(store)
sessionAdapter := user.NewWebAuthnSessionAdapter(store)
credentialAdapter := user.NewWebAuthnCredentialAdapter(store)

// Create WebAuthn service with user-backed stores
cfg := webauthn.Config{
    RPID:          "example.com",
    RPDisplayName: "Example App",
    RPOrigins:     []string{"https://example.com"},
}

service, err := webauthn.NewService(cfg, userAdapter, sessionAdapter, credentialAdapter)
```

### WebAuthn User Interface

Users implement the `webauthn.User` interface:

```go
// WebAuthnID returns the user's unique identifier
func (u *User) WebAuthnID() []byte

// WebAuthnName returns the username (email)
func (u *User) WebAuthnName() string

// WebAuthnDisplayName returns the display name
func (u *User) WebAuthnDisplayName() string

// WebAuthnCredentials returns all registered credentials
func (u *User) WebAuthnCredentials() []webauthn.Credential
```

## RBAC Integration

The user package includes an RBAC adapter that implements `rbac.RBACAdapter`:

```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/user"
    "github.com/jeremyhahn/go-keychain/pkg/adapters/rbac"
)

// Create RBAC adapter backed by user store
rbacAdapter := user.NewUserRBACAdapter(store)

// Check permissions
allowed, err := rbacAdapter.CheckPermission(ctx, "user@example.com",
    rbac.NewPermission(rbac.ResourceKeys, rbac.ActionSign))

// Get user roles
roles, err := rbacAdapter.GetUserRoles(ctx, "user@example.com")

// Assign role
err = rbacAdapter.AssignRole(ctx, "user@example.com", rbac.RoleOperator)
```

### Role Mapping

The package provides functions to convert between user roles and RBAC roles:

```go
// User role to RBAC role name
rbacRole := user.RoleToRBAC(user.RoleOperator) // "operator"

// RBAC role name to user role
userRole := user.RBACToRole("operator") // user.RoleOperator
```

## Session Management

The store provides session management with automatic expiration:

```go
// Save session data (e.g., WebAuthn challenge)
err := store.SaveSession(ctx, "session-id", sessionData, 5*time.Minute)

// Retrieve session
data, err := store.GetSession(ctx, "session-id")

// Delete session
err = store.DeleteSession(ctx, "session-id")

// Expired sessions are automatically cleaned up
```

## REST API Endpoints

When using the REST server, these endpoints are available:

| Endpoint | Method | Permission | Description |
|----------|--------|------------|-------------|
| `/api/v1/users` | GET | `users:list` | List all users |
| `/api/v1/users` | POST | `users:create` | Create new user |
| `/api/v1/users/{id}` | GET | `users:read` | Get user by ID |
| `/api/v1/users/{id}` | PUT | `users:update` | Update user |
| `/api/v1/users/{id}` | DELETE | `users:delete` | Delete user |

## Error Handling

The package defines typed errors:

```go
var (
    ErrUserNotFound      = errors.New("user not found")
    ErrUserAlreadyExists = errors.New("user already exists")
    ErrInvalidUsername   = errors.New("invalid username")
    ErrInvalidRole       = errors.New("invalid role")
    ErrLastAdmin         = errors.New("cannot delete last admin")
    ErrStorageClosed     = errors.New("storage is closed")
    ErrSessionNotFound   = errors.New("session not found")
    ErrSessionExpired    = errors.New("session expired")
)
```

## Best Practices

1. **Always close the store** - Use `defer store.Close()` to ensure cleanup
2. **Validate roles** - Use `role.IsValid()` before assigning roles
3. **Normalize usernames** - Usernames are automatically lowercased
4. **Handle the last admin** - The store prevents deleting the last admin user
5. **Use RBAC for permissions** - Don't check roles directly; use the RBAC adapter
6. **Clean up sessions** - Configure appropriate cleanup intervals for production

## Related Documentation

- [WebAuthn Authentication](webauthn.md) - Passwordless authentication setup
- [RBAC](../architecture/rbac.md) - Role-based access control
- [Server Architecture](../architecture/server-architecture.md) - API server configuration
