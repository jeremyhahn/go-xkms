# Auth Package

`pkg/auth` defines the authentication client interface and provides an in-memory implementation for testing.

## Client Interface

```go
type Client interface {
    ValidateToken(ctx context.Context, token string) (*TokenClaims, error)
    RefreshToken(ctx context.Context, token string) (string, error)
    RevokeToken(ctx context.Context, token string) error
}
```

Production implementations delegate to QRDB Auth for token validation, refresh, and revocation.

## TokenClaims

Represents validated token data:

| Field | Type | Description |
|-------|------|-------------|
| `UserID` | `string` | Unique user identifier |
| `Username` | `string` | Display username |
| `Email` | `string` | User email |
| `TenantID` | `string` | Tenant scope |
| `Roles` | `[]string` | Assigned roles |
| `Groups` | `[]string` | Group memberships |
| `Permissions` | `[]string` | Granted permissions |
| `SessionID` | `string` | Session identifier |
| `IssuedAt` | `time.Time` | Token issue time |
| `ExpiresAt` | `time.Time` | Token expiry time |
| `Valid` | `bool` | Validity flag |

## MemoryClient

`MemoryClient` is an in-memory `Client` implementation for unit testing. Uses `sync.Map` for lock-free concurrent access.

### Usage

```go
client := auth.NewMemoryClient()

// Seed a token for testing
client.AddToken("test-token", &auth.TokenClaims{
    UserID:   "user-1",
    TenantID: "tenant-1",
    Roles:    []string{"admin"},
    ExpiresAt: time.Now().Add(time.Hour),
    Valid:     true,
})

// Validate
claims, err := client.ValidateToken(ctx, "test-token")

// Refresh (generates new token, removes old, extends expiry by 1 hour)
newToken, err := client.RefreshToken(ctx, "test-token")

// Revoke
err = client.RevokeToken(ctx, newToken)
```

### Additional Methods

- `AddToken(token, claims)` -- Pre-load tokens into the store.
- `RemoveToken(token)` -- Remove a token without going through `RevokeToken` validation.

## Typed Errors

| Error Type | Description | Checker |
|------------|-------------|---------|
| `InvalidTokenError` | Token is empty, not found, or corrupted | `IsInvalidToken(err)` |
| `TokenExpiredError` | Token has passed its `ExpiresAt` time | `IsTokenExpired(err)` |
| `TokenRevokedError` | Token has been revoked | `IsTokenRevoked(err)` |
| `AuthServiceError` | Auth service communication failure (wraps cause) | -- |
