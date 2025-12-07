# WebAuthn Authentication

go-keychain provides server-side WebAuthn/FIDO2 support for passwordless authentication.

## Overview

The WebAuthn package (`pkg/webauthn`) implements the server-side WebAuthn protocol for:
- User registration with passkeys/security keys
- User authentication with discoverable credentials
- Session management for WebAuthn ceremonies

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      HTTP Handlers                          │
│  (pkg/webauthn/http)                                        │
├─────────────────────────────────────────────────────────────┤
│                      WebAuthn Service                       │
│  (pkg/webauthn/service.go)                                  │
├─────────────────────────────────────────────────────────────┤
│  UserStore      │  SessionStore    │  CredentialStore       │
│  (interface)    │  (interface)     │  (interface)           │
├─────────────────────────────────────────────────────────────┤
│                   Storage Backends                          │
│  Memory (testing) │ Database (production)                   │
└─────────────────────────────────────────────────────────────┘
```

## REST API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/webauthn/registration/status` | GET | Check if user has registered credentials |
| `/api/v1/webauthn/registration/begin` | POST | Start registration ceremony |
| `/api/v1/webauthn/registration/finish` | POST | Complete registration ceremony |
| `/api/v1/webauthn/login/begin` | POST | Start authentication ceremony |
| `/api/v1/webauthn/login/finish` | POST | Complete authentication ceremony |

## Usage

### Server Setup

```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/webauthn"
    webauthnhttp "github.com/jeremyhahn/go-keychain/pkg/webauthn/http"
)

// Create stores (use database-backed stores for production)
userStore := webauthn.NewMemoryUserStore()
sessionStore := webauthn.NewMemorySessionStore()
credStore := webauthn.NewMemoryCredentialStore()

// Create WebAuthn configuration
cfg := webauthn.Config{
    RPID:          "example.com",
    RPDisplayName: "Example Application",
    RPOrigins:     []string{"https://example.com"},
}

// Create service
service, err := webauthn.NewService(cfg, userStore, sessionStore, credStore)
if err != nil {
    log.Fatal(err)
}

// Mount HTTP handlers
handlers := webauthnhttp.NewHandlers(service)
// handlers.Mount(router) - mount to your router
```

### Registration Flow

1. **Begin Registration** (POST `/api/v1/webauthn/registration/begin`)
```json
{
  "email": "user@example.com",
  "display_name": "John Doe"
}
```

Response includes `X-Session-Id` header and WebAuthn `publicKey` options.

2. **Finish Registration** (POST `/api/v1/webauthn/registration/finish`)

Include `X-Session-Id` header and authenticator response from browser.

### Authentication Flow

1. **Begin Login** (POST `/api/v1/webauthn/login/begin`)
```json
{
  "email": "user@example.com"
}
```

Or empty body `{}` for discoverable credentials.

2. **Finish Login** (POST `/api/v1/webauthn/login/finish`)

Include `X-Session-Id` header and authenticator assertion from browser.

## Store Interfaces

Implement these interfaces for production storage:

```go
// UserStore manages WebAuthn users
type UserStore interface {
    GetByID(ctx context.Context, userID []byte) (User, error)
    GetByEmail(ctx context.Context, email string) (User, error)
    Create(ctx context.Context, email, displayName string) (User, error)
    Save(ctx context.Context, user User) error
    Delete(ctx context.Context, userID []byte) error
}

// SessionStore manages WebAuthn sessions
type SessionStore interface {
    Save(ctx context.Context, data *webauthn.SessionData) (string, error)
    Get(ctx context.Context, sessionID string) (*webauthn.SessionData, error)
    Delete(ctx context.Context, sessionID string) error
}

// CredentialStore manages WebAuthn credentials
type CredentialStore interface {
    Save(ctx context.Context, cred *Credential) error
    GetByUserID(ctx context.Context, userID []byte) ([]*Credential, error)
    GetByCredentialID(ctx context.Context, credID []byte) (*Credential, error)
    Update(ctx context.Context, cred *Credential) error
    Delete(ctx context.Context, credID []byte) error
    DeleteByUserID(ctx context.Context, userID []byte) error
}
```

## Testing

Use the provided memory stores for unit testing:

```go
userStore := webauthn.NewMemoryUserStore()
sessionStore := webauthn.NewMemorySessionStore()
credStore := webauthn.NewMemoryCredentialStore()

// After tests
userStore.Clear()
sessionStore.Clear()
credStore.Clear()
```

## Session TTL

Default session TTL is 2 minutes. Configure with:

```go
sessionStore := webauthn.NewMemorySessionStoreWithTTL(5 * time.Minute)
```

## Error Handling

The package defines typed errors:

- `ErrUserNotFound` - User does not exist
- `ErrUserAlreadyExists` - Email already registered
- `ErrSessionNotFound` - Invalid session ID
- `ErrSessionExpired` - Session has expired
- `ErrCredentialNotFound` - Credential does not exist
- `ErrCredentialAlreadyExists` - Credential ID already registered
- `ErrNoCredentials` - User has no registered credentials
- `ErrInvalidRequest` - Malformed request

## Security Considerations

1. **Use HTTPS** - WebAuthn requires secure context
2. **Validate Origins** - Configure `RPOrigins` correctly
3. **Session Cleanup** - Call `sessionStore.Cleanup()` periodically
4. **Rate Limiting** - Implement rate limiting on registration endpoints
