# WebAuthn Authentication

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: the go-xkms WebAuthn relying party (`pkg/webauthn`, `pkg/webauthn/http`); the normative reference is [`docs/webauthn/`](../../../docs/webauthn/architecture.md).

go-xkms provides the server side of WebAuthn: passkey registration, login
with discoverable or account-bound credentials, and the ceremony session
state between the begin and finish steps.

## Architecture

```
HTTP handlers        pkg/webauthn/http (Handler, Mount* helpers)
WebAuthn service     pkg/webauthn/service.go (Service)
Stores               UserStore · SessionStore · CredentialStore (interfaces)
Implementations      go-qrdb users + DAO credentials · in-memory sessions
```

## REST endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/webauthn/registration/begin` | POST | Start registration of an account's first passkey |
| `/api/v1/webauthn/registration/finish` | POST | Complete a registration ceremony |
| `/api/v1/webauthn/login/begin` | POST | Start a login ceremony |
| `/api/v1/webauthn/login/finish` | POST | Complete a login ceremony |
| `/api/v1/webauthn/credentials/begin` | POST | Start adding a passkey to the signed-in account (session required) |

xkmsd also serves `/api/v1/webauthn/sdk/registration/{begin,finish}` and
`/api/v1/webauthn/sdk/authentication/{begin,finish}` (`pkg/api/rest/routes.go:443`).

The mount helpers `MountChi`, `MountMux`, `MountStdlib`, `Handler.Routes` and
`Handler.HandlerFunc` register only the four public ceremonies
(`pkg/webauthn/http/routes.go:30`). `BeginAddCredential` must be mounted by
hand behind authentication middleware; the account comes from the session
identity, never from the request (`pkg/webauthn/http/handler.go:98`).

## Server setup

```go
import (
    "github.com/jeremyhahn/go-xkms/pkg/webauthn"
    webauthnhttp "github.com/jeremyhahn/go-xkms/pkg/webauthn/http"
)

// Users are go-qrdb's; credentials are go-qrdb DAO entities on the
// datastore's DAO factory. Sessions are short-lived and held in memory.
users, creds, err := webauthn.NewQRDBUserStoreAdapter(webauthn.QRDBUserStoreOptions{
    Users:      qrdbClient.Users(),
    DAOFactory: daoFactory,
    TenantID:   "system",
})
if err != nil {
    log.Fatal(err)
}

service, err := webauthn.NewService(webauthn.ServiceParams{
    Config: &webauthn.Config{
        RPID:          "example.com",
        RPDisplayName: "Example Application",
        RPOrigins:     []string{"https://example.com"},
    },
    UserStore:       users,
    SessionStore:    webauthn.NewMemorySessionStore(),
    CredentialStore: creds,
})
if err != nil {
    log.Fatal(err)
}

handler := webauthnhttp.NewHandler(service)
r.Route("/api/v1/webauthn", func(r chi.Router) {
    webauthnhttp.MountChi(r, handler)
})
go service.SweepSessions(ctx, webauthn.DefaultSessionSweepInterval)
```

`ServiceParams` also takes an optional `JWTGenerator` and `AuditLogger`.

## Registration

Registration is invite-only by default: `Config.AllowPublicRegistration` is
nil, meaning false, so `registration/begin` creates no account for an email it
has never seen (`pkg/webauthn/config.go:67`). An account provisioned through
the authorized user-creation path still enrols its first passkey through
`registration/begin`. An account that already has a passkey adds more through
`credentials/begin`.

1. `POST /registration/begin`:

   ```json
   {"email": "user@example.com", "display_name": "Example User"}
   ```

   The response is the WebAuthn creation options, with the session ID in the
   `X-Session-Id` header.

2. `POST /registration/finish` with the same `X-Session-Id` header and the
   browser's attestation response.

The begin route refuses an existing account and, with public registration off,
an unknown email in the same way, so it does not reveal which accounts exist.

## Login

1. `POST /login/begin` with `{"email": "..."}` or `{"user_id": "..."}`, or
   `{}` for a discoverable credential. An unknown account gets decoy options
   rather than an error.
2. `POST /login/finish` with the `X-Session-Id` header and the browser's
   assertion. The response carries `token` and `user_id`, plus
   `refresh_token` when the token generator issues pairs.

## Store interfaces

Defined in `pkg/webauthn/interfaces.go`:

```go
type UserStore interface {
    GetByID(ctx context.Context, userID []byte) (User, error)
    GetByEmail(ctx context.Context, email string) (User, error)
    Create(ctx context.Context, email, displayName string) (User, error)
    Save(ctx context.Context, user User) error
    Delete(ctx context.Context, userID []byte) error
}

type SessionStore interface {
    Save(ctx context.Context, data *webauthn.SessionData) (string, error)
    Get(ctx context.Context, sessionID string) (*webauthn.SessionData, error)
    Take(ctx context.Context, sessionID string) (*webauthn.SessionData, error)
    Delete(ctx context.Context, sessionID string) error
}

type CredentialStore interface {
    Save(ctx context.Context, cred *Credential) error
    GetByUserID(ctx context.Context, userID []byte) ([]*Credential, error)
    GetByCredentialID(ctx context.Context, credID []byte) (*Credential, error)
    Update(ctx context.Context, cred *Credential) error
    Delete(ctx context.Context, credID []byte) error
    DeleteByUserID(ctx context.Context, userID []byte) error
}
```

`Take` claims a session atomically, returning it and removing it at once, so
two concurrent finish requests cannot both validate against one challenge.

## Sessions

`NewMemorySessionStore` holds sessions for 2 minutes
(`pkg/webauthn/session_store.go:99`); `NewMemorySessionStoreWithTTL` sets
another TTL. A store that implements `SessionCleaner` keeps expired sessions
until swept; run `Service.SweepSessions` (or the package-level
`SweepSessions`) on a goroutine you own (`pkg/webauthn/session_sweeper.go:34`).

## Errors

Sentinels in `pkg/webauthn/errors.go` include `ErrUserNotFound`,
`ErrUserAlreadyExists`, `ErrCredentialNotFound`, `ErrCredentialAlreadyExists`,
`ErrSessionNotFound`, `ErrSessionExpired`, `ErrInvalidRequest`,
`ErrVerificationFailed`, `ErrNoCredentials`, `ErrClonedAuthenticator`,
`ErrRegistrationRefused`, `ErrSessionAccountMismatch`,
`ErrCredentialOwnerMismatch` and `ErrCredentialUpdateConflict`.

## Testing

Tests run the production stores on a real in-process DAO factory over a
memory store (`testutil.NewMemoryDAOFactory()`) and go-qrdb's in-process user
client, so there is no separate test-only user or credential store.

## Security considerations

1. Serve over HTTPS: browsers allow WebAuthn only in a secure context.
2. Set `RPOrigins` to exactly the origins that serve the login page.
3. Run the session sweeper.
4. Rate-limit the begin endpoints.
