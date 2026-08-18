# User-Side Auth Factors (N-Factor)

A user may hold several authentication factors — a passkey, a PIV card, an
mTLS client certificate — and any one of them can identify them at login.
This is the surface that manages that set.

## Who owns what

Factor records belong to **go-qrdb**. xkms stores none of them and adds no
rules of its own. There are two paths to the same qrdb service:

```
xkmsctl auth factor …                          (CLI)
  └─ qrdb SDK client (unix / grpc transport)
      └─ qrdb UserAuthFactorService            (registered by
                                                pkg/server/qrdb_control_plane.go)

web GUI / TS SDK
  └─ REST /api/v1/factors/*        (pkg/api/rest/handlers_authfactor.go)
      └─ XKMSService passthrough   (pkg/xkms/servicer_authfactor.go)
          └─ qrdb UserAuthFactorClient   (embedded node)
```

The REST proxy exists for HTTP-only consumers (the web GUI via the TS
SDK); the CLI drives qrdb's own service directly.

## Resolution is not authentication

`POST /factors/login` maps a `(type, lookup_key)` pair to a principal. That
is a database lookup and **nothing more**.

The hardware proof — a FIDO2 assertion, a PIV signature, an mTLS handshake —
must be verified by the caller *before* the result is treated as an
authenticated identity. Reaching this endpoint is not evidence that anyone
proved possession of anything.

## Endpoints

| Method | Path | Purpose | Permission |
|--------|------|---------|-----------|
| GET | `/api/v1/factors?user_id=N` | List a user's factors (active and revoked) | `users:read` |
| POST | `/api/v1/factors` | Enrol a factor (owner in body) | `users:update` |
| GET | `/api/v1/factors/{factorID}` | Read one factor | `users:read` |
| DELETE | `/api/v1/factors/{factorID}` | Revoke a factor | `users:update` |
| PATCH | `/api/v1/factors/{factorID}` | Relabel a factor | `users:update` |
| POST | `/api/v1/factors/{factorID}/rotate` | Add a replacement and revoke the old one atomically | `users:update` |
| POST | `/api/v1/factors/login` | Resolve `(type, lookup_key)` to a principal | `users:read` |

Mutations carry `users:update` because enrolling or revoking a factor changes
who can log in as that user.

### Lookup keys

| Type | `lookup_key` |
|------|--------------|
| `mtls` | SHA-256 of the certificate |
| `fido2` | WebAuthn credential ID bytes |
| `piv` | SHA-256 of the slot certificate |

### Removing the last factor

qrdb refuses to revoke a user's last active factor, because doing so locks
them out. `?force=true` overrides that and moves the user to inactive. Force
is opt-in — a routine delete never sets it.

## CLI

```
xkmsctl auth factor list   --user-id 42
xkmsctl auth factor add    --user-id 42 --type fido2 --label "yubikey"
xkmsctl auth factor get    --factor-id f-123
xkmsctl auth factor remove --factor-id f-123 [--force]
xkmsctl auth factor rotate --factor-id f-123 --type piv
```

The CLI does not use the REST proxy above. It derives a qrdb SDK
transport (unix socket by default, `grpc://` / `grpcs://` per the
standard `--server`/`--transport` conventions) and calls qrdb's
`UserAuthFactorService` — hosted on xkmsd's gRPC server and unix socket
by `pkg/server/qrdb_control_plane.go` — through the SDK's
`UserAuthFactors()` surface (`cmd/xkmsctl/auth_factor_handlers.go`).

## SDK Login Plane

Higher-level projects consume the complete login plane through `sdk/go`
without importing `pkg/*`:

- **FIDO2 / WebAuthn login** — the six-transport `Servicer` ceremony
  (`BeginRegistration` / `FinishRegistration`, `BeginAuthentication` /
  `FinishAuthentication`); a successful assertion returns the session
  token. Available on every transport (embedded, rest, grpc, quic, mcp,
  unix).
- **PIV login and session verbs** — `xkms.NewLoginClient`
  (`sdk/go/login.go`): `PIVLogin` presents the PIV slot certificate as
  the TLS client certificate (possession of the card key IS the
  credential, so this client speaks raw mTLS HTTPS — the same convention
  as the credential and init-officer clients), plus `Refresh`, `Logout`,
  and `Validate` for the access/refresh pair lifecycle.
- **mTLS login** — no ceremony: the SPKI-bound client certificate
  authenticates every request directly.
- **Factor verifiers for embedders** — `xkms.WithXKMSFactorVerifiers`
  (`sdk/go/auth.go`) returns the WebAuthn / PIV / PKCS#11 verifiers
  behind go-qrdb's `FactorVerifier` seam, so any project embedding a
  qrdb node wires hardware factor verification with
  `node.WithLoginFactorVerifier(...)` instead of hand-rolling adapters.
- **Factor management** — `xkms.Auth(client).Factors()` (the qrdb SDK
  factors lane): enroll, list, and remove mtls / fido2 / piv / pkcs11
  factors.

## Cross-References

- [Auth bootstrap](bootstrap.md) — how an identity is established in the first place
- [Auth layering](layering.md) — where the factor plane sits relative to RBAC and sessions
- [WebAuthn RP](../webauthn/README.md) — where FIDO2 factors come from
- [PIV](../piv/README.md) — where PIV factors come from

The N-factor model itself is specified in go-qrdb's
`docs/08-bootstrap-auth-architecture.md` §5e; xkms implements the proxy only.
