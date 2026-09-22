# WebAuthn Relying Party — API

> **Status: NORMATIVE** · Feature: `webauthn` · Repo: `go-xkms` · Last verified: 2026-09-21

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped".

## Route group

WebAuthn routes live in `GroupWebAuthn` (`pkg/api/rest/routes.go`), registered
under `/api/v1/webauthn` when `hasWebAuthn` is true. The group's own comment
states the contract: these routes **sit behind the login rate limiter and are
unauthenticated — WebAuthn is the auth mechanism.**

## Capability matrix

| Capability | REST | gRPC / Unix (`KeystoreService.`) | QUIC (HTTP/3) | MCP | Embedded (`FIDO2Service.`) | Auth |
|---|---|---|---|---|---|---|
| Begin registration | `POST /api/v1/webauthn/registration/begin` | `BeginRegistration` | same as REST | **Excluded (#193)** | `BeginRegistration` | public |
| Finish registration | `POST /api/v1/webauthn/registration/finish` | `FinishRegistration` | same as REST | **Excluded (#193)** | `FinishRegistration` | public |
| Registration status | `GET /api/v1/webauthn/registration/status` | **MISSING — docs/13** | same as REST | **MISSING — docs/13** | `Service.IsRegistered` (in-process) | public |
| Begin login | `POST /api/v1/webauthn/login/begin` | `BeginAuthentication` | same as REST | **Excluded (#193)** | `BeginAuthentication` | public |
| Finish login | `POST /api/v1/webauthn/login/finish` | `FinishAuthentication` | same as REST | **Excluded (#193)** | `FinishAuthentication` | public |
| SDK begin registration | `POST /api/v1/webauthn/sdk/registration/begin` | — | same as REST | — | — | public |
| SDK finish registration | `POST /api/v1/webauthn/sdk/registration/finish` | — | same as REST | — | — | public |
| SDK begin authentication | `POST /api/v1/webauthn/sdk/authentication/begin` | — | same as REST | — | — | public |
| SDK finish authentication | `POST /api/v1/webauthn/sdk/authentication/finish` | — | same as REST | — | — | public |

**MCP carries none of the WebAuthn ceremony, and it never will.** Owner
ruling 2026-09-21 (issue #193, option C) settled this as a named exclusion,
not the transport gap this table used to record it as: an MCP tool-call
surface is agent-facing, and it must not mint sessions or enrol credentials
— WebAuthn registration and authentication do both, and MCP holds no
identity-ceremony state to correlate a Begin call with its matching Finish
call. Session minting and credential enrolment stay on operator-facing
transports (REST, gRPC).
`pkg/api/transport/mcp.Transport.BeginRegistration` / `FinishRegistration` /
`BeginAuthentication` / `FinishAuthentication` always fail with the typed
`pkg/api/transport/mcp.ErrIdentityCeremonyExcluded`, and the MCP server's
capability surface (`pkg/api/mcp.ModuleMethods`) never lists a tool for
them, so a client can discover the exclusion without calling and failing.
Registration status remains real, unconverted debt (docs/13) — it is not
part of this exclusion.

The `/sdk/...` variants are the programmatic ceremony for non-browser clients
(`pkg/webauthn/client`, the xkey virtual authenticator). They exist only on the
HTTP-shaped transports because that is what those clients speak.

### SDK ceremony bodies

`POST /api/v1/webauthn/sdk/registration/begin` decodes
`transport.BeginRegistrationRequest`:

| Field | Meaning |
|---|---|
| `email` | the **canonical tenant-unique login key** of the account the credential is enrolled against; the server resolves it with `GetByEmail` |
| `display_name` | human-readable name; defaults to the email |

`POST /api/v1/webauthn/sdk/authentication/begin` decodes
`transport.BeginAuthenticationRequest` (`email`), and
`POST /api/v1/webauthn/sdk/authentication/finish` decodes
`transport.FinishAuthenticationRequest` (`session_id`, `email`,
`assertion_json`); both name the account by the same login key, which the
server resolves with `GetUserByEmail`.

The gRPC and Unix `BeginRegistrationRequest`, `BeginAuthenticationRequest`
and `FinishAuthenticationRequest` carry the same field as `email` (the field
numbers are unchanged, so the binary encoding is compatible with earlier
clients).

**BREAKING (2026-09-22).** The field was previously spelled `username` on the
wire in all three requests while carrying the email, which invited a caller
to read the name literally and run the ceremony against the wrong account.
The `username` key, its parallel encoding, and the conflict-detection
decoders have been removed outright: `email` is the only login key any
decoder reads, and a body that still carries `username` has that key ignored
rather than honoured.

## Related identity routes

Not part of the RP, but where its output is used:

| Capability | REST | Group | Auth |
|---|---|---|---|
| PIV login | `POST /api/v1/auth/login/piv` | `GroupAuthSession` | public — it *is* the authentication |
| Refresh | `POST /api/v1/auth/refresh` | `GroupAuthSession` | public |
| Who am I | `GET /api/v1/auth/me` | `GroupAuthSession` | session |
| Validate | `GET /api/v1/auth/validate` | `GroupAuthSession` | session |
| Logout | `POST /api/v1/auth/logout` | `GroupAuthSession` | session |
| List a user's credentials | `GET /api/v1/users/{username}/credentials` | `GroupUsers` | `users:read` |

All `GroupAuthSession` routes are gated on `hasIssuer` — without a token issuer
configured they are not registered at all.

## Request and response schemas

The ceremony payloads are the W3C WebAuthn structures, carried as the
`go-webauthn/webauthn` protocol types: `protocol.CredentialCreation`,
`protocol.ParsedCredentialCreationData`, `protocol.CredentialAssertion`,
`protocol.ParsedCredentialAssertionData`. This is a standard wire format; go-xkms
does not define its own.

Finish responses carry a token. With a `TokenPairGenerator` injected the
handlers return an access/refresh pair; with a plain `JWTGenerator` they return
a single token. The selection is a type assertion in the handler, so the same
route serves both shapes depending on server configuration — a client must
handle the shape its deployment produces.

### `GET /api/v1/auth/me`

`authMeResponse` (`pkg/api/rest/handlers_auth.go`) answers "who is this token
for", and the TypeScript `AuthMeResponse` (`sdk/ts/src/types/auth.ts`) mirrors
it field for field:

| Field | Meaning |
|---|---|
| `subject` | the identity's subject; always present |
| `tenant_id` | the tenant the principal belongs to |
| `username` | the display login name |
| `email` | the **canonical tenant-unique login key** — the identifier a client re-authenticates with |
| `display_name` | human-readable name |
| `auth_method` | how *this request* authenticated (`jwt` for a bearer request), not the ceremony that minted the token |
| `roles`, `permissions`, `capabilities` | what the UI may show and the server offers |

Every field but `subject` is `omitempty`. `email` is therefore **absent, not
empty**, for a principal that has none — a service or bootstrap account bound
only by certificate. It is never fabricated from the username, and a client
must treat its absence as "this principal has no email login key" rather than
falling back to `username`.

The key rides the identity from wherever the principal was established — the
qrdb-backed mTLS user record, the WebAuthn user, or an OIDC `email` claim — and
is minted onto both halves of a token pair, so it survives a refresh.

## Status and error mapping

| Condition | REST | gRPC / Unix |
|---|---|---|
| ceremony options issued | 200 | `OK` |
| registration or login succeeded | 200 with token(s) | `OK` |
| unknown or expired session | 401 | `Unauthenticated` |
| origin or RP id mismatch | 401 | `Unauthenticated` |
| invalid attestation or assertion | 401 | `Unauthenticated` |
| non-increasing signature counter | 401 | `Unauthenticated` |
| public registration disabled | 403 | `PermissionDenied` |
| rate limited | 429 | `ResourceExhausted` |
| WebAuthn not configured | route absent (404) | `Unimplemented` |

**The uniform 401 is deliberate.** Internally these are distinct typed errors
(`pkg/webauthn/errors.go`, exercised by `verification_error_test.go`); on the
wire they are indistinguishable, so a caller cannot use failure shapes to
enumerate users or probe which authenticator a user holds. The detail stays in
the server log.

## Pagination

Not applicable to ceremonies. `GET /api/v1/users/{username}/credentials` returns
a user's credential list, bounded by the number of authenticators a user has
enrolled.

## Versioning and deprecation

WebAuthn is a W3C standard; the ceremony payloads are versioned by the spec, not
by us. The `/sdk/...` routes are an addition, not a replacement — the browser
routes are not deprecated.

Changing `RPID` is not a version change, it is an invalidation: every enrolled
credential stops working. Treat it as a migration with user impact, never as
configuration tidying.
