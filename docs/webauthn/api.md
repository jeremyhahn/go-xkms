# WebAuthn Relying Party — API

> **Status: NORMATIVE** · Feature: `webauthn` · Repo: `go-xkms` · Last verified: 2026-10-27

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped".

## Route group

WebAuthn routes live in `GroupWebAuthn` (`pkg/api/rest/routes.go`), registered
under `/api/v1/webauthn` when `hasWebAuthn` is true. All of them sit behind the
login rate limiter. The ceremonies are **unauthenticated — WebAuthn is the auth
mechanism** — with one exception: adding a passkey to an account that already
has one is `RouteAuthSession` and requires a session authenticated as that
account (go-xkms#1294).

## Capability matrix

| Capability | REST | gRPC / Unix (`KeystoreService.`) | QUIC (HTTP/3) | MCP | Embedded (`FIDO2Service.`) | Auth |
|---|---|---|---|---|---|---|
| Begin registration | `POST /api/v1/webauthn/registration/begin` | `BeginRegistration` | same as REST | **Excluded (#193)** | `BeginRegistration` | public |
| Finish registration | `POST /api/v1/webauthn/registration/finish` | `FinishRegistration` | same as REST | **Excluded (#193)** | `FinishRegistration` | public |
| Add a passkey to the session's account (begin) | `POST /api/v1/webauthn/credentials/begin`; finish with `registration/finish` | — | same as REST | **Excluded (#193)** | `Service.BeginAddCredential` (in-process) | session |
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
The unauthenticated `GET /api/v1/webauthn/registration/status` probe was
deleted (go-xkms#1296): it told anyone whether an email had a passkey, and
nothing used it. A signed-in client learns about its own account from
`GET /api/v1/auth/me`.

Adding a passkey is REST-only for now. The SDK transports (gRPC, Unix, the
`/sdk/...` routes) carry only the first-passkey ceremony, and refuse an
account that already has a passkey like the browser route does.

## Registration and enumeration rules

| Rule | Where it is enforced |
|---|---|
| The public begin (`registration/begin`, `/sdk/registration/begin`, gRPC `BeginRegistration`) enrols a first passkey ONLY for an account it creates itself, in the same call, under open self-registration. Any account that already existed before the call — whether it holds a credential or not — is refused with `ErrRegistrationRefused`. | `Service.BeginRegistration` (`pkg/webauthn/service.go`) |
| A further passkey on an existing account is added only through `POST /api/v1/webauthn/credentials/begin`, served to an authenticated session. The account is the session's own: the handle in the token subject and the `email` claim must name the same existing account. The request body is ignored. | `Handler.BeginAddCredential` (`pkg/webauthn/http/handler.go`), `SessionAccountFromIdentity` (`pkg/webauthn/session_account.go`), `Service.BeginAddCredential` |
| With public registration off, an unknown email is refused with the same `ErrRegistrationRefused`: same status, code, message and headers as an account that already has a passkey. | `Service.BeginRegistration` |
| An account provisioned by an administrator (zero credentials, `LifecyclePending`) enrols its first passkey through the separate invite-authorized ceremony, never through the public begin: `BeginInviteRegistration`/`FinishInviteRegistration`, reached only via a valid single-use invitation token (`../user-onboarding/api.md`, go-xkms#1294 part B). The public begin refuses such an account exactly like any other pre-existing one. | `Service.BeginInviteRegistration` / `FinishInviteRegistration` (`pkg/webauthn/service.go`), orchestrated by `pkg/xkms/servicer_invite.go` |
| Login begin never reveals whether an account exists. An unknown email or user ID, or an account without credentials, gets well-formed decoy options: a real go-webauthn ceremony whose `allowCredentials` are derived with HKDF-SHA256 from a per-process key and the email (or handle). Repeated probes for one email see the same descriptors. A finish against a decoy session fails as `verification_failed`, like a wrong assertion. | `Service.BeginLoginForEmail` / `BeginLoginForHandle`, `pkg/webauthn/decoy.go` |
| Only an account in good standing authenticates: lifecycle `active`, and an auth-method policy that is empty or names `webauthn`. Login begin answers any other account with the decoy an unknown one gets; finish (browser, SDK, gRPC, discoverable, and the qrdb FIDO2 factor) refuses a valid assertion as `verification_failed`; registration begin and add-passkey refuse it with `ErrRegistrationRefused`. The response never names the account's state; the server log does. | `CheckAccountStanding` (`pkg/webauthn/account_standing.go`), `Service.beginLoginOrDecoy` / `finishLoginUser` / `beginRegistrationFor` |
| No user identifier before a successful login. The `X-User-Id` header is gone from login begin and is no longer read on login finish; the user ID comes back in the finish response. | `pkg/webauthn/http/handler.go` |
| A credential ID belongs to exactly one account. Creating one that is already registered, to any account, fails with `ErrCredentialAlreadyExists`. | `CredentialStore.Save` (every store) |
| A credential enrolled under the shared pre-tenant keyspace (`__xkms:webauthn/credentials/`) moves into its owner's tenant store when the consumer opens that store: the consumer calls `MigrateWebAuthnLegacyCredentials` before serving a ceremony from it. The old key is deleted only after the save; a record that cannot be moved stays in place and is reported, never dropped. | `MigrateLegacyCredentials` (`pkg/webauthn/legacy_migration.go`), re-exported as `sdk/go.MigrateWebAuthnLegacyCredentials` |

The decoy key is drawn at startup and kept only in memory; the WebAuthn
configuration has no server secret. So decoys change on restart and differ
between cluster nodes, while a real account's descriptors do not. Telling them
apart that way means probing the same email across a restart or across nodes.
The decoy path also skips the credential lookup a real account needs, so its
latency differs slightly.

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
`transport.BeginAuthenticationRequest` (`email`), which names the account by
the same login key; an unknown email gets decoy options, like the browser
route. `POST /api/v1/webauthn/sdk/authentication/finish` decodes
`transport.FinishAuthenticationRequest` (`session_id`, `email`,
`assertion_json`). The session begun for the email decides the account, so
finish does not resolve `email` again.

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

### Legacy credential migration (go-xkms#1749)

```go
report, err := xkms.MigrateWebAuthnLegacyCredentials(ctx, xkms.WebAuthnLegacyCredentialMigration{
    Legacy:   kv,       // qrdb KVClient over the shared legacy keyspace
    Users:    users,    // qrdb UserClient: resolves each credential's tenant
    TenantID: tenantID, // the tenant whose store is being opened
    Store:    store,    // that tenant's store from NewWebAuthnQRDBUserStoreAdapter
})
```

`WebAuthnCredentialMigrationReport` counts `Migrated`, `Skipped` (another
tenant's credential, left for that tenant's store open) and `Failed`, with one
typed error per record left in place in `Failures`. A second run reports zero
migrated. Errors:

| Error | Meaning |
|---|---|
| `*WebAuthnCredentialMigrationConfigError` | a field is missing (`Field`); nothing is read |
| `*WebAuthnLegacyCredentialScanError` | the legacy keyspace cannot be read (sealed barrier, transport fault) |
| `*WebAuthnLegacyCredentialCorruptError` | a record does not decode to the credential its key names |
| `*WebAuthnCredentialOwnerUnresolvedError` | the credential's user, or the user's tenant, cannot be resolved |
| `*WebAuthnCredentialMoveError` | a save, existing-record read or legacy delete failed (`Op`) |
| `*WebAuthnCredentialMigrationIncompleteError` | returned with the report whenever `Failed > 0`; unwraps to every failure |

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

### Publishing the session signing key (JWKS)

A host that embeds the `xkms` ServiceModule and verifies the module's session
tokens itself (go-quicbaas does, against its own JWKS) publishes the module's
signing key with:

```go
func ServiceModuleSessionSigningJWK(ctx context.Context, svc *xkms.XKMSService,
    opts *ServiceModuleSessionOptions) (*JWK, error)
```

`sdk/go/apimodule.go:142` re-exports `rest.SessionSigningJWK`
(`pkg/api/rest/session_jwk.go:93`). It returns the public key only, as an RFC
7517 JWK: `kty` `EC`, `crv` `P-256`, `use` `sig` (§4.2), `alg` `ES256` (§4.4,
RFC 7518 §3.4), with `x` and `y` at the full 32 octets (RFC 7518 §6.2.1.2,
§6.2.1.3). The encoding is `pkg/encoding/jwk`'s `FromPublicKey`. The private
key stays in the backend.

**The `kid` rule.** Pass the same `opts` the module was built with
(`WithServiceModuleSession`; nil selects the defaults), so the accessor reads
the key under the same signing CN: `SigningKeyCN`, or `xkms-jwt-signing` when
it is empty (`sessionSigningKeyCN`, `pkg/api/rest/host.go:252`). RFC 7517 §4.5
leaves the `kid` value to the application. Here it is `jwk.SPKIKeyID`
(`pkg/encoding/jwk/kid.go:46`, re-exported as `JWKSPKIKeyID`): the unpadded
base64url (RFC 7515 §2) of SHA-256 over the key's DER SubjectPublicKeyInfo
(RFC 5280 §4.1.2.7). That is the identifier go-quicbaas publishes each JWKS key
under (#1724, comment c181516). `BuildTokenIssuer` (`pkg/api/rest/host.go:226`)
derives the `kid` in every token's JWS header (RFC 7515 §4.1.4) from the same
public key, so a token's `kid` always selects this JWK. The CN only names the
key in the backend; it is not the `kid`.

**The `typ` option.** `AccessTokenType` on `ServiceModuleSessionOptions`
(`rest.SessionOptions`) sets the access token's `typ` header (RFC 7515 §4.1.9).
`"at+jwt"` (`token.ATJWTType`) marks it as an OAuth 2.0 JWT access token, as
RFC 9068 §2.1 requires; empty keeps `JWT`. Refresh tokens always keep `JWT`, so
a verifier that demands `at+jwt` never accepts a refresh token as an access
token. An `at+jwt` access token also carries the rest of the RFC 9068 §2.2
claim set: `client_id` from the `ClientID` option (RFC 8693 §4.3) and a fresh
`jti`. `at+jwt` without a `ClientID` fails with
`token.ATJWTClientIDRequiredError`. xkmsd reads the same options from
`auth.session.access_token_type` and `auth.session.client_id`, and refuses
`at+jwt` without a `client_id` with `*config.SessionConfigError`
([web console guide](../web-console/user.md)).

The call reads the key and never creates it. The module creates the key when
it builds its REST surface, on the first request it serves. Call the accessor
after that, or retry it on `ServiceModuleSessionSigningKeyMissingError`.

| Error | When |
|---|---|
| `ServiceModuleSessionSigningKeyMissingError` (`CN`, `Backend`, wrapped cause) | The service has no default backend, or that backend holds no key under the CN |
| `ServiceModuleSessionSigningKeyExportError` (`CN`, `Backend`, wrapped cause) | The backend holds the key but cannot return its public half. A signer with no public key wraps `ErrServiceModuleSessionSigningKeyNoPublicKey` |
| `ServiceModuleSessionSigningKeyTypeError` (`CN`, `KeyType`) | The key is not a valid ECDSA P-256 key, so no ES256 JWK describes it |

A nil service fails with `rest.HostXKMSServiceRequiredError`.

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
| login finish: missing or already-consumed session | 400, code `invalid_session` | `InvalidArgument` |
| login finish: expired session | 400, code `session_expired` | `InvalidArgument` |
| login finish failed for any other reason: wrong assertion, unknown or refused account, account not in standing, unknown credential, or a malformed assertion | 401, code `verification_failed`, text "verification failed" | `Unauthenticated`, text "verification failed" |
| registration: invalid attestation, or origin/RP id mismatch | 401 | `Unauthenticated` |
| non-increasing signature counter | 401 | `Unauthenticated` |
| registration refused: the account already has a passkey, or (public registration off) no such account | 403, code `registration_refused` | `PermissionDenied` |
| add-passkey without a session | 401 | — |
| add-passkey with a session that names no WebAuthn account | 403, code `session_account_mismatch` | — |
| credential ID already registered | 409, code `credential_exists` (`/sdk/registration/finish`: 400) | `InvalidArgument` |
| session store full (too many unfinished ceremonies) | 503, code `session_limit` | `ResourceExhausted` |
| request body over 1 MiB | 413 | — (the gRPC message limit applies) |
| rate limited | 429 | `ResourceExhausted` |
| WebAuthn not configured | route absent (404) | `Unimplemented` |

**A full session store is a 503, not a 401.** It says nothing about the
caller or an account, only that the relying party is holding its maximum of
unfinished ceremonies; retry after the abandoned ones expire
(`pkg/webauthn/http/handler.go:315`, `pkg/api/rest/handlers_fido2.go:62,122`,
`pkg/api/grpc/service_fido2.go:55,125`). See
[engineering.md](engineering.md) §"Session lifetime and the session cap".

**The rate limit keys on the client IP**, taken from the transport peer with
its port removed. `X-Forwarded-For` / `X-Real-IP` are believed only from a
proxy listed in `server.trusted_proxies`; see
[`../xkmsd-configuration/user.md`](../xkmsd-configuration/user.md)
§"Behind a reverse proxy".

**The uniform 401 is deliberate.** Internally these are distinct typed errors
(`pkg/webauthn/errors.go`, exercised by `verification_error_test.go`); on the
wire they are indistinguishable, so a caller cannot use failure shapes to
enumerate users or probe which authenticator a user holds. The detail stays in
the server log.

**All three login-finish transports classify the same way.** The browser
route (`Handler.handleLoginFinishError`, `pkg/webauthn/http/handler.go`),
gRPC (`loginFinishStatusError`, `pkg/api/grpc/service_fido2.go`) and the SDK
REST route (`Server.writeLoginFinishError`, `pkg/api/rest/handlers_fido2.go`)
all call `webauthn.ClassifyLoginFinish` — the one place that decides whether
an error is a missing/expired session or the uniform failure — so a decoy
finish and a wrong-assertion finish against a real account produce
byte-identical responses on every transport, not only the browser route
(go-xkms#1310). Before that fix, gRPC and the SDK REST route each echoed the
raw error text (`status.Error(codes.InvalidArgument, err.Error())` and an
equivalent REST 400), which let a caller distinguish "no such account" from
"wrong assertion" on either transport even though the browser route already
hid it.

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
