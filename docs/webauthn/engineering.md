# WebAuthn Relying Party — Engineering Contract

> **Status: NORMATIVE** · Feature: `webauthn` · Repo: `go-xkms` · Last verified: 2026-09-21

## Exported surface — `pkg/webauthn`

### `Service` (`service.go:43`), constructed by `NewService(params ServiceParams) (*Service, error)`

```go
func (s *Service) BeginRegistration(ctx, email, displayName string) (*protocol.CredentialCreation, string, error)
func (s *Service) FinishRegistration(ctx, sessionID string, response *protocol.ParsedCredentialCreationData) (string, User, error)
func (s *Service) FinishRegistrationPair(ctx, sessionID string, response *protocol.ParsedCredentialCreationData) (*TokenPair, User, error)
func (s *Service) BeginLogin(ctx, userID []byte) (*protocol.CredentialAssertion, string, error)
func (s *Service) FinishLogin(ctx, sessionID string, userID []byte, response *protocol.ParsedCredentialAssertionData) (string, User, error)
func (s *Service) FinishLoginPair(ctx, sessionID string, userID []byte, response *protocol.ParsedCredentialAssertionData) (*TokenPair, User, error)
func (s *Service) IsRegistered(ctx, userID []byte) (bool, error)
func (s *Service) GetUser(ctx, userID []byte) (User, error)
func (s *Service) GetUserByEmail(ctx, email string) (User, error)
func (s *Service) GetCredentials(ctx, userID []byte) ([]*Credential, error)
func (s *Service) DeleteCredential(ctx, credID []byte) error
func (s *Service) DeleteUser(ctx, userID []byte) error
func (s *Service) Config() *Config
```

The `…Pair` variants return access + refresh. Handlers select them by **type
assertion** on the injected generator: a `TokenPairGenerator` gets the pair
path, a plain `JWTGenerator` gets the single-token path. Both are supported;
neither is deprecated.

### Store interfaces (`interfaces.go`)

`UserStore`, `SessionStore`, `CredentialStore` — method sets in
[`architecture.md`](architecture.md). Implementations: `memory_stores.go`,
`qrdb_userstore.go`, `backend_stores.go`.

**`SessionStore` contract change:** The interface now defines an atomic `Take`
method that claims a session in one indivisible operation:

```go
type SessionStore interface {
    // ... other methods ...

    // Take atomically claims a session: it returns the session data AND
    // removes it in one indivisible operation, so exactly one caller can ever
    // observe a given session.
    //
    // A WebAuthn ceremony session is single-use. Finishing a ceremony must
    // claim it with Take BEFORE validating the authenticator response;
    // validating first and deleting afterwards leaves a window in which two
    // concurrent finish requests both validate against the same challenge and
    // both succeed.
    //
    // Returns ErrSessionNotFound when no session was claimed (missing, or
    // already taken by a concurrent caller) and ErrSessionExpired when the
    // claimed session had aged out. An expired session is consumed all the
    // same, so it cannot be retried.
    //
    // Implementations that cannot make this atomic must not be used: a
    // non-atomic take is the defect this method exists to remove.
    Take(ctx context.Context, sessionID string) (*webauthn.SessionData, error)
}
```

This is a **load-bearing safety invariant** — session replay and concurrent
ceremony exploitation depends on atomicity. Implementors must use a backend
capable of compare-and-swap, or fail construction rather than serve a weaker
guarantee. The certification ceremony finish path calls `Take` BEFORE validating
the authenticator's response, ensuring exactly one caller observes a given
session.

### Token generation

```go
type JWTGenerator interface       { GenerateToken(ctx, user User) (string, error) }
type TokenPairGenerator interface { GenerateTokenPair(ctx, user User) (access, refresh string, err error) }
```

### Headless client

`pkg/webauthn/client` — the programmatic "browser" used by `xkmsctl` and tests.
`pkg/webauthn/mock_authenticator.go` is the in-process authenticator for unit
tests.

## `Config` (`config.go`)

| Field | YAML key | Meaning |
|---|---|---|
| `RPID` | `id` | Relying-party id. Binds credentials to a domain. |
| `RPDisplayName` | `display_name` | Shown by the authenticator. |
| `RPOrigins` | `origins` | Allowed origins; ceremony responses are checked against this list. |
| `RPIcon` | `icon` | Optional. |
| `Timeout` | `timeout` | Ceremony timeout. |
| `UserVerification` | `user_verification` | `required`, `preferred`, `discouraged`. |
| `AttestationPreference` | `attestation` | `none`, `indirect`, `direct`. |
| `ResidentKeyRequirement` | `resident_key` | Discoverable-credential policy. |
| `AuthenticatorAttachment` | `authenticator_attachment` | `platform`, `cross-platform`. |
| `AllowPublicRegistration` | `allow_public_registration` | `*bool` — nil means disabled; nil is still distinguishable from an explicit false. |
| `Debug` | `debug` | Verbose ceremony logging. Never in production. |

`RPID` and `RPOrigins` are the two that are load-bearing for security. A
credential enrolled under one `RPID` cannot be used under another — changing it
invalidates every existing credential.

## Invariants

- **A session is single-use.** `BeginRegistration`/`BeginLogin` create it,
  `Finish…` consumes and deletes it. Replaying a finish fails.
- **`FinishLogin`/`FinishLoginPair`'s `userID` is advisory, not authoritative.**
  The session created by `BeginLogin` already records whether the ceremony is
  discoverable (empty `SessionData.UserID`) or user-identified (the resolved
  handle); that record always decides which validation path runs, so `userID`
  may be nil for either flow and a caller that supplies one — as
  `pkg/auth_factors`'s `WebAuthnFactorVerifier.Verify` does once it has
  resolved a qrdb factor to a user — cannot flip a discoverable session into
  the identified path or vice versa (go-xkms#558).
- **Challenges are server-generated and stored in the session**, never taken
  from the request.
- **Origin and RP id are verified on every finish.** A response from an
  unlisted origin fails.
- **Signature counters move forward.** A counter that does not increase is
  treated as a cloning signal, not as a retry.
- **`AllowPublicRegistration` defaults closed, and nil ≠ false.** An unset
  flag means registration is disabled (go-xkms#184: the stack registration
  model is invite-only by default, and a setting that can silently produce an
  open surface is a defect). Code that reads it must still handle three
  states: nil records "never decided", which compliance profiling and the
  composed-host projection both depend on. When xkms runs as a ServiceModule,
  the host-projected value (quicbaas `WithServiceModuleWebAuthn` →
  `WebAuthnConfigFromXKMS`) passes through verbatim and is authoritative.
- **Nothing here decides authorization.** A successful ceremony yields a token;
  what that token may do is go-qrdb's RBAC.
- **Concurrency.** `Service` is safe for concurrent ceremonies; sessions are
  keyed and independent.

## Error semantics

`pkg/webauthn/errors.go`. Typed errors, never `fmt.Errorf`. The verification
path has its own suite (`verification_error_test.go`) because these are the
errors that must never be collapsed into a generic failure internally, even
though they must be indistinguishable to the client.

**The SDK ceremony requests' login key** is the `Email` field of
`BeginRegistrationRequest`, `BeginAuthenticationRequest` and
`FinishAuthenticationRequest` (`pkg/api/transport/types.go`). Their decoders
share one resolution (`loginKeyFromWire`): the legacy `username` JSON key is
accepted for one release, and a body naming different values under both keys
is refused with `transport.ErrRegistrationLoginKeyConflict` or
`transport.ErrAuthenticationLoginKeyConflict`; see [api.md](api.md) §"SDK
ceremony bodies".

**Fail closed:** unknown session, expired session, origin mismatch, RP id
mismatch, attestation that does not satisfy policy, invalid signature,
non-increasing counter, missing credential. All produce an authentication
failure.

**Deliberate ambiguity toward the client:** the transport maps these to a
uniform 401 so a caller cannot distinguish "no such user" from "wrong
authenticator". The distinction stays in the logs.

**Not-found is decided by type, never by text (#183).** The qrdb-backed
stores map a missing record to `ErrUserNotFound` / `ErrCredentialNotFound`
only when the SDK returns its typed not-found: `*transport.UserNotFoundError`
(REST), `*transport.KeyNotFoundError` (gRPC, MCP, embedded), or the embedded
DAO's not-found. QUIC carries the user service's message opaquely inside
`*transport.RequestError` (go-qrdb#289), and for that path alone the message
is matched by exact prefix against the service's two canonical forms. Any
other failure, including one whose text happens to say "not found", is
returned as an error. A false absence is what licenses a consumer's rollback
to delete a credential it did not create, and what makes the registration
ceremony create a duplicate account; a false error costs a retry.

## Persistence

Through the three store interfaces. Production wiring is go-qrdb via
`go-qrdb/sdk/go` (`qrdb_userstore.go`, `backend_stores.go`). Credentials carry
the credential id, public key, AAGUID, sign counter and user handle. Sessions
are short-lived and deleted on finish.

go-xkms defines no user model of its own — `User` is an interface satisfied by
qrdb's identity.

### Credential-store decoration — the composed-host seam

`rest.BuildWebAuthnService` derives the qrdb-backed credential store itself.
A composing host that needs its own side effect on every registration served
by xkms's relying party supplies a decorator rather than a second relying
party over the same store:

```go
type WebAuthnCredentialStoreDecorator func(webauthn.CredentialStore) webauthn.CredentialStore
```

| Level | Seam |
|---|---|
| builder | `rest.WebAuthnServiceParams.CredentialStoreDecorator` |
| self-built host surface | `rest.HostConfig.WebAuthnCredentialStoreDecorator` |
| ServiceModule | `apimodule.WithWebAuthnCredentialStoreDecorator` |
| SDK re-export | `xkms.WithServiceModuleWebAuthnCredentialStoreDecorator` |

Contract:

- The decorator runs **once, at construction**, and receives the qrdb-backed
  store. The store it returns backs both ceremony lanes — the browser routes
  and the `/sdk/...` routes — because both resolve the same `Service`.
- The returned store MUST preserve the wrapped store's persistence
  semantics. Returning nil — including a typed nil such as `(*T)(nil)`,
  which would otherwise panic on the first `Save` — fails construction with
  `rest.ErrWebAuthnCredentialStoreDecoratorNil`; on the self-built host
  surface that failure is logged and leaves the WebAuthn route family
  unmounted, as every other WebAuthn construction failure does.
- It is a **persistence** seam, not an authorization one. The relying party
  has already verified attestation, origin, RP ID, challenge and user handle
  before it calls `Save`, so a decorator can neither reach nor relax a
  ceremony check.
- Unset, the qrdb-backed store is used directly — the default composition is
  byte-for-byte what it was.

The motivating case (go-xkms#350): a composed node whose unified login
ceremony resolves a qrdb **auth factor**, not the credential record. Without
the seam, a passkey enrolled through xkms's own registration routes created
no factor, and login failed with "factor not found" while the credential sat
in the shared store.

### Session expiry takes an injectable clock

`MemorySessionStore` measures a session's TTL against a `Clock` — a
`func() time.Time` supplied by `WithClock` on `NewMemorySessionStore` /
`NewMemorySessionStoreWithTTL`. It is optional and variadic: nil, or no option
at all, selects `time.Now`, so production behaviour and every existing call
site are unchanged. `rest.WebAuthnStoresConfig` carries the same seam through
as its `Clock` field.

It exists for tests. Expiry is a comparison against the wall clock, so a test
that establishes it by sleeping is asserting the machine was not busy —
`time.Sleep` guarantees a minimum and never a maximum. "Save a session with a
100ms TTL, then read it back and require success" fails whenever those two
statements land more than 100ms apart, which under `-race` on a shared runner
they can (#287).

**The cleanup routine is the deliberate exception.** `StartCleanupRoutine`
ticks on a real `time.Ticker`, so a test for it keeps real time and a short TTL
and waits on the *event* — `MemorySessionStore.Count()` reaching zero — rather
than on a duration. Handing that test a fake clock would stop the session ever
expiring by the routine's reckoning, and it would wait for an event that cannot
happen.

## Test strategy

- **Unit** — `service_test.go`, `config_test.go`, `types_test.go`,
  `registration_policy_test.go`, `verification_error_test.go`,
  `error_paths_test.go`, `memory_stores_test.go`, `backend_stores_test.go`,
  `backend_stores_gaps_test.go`, `mock_authenticator_test.go`.
- **Store conformance** — `qrdb_userstore_test.go`, `qrdb_userstore_gaps_test.go`,
  `qrdb_error_paths_test.go`, and `qrdb_register_login_repro_test.go` (a
  regression reproduction kept as a permanent test).
- **Conformance** — `conformance_test.go`.
- **Integration** — `integration_test.go`, `test/integration/webauthn-browser`
  (real browser), `test/integration/logins`.
- **Fixtures** — `mock_authenticator.go` for unit work,
  `pkg/webauthn/client` for headless end-to-end.

## Observability

Ceremony outcomes are logged with the correlation ID. `Config.Debug` adds
verbose ceremony detail and must stay off in production — it logs material
useful to an attacker. Failures are audited through `pkg/audit`; the login
route groups sit behind the rate limiter (`pkg/ratelimit`), whose rejections are
metered in `pkg/metrics`.

## The headless client — `pkg/webauthn/client`

The "browser" in the WebAuthn protocol, for callers that are not one. It sits
between the relying party and a local authenticator and runs both ceremonies
programmatically. `xkmsctl` and the test suites drive it.

```
  RP Server (go-xkms)          Headless Client           Authenticator
       |                            |                         |
       |  POST registration/begin   |                         |
       |<---------------------------|                         |
       |  CreationOptions           |                         |
       |--------------------------->|                         |
       |                            |  MakeCredential()       |
       |                            |------------------------>|
       |                            |  AttestationResponse    |
       |                            |<------------------------|
       |  POST registration/finish  |                         |
       |<---------------------------|                         |
       |  { user_id, token }        |                         |
       |--------------------------->|                         |
```

### Client API

| Method | Description |
|---|---|
| `NewClient(config)` | Creates a client with an authenticator adapter |
| `Register(ctx, req)` | Full registration ceremony: begin, CTAP, finish |
| `Login(ctx, req)` | Full authentication ceremony: begin, CTAP, finish |
| `Available(ctx)` | Checks both server and authenticator reachability |

### `AuthenticatorAdapter`

| Method | Description |
|---|---|
| `MakeCredential(options)` | Creates a credential from JSON CreationOptions; returns JSON attestation |
| `GetAssertion(options)` | Gets an assertion from JSON RequestOptions; returns JSON assertion |
| `Available()` | Reports whether the authenticator is ready |

Two adapters ship. `SoftwareAdapter` is the in-memory one for testing:
ephemeral ECDSA P-256 keypairs, `"none"` attestation format, a per-credential
sign counter, thread-safe credential storage. The CTAP2 adapter bridges to real
hardware through [`../fido2-ctap2/`](../fido2-ctap2/engineering.md).

### `Config`

```go
type Config struct {
	ServerURL            string               // RP server base URL (required)
	HTTPClient           *http.Client         // custom HTTP client (optional)
	TLSConfig            *tls.Config          // used when HTTPClient is nil
	Timeout              time.Duration        // default 30s
	AuthenticatorAdapter AuthenticatorAdapter // CTAP2 bridge (required)
}
```

```go
adapter := client.NewSoftwareAdapter()
c, _ := client.NewClient(&client.Config{
	ServerURL:            "https://kms.example.com:8443",
	AuthenticatorAdapter: adapter,
})

reg, err := c.Register(ctx, &client.RegistrationRequest{
	Username:    "alice@example.com",
	DisplayName: "Alice",
	AuthToken:   setupToken, // optional JWT or bootstrap token
})
// reg.UserID, reg.JWT

login, err := c.Login(ctx, &client.AuthenticationRequest{
	Username:  "alice@example.com",
	AuthToken: existingJWT, // optional
})
// login.UserID, login.JWT
```

### Ceremony correlation headers

| Header | Direction | Purpose |
|---|---|---|
| `X-Session-Id` | server → client → server | correlates begin with finish |
| `X-User-Id` | server → client → server | correlates the user during login |
| `Authorization` | client → server | `Bearer <token>` on authenticated requests |

### Client errors

`ErrServerURLRequired`, `ErrUsernameRequired`, `ErrRegistrationFailed`,
`ErrAuthenticationFailed`, `ErrServerUnavailable`, `ErrAuthenticatorNotFound`,
`ErrCTAPOperationFailed`, `ErrInvalidServerResponse`, `ErrInvalidChallenge`.
