# WebAuthn Relying Party — Engineering Contract

> **Status: NORMATIVE** · Feature: `webauthn` · Repo: `go-xkms` · Last verified: 2026-09-23

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

`pkg/webauthn/client` — the single programmatic "browser" ceremony driver,
re-exported at `sdk/go/webauthnclient` and used by `xkey`, `xkmsctl` and
tests; see [§"The headless client"](#the-headless-client--pkgwebauthnclient)
below. `pkg/webauthn/mock_authenticator.go` is a separate, RP-side test
double for `pkg/webauthn` itself (not the client).

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
`FinishAuthenticationRequest` (`pkg/api/transport/types.go`), tagged
`json:"email"` with no other spelling accepted; see [api.md](api.md) §"SDK
ceremony bodies".

**Fail closed:** unknown session, expired session, origin mismatch, RP id
mismatch, attestation that does not satisfy policy, invalid signature,
non-increasing counter, missing credential. All produce an authentication
failure.

**Deliberate ambiguity toward the client:** the transport maps these to a
uniform 401 so a caller cannot distinguish "no such user" from "wrong
authenticator". The distinction stays in the logs.

**MCP transport exclusion (#193).** `pkg/api/transport/mcp.Transport`'s
`BeginRegistration`, `FinishRegistration`, `BeginAuthentication`, and
`FinishAuthentication` always return the typed
`pkg/api/transport/mcp.ErrIdentityCeremonyExcluded`, re-exported unchanged as
`sdk/go/transport/mcp.ErrIdentityCeremonyExcluded`. This is a named,
permanent exclusion rather than an unimplemented tool: an MCP tool-call
surface is agent-facing and must not mint sessions or enrol credentials.
`pkg/api/mcp.ModuleMethods`, the capability surface a client can query
without calling and failing, never lists a tool for these four methods
either — see [api.md](api.md) §Capability matrix.

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

The **single** headless WebAuthn ceremony driver in go-xkms: the "browser" in
the protocol, for callers that are not one. It bridges a `RelyingParty` (the
server side) and an `AuthenticatorAdapter` (the authenticator side) and runs
both ceremonies programmatically. Re-exported at `sdk/go/webauthnclient`;
`xkey`, `xkmsctl` and the test suites all drive ceremonies through this one
`Client`, with one `RelyingParty`/`AuthenticatorAdapter` pair each — none
reimplements the ceremony (go-xkms#721 consolidated three prior
implementations onto it).

```
  RelyingParty                 Client                   AuthenticatorAdapter
       |                            |                         |
       |  BeginRegistration         |                         |
       |<---------------------------|                         |
       |  CreationOptions           |                         |
       |--------------------------->|                         |
       |                            |  MakeCredential()       |
       |                            |------------------------>|
       |                            |  AttestationResponse    |
       |                            |<------------------------|
       |  FinishRegistration        |                         |
       |<---------------------------|                         |
       |  { credential_id, token }  |                         |
       |--------------------------->|                         |
```

### `RelyingParty` — the server-side seam

`Client` is deliberately thin: it drives begin → authenticator → finish and
leaves both sides pluggable. Two `RelyingParty` implementations ship:

| Implementation | Speaks | Used by |
|---|---|---|
| `HTTPRelyingParty` (`NewHTTPRelyingParty`, or the `Client` default built from `Config.ServerURL`) | The browser-shaped `pkg/webauthn/http` routes (`registration/begin`, `.../finish`, `login/begin`, `.../finish`) | Direct HTTP callers, tests |
| `TransportRelyingParty` (`NewTransportRelyingParty(TransportClient)`) | The SDK transport routes (`/api/v1/webauthn/sdk/...`) through a `pkg/api/transport.Client`, any protocol (REST, gRPC, QUIC, Unix, MCP) | `xkey`, `xkmsctl` |

```go
type RelyingParty interface {
	BeginRegistration(ctx context.Context, req *RegistrationRequest) (*BeginResult, error)
	FinishRegistration(ctx context.Context, begin *BeginResult, req *RegistrationRequest, attestation []byte) (*RegistrationResult, error)
	BeginAuthentication(ctx context.Context, req *AuthenticationRequest) (*BeginResult, error)
	FinishAuthentication(ctx context.Context, begin *BeginResult, req *AuthenticationRequest, assertion []byte) (*AuthenticationResult, error)
}
```

`TransportClient` is the four-method SDK-ceremony subset of
`pkg/api/transport.Client`; a connected `sdk/go` `Client` (any protocol
binding) satisfies it directly with no adapter. Unlike `HTTPRelyingParty`,
which sends `RegistrationRequest.AuthToken`/`AuthenticationRequest.AuthToken`
as a bearer header per request, `TransportRelyingParty` ignores that field —
the transport connection already carries its own authentication.

### Client API

| Method | Description |
|---|---|
| `NewClient(config)` | Creates a client with a `RelyingParty` and an `AuthenticatorAdapter` |
| `Register(ctx, req)` | Full registration ceremony: begin, authenticator, finish |
| `Login(ctx, req)` | Full authentication ceremony: begin, authenticator, finish |
| `Available(ctx)` | Checks both the relying party (if it implements `AvailabilityChecker`) and the authenticator |

### `AuthenticatorAdapter` — the authenticator-side seam

```go
type AuthenticatorAdapter interface {
	MakeCredential(ctx context.Context, opts *CeremonyOptions) ([]byte, error)
	GetAssertion(ctx context.Context, opts *CeremonyOptions) ([]byte, error)
	Available() bool
}
```

`CeremonyOptions` carries the relying party's JSON options plus the two
things they cannot carry: `Origin` (a browser takes it from its security
context) and `PIN` (a browser prompts for it).

Two adapters ship:

- **`SoftwareAdapter`** (`NewSoftwareAdapter`) — the in-memory one for
  headless testing and CI: ephemeral ECDSA P-256 keypairs, `"none"`
  attestation format, a per-credential sign counter, thread-safe credential
  storage, no PIN. No HID or hardware required.
- **`HardwareAdapter`** (`NewHardwareAdapter(config *fido2.Config, enumerator fido2.HIDDeviceEnumerator)`)
  — drives a real CTAP2 authenticator over HID through `pkg/fido2`, the
  single canonical FIDO2 CTAP2 implementation in the stack (see
  [`../fido2-ctap2/`](../fido2-ctap2/engineering.md)), including xkey's
  virtual "xkey fido2" uhid authenticator, which enumerates
  indistinguishably from real hardware. It fails closed
  (`ErrAuthenticatorNotFound`) when discovery finds no device, and carries
  the CTAP2 PIN through `CeremonyOptions.PIN`, surfacing a PIN-protected
  authenticator's refusal as `ErrPINRequired` rather than the raw
  `CTAP2_ERR_PIN_REQUIRED`.

### `Config`

```go
type Config struct {
	ServerURL            string               // RP server base URL; required unless RelyingParty is set
	HTTPClient           *http.Client         // default HTTPRelyingParty's client (optional)
	TLSConfig            *tls.Config          // used when HTTPClient is nil
	Timeout              time.Duration        // default 30s
	Origin               string               // WebAuthn origin; empty derives it from ServerURL
	AuthenticatorAdapter AuthenticatorAdapter // required
	RelyingParty         RelyingParty         // nil builds the default HTTPRelyingParty from ServerURL
}
```

Browser-shaped RP with a real authenticator:

```go
adapter, err := webauthnclient.NewHardwareAdapter(nil, nil) // defer adapter.Close()
c, _ := webauthnclient.NewClient(&webauthnclient.Config{
	ServerURL:            "https://kms.example.com:8443",
	AuthenticatorAdapter: adapter,
})

reg, err := c.Register(ctx, &webauthnclient.RegistrationRequest{
	Username:    "alice@example.com",
	DisplayName: "Alice",
	AuthToken:   setupToken, // optional JWT or bootstrap token
})
// reg.CredentialID, reg.JWT

login, err := c.Login(ctx, &webauthnclient.AuthenticationRequest{
	Username:  "alice@example.com",
	AuthToken: existingJWT, // optional
})
// login.UserID, login.JWT
```

SDK-transport RP (the `xkey`/`xkmsctl` shape), over an already-connected
`sdk/go` client:

```go
rp, _ := webauthnclient.NewTransportRelyingParty(transportClient)
c, _ := webauthnclient.NewClient(&webauthnclient.Config{
	RelyingParty:         rp,
	AuthenticatorAdapter: adapter,
})
```

### `HTTPRelyingParty` correlation headers

| Header | Direction | Purpose |
|---|---|---|
| `X-Session-Id` | server → client → server | correlates begin with finish |
| `X-User-Id` | server → client → server | correlates the user during login |
| `Authorization` | client → server | `Bearer <token>` on authenticated requests |

`TransportRelyingParty` carries the equivalent correlation (session ID, email)
inside the SDK's typed request/response bodies instead of headers, and relies
on the transport connection for authentication.

### Client errors

`ErrServerURLRequired`, `ErrUsernameRequired`, `ErrRegistrationFailed`,
`ErrAuthenticationFailed`, `ErrServerUnavailable`, `ErrAuthenticatorNotFound`,
`ErrCTAPOperationFailed`, `ErrInvalidServerResponse`, `ErrInvalidChallenge`,
`ErrPINRequired`, `ErrNilTransportClient`. `ServerError` reports an
`HTTPRelyingParty` non-2xx response; `RelyingPartyRejection` reports a
`TransportRelyingParty` ceremony the server completed but declined
(`Success: false`).
