# WebAuthn Relying Party — Engineering Contract

> **Status: NORMATIVE** · Feature: `webauthn` · Repo: `go-xkms` · Last verified: 2026-10-08

## Exported surface — `pkg/webauthn`

### `Service` (`service.go:43`), constructed by `NewService(params ServiceParams) (*Service, error)`

```go
func (s *Service) BeginRegistration(ctx, email, displayName string) (*protocol.CredentialCreation, string, error)
func (s *Service) BeginAddCredential(ctx, acct SessionAccount) (*protocol.CredentialCreation, string, error)
func (s *Service) FinishRegistration(ctx, sessionID string, response *protocol.ParsedCredentialCreationData) (string, User, error)
func (s *Service) FinishRegistrationPair(ctx, sessionID string, response *protocol.ParsedCredentialCreationData) (*TokenPair, User, error)
func (s *Service) BeginLogin(ctx, userID []byte) (*protocol.CredentialAssertion, string, error)
func (s *Service) BeginLoginForEmail(ctx, email string) (*protocol.CredentialAssertion, string, error)
func (s *Service) BeginLoginForHandle(ctx, userID []byte) (*protocol.CredentialAssertion, string, error)
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

`BeginRegistration` is the public first-passkey ceremony: it refuses an
account that already holds a credential, and (public registration off) an
unknown email, both with `ErrRegistrationRefused`. `BeginAddCredential` adds a
passkey to the account a `SessionAccount` names; `SessionAccountFromIdentity`
(`session_account.go`) builds one from an authenticated `auth.Identity` (base64url
handle in `Subject`, `email` metadata, the inverse of `WebAuthnTokenAdapter`),
and the service checks both name the same existing account
(`ErrSessionAccountMismatch` otherwise). `BeginLoginForEmail` and
`BeginLoginForHandle` answer an unknown account, or one without credentials,
with a decoy ceremony (`decoy.go`) instead of an error; `BeginLogin` keeps
returning `ErrUserNotFound` / `ErrNoCredentials` for in-process callers such as
`pkg/auth_factors`. See [api.md](api.md) §"Registration and enumeration rules".

**Account standing (go-xkms#1298).** `User` carries `Lifecycle()
qrdbsdk.Lifecycle` and `AuthMethods() []string`; the qrdb store copies both
from the qrdb record, and `DefaultUser` starts `active` with no restriction
(`SetLifecycle`, `SetAuthMethods`). `CheckAccountStanding(user)`
(`account_standing.go`) returns `*AccountNotActiveError` unless
`Lifecycle().CanAuthenticate()`, and otherwise applies
go-qrdb's `qrdbsdk.CheckAuthMethod(…, qrdbsdk.MethodWebAuthn)` — the one
permitted-method check the mTLS authenticator and qrdb's own middleware also
use; a refusal is `*qrdbsdk.AuthMethodNotPermittedError`. The service applies it at every login
begin (a refused account gets the decoy, or `ErrUserNotFound` from
`BeginLogin`) and at `finishLoginUser` after the assertion validates (a bare
`ErrVerificationFailed`); registration begin, add-passkey and registration
finish check the lifecycle and refuse with `ErrRegistrationRefused`.
`pkg/auth_factors`'s `BeginChallenge` treats a hint naming such an account as
an unknown hint. The detailed reason is logged at Warn, never returned.

The `…Pair` variants return access + refresh. Handlers select them by **type
assertion** on the injected generator: a `TokenPairGenerator` gets the pair
path, a plain `JWTGenerator` gets the single-token path. Both are supported;
neither is deprecated.

### Store interfaces (`interfaces.go`)

`UserStore`, `SessionStore`, `CredentialStore` — method sets in
[`architecture.md`](architecture.md). One implementation each:
`qrdb_userstore.go` (users are go-qrdb's), `credential_store.go` (credentials
are go-qrdb DAO entities) and `session_store.go` (sessions, in memory).

**One credential store, on the injected DAO factory.**
`NewQRDBUserStoreAdapter(QRDBUserStoreOptions{Users, DAOFactory, TenantID})`
(`qrdb_userstore.go:58`) returns the user store and the credential store
together; a nil `DAOFactory` is refused with `*QRDBAdapterConfigError`. The
credential store (`credential_store.go:59`) is built with `dao.New` on the
factory's default database, entity type `webauthn_credentials`. Each credential
is a `credentialEntity` whose ID is a SHA-256 of the base64url credential ID
and whose `UserID` is indexed, so lookup by credential ID is a natural-key read
and lookup by user is an indexed query. `pkg/webauthn` never imports
`pkg/datastore`: xkmsd passes `Datastore.DAOFactory()`, the API-module host
passes `HostConfig.DAOFactory`, and tests use `testutil.NewMemoryDAOFactory()`.

**`CredentialStore.Save` creates and `Update` edits (go-xkms#1295).** `Save`
refuses a credential ID that is already stored, under any account, with
`ErrCredentialAlreadyExists` and leaves the stored record alone (the DAO's
`SaveIfAbsent`). `Update` is the path a login's sign counter, clone flag and
last-used time take: it requires the credential to exist
(`ErrCredentialNotFound`) and to belong to the user the update names
(`ErrCredentialOwnerMismatch`). It is a `CompareAndSwap` against the record it
checked, so a credential deleted or replaced meanwhile is never resurrected
(`ErrCredentialUpdateConflict`).

**Legacy credentials move into the tenant store (go-xkms#1749).** Before
go-qrdb v0.46 (go-xkms#1428) credentials lived in one shared qrdb KV keyspace
with no tenant segment: `__xkms:webauthn/credentials/<base64url ID>` holds the
JSON `Credential` and `__xkms:webauthn/users/<qrdb user ID>/credentials` the
user's credential-ID index. The records are plain JSON, protected at rest only
by the qrdb barrier. `MigrateLegacyCredentials` (`legacy_migration.go:108`),
called by the consumer at each tenant store open, scans that prefix in key
order and for each record:

1. decodes it and checks that its ID is the one its key names, else
   `*LegacyCredentialCorruptError`;
2. resolves the tenant from the owner: `UserIDFromHandle`, then
   `UserClient.GetUser`, then `User.TenantID`, else
   `*CredentialOwnerUnresolvedError` (`ErrCredentialOwnerHasNoTenant` for a
   user without a tenant);
3. skips a credential of another tenant, leaving it for that tenant's open;
4. saves it with `CredentialStore.Save`. `ErrCredentialAlreadyExists` for the
   same user is an earlier run interrupted between save and delete, and counts
   as saved; for another user it fails with `ErrCredentialOwnerMismatch`;
5. deletes the legacy key only after the save succeeded.

Once every record is processed, a user's index is deleted when none of that
user's legacy credentials remain. A run that leaves a record whose owner is
unknown (step 1 failed, or `UserIDFromHandle` in step 2) deletes no index: that
record can belong to any of them, and the run after its repair or removal
cleans up (`pkg/webauthn/legacy_migration.go`, `MigrateLegacyCredentials`). A
failed step leaves the record in place and
adds a typed error to the report; the run then returns
`*CredentialMigrationIncompleteError`, and the next run retries it. The context
is checked before each record.

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
- **A counter that does not advance is reported, not refused.** go-webauthn
  flags it as `CloneWarning`; `finishLoginUser` logs it at Warn and records
  a `CloneWarningAuditAction` (`auth.webauthn.clone_warning`) audit event
  through `ServiceParams.AuditLogger` (`service.go:91,440`,
  `clone_warning.go:29,48`), and the login proceeds. The flag is sticky on the
  stored credential, so every later login with it is reported
  (`first_detection` marks the one that raised it). The action classifies
  `SeveritySecurity`: a failed audit write fails the login. Refusing a flagged
  credential is relying-party policy that this service does not impose.
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

Through the three store interfaces. Users are go-qrdb's, through
`go-qrdb/sdk/go` (`qrdb_userstore.go`); credentials are go-qrdb DAO entities
on the injected DAO factory (`credential_store.go`). Credentials carry
the credential id, public key, AAGUID, sign counter and user handle. Sessions
are short-lived and in memory; see §"Session lifetime and the session cap".

go-xkms defines no user model of its own — `User` is an interface satisfied by
qrdb's identity.

### Credential-store decoration — the composed-host seam

`rest.BuildWebAuthnService` (`pkg/api/rest/host.go:398`) derives the
DAO-backed credential store itself from `WebAuthnServiceParams.DAOFactory`
(`:352`; the self-built host surface takes it as `HostConfig.DAOFactory`,
`:635`). `rest.NewServer` builds no stores of its own: a WebAuthn config
without a pre-built service is refused with `rest.ErrWebAuthnServiceRequired`.
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

### Session lifetime and the session cap

A begin request stores a ceremony session before anyone is authenticated
(`POST /api/v1/webauthn/login/begin` with an empty body is enough), so the
session store is bounded two ways:

- **Swept.** `SweepSessions(ctx, store, interval)`
  (`pkg/webauthn/session_sweeper.go:34`) calls `Cleanup` on any store that
  implements `SessionCleaner` (`interfaces.go:47`) every interval until `ctx`
  ends, then returns; `Service.SweepSessions` (`session_sweeper.go:57`) runs it
  on the service's own store. The default interval,
  `DefaultSessionSweepInterval` (`session_sweeper.go:24`), is one minute.
- **Capped.** `MemorySessionStore` holds at most `DefaultMaxSessions` (10,000,
  `session_store.go:64`; `WithMaxSessions`, `:52`, overrides it). At the cap
  `Save` (`:122`) first removes expired sessions itself, and refuses with
  `*SessionLimitError` (`errors.go:79`; `IsSessionLimit`, `:90`) only when
  every held session is still live. Transports map it to 503 /
  `ResourceExhausted` ([api.md](api.md) §"Status and error mapping").

**One owner for the sweeper.** xkmsd owns the one `Service` shared by the
browser and SDK ceremonies, so `pkg/server` runs its sweeper:
`startWebAuthnSessionSweeper` (`pkg/server/server.go:2634`), called from
`Start` (`:2524`), runs it on a goroutine tracked by the server's wait group
under the server context. `Shutdown` cancels that context and waits on the
group, so the sweeper stops with the server and does not leak.

A composing host's self-built surface (`rest.NewHostServer`) has no lifecycle
hook to stop a goroutine, so it runs no sweeper; the sweep-on-save at the cap
keeps its store bounded and self-healing.

### Session expiry takes an injectable clock

`MemorySessionStore` measures a session's TTL against a `Clock` — a
`func() time.Time` supplied by `WithClock` on `NewMemorySessionStore` /
`NewMemorySessionStoreWithTTL`. It is optional and variadic: nil, or no option
at all, selects `time.Now`, so production behaviour and every existing call
site are unchanged.

It exists for tests. Expiry is a comparison against the wall clock, so a test
that establishes it by sleeping is asserting the machine was not busy —
`time.Sleep` guarantees a minimum and never a maximum. "Save a session with a
100ms TTL, then read it back and require success" fails whenever those two
statements land more than 100ms apart, which under `-race` on a shared runner
they can (#287).

**The sweeper ticks on a real `time.Ticker`**, but expiry is still measured
against the store's clock. `session_sweeper_test.go` therefore advances an
injected clock past the TTL, runs the sweeper with a one-millisecond interval,
and waits on the *event* — `MemorySessionStore.Count()` reaching the expected
value — rather than on a duration.

## Test strategy

- **Unit** — `service_test.go`, `config_test.go`, `types_test.go`,
  `registration_policy_test.go`, `verification_error_test.go`,
  `error_paths_test.go`, `session_store_test.go`, `mock_authenticator_test.go`,
  `session_sweeper_test.go` (cap refuses then recovers after a sweep, the
  sweeper removes expired sessions and returns when its context ends). The
  lifecycle ownership is pinned in `pkg/server/rest_limits_test.go`.
- **Store conformance** — `credential_store_test.go` (credentials round-trip
  through a real in-process DAO, lookup by credential ID and by user, sign
  counts persist, a duplicate ID is refused, not-found is
  `ErrCredentialNotFound`, a nil factory is refused),
  `qrdb_userstore_test.go`, `qrdb_userstore_gaps_test.go`,
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
useful to an attacker. Failures are audited through `pkg/audit`, and so is a
login with a possibly cloned credential (see Invariants); xkmsd wires its audit
logger in before the service is built. The login
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
context) and `PIN` (a browser prompts for it). `Origin` is required: both
adapters refuse an empty one, and refuse a server rpId the origin does not
cover, through `fido2.ValidateRPID` (`software_adapter.go:115,253`; the
hardware adapter through `pkg/fido2`). `NewClient` refuses a configuration
from which no origin can be derived (`client.go:64`).

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
	Origin               string               // WebAuthn origin; empty derives it from ServerURL (OriginFromURL); none derivable fails NewClient
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
	Origin:               "https://kms.example.com", // required: no ServerURL to derive it from
	AuthenticatorAdapter: adapter,
})
```

### `HTTPRelyingParty` correlation headers

| Header | Direction | Purpose |
|---|---|---|
| `X-Session-Id` | server → client → server | correlates begin with finish |
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
