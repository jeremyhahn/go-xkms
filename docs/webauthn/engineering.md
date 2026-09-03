# WebAuthn Relying Party — Engineering Contract

> **Status: NORMATIVE** · Feature: `webauthn` · Repo: `go-xkms` · Last verified: 2026-08-19

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

**Fail closed:** unknown session, expired session, origin mismatch, RP id
mismatch, attestation that does not satisfy policy, invalid signature,
non-increasing counter, missing credential. All produce an authentication
failure.

**Deliberate ambiguity toward the client:** the transport maps these to a
uniform 401 so a caller cannot distinguish "no such user" from "wrong
authenticator". The distinction stays in the logs.

## Persistence

Through the three store interfaces. Production wiring is go-qrdb via
`go-qrdb/sdk/go` (`qrdb_userstore.go`, `backend_stores.go`). Credentials carry
the credential id, public key, AAGUID, sign counter and user handle. Sessions
are short-lived and deleted on finish.

go-xkms defines no user model of its own — `User` is an interface satisfied by
qrdb's identity.

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
