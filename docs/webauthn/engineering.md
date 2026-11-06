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
handle in `Subject`, `email` metadata and `TenantID`, the inverse of
`WebAuthnTokenAdapter`), and the service checks both name the same existing
account (`ErrSessionAccountMismatch` otherwise).

**Which sessions may add a passkey (Codex 9037).** Only a WebAuthn session:
`SessionAccountFromIdentity` refuses an identity whose
`auth.SubjectKindMetadataKey` is not `auth.SubjectKindUserHandle`. A username
subject (mTLS, PIV, certificate login) is refused even when it decodes as
base64url, since its owner chose it and could choose another account's
handle. A bearer session keeps the kind because the access token carries
the `sub_kind` claim and `auth.JWTAuthenticator` restores it.
`BeginAddCredential` then refuses, before any user lookup, a session
whose `TenantID` is not exactly the tenant the user store serves
(`qrdbUserStore.TenantID`); an empty tenant matches nothing, and a store that
declares no tenant refuses every session. The lookup runs on the store's
`CallContext`, which may be the service principal, so a session from another
tenant never reaches it (`TestWebAuthnBeginAddCredential_CertificateLoginCannotTakeOver`). `BeginLoginForEmail` and
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

**A registered user's qrdb `Username` is its qrdb user ID, never the email
(owner ruling 166, go-xkms#1468).** qrdb uses `Username` as the certificate CN,
so it carries no PII; the email stays in `Email`, qrdb's tenant-unique login
key, and in the rfc822Name SAN. qrdb assigns the ID at create and refuses an
empty `Username`, so `Create` (`qrdb_userstore.go:220`) creates the record under
a random `webauthn-pending-` placeholder and then renames it with `UpdateUser`
to the decimal ID (`assignUsername`, `qrdb_userstore.go:508`), which qrdb re-validates for
uniqueness and re-indexes atomically. A failed rename returns
`*QRDBUsernameAssignError` (`qrdb_userstore.go:750`) and leaves the record
under its placeholder: the embedded node's service principal holds no
`users:delete`, so there is no rollback. `GetByEmail` reports such a record,
while it has no credential, as not found, and the next `Create` for the email
finishes the rename and returns that user (`claimExisting`, `qrdb_userstore.go:279`).

The `Username` is never evidence that public sign-up created a record: qrdb
accepts any account name, so an account activated another way (a PIV
invitation, an administrator) can carry a `webauthn-pending-` name. Before its
`CreateUser`, `Create` writes the placeholder's provenance record,
`webauthn/enrolment-placeholder/<tenantID>/<placeholder>`
(`enrolmentPlaceholderPrefix`, `qrdb_userstore.go:898`), with `PutIfAbsent`;
only this store writes that prefix. A record is a recoverable placeholder only
when its name has the placeholder shape **and** that record exists
(`isPlaceholder`, `qrdb_userstore.go:557`). A placeholder-named account without
one is an ordinary account: `GetByEmail` returns it and `Create` refuses it
with `ErrRegistrationRefused`, taking no claim and renaming nothing. A
`CreateUser` that fails, or a process that dies, after the provenance write
leaves an orphan no account carries. The record is kept after the rename, since
no account carries its placeholder again. A drawn placeholder whose record
already exists is `*QRDBPlaceholderTakenError` (`qrdb_userstore.go:909`). A
placeholder that already holds a credential is never taken over: `Create`
returns `*QRDBPendingUserClaimedError` (`qrdb_userstore.go:769`). Nothing in the WebAuthn path reads
`Username`: login resolves by email (`GetUserByEmail`), and a WebAuthn token's
subject is the user handle (`SubjectKindUserHandle`), so records created
before the change, with the email as `Username`, still log in unchanged.

### Enrolment claims — one winner per email

Concurrent public registrations of one email race to rename the same
credential-free record. A durable claim in qrdb's KV picks one winner; only
the winner renames the record and gets a session.

- **Requirement.** `QRDBUserStoreOptions.KV` must be a qrdb
  `GuardedKVClient`, which adds `PutIfAbsent`, `CompareAndSwap` and
  `CompareAndDelete` to `KVClient`. `NewQRDBUserStoreAdapter`
  (`qrdb_userstore.go:84`) type-asserts it and otherwise fails with
  `*QRDBGuardedKVUnsupportedError` (`qrdb_userstore.go:868`).
- **Key and value.** The key is `webauthn/enrolment-claims/<tenantID>/<userID>`
  (`enrolmentClaimPrefix`, `qrdb_userstore.go:806`). The value is an 8-byte big-endian expiry in Unix
  nanoseconds followed by the token, a `crypto/rand` string
  (`encodeEnrolmentClaim`, `qrdb_userstore.go:534`).
- **TTL.** `EnrolmentClaimTTL`, `DefaultEnrolmentClaimTTL` (60 s) when zero
  (`DefaultEnrolmentClaimTTL`, `qrdb_userstore.go:823`). The REST host sets it to the WebAuthn
  `Config.Timeout` (`BuildWebAuthnService`, `pkg/api/rest/host.go:471`). It must be at least the
  ceremony timeout, or a slow but honest finish loses its claim to a
  recovering registration.
- **Acquire** (`acquireClaim`, `qrdb_userstore.go:299`). `Create` takes the
  claim on a new record with `PutIfAbsent`. On an existing record:
  - an absent claim is taken on a placeholder and refused on a renamed
    record (`ErrRegistrationRefused`);
  - a live claim is `*EnrolmentInProgressError`;
  - an expired or undecodable claim is taken over with `CompareAndSwap`
    against the value read, and a lost swap is `*EnrolmentInProgressError`.

  A record that holds a credential is never claimed (`claimExisting`,
  `qrdb_userstore.go:258`). The winner's session carries the token in its
  challenge (`withEnrolmentChallenge`, `service.go:482`). Sessions are
  server-side, so a client cannot forge the token.
- **Consume** (`consumeEnrolmentClaim`, `qrdb_userstore.go:362`). Finish
  refuses a user that already holds a credential (`consumeEnrolment`,
  `service.go:513`). It then swaps the live claim for a consumed claim
  (token `consumed:<token>`, a fresh expiry) with `CompareAndSwap`. The
  consumed claim stays held while the credential is saved, so a concurrent
  registration of the email is refused. An absent, expired, foreign or
  already-consumed claim is `*EnrolmentClaimLostError`
  (`qrdb_userstore.go:895`), and nothing is saved.
- **Credential marker** (`enrolmentCredentialPrefix`, `qrdb_userstore.go:818`).
  The consumed claim expires, and a credential save can outlast it; a
  registration that then took the claim over would write a second passkey.
  So the consume also wins `webauthn/enrolment-credential/<tenantID>/<userID>`
  (`credentialMarkerKey`, `qrdb_userstore.go:519`) with `PutIfAbsent`, value
  the claim token. The marker has no expiry and no path takes it over. A
  marker already held is `*EnrolmentCredentialMarkedError`
  (`qrdb_userstore.go:909`): the claim is released and nothing is saved.
  This is the invariant: the unauthenticated path writes at most one
  credential per account, whatever the timing. qrdb's `TransactionClient`
  could not fence the save itself: the credential store writes through the
  DAO, whose keys are internal to it.
- **Settle** (`settleEnrolmentClaim`, `qrdb_userstore.go:404`, called from
  `runFinishRegistration`, `service.go:416`).
  - **Saved credential:** the claim is removed with `CompareAndDelete`, and
    the marker stays for good. A claim that expired during the save is not an
    error: the marker holds the account.
  - **Save proven not written:** the marker is removed with
    `CompareAndDelete` against this finish's token (`dropCredentialMarker`,
    `qrdb_userstore.go:434`), and the claim is released. Only a result that
    proves no write happened counts (`outcomeOfCredentialSave`,
    `credential_store.go:218`): `ErrInvalidCredential` and the DAO's
    `DAOAtomicWriteUnsupportedError` and `DAOSerializationFailedError`, all
    raised before any write is sent, and `ErrCredentialAlreadyExists`,
    `SaveIfAbsent`'s `(false, nil)`.
  - **Unknown outcome:** any other save error. The pinned qrdb
    `GenericDAO.SaveIfAbsent` contract says a non-nil error leaves the
    outcome unknown: a transport, timeout or commit error can still commit,
    and reading the credential back proves nothing, since a pending proposal
    can commit after the read. The marker stays and the claim is released, so
    a later registration of the email is refused (`ErrRegistrationRefused` at
    begin, `*EnrolmentCredentialMarkedError` at finish) until the
    administrator deletes the account. The save error reaches the caller.
  - **Process death between marker and save** leaves a marker and no
    credential. Public sign-up then refuses the account: it fails closed,
    never open. The administrator clears it by deleting the account
    (`Delete`, which also deletes the marker); the email then enrols afresh.
- **Account delete** (`Service.DeleteUser`, `service.go:889`; `Delete`,
  `qrdb_userstore.go:676`). The caller's own grant authorizes it: the lookup,
  the account delete and the cleanup run on the caller's context, never
  `CallContext`'s, and need only `users:read`, `users:delete` and
  `kv:delete`. The service principal holds no `users:delete`. The account
  delete and the cleanup run on the caller's context pinned to the store's
  tenant, so the marker delete always targets this tenant's key.
  - **Deletion record.** `webauthn/account-deletion/<tenantID>/<userID>`
    (`enrolmentDeletionPrefix`, `qrdb_userstore.go:964`; `deletionKey`,
    `qrdb_userstore.go:548`) is the evidence that this tenant's delete of the
    account was authorized. It is written, read and dropped on `CallContext`'s
    context pinned to the store's tenant, never the caller's.
  - **Fresh delete.** Only an account the caller can read in its tenant is
    deleted afresh. `Delete` writes the record, then deletes the account,
    then removes the credentials, then the marker (`finishDelete`,
    `qrdb_userstore.go:753`), then the record.
  - **Interrupted delete.** An account delete error is returned with the
    record kept, whatever the error. qrdb can remove the account and then
    fail (an identity-index error after the primary record went, or
    `CommitOutcomeUnknownError`), and the administrator's retry then finds
    no account and resumes the cleanup on the kept record.
  - **Concurrent deletes.** Two `Delete` calls that both read the live
    account write the same record. A refusal (the caller lacks
    `users:delete`) proves only that this call removed nothing, so it never
    drops the record: a concurrent administrator whose cleanup failed after
    the account went still needs it to finish (Codex 9035;
    `TestWebAuthnDeleteUser_RefusedConcurrentDeleteKeepsRecord`). A record
    kept on an account that is still live removes nothing: the resume
    answers `ErrUserNotFound` while the account is live and still needs
    `users:delete`, and a fresh delete writes the record again.
  - **Resumed delete** (`resumeDelete`, `qrdb_userstore.go:725`). An account
    the caller cannot see is cleaned only when this tenant's record exists
    and the account is no longer live in the store's tenant. Before anything
    is removed, the caller must still hold `users:delete` in the store's
    tenant: the resume repeats the account delete on the pinned context, and
    only not-found lets it go on. Any other answer, including qrdb's refusal
    of an identity not in the target tenant, is returned with nothing
    removed and the record kept. A retry by this tenant's administrator then
    finishes a cleanup that failed, including a failed marker delete, and
    returns nil. Otherwise it is `ErrUserNotFound` with nothing removed. So
    another tenant's administrator can neither delete this tenant's passkeys
    nor finish or end its interrupted delete. The liveness check also
    covers a delete still in flight: until its account delete lands, the
    account is live and no other caller resumes it.
- **Release** (`releaseClaim`, `qrdb_userstore.go:340`). `CompareAndSwap`
  replaces the claim this store still holds with an expired one; release
  never deletes. It runs when a rename, materialization or credential save
  fails.
- **Recovery.** Public `BeginRegistration` (`service.go:176`) refuses an
  email whose account exists, unless that record carries a released or
  expired claim (`enrolmentRecoverable`, `qrdb_userstore.go:453`): a public
  enrolment that never saved its credential. That record goes to `Create`,
  which takes the claim over. A record with no claim on file, a live claim, a
  held credential marker or a credential is refused.

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
