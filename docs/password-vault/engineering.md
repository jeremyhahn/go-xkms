# Password Vault — Engineering Contract

> **Status: NORMATIVE** · Feature: `password-vault` · Repo: `go-xkms` · Last verified: 2026-10-01

## Exported surface — `pkg/staticpw`

### Access control (`access.go`)

```go
type AccessMode string

const (
	// AccessPINPerOperation requires a PIN for every decryption operation.
	AccessPINPerOperation AccessMode = "pin_per_operation"
	// AccessSessionBased requires a single PIN unlock, then allows free
	// access until the store is locked again.
	AccessSessionBased AccessMode = "session_based"
)
```

`access.go` defines only this type and the two constants -- no store
implementation lives here. `AccessSessionBased` is implemented by
`TenantPasswordStoreManager`: a user's session is the user's DEK, unwrapped by
one of the user's vault factors and held until the user locks or the tenant
barrier seals. There is no store implementation of `AccessPINPerOperation`:
`XKMSService.PasswordStoreSetAccessMode` only succeeds when the requested mode
already equals the store's active mode, and the active mode for a tenant
store is always `AccessSessionBased`.

### The personal vault (`vault.go`, `dek_backend.go`)

```go
type FactorType string // FactorPassphrase, FactorPasskey, FactorRecovery

type VaultCredential struct {
	Type         FactorType
	Secret       *secure.Secret // passphrase, hmac-secret output, or recovery code
	CredentialID []byte         // passkey
	PRFSalt      []byte         // passkey enrollment: the 32-byte hmac-secret salt
	Label        string
}

// TenantPasswordStoreManager
VaultStatus(ctx, tenant, subject) (*VaultStatus, error)
EnrollFactor(ctx, tenant, subject, cred) (*EnrollResult, error) // first: mints DEK + recovery code
UnlockUser(ctx, tenant, subject, cred) error                   // passphrase or passkey
RotateFactor(ctx, tenant, subject, factorID, cred) (*EnrollResult, error)
RemoveFactor(ctx, tenant, subject, factorID) error
RecoverVault(ctx, tenant, subject, recoveryCode, cred) (*EnrollResult, error)
LockUser(tenant, subject) error
```

Constants: `MinPassphraseLength` 8 (NIST SP 800-63B), `PasskeySecretLength`
32, `PRFSaltLength` 32. Passphrase KEK: Argon2id at `kdf.DefaultParams`
(64 MiB, t=3, p=4), the cost recorded on each factor. Passkey and recovery
KEKs: HKDF-SHA256 with a per-factor salt and a domain-separated info string.
Every wrap and every personal entry is AES-256-GCM with associated data
binding it to its tenant, user and factor (wraps) or storage key (entries).

`VaultCredential.Secret` is sealed in protected memory
(`sdk/go/secure.Secret`), never a plain `[]byte` or `string` struct field. It
is opened only for the duration of a key-encryption-key derivation
(`vaultFactor.kek`) or a length check (`VaultCredential.validate`), and the
opened `*secure.Buffer` is destroyed immediately after. The servicer layer
(`pkg/xkms`'s `vaultCredential`) is the boundary: it seals a transport
request's plaintext secret into a `*secure.Secret` and the caller destroys it
after the vault call returns. Wire and transport types
(`transport.PasswordVaultCredential`, and the REST/gRPC/MCP request types)
carry the secret as plaintext bytes up to that boundary.

Invariants: the DEK never changes; a vault always has a recovery factor
(written before the first factor); a user's vault changes are serialized per
user, so racing first enrollments mint one DEK; rotation writes the new wrap
before removing the old one; recovery writes the new factor and the new code
before retiring the used code.

Errors: `ErrVaultNotInitialized`, `ErrVaultCredentialRejected` (a wrong
secret, unknown passkey or wrong code -- never says which),
`ErrVaultInvalidCredential`, `ErrVaultFactorNotFound`, `ErrVaultLastFactor`,
`ErrVaultRecoveryFactor`, `ErrVaultPasskeyExists`, `*VaultStoreError`,
`*VaultCryptoError`, `*PersonalEntryDecryptError`.

Service layer (`pkg/xkms/servicer_password_vault.go`): `PasswordVaultStatus`,
`PasswordVaultEnroll`, `PasswordVaultRotate`, `PasswordVaultRemoveFactor`,
`PasswordVaultRecover`, and `PasswordStoreUnlock` with a
`transport.PasswordVaultCredential`. Each acts on the caller's own vault; a
request without an identity gets `ErrOperationNotSupported`.

### Scoping (`scope.go`, `scoped_store.go`)

```go
type PasswordScope string          // scope.go:17
```

Scoped and tenant-scoped stores compose over the base store:
`scoped_store.go`, `tenant_store_manager.go`. The team store
(`team_entity.go`, `team_store.go`) only records teams and their members for
xkey's local GUI; no password is shared through it.

### Stores

`store.go`: `BackendStore` (`store.go:107`), wrapping a `storage.Backend` --
at-rest confidentiality is the backend's (the tenant barrier), not a
`staticpw`-owned cipher. `scoped_store.go`: `ScopedStore`, splitting personal
and shared entries over two `BackendStore`s. Both implement `Store`
and share one `Get` contract: return the entry exactly as stored, with no
decrypt- or PIN-aware variant. Entries: `entity.go`, `team_entity.go`,
`types.go`. Support: `generator.go`, `expiry.go`, `validation.go`,
`errors.go`.

### Client contract — `sdk/go/transport`

```go
type PasswordService interface {
	PasswordAdd(ctx, req *PasswordAddRequest) (*PasswordAddResponse, error)
	PasswordGet(ctx, req *PasswordGetRequest) (*PasswordGetResponse, error)
	PasswordList(ctx, req *PasswordListRequest) (*PasswordListResponse, error)
	PasswordUpdate(ctx, req *PasswordUpdateRequest) error
	PasswordDelete(ctx, req *PasswordDeleteRequest) error
	PasswordStoreUnlock(ctx, req *PasswordStoreUnlockRequest) error
	PasswordStoreLock(ctx) error
	PasswordStoreStatus(ctx) (*PasswordStoreStatusResponse, error)
	PasswordStoreSetAccessMode(ctx, req *PasswordStoreSetAccessModeRequest) error
	PasswordGenerate(ctx, req *PasswordGenerateRequest) (*PasswordGenerateResponse, error)
}
```

## Invariants

- **`PasswordGet` returns entries exactly as stored.** There is no per-request
  decryption step and no plaintext/metadata split
  (`pkg/xkms/servicer_password.go:168`); `PasswordList` never returns the
  password field, matching `PasswordGet`.
- **Only `session_based` is reachable, and sessions are per user.** A caller
  must unlock its own personal session before any personal read or write
  succeeds; shared entries need no session, only an unsealed tenant barrier; there is no way to satisfy an operation with a
  per-call PIN instead (`access.go:17`-`26`).
- **A locked store answers status, not secrets.** `PasswordStoreStatus` works
  while locked; that is what makes it useful.
- **Scope is enforced, not advisory.** `own | shared | all` determines what a
  listing returns; a caller cannot widen it by asking.
- **Expiry is metadata.** `expires_at` marks an entry; nothing in this package
  invalidates the credential.
- **Generation has one implementation.** `generator.go`. A second generator at a
  call site is a defect.
- **Encryption is the barrier's.** `BackendStore` delegates to `storage.Backend`
  (`store.go:105`-`117`); `staticpw` does not implement a cipher.
- **Concurrency.** Stores are safe for concurrent use. Session state in
  `TenantPasswordStoreManager` is a lock-free `sync.Map` of open sessions per
  tenant, keyed by subject: `UnlockUser`/`LockUser` touch only the caller's
  entry, so one user's session never opens or closes another's. Sealing the
  tenant barrier clears every session of that tenant.
- **Manager API.** `ResolveScopedStore(tenant, subject)` (shared entries,
  plus personal ones while the session is open; `""` tenant is the unscoped
  system store for identity-less requests), `UnlockUser`, `LockUser`,
  `IsUserLocked`, `UserStoreStatus`. The system tenant (`"system"`) is served
  over the registry's system barrier. The transports never call the manager:
  they call the `XKMSService` password servicer, which resolves the caller
  with `scope.TenantName(identity.TenantID)` and `identity.Subject`.

## Error semantics

`pkg/staticpw/errors.go`. The distinctions that matter:

| Condition | Meaning |
|---|---|
| store locked | a personal operation without the caller's session open |
| vault not initialized | unlock or factor management before any enrollment |
| invalid credential | a malformed credential (short passphrase, wrong-length hmac-secret output or salt, unknown factor) |
| credential rejected | the credential unwraps no factor (wrong passphrase, unknown passkey, wrong output or code) |
| entry not found | wrong ID, or out of the caller's scope |
| validation failure | malformed entry — `validation.go` |

**Fail closed:** a locked session, a missing, malformed or wrong credential,
and an out-of-scope entry all refuse. An out-of-scope entry reports as not-found
rather than forbidden, so entry existence is not enumerable across scopes.

## Configuration

`PasswordStoreSetAccessMode` (`xkmsctl password access-mode <mode>`) validates
against the store's already-active mode rather than switching it; see
"Access control" above. A deployment's access mode is fixed by which store is
wired at startup, not by this call.

Per-entry: name, username, URL, notes, folder, `expires_at` (RFC 3339),
`tenant_id`, `shared`.

Per-listing: `folder`, `tenant_id`, `scope` (`own | shared | all`).

Generation: `length` (`0` = server default).

xkey's daemon takes `--password-store` (default `./data/staticpw`) for the
desktop-local store.

## Persistence

Through `BackendStore` to a `storage.Backend` that is the tenant barrier for
encryption at rest, under the `pkg/scope` keyspace. Tenant and user scoping is
`tenant_store_manager.go` + `scoped_store.go`.

There is no dedicated migration file in this package; entry-layout changes
go through the same `Store`/DAO surface as any other change (no-backward-compat:
pre-release, so old layouts are not carried forward).

## Test strategy

- **Unit** — one suite per file in `pkg/staticpw`, with `access`, `scope`,
  `team_*`, `expiry`, `generator` and `validation` each covered independently.
- **Transport** — `pkg/api/rest/password_handlers_test.go`;
  `pkg/api/mcp/handlers_password_test.go`, `handlers_password_unlock_test.go`;
  `pkg/xkms/servicer_password_test.go`.
- **Cross-module** — xkey's autofill and extension suites exercise the same
  store through IPC.

The two cases worth explicit tests in any consumer: a `get` against a locked
store, and a read of an entry outside the caller's scope. Both must fail, and
the second must fail as not-found
(`TestPasswordGet_LockedSessionReturnsErrStoreLocked`,
`pkg/xkms/servicer_password_test.go:1421`).

## Observability

Password reads are auditable events — `subject`, `action`, `resource:
passwords`, `resource_id`, `outcome` — through
[`../audit-log/`](../audit-log/engineering.md). **Entry names and IDs are
loggable; values never are**, and neither are the fields around them that people
put passwords in by mistake (`notes` is free-form and reaches storage).
