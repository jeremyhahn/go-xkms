# Password Vault — Engineering Contract

> **Status: NORMATIVE** · Feature: `password-vault` · Repo: `go-xkms` · Last verified: 2026-09-28

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

`access.go` (38 lines total) defines only this type and the two constants --
no store implementation lives here. `AccessSessionBased` is implemented
directly by `TenantPasswordStoreManager` against the qrdb `TenantBarrier`'s
own unseal/reseal (`tenant_store_manager.go`); the PIN check for
`PasswordStoreUnlock` is performed at the servicer layer
(`XKMSService.verifyPasswordStoreUserPIN`,
`pkg/xkms/servicer_password.go:346`). There is no store implementation of
`AccessPINPerOperation`: `XKMSService.PasswordStoreSetAccessMode` only
succeeds when the requested mode already equals the store's active mode, and
the active mode for a tenant store is always `AccessSessionBased`
(`pkg/xkms/servicer_password.go:452`-`474`, `access.go:17`-`26`).

### Scoping (`scope.go`, `scoped_store.go`)

```go
type PasswordScope string          // scope.go:17
```

Scoped, team-scoped and tenant-scoped stores compose over the base store:
`scoped_store.go`, `team_scoped_store.go`, `tenant_store_manager.go`,
`tenant_dao_factory.go`.

### Stores

`store.go`: `BackendStore` (`store.go:107`), wrapping a `storage.Backend` --
at-rest confidentiality is the backend's (the tenant barrier), not a
`staticpw`-owned cipher. `scoped_store.go`: `ScopedStore`, splitting personal
and shared entries over two `BackendStore`s. `dao_store.go`: `DAOStore`,
persistence through go-qrdb's `qrdbsdk.NewDAO`. All three implement `Store`
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
- **Only `session_based` is reachable.** A caller must unlock the store before
  any read or write succeeds; there is no way to satisfy an operation with a
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
  `TenantPasswordStoreManager` (`locked atomic.Bool` per tenant,
  `tenant_store_manager.go:35`-`38`) is shared, process-wide state — unlocking
  is not per-caller, and that is exactly why `session_based` has the blast
  radius it does.

## Error semantics

`pkg/staticpw/errors.go`. The distinctions that matter:

| Condition | Meaning |
|---|---|
| store locked | an operation was attempted without an unlock |
| PIN required (unlock only) | `PasswordStoreUnlock` called with no PIN |
| PIN invalid (unlock only) | wrong PIN on `PasswordStoreUnlock` |
| entry not found | wrong ID, or out of the caller's scope |
| validation failure | malformed entry — `validation.go` |

**Fail closed:** a locked store, a missing or wrong unlock PIN, and an
out-of-scope entry all refuse. An out-of-scope entry reports as not-found
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

Through `dao_store.go` to go-qrdb (`qrdbsdk.NewDAO`), over a `storage.Backend`
that is the tenant barrier for encryption at rest. Tenant scoping is
`tenant_dao_factory.go` + `tenant_store_manager.go`; team scoping is the
`team_*` files.

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
