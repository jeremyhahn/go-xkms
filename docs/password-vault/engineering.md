# Password Vault — Engineering Contract

> **Status: NORMATIVE** · Feature: `password-vault` · Repo: `go-xkms` · Last verified: 2026-09-28

## Exported surface — `pkg/staticpw`

### Access control (`access.go`)

```go
type AccessMode string

const (
	// Defined, but no store implementation exists (access.go:16-28).
	AccessPINPerOperation AccessMode = "pin_per_operation"
	// The only mode actually implemented.
	AccessSessionBased AccessMode = "session_based"
)
```

`session_based` is implemented by `TenantPasswordStoreManager.UnlockTenant`/
`LockTenant` (`tenant_store_manager.go:162`, `:143`), which hold a per-tenant
`atomic.Bool` session lock rather than a store decorator. There is no
`PINAccessStore` or `SessionStore` type in this package — both were removed
(go-xkms#864); `pkg/staticpw` has no store that itself gates on a PIN.

### Scoping (`scope.go`, `scoped_store.go`)

```go
type PasswordScope string          // scope.go:17
```

Scoped, team-scoped and tenant-scoped stores compose over the base store:
`scoped_store.go`, `team_scoped_store.go`, `tenant_store_manager.go`,
`tenant_dao_factory.go`.

### Stores

`store.go` (`BackendStore`, the sole concrete `Store` — encryption at rest is
a property of the `storage.Backend` it wraps, not a decorator in this
package), `dao_store.go` (persistence through go-qrdb). Entries: `entity.go`,
`team_entity.go`, `types.go`. Support: `generator.go`, `expiry.go`,
`validation.go`, `migration.go`, `errors.go`.

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

- **Plaintext is opt-in.** `PasswordGet` returns the plaintext only when the
  request asks for it (`--decrypt`); listing and metadata never do.
- **The access mode gates every plaintext read.** Under `session_based`
  (the only implemented mode) a prior `UnlockTenant` is required; there is no
  bypass. `pin_per_operation` is a defined `AccessMode` value with no store
  behind it (`access.go:16-28`) — it cannot become the active mode through
  the servicer that owns this vocabulary.
- **A locked store answers metadata, not secrets.** `PasswordStoreStatus` works
  while locked; that is what makes it useful.
- **Scope is enforced, not advisory.** `own | shared | all` determines what a
  listing returns; a caller cannot widen it by asking.
- **Expiry is metadata.** `expires_at` marks an entry; nothing in this package
  invalidates the credential.
- **Generation has one implementation.** `generator.go`. A second generator at a
  call site is a defect.
- **Encryption is the barrier's.** `BackendStore` implements no cipher; it
  writes plain JSON to whatever `storage.Backend` it is given. A tenant
  store's encryption comes from wrapping the tenant barrier as that backend
  (`seal.NewBarrierBackend`, `tenant_store_manager.go:176`).
- **Concurrency.** Stores are safe for concurrent use. The session lock held
  by `TenantPasswordStoreManager` is per-tenant, not per-caller — unlocking a
  tenant is visible to every caller scoped to that tenant, and that is
  exactly why `session_based` has the blast radius it does.

## Error semantics

`pkg/staticpw/errors.go`. The distinctions that matter:

| Condition | Meaning |
|---|---|
| store locked | any operation was attempted against a tenant store before `UnlockTenant` |
| PIN required | `PasswordStoreUnlock` called with no `user_pin` |
| PIN invalid | wrong PIN |
| entry not found | wrong ID, or out of the caller's scope |
| validation failure | malformed entry — `validation.go` |
| expired | metadata state, surfaced on read |

**Fail closed:** a locked store, a missing or wrong PIN, and an out-of-scope
entry all refuse. An out-of-scope entry reports as not-found rather than
forbidden, so entry existence is not enumerable across scopes.

## Configuration

Access mode is set at runtime — `PasswordStoreSetAccessMode`, or
`xkmsctl password access-mode <mode>`. It is a security policy that a deployment
should set deliberately rather than inherit.

Per-entry: name, username, URL, notes, folder, `expires_at` (RFC 3339),
`tenant_id`, `shared`.

Per-listing: `folder`, `tenant_id`, `scope` (`own | shared | all`).

Generation: `length` (`0` = server default).

xkey's daemon takes `--password-store` (default `./data/staticpw`) for the
desktop-local store.

## Persistence

Through `dao_store.go` to go-qrdb, or through `store.go`'s `BackendStore`
directly to a `storage.Backend`; encrypted whenever that backend is a tenant
barrier (`seal.NewBarrierBackend`, wired by `tenant_store_manager.go:176`),
not by a store-level decorator. Tenant scoping is `tenant_dao_factory.go` +
`tenant_store_manager.go`; team scoping is the `team_*` files.

`migration.go` handles entry-layout changes. Passwords are long-lived data —
people keep entries for years — so migrations here need to be additive and
reversible in a way that key material does not.

## Test strategy

- **Unit** — one suite per file in `pkg/staticpw`, with `scope`, `team_*`,
  `tenant_store_manager` (session lock, both locked/unlocked paths),
  `expiry`, `generator`, `validation` and `migration` each covered
  independently. There is no dedicated `access` suite: `access.go` declares
  the `AccessMode` type and its two constants, and carries no logic of its
  own to test.
- **Transport** — `pkg/api/rest/password_handlers_test.go`;
  `pkg/api/mcp/handlers_password_test.go`, `handlers_password_unlock_test.go`.
- **Cross-module** — xkey's autofill and extension suites exercise the same
  store through IPC.

The two cases worth explicit tests in any consumer: a plaintext read against a
locked store, and a read of an entry outside the caller's scope. Both must fail,
and the second must fail as not-found.

## Observability

Password reads are auditable events — `subject`, `action`, `resource:
passwords`, `resource_id`, `outcome` — through
[`../audit-log/`](../audit-log/engineering.md). **Entry names and IDs are
loggable; values never are**, and neither are the fields around them that people
put passwords in by mistake (`notes` is free-form and reaches storage).
