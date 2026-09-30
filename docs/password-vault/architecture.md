# Password Vault — Architecture

> **Status: NORMATIVE** · Feature: `password-vault` · Repo: `go-xkms` · Last verified: 2026-09-30

## The problem

Not every secret is a key. A trusted-computing stack still has to deal with the
ordinary ones — the login for an upstream service, a database password, the
credential a browser autofills — and those have properties keys do not: they are
human-readable, they get shared within a team, they expire, and someone has to
be able to *see* them.

`pkg/staticpw` is that store, and it lives here rather than in xkey because the
desktop companion is one client of it, not its owner.

## Shape chosen: an entity store with scope, expiry, and two access modes

The core is a set of small, composable stores rather than one type:

| Concern | File |
|---|---|
| Entry model | `types.go` |
| Base store | `store.go` |
| Scoping | `scope.go`, `scoped_store.go` |
| Teams (xkey's local team list only) | `team_entity.go`, `team_store.go` |
| Tenancy | `tenant_store_manager.go` |
| Access control | `access.go` |
| Expiry | `expiry.go` |
| Generation | `generator.go` |
| Validation, errors | `validation.go`, `errors.go` |

`pkg/staticpw` has no encrypted-store or PIN-store decorator file: `store.go`'s
`BackendStore` is the only concrete `Store`, and encryption at rest is a
property of the `storage.Backend` it is given (see "Component boundaries"
below), not a wrapper type in this package.

The design decision that shapes everything else is **access mode**
(`access.go:23`):

```go
type AccessMode string

const (
	AccessPINPerOperation AccessMode = "pin_per_operation"
	AccessSessionBased    AccessMode = "session_based"
)
```

- **`pin_per_operation`** — every read of a plaintext password requires the user
  PIN. Maximum protection, maximum friction.
- **`session_based`** — unlock once, then reads work until the store is locked
  again. What people actually use.

Only `session_based` is a reachable code path today, and a session belongs to
one **user**, not to the tenant: `TenantPasswordStoreManager.UnlockUser` /
`LockUser` open and close one user's personal session, with the PIN checked
one layer up by `XKMSService.verifyPasswordStoreUserPIN`
(`pkg/xkms/servicer_password.go`). `pin_per_operation` is a defined
`AccessMode` constant (`access.go`) with no store implementation behind it.
Making the mode an explicit, switchable value rather than a hardcoded policy
is what leaves room for a future per-operation implementation without another
API shape.

### Scope and lock semantics

The vault follows the xkms scope model
([`../multi-tenancy/architecture.md`](../multi-tenancy/architecture.md#ownership-scopes)):

| Entries | Keyspace | Who sees them | When |
|---|---|---|---|
| Shared | `{tenant}/staticpw/shared/` | every authenticated user of the tenant | whenever the tenant barrier is unsealed; no session needed |
| Personal | `{tenant}/staticpw/users/{subject}/` | only their owner | only while the owner's personal session is unlocked |

- **One user locking never locks another.** Sessions are held per
  `(tenant, subject)`. A locked user still reads and writes shared entries;
  personal operations answer `ErrStoreLocked`, and a listing of all entries
  holds the shared ones only.
- **Sealing ends every session.** A tenant barrier that is sealed and later
  unsealed does not resume the sessions it ended.
- **Modifying a shared entry** is restricted to its owner or a member of the
  tenant's Admin/SO built-in role (`checkSharedPasswordOwnership`); any tenant
  user may read it.
- **The system tenant is a tenant.** A system-tenant identity is served from
  `system/staticpw/...` under the system barrier, with its own shared and
  personal entries, and never sees a tenant's entries (nor a tenant the
  system tenant's). Only a request with no identity at all (an internal caller,
  or authentication disabled) is served from the unscoped system store.

Rejected for the lock: a tenant-wide session (the previous design). One user
locking locked everyone, and one user unlocking opened every user's session.

Rejected alternatives:

- **Storing passwords as keys in the keystore.** Rejected: keys are not
  readable by design, and a password that cannot be read is not a password.
- **Implementing the vault in xkey.** Rejected by the ownership rule — reusable
  logic lands in `go-xkms/pkg/*` and xkey consumes it through
  `go-xkms/sdk/go`. xkey is a shell, never a second implementation.
- **One access policy.** Rejected — see above.

## Component boundaries

| Piece | Where | Owner |
|---|---|---|
| The vault | `pkg/staticpw` | go-xkms |
| Wire surface | `pkg/api/rest/password_handlers.go`, `pkg/api/mcp/handlers_password.go`, `transport.PasswordService` | go-xkms |
| CLI | `cmd/xkmsctl/password.go` | go-xkms |
| Desktop client, autofill, browser extension | `xkey` (`xkey password …`, `xkey/pkg/autofill`, `xkey/extension`) | go-xkms (xkey surface) |
| Encryption at rest | the barrier — [`../sealing-and-barrier/`](../sealing-and-barrier/architecture.md) | **go-qrdb** owns the barrier |
| Tenancy model | go-qrdb | **go-qrdb** |

Capability row: **"Password vault + autofill (core store: `go-xkms/pkg/staticpw`)"**
under the xkey product surface — note that the row itself names this package as
the core.

## Data flow

```
add:     xkmsctl password add NAME --password -
           → validation → entity → scoped/team/tenant store
             → storage.Backend → the barrier

read:    xkmsctl password get ID
           → shared entry: served while the tenant barrier is unsealed
           → personal entry: the caller's own session gate (session_based,
             the only implemented mode — requires the caller's own prior
             `password unlock`)
             → store.Get → entry returned exactly as stored

           `--decrypt`/`--user-pin` on this call always fail with
           ErrPasswordDecryptNotSupported (servicer_password.go:188): there
           is no field-level decrypt step to opt into — a plain `get`
           already returns the entry as stored, because `pkg/staticpw` does
           not encrypt the `Password` field itself.

autofill: browser extension → native-messaging host → xkey IPC → the same store
```

Locking (`password lock`) drops the caller's own session; `password status`
reports whether the caller's session is unlocked, whether the tenant barrier is
sealed, and how many entries the caller can read now.

Every transport (REST, gRPC, MCP) reaches the store only through the
`XKMSService` password servicer, so the scope rule, the ownership check and the
session gate are enforced once.

## Trust boundaries

- **There is no field-level decrypt boundary.** `PasswordGet` refuses
  `--decrypt`/`--user-pin` outright (`ErrPasswordDecryptNotSupported`,
  `pkg/xkms/servicer_password.go:188`): a plain `get` already returns the
  entry exactly as stored, because `pkg/staticpw` never encrypted the
  `Password` field on its own. The real boundaries are the scope (a user's
  personal entries live under that user's own keyspace and no other caller's
  store contains them) and the per-user session lock: personal
  `list`/`get` fail with `ErrStoreLocked` until that user's `password
  unlock` succeeds.
- **Access mode is the policy.** `session_based` — the only implemented mode
  — means anything that can act as a user while that user's session is
  unlocked can read that user's personal entries, and any tenant user can
  read the shared ones. `pin_per_operation` is a defined value with no store
  behind it; it re-authenticates nothing today.
- **Personal entries are not separately encrypted.** They are protected by the
  tenant barrier and by scope, not by a per-user key: a holder of the tenant
  barrier key can read them. A per-user DEK is an open design question.
- **Scope and sharing are access control, not organisation.** `--shared` shares
  an entry with the tenant; `--scope own|shared|all` chooses what a listing
  reveals. There is no team-scoped sharing: a user-group model belongs to
  go-qrdb and does not exist yet, so the old unwired team-scoped store, team
  REST handlers and per-tenant DAO factory were deleted.
- **Expiry is metadata, not enforcement.** `expiry.go` records
  `--expires-at`; treat an expired entry as a signal to rotate, not as a
  guarantee that the credential stopped working.
- **Tenant isolation applies.** Entries carry `--tenant-id` and the store is
  tenant-scoped — see [`../multi-tenancy/`](../multi-tenancy/architecture.md).
- **Generated passwords are only as good as the generator.** `generator.go` is
  the single source; do not add a second one at a call site.

## What this feature deliberately does not do

- **It does not encrypt anything itself.** At-rest protection is the barrier's.
- **It is not a key store.** Keys are [`../key-management/`](../key-management/architecture.md).
- **It is not the platform secret store.** Those are
  [`../platform-secrets/`](../platform-secrets/architecture.md) — platform-owned,
  sealed, not human-facing.
- **It does not own tenancy, users or teams' identity** — those come from
  go-qrdb.
- **It does not implement autofill.** The browser extension and native-messaging
  host are xkey's; this is the store behind them.
