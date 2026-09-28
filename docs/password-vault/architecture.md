# Password Vault — Architecture

> **Status: NORMATIVE** · Feature: `password-vault` · Repo: `go-xkms` · Last verified: 2026-09-28

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
| Entry model | `entity.go`, `types.go` |
| Base store | `store.go` |
| DAO-backed store | `dao_store.go` |
| Scoping | `scope.go`, `scoped_store.go` |
| Teams | `team_entity.go`, `team_store.go`, `team_scoped_store.go` |
| Tenancy | `tenant_dao_factory.go`, `tenant_store_manager.go` |
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

Only `session_based` is a reachable code path today:
`TenantPasswordStoreManager.UnlockTenant`/`LockTenant` (`tenant_store_manager.go:162`,
`:143`) hold the per-tenant session lock, gated on the tenant barrier being
unsealed, with the PIN itself checked one layer up by
`XKMSService.verifyPasswordStoreUserPIN` (`pkg/xkms/servicer_password.go:361`).
`pin_per_operation` is a defined `AccessMode` constant (`access.go:33`) with
no store implementation behind it — see `access.go:16-28`. Making the mode an
explicit, switchable value rather than a hardcoded policy is what leaves room
for a future per-operation implementation without another API shape.

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
           → session lock gate (tenant stores only; session_based, the only
             implemented mode — requires a prior `password unlock`)
             → store.Get → entry returned exactly as stored

           `--decrypt`/`--user-pin` on this call always fail with
           ErrPasswordDecryptNotSupported (servicer_password.go:188): there
           is no field-level decrypt step to opt into — a plain `get`
           already returns the entry as stored, because `pkg/staticpw` does
           not encrypt the `Password` field itself.

autofill: browser extension → native-messaging host → xkey IPC → the same store
```

Locking (`password lock`) drops the session; `password status` reports whether
the store is unlocked and in which mode.

## Trust boundaries

- **There is no field-level decrypt boundary.** `PasswordGet` refuses
  `--decrypt`/`--user-pin` outright (`ErrPasswordDecryptNotSupported`,
  `pkg/xkms/servicer_password.go:188`): a plain `get` already returns the
  entry exactly as stored, because `pkg/staticpw` never encrypted the
  `Password` field on its own. The real boundary is the session lock:
  `list`/`get` on a tenant store fail with `ErrStoreLocked` until `password
  unlock` succeeds.
- **Access mode is the policy.** `session_based` — the only implemented mode
  — means anything that can reach the store while a tenant is unlocked can
  read every entry in scope. `pin_per_operation` is a defined value with no
  store behind it; it re-authenticates nothing today.
- **Scope and sharing are access control, not organisation.** `--shared` shares
  an entry with the tenant; `--scope own|shared|all` chooses what a listing
  reveals. Team stores (`team_*`) extend this to groups.
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
