# Multi-Tenancy — Architecture

> **Status: NORMATIVE** · Feature: `multi-tenancy` · Repo: `go-xkms` · Last verified: 2026-10-04

## The problem

"Multi-tenant" covers a range from "prefix the keys" to "a separate database
cluster per customer", and the right answer differs per customer within the same
deployment. A model that offers only the cheap option cannot serve a regulated
customer; one that offers only the expensive option cannot serve anyone
profitably.

## Shape chosen: four isolation modes, gated by entitlements

A tenant declares an **isolation mode** at creation:

| Mode | What is separated |
|---|---|
| `prefix` | key namespace — the default, cheapest |
| `barrier` | a dedicated barrier per tenant, with its own root key |
| `volume` | dedicated storage |
| `raft` | a dedicated Raft database |

Modes are not freely chosen: **entitlements** decide which a tenant may use
(`--isolation-modes`, `--allow-raft`, `--allow-volume`,
`--allow-system-managed`), and **quotas** bound what they may consume
(`--max-databases`, `--max-keys`, `--max-collections`, `--max-storage-bytes`,
`--max-users`, `--max-roles`, `--max-certificates`).

Splitting the two is the design decision: entitlements are what a tenant is
*permitted* to be, quotas are how much they may *have*. Conflating them makes
every upgrade a code change.

Rejected alternatives:

- **One isolation model for everyone.** Rejected — see the problem statement.
- **Letting tenants pick their own mode.** Rejected: `barrier`, `volume` and
  `raft` cost real resources, so the entitlement gate is what makes the choice
  an operator's.
- **Owning the tenant model here.** Rejected by ownership: tenancy, identity and
  RBAC are go-qrdb's. go-xkms adds the *key-domain* half — per-tenant barriers
  and tenant-scoped key operations.

## The per-tenant barrier

The mode that changes the security story. With `barrier` isolation a tenant has
its own root key, initialized and unsealed independently
(operated through go-qrdb's own barrier surface; xkms exposes no tenant-barrier
verb), using any of the same strategies as the system barrier — `passphrase`, `none`, `shamir`,
`tpm2`, `pkcs11`, `awskms`, `gcpkms`, `azurekv`, `vault`.

The consequence worth understanding: **a tenant's data is unavailable until that
tenant's barrier is unsealed**, independently of the system barrier. That is the
isolation, and it is also the operational cost.

`--barrier-auto-unseal` exists for dedicated-isolation tenants and is
**entitlement-gated** (`--allow-system-managed`). System-managed auto-unseal
trades some of the isolation back for availability, which is why it is a
permission rather than a flag.

## Ownership scopes

Inside a tenant, every stored security object has one of three scopes, and
`pkg/scope` is the single implementation of the rule and the layout — the
password vault, SSH and TPM policies all use it rather than each deciding for
itself:

| Scope | Keyspace | Who may address it |
|---|---|---|
| `tenant` (shared) | `{tenant}/{feature}/shared/...` | every user of the tenant; a platform caller for any tenant |
| `user` (personal) | `{tenant}/{feature}/users/{subject}/...` | only the owning subject, in its own tenant — **a platform caller included** |
| `service` | `{tenant}/{feature}/services/{owner}/...` | only a caller holding the feature's explicit service permission (`ssh:service`), in its own tenant |

- **The system tenant is a tenant.** Its scope name is `system` (go-qrdb's
  `SystemTenantID`); the empty tenant maps to it. It has its own shared and
  personal objects and is isolated from every tenant in both directions.
- **A refusal looks like a miss.** `Principal.Authorize` returns
  `*CrossTenantError`, `*CrossUserError` or `*ServiceScopeError` (all match
  `scope.ErrRefused`) for diagnostics; each feature answers the caller exactly
  as it answers an object that does not exist.
- **Permission scopes complement object scopes.** A permission's go-qrdb
  scope (`ScopeSelf`, `ScopeTenantOnly`, `ScopeCross`) decides which tenant an
  identity may exercise it in; the object scope then decides which objects in
  that tenant it reaches. See [`../rbac/architecture.md`](../rbac/architecture.md#permission-tenancy-scopes).
- **The platform store stays system scope.** The sealed platform store
  (`SealStore*` on `XKMSService`, served by `seal.SealedPlatformStore`, which
  `compose.BuildPlatformStore` builds over a `sealedstorage` view;
  [`../platform-secrets/`](../platform-secrets/architecture.md)) holds the
  platform's own secrets. It has no tenant or user scope: every call is
  refused to a tenant-scoped caller (`requirePlatformScope`), so only
  system-tenant callers reach it.

## Component boundaries

| Piece | Where | Owner |
|---|---|---|
| Tenant model, identity, RBAC | `go-qrdb/sdk/go` | **go-qrdb** |
| Tenant middleware | `pkg/api/rest/middleware_tenant.go`; `pkg/api/grpc/interceptor_tenant.go`; `pkg/api/tenantgate` | go-xkms |
| Per-tenant barriers | `pkg/seal/platform_store_tenant.go`, `pkg/xkms/backend_tenant.go` | go-xkms |
| Tenant surface | `pkg/api/rest/handlers_tenant.go`, `transport.TenantService` | go-xkms |
| Tenant composition | `sdk/go/tenant_compose.go`, `tenant_factories.go` | go-xkms |
| SPIFFE identity | `pkg/spiffe` | go-xkms |

## Data flow

```
request → tenant middleware resolves the tenant from the identity
        → tenant DAO scope selected
          → key / cert / barrier operations run inside that scope
```

Every `/api/v1` route carrying `GroupAPIv1` runs behind tenant middleware. Two
groups deliberately do not: **`GroupUsers`** — "the user plane is
identity-scoped, not tenant-scoped" — and `GroupRoot`.

The **system tenant** is the control-plane exception. The SO/bootstrap
certificate from the init ceremony is always scoped to `system` so the control
plane works before any tenant barrier unseals
([`../init-ceremony/`](../init-ceremony/architecture.md)).

## Trust boundaries

- **The middleware admits the request; the tenant-scoped backend narrows the
  key namespace.** A key ID is only resolvable inside its tenant *because* the
  handler resolves it through `xkms.TenantScopedBackend`. A key ID is a common
  name, unique only within a tenant, so a lookup against an unscoped backend
  matches whichever tenant's key is listed first — see
  [`api.md`](api.md#what-actually-narrows-the-key-namespace).
- **Isolation modes are not equally strong.** `prefix` separates namespaces
  within one barrier and one store; `barrier` separates root keys; `volume` and
  `raft` separate storage and consensus. Selling `prefix` as isolation to a
  customer who needs `barrier` is a compliance problem, not a technical one.
- **Entitlements gate capability, quotas gate consumption.** Both are
  operator-set; neither is tenant-settable.
- **Auto-unseal weakens the barrier isolation it is applied to** — hence the
  separate entitlement.
- **Per-tenant barriers isolate tenants from each other, not from the
  operator.**

## What this feature deliberately does not do

- **It does not own tenancy, identity, users or RBAC** — all go-qrdb's, reached
  through `go-qrdb/sdk/go`. No local user model, no local cert-binding scheme.
- **It does not let a tenant change its own isolation, entitlements or quotas.**
- **It does not make `prefix` into `barrier`.** Changing isolation mode is a
  migration, not a setting.
