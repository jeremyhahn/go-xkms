# Multi-Tenancy — User Guide

> **Status: NORMATIVE** · Feature: `multi-tenancy` · Repo: `go-xkms` · Last verified: 2026-08-19

## Choose the isolation mode with the customer's requirement in front of you

This is fixed at creation. Changing it later is a data migration, not a setting.

| Mode | What is actually separated | Use when |
|---|---|---|
| `prefix` | the key namespace | tenants are internal teams and share a trust boundary |
| `barrier` | a dedicated root key per tenant | a tenant's data must be unreadable without their own credential |
| `volume` | dedicated storage | storage-level separation is required |
| `raft` | a dedicated database cluster | full separation, at full cost |

Calling `prefix` "isolation" to a customer who needs `barrier` is a compliance
problem rather than a technical one. Everything in `prefix` mode lives under one
root key.

```
xkmsctl tenant create --id acme --name "Acme Corp" --isolation barrier
xkmsctl tenant list -o json
xkmsctl tenant show --id acme -o json
```

If the mode is refused, the tenant is not entitled to it — see entitlements
below.

## Per-tenant barriers

With `barrier` isolation, each tenant has their own root key, initialized and
unsealed independently:

```
xkmsctl tenant barrier-init --id acme --strategy shamir --threshold 2 --shares 3
xkmsctl tenant barrier-status --id acme -o json
xkmsctl tenant barrier-unseal --id acme --share "$SHARE"
```

Strategies are the same set as the system barrier.

**The operational consequence:** a tenant's data is unavailable while *their*
barrier is sealed, regardless of the system barrier. When one customer reports
an outage and everyone else is fine, `tenant barrier-status --id <them>` is the
first command to run.

`--barrier-auto-unseal` trades some of that isolation back for availability, and
needs the `--allow-system-managed` entitlement — which is why it is a grant
rather than a flag.

## Entitlements and quotas are different things

**Entitlements** — what the tenant is allowed to *be*:

```
xkmsctl tenant update-entitlements --id acme \
    --isolation-modes prefix,barrier --allow-volume
```

**Quotas** — how much they may *have*:

```
xkmsctl tenant update-quotas --id acme --max-keys 10000 --max-certificates 500
```

Keeping them separate is what makes plan changes configuration rather than code.
A tenant entitled to `raft` but limited to one database is perfectly coherent.

**`0` means "use the system default", not "zero allowed".** Every quota field
works this way, and it catches people.

## What tenants cannot do

Tenants cannot change their own isolation mode, entitlements or quotas. All
three are operator-set. There is also no self-service upgrade path from `prefix`
to `barrier` — that is a migration you plan.

## A tenant you cannot see looks like a tenant that does not exist

Cross-tenant access returns "not found", not "forbidden". That is deliberate:
"forbidden" would confirm the tenant exists and make tenant IDs enumerable. When
debugging, do not read a 404 as proof that a tenant was never created.

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| one tenant is down, others are fine | that tenant's barrier is sealed | `tenant barrier-status --id <them>` |
| isolation mode refused at create | the tenant is not entitled to it | `tenant update-entitlements` first |
| operations rejected as over quota | the tenant hit a limit | `tenant update-quotas`; remember `0` = default |
| a tenant "does not exist" that you created | you may be in a different scope | cross-tenant access reports not-found |
| tenant routes return 404 | tenancy is not configured on this server | server-side configuration |
| user operations ignore the tenant | expected — the user plane is identity-scoped, not tenant-scoped | not a bug |
| the control plane works before any tenant is unsealed | expected — the SO certificate is scoped to the `system` tenant | not a bug |

## Where to go next

- Barrier strategies and recovery: [`../sealing-and-barrier/user.md`](../sealing-and-barrier/user.md)
- Where the system tenant's certificate comes from: [`../init-ceremony/user.md`](../init-ceremony/user.md)
- Filtering audit records by tenant: [`../audit-log/user.md`](../audit-log/user.md)
