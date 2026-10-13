# Multi-Tenancy — CLI

> **Status: NORMATIVE** · Feature: `multi-tenancy` · Repo: `go-xkms` · Last verified: 2026-10-12

Binary: `xkmsctl`, group `tenant` (`cmd/xkmsctl/tenant.go`). Global flags:
[`../key-management/cli.md`](../key-management/cli.md).

## Who the CLI acts as

Over the unix socket — `xkmsctl`'s default transport — the daemon identifies
the CLI by its kernel credentials: subject `uid:<your uid>` in the `system`
tenant (see [`api.md`](api.md#identity-on-the-unix-socket)). That identity
administers the tenant registry and plans below, but it is confined to the
system tenant for everything else: `xkmsctl` over the socket cannot sign a
CSR for, revoke a certificate of, or read the SSH assets or TPM policies of
another tenant. Act as that tenant's own identity instead (a tenant
certificate over gRPC/TLS or REST).

## `tenant create`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--id` | string | — | **yes** |
| `--name` | string | — | **yes** — display name |
| `--isolation` | string | `prefix` | no — `prefix`, `barrier`, `volume`, `raft` |
| `--barrier-auto-unseal` | bool | `false` | no — system-managed auto-unseal, **entitlement-gated** |

```
xkmsctl tenant create --id acme --name "Acme Corp" --isolation barrier
```

**Isolation mode is fixed at creation.** Moving from `prefix` to `barrier` later
is a data migration, not a setting. Pick it with the customer's actual
requirement in front of you.

A mode the tenant is not entitled to is refused, not downgraded.

## `tenant list` / `show` / `delete`

| Verb | Flags |
|---|---|
| `tenant list` | — |
| `tenant show` | `--id` (**required**) |
| `tenant delete` | `--id` (**required**) |

```
xkmsctl tenant list -o json
xkmsctl tenant show --id acme -o json
```

`tenant delete` is destructive. It does not release the tenant's key material as
a side effect.

## Per-tenant barriers

Only meaningful with `barrier` (or higher) isolation.

### `tenant barrier-init`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--id` | string | — | **yes** |
| `--strategy` | string | `passphrase` | no — `passphrase`, `none`, `shamir`, `tpm2`, `pkcs11`, `awskms`, `gcpkms`, `azurekv`, `vault` |
| `--passphrase` | string | `""` | required for passphrase/shamir strategies |
| `--threshold` | int | `0` | Shamir M |
| `--shares` | int | `0` | Shamir N |

```
xkmsctl tenant barrier-init --id acme --strategy shamir --threshold 2 --shares 3
```

### `tenant barrier-unseal` / `barrier-status`

| Flag | Type | Required |
|---|---|---|
| `--id` | string | **yes** |
| `--share` | string | base64 Shamir share (unseal only) |

```
xkmsctl tenant barrier-status --id acme -o json
xkmsctl tenant barrier-unseal --id acme --share "$SHARE"
```

**A tenant's data is unavailable while its barrier is sealed**, independently of
the system barrier. `barrier-status` is the first thing to check when one tenant
is down and the rest are fine.

## `tenant update-entitlements`

What the tenant is *permitted* to be.

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--id` | string | — | **required** |
| `--isolation-modes` | string slice | — | permitted modes, comma-separated: `prefix,barrier,volume,raft` |
| `--allow-raft` | bool | `false` | permit dedicated-Raft databases |
| `--allow-volume` | bool | `false` | permit dedicated-volume storage |
| `--allow-system-managed` | bool | `false` | permit system-managed auto-unseal |

```
xkmsctl tenant update-entitlements --id acme \
    --isolation-modes prefix,barrier --allow-volume
```

## `tenant update-quotas`

How much the tenant may *have*. All `int64`; **`0` means the system default**,
not zero.

| Flag | Purpose |
|---|---|
| `--id` | **required** |
| `--max-databases` | databases |
| `--max-keys` | keys |
| `--max-collections` | collections |
| `--max-storage-bytes` | storage |
| `--max-users` | users |
| `--max-roles` | roles |
| `--max-certificates` | certificates |

```
xkmsctl tenant update-quotas --id acme --max-keys 10000 --max-certificates 500
```

Entitlements and quotas are independent on purpose: a tenant entitled to `raft`
but limited to one database is a coherent plan.

## Exit codes

`0` on success. A sealed tenant barrier is a reported state, not an error.
Non-zero for an unentitled isolation mode, an exceeded quota, or an unknown
tenant — note that a tenant in another scope reports as not-found rather than
forbidden, so tenant existence is not enumerable.

## Parity coverage

**Defect: no `tenant` verb has a `CommandDefinition` in
`test/integration/api/commands/commands.go`**, despite all nine operations
having routes on REST, gRPC, QUIC and Unix.
