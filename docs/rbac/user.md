# RBAC — User Guide

> **Status: NORMATIVE** · Feature: `rbac` · Repo: `go-xkms` · Last verified: 2026-09-28 (#1115, #1230, #1231)

## What RBAC controls

Once enabled, every request against `xkmsd` — over REST, gRPC, QUIC, or MCP
— is checked against the roles your account holds before it runs. Without
RBAC enabled, any authenticated caller can do anything the transport
exposes; RBAC is what makes roles mean something.

## Turning it on

RBAC needs the `qrdb` storage backend — it is the identity plane role
grants live in. In `xkmsd.yaml`:

```yaml
storage:
  backend: "qrdb"

auth:
  enabled: true
  type: mtls
  enable_rbac: true
```

If you set `enable_rbac: true` with any other `storage.backend`, the server
refuses to start. This is not a workaround-able limit — it exists because
RBAC without the identity plane would silently authorize everything while
believing it was enforcing roles, which is worse than RBAC being visibly
off.

## The roles

| Role | What it can do |
|---|---|
| `so` | Security Officer: module initialization, PIN and ceremony management — deliberately excludes cryptographic key operations (separation of duties) |
| `admin` | Full access, including everything xkms's own surface (SSH, PIV, passwords, seal, barrier, ceremony...) exposes |
| `operator` | Manage keys and certificates, not users |
| `user` | Use keys for cryptographic operations, not manage them |
| `auditor` | View audit logs and key metadata only |
| `custodian` | Hold and submit Shamir shares during barrier ceremonies |

`admin` and `owner` (the latter not assignable through `xkmsctl`) are the
only roles guaranteed to reach every xkms-specific capability — SSH agent
sessions, PIV, the password vault, seal/barrier operations, and the
first-boot ceremony. The other four roles get whatever go-qrdb's own
built-in definitions grant them for the permission names xkms shares with
qrdb's general vocabulary (key and certificate operations); they are not
automatically extended to xkms's own hardware and ceremony surfaces. If you
need, say, an `operator` who can also drive SSH agent sessions, build a
custom role through the SDK (below) rather than assuming the built-in
`operator` already covers it.

## Assigning a role

Role assignment happens once, at registration:

```bash
xkmsctl user register alice --email alice@example.com --role operator
```

The very first user your deployment registers becomes `admin` regardless
of `--role` — that is intentional, so a fresh server always has an
administrator.

There is no command to change a role afterward. If someone's role needs to
change, register a new account with the right role rather than looking for
an "update role" verb — it does not exist today.

## Custom roles

The six built-in roles cover the common separation-of-duties cases. If you
need something narrower or broader, a custom role can be created — but only
through code, not the CLI or REST API:

```go
import xkms "github.com/jeremyhahn/go-xkms/sdk/go"

ac := xkms.Auth(qrdbClient)
ac.Roles().CreateRole(ctx, &transport.CreateRoleRequest{ /* ... */ })
```

There is no `xkmsctl role create` and no `POST /api/v1/roles` — if your
workflow needs custom roles managed operationally rather than
programmatically, that gap is worth knowing about before you design around
it.

## What RBAC does not cover

- **The cluster control plane** (`xkmsctl cluster`/`rebalance`) is not
  gated by these roles today — it trusts whoever can reach the transport
  (TLS-authenticated network access, or the Unix socket's filesystem
  permissions). See [`../clustering/user.md`](../clustering/user.md).
- **The ACME server's tenant admin API** has its own, separate role model
  for ACME tenant administration — not the same roles or grants as here.

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| server refuses to start: RBAC compliance gap | `auth.enable_rbac: true` with a non-`qrdb` storage backend | switch `storage.backend` to `qrdb`, or turn RBAC off |
| `403 Forbidden` on a request you expect to work | the identity's role doesn't hold that permission, or the tenant scope excludes it | check which role the account has (`xkmsctl user get <username>`) against the table above |
| `xkmsctl user register ... --role readonly` fails | `readonly` is not a real role — the help text is wrong (see cli.md) | use one of `so`, `admin`, `operator`, `user`, `auditor`, `custodian` |
| new user isn't `admin` even though you passed `--role admin` on the very first registration | irrelevant — the first user is always `admin` regardless of the flag | nothing to fix |
| an `operator`/`user`/`auditor`/`custodian` can't reach SSH/PIV/password-vault/seal operations | those built-in roles are not automatically extended to xkms's own hardware surfaces | grant `admin`, or build a custom role via the SDK |
| an identity provider puts `admin` or `so` in the token's `roles`/`groups` claim, but the caller still gets `403` | xkms and qrdb match a role by its qrdb identifier, never by name: a claimed role name confers nothing | create the account in qrdb with the role (`xkmsctl user register --role ...`); authentication then carries the role's identifier |
| a tenant's own Security Officer gets `403 tenant not found` or `503 tenant barrier is sealed` | only system-tenant identities are cross-tenant; a tenant officer is scoped to its tenant like any other tenant identity | register the tenant, or unseal its barrier, first |
| an `admin` or `so` changes another user's shared vault entry, but an `operator` gets `not the owner` | only the owner, or a tenant Admin or SO, may change a shared entry | as designed |

## Tenant admins stay in their tenant

A tenant's Admin manages keys, users and audit for that tenant only. Naming
another tenant in a request does not widen that. Naming another tenant's key
reads as "key not found", and listing keys shows only your own tenant's. The
same holds for FROST threshold keys and their signing rounds. PKCS#11 token-state calls that
name another tenant are refused. An audit query that names another tenant, or
none, returns only your own tenant's events. Reading every tenant's audit
events takes a platform (system-tenant) identity whose role holds
`audit:read:cross`. The built-in Admin role has it and Auditor does not.

SSH keys, known-hosts pins and authorized_keys entries follow the same rule,
per owner: in a tenant you reach `--scope tenant` assets of your own tenant
and `--scope user`/`service` assets of your own subject, and nothing else —
not even another user's in your tenant. Anything else reads as "not found",
and creating a key or authorizing a login under someone else's owner creates
nothing. See [`../ssh-keys/user.md`](../ssh-keys/user.md) §"Scoping keys to a
tenant, user, or service".

## Where to go next

- [Storage engines](../storage-engines/user.md) — the `qrdb` backend RBAC
  requires
- [Clustering](../clustering/user.md) — the control plane's different
  authorization posture
- [Init ceremony](../init-ceremony/) — how the first administrator is
  bootstrapped
