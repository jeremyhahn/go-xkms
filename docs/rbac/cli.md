# RBAC — CLI

> **Status: NORMATIVE** · Feature: `rbac` · Repo: `go-xkms` · Last verified: 2026-09-24

Binary: `xkmsctl`. There is no `xkmsctl role` command group — verified
absent from `cmd/xkmsctl/`. Role **assignment** happens as one flag on user
registration; role **definition** (custom roles) has no CLI surface at all
(see engineering.md's SDK-only note). This page covers the `--role` flag
only; the rest of `xkmsctl user`'s flags (email, display name, WebAuthn
enrollment, and so on) belong to a different, not-yet-converted feature
folder.

## `xkmsctl user register` — the `--role` flag

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--role` | string | `""` (resolves to `user`) | a built-in role (`so`, `admin`, `operator`, `user`, `auditor`) or a custom role the tenant holds; the server refuses a role the tenant does not hold |

```
xkmsctl user register alice --email alice@example.com --role operator
```

**The first user ever registered always receives `admin`**, regardless of
what `--role` is passed. Every subsequent registration honors `--role`,
defaulting to `user` when omitted.

An unrecognized role name is rejected before any request reaches the
server:

```
xkmsctl user register bob --role readonly
# error: invalid role: readonly
```

## `xkmsctl admin` — always `admin`

Every admin-enrollment verb under `xkmsctl admin` (`cmd/xkmsctl/admin.go`)
assigns the `admin` role unconditionally; there is no `--role` flag to
override it, because an administrator is by definition the `admin` role.

## No role-reassignment verb

`xkmsctl user update <username>` exists, but only toggles
`--enable`/`--disable`. There is no command to change an existing user's
role. To change a user's effective permissions, either use the SDK's
`xkms.Auth(qrdbClient)` accessors directly (engineering.md), or delete and
re-register the user with the desired `--role`.

## Enabling RBAC itself

RBAC is a server configuration, not a CLI flag — there is no `xkmsctl
config set auth.enable_rbac=true` equivalent. Set `auth.enable_rbac: true`
(and `storage.backend: "qrdb"`) in `xkmsd`'s own configuration; see
[`../xkmsd-configuration/cli.md`](../xkmsd-configuration/cli.md) for how
`xkmsd` resolves configuration, and engineering.md's Configuration section
for the exact keys.
