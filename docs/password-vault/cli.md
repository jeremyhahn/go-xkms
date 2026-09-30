# Password Vault — CLI

> **Status: NORMATIVE** · Feature: `password-vault` · Repo: `go-xkms` · Last verified: 2026-09-30

Binary: `xkmsctl`, group `password` (`cmd/xkmsctl/password.go`). Global flags:
[`../key-management/cli.md`](../key-management/cli.md).

The desktop equivalent is `xkey password …`. It reaches the store differently:
`xkmsctl` always talks to a server, while `xkey` asks the running desktop
daemon over its IPC socket and falls back to the on-disk store, naming which
answered. See
[`xkey/docs/usage/live-state.md`](../../xkey/docs/usage/live-state.md).

## Unlocking

Under the `session_based` access mode your personal entries are unreadable
until you unlock your own session (shared entries need no unlock; the session
is per user, so it neither opens nor closes anyone else's):

```
xkmsctl password unlock --user-pin -
xkmsctl password status -o json
xkmsctl password lock
```

`--user-pin` accepts `-` for stdin and prompts when omitted.

## `password add <name>`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--password` | string | `""` | value; `-` reads stdin; prompted when omitted |
| `--username` | string | `""` | associated username |
| `--url` | string | `""` | associated URL |
| `--notes` | string | `""` | free-form notes |
| `--folder` | string | `""` | folder path |
| `--expires-at` | string | `""` | RFC 3339 |
| `--tenant-id` | string | `""` | tenant scope |
| `--shared` | bool | `false` | share with the tenant |

```
xkmsctl password add "upstream-portal" --username ops@example.com \
    --url https://portal.example.com --folder infra --password -
```

Omit `--password` and it prompts. `-` reads stdin. A literal value goes into
shell history.

**`--notes` reaches durable storage.** It is where people put "the other
password"; do not.

## `password get <id>`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--tenant-id` | string | `""` | tenant scope |

```
xkmsctl password get pw-123 -o json
```

The store must be unlocked first (`password unlock`); the entry, including the
password field, comes back exactly as stored
(`pkg/xkms/servicer_password.go:168`). There is no per-request decrypt option:
confidentiality at rest is provided by the tenant barrier, not by a decryption
step on `get`, and every store reachable through this servicer
(`staticpw.BackendStore`, `staticpw.ScopedStore`, `staticpw.DAOStore`) returns
entries the same way. `xkmsctl` never accepted a `--decrypt` or `--user-pin`
flag on `get`; earlier revisions of this page described one, but the servicer
never implemented it (removed in #1061).

## `password list`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--folder` | string | `""` | filter by folder |
| `--tenant-id` | string | `""` | tenant scope |
| `--scope` | string | `""` | `own`, `shared`, or `all` |

```
xkmsctl password list --folder infra --scope all -o json
```

Listing never returns plaintext.

## `password update <id>`

`--name`, `--username`, `--password` (`-` for stdin; empty prompts), `--url`,
`--notes`, `--folder`, `--expires-at`, `--tenant-id`.

```
xkmsctl password update pw-123 --password - --expires-at 2027-01-01T00:00:00Z
```

## `password delete <id>`

`--tenant-id`.

## `password access-mode <mode>`

```
xkmsctl password access-mode session_based
```

`session_based` is the only mode that can actually take effect: the mode is
fixed by how the store was set up when the server started
(`pkg/staticpw/access.go:17`-`26`). Requesting the mode already in force
succeeds; requesting `pin_per_operation` against a `session_based` store
fails rather than silently doing nothing.

- **`session_based`** — unlock once, read your personal entries freely until
  you lock. Anything that can act as you while your session is unlocked can
  read them. `password lock` when you are done.

## `password generate`

| Flag | Type | Default |
|---|---|---|
| `--length` | int | `0` — server default |

```
xkmsctl password generate --length 32
```

## `password status`

Works while locked — that is the point. Reports whether your own session is
unlocked, whether the tenant barrier is sealed, how many entries you can read
now, and which access mode is in force.

## Exit codes

`0` on success. Non-zero for a locked store, a missing or wrong PIN, or an
unknown ID. An entry outside your scope reports as **not found**, not
forbidden — so a 404 here is not proof the entry does not exist somewhere.

## Parity coverage

**Defect: no `password` verb has a `CommandDefinition` in
`test/integration/api/commands/commands.go`**, despite all ten operations having
routes on REST, gRPC, QUIC, Unix **and** MCP — the password surface is one of
only three features with complete MCP coverage, and none of it is in the parity
runner.
