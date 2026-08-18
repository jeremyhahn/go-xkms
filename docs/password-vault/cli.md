# Password Vault — CLI

> **Status: NORMATIVE** · Feature: `password-vault` · Repo: `go-xkms` · Last verified: 2026-08-19

Binary: `xkmsctl`, group `password` (`cmd/xkmsctl/password.go`). The desktop
equivalent is `xkey password …`, over the same store. Global flags:
[`../key-management/cli.md`](../key-management/cli.md).

## Unlocking

Under the `session_based` access mode nothing decrypts until you unlock:

```
xkmsctl password unlock --user-pin -
xkmsctl password status -o json
xkmsctl password lock
```

`--user-pin` accepts `-` for stdin and prompts when omitted.

Under `pin_per_operation` there is no unlock step — every read carries the PIN.

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
| `--decrypt` | bool | `false` | **include the plaintext** |
| `--user-pin` | string | `""` | required in `pin_per_operation` mode |
| `--tenant-id` | string | `""` | tenant scope |

```
xkmsctl password get pw-123 -o json                 # metadata only
xkmsctl password get pw-123 --decrypt --user-pin -  # the actual password
```

Plaintext is opt-in. Without `--decrypt` you get metadata, which is usually what
a script wants and always what a screen-share wants.

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
xkmsctl password access-mode pin_per_operation
```

This is a security policy, not a preference:

- **`session_based`** — unlock once, read freely until locked. Anything that can
  reach the store while unlocked can read every entry in scope.
- **`pin_per_operation`** — the PIN on every read. More friction, much smaller
  window.

## `password generate`

| Flag | Type | Default |
|---|---|---|
| `--length` | int | `0` — server default |

```
xkmsctl password generate --length 32
```

## `password status`

Works while locked — that is the point. Reports whether the store is unlocked
and which access mode is in force.

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
