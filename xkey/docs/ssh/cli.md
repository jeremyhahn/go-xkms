# SSH — CLI

> **Status: NORMATIVE** · Feature: `ssh` · Module: `go-xkms/xkey` · Last verified: 2026-09-27

Binary: `xkey`. Parent command: `xkey ssh` (`SSHCmd`, `xkey/cmd/xkey/cmd/ssh.go`).

Persistent flags on `xkey ssh` (inherited by every subcommand):

| Flag | Default | Description |
|---|---|---|
| `--server` | *(empty)* | Remote xkmsd URL, e.g. `grpcs://host:9443`, `quic://host:8444`, `unix:///path/xkms.sock` |
| `--tls-ca` | *(empty)* | TLS CA certificate file used to verify the server |

Without `--server`: `XKMSD_URL` (env) or `xkmsd_url` (config) selects
REST; otherwise the command uses the local embedded store (see
[engineering.md](engineering.md#configuration)). `XKMSD_TOKEN` supplies an
auth token when set.

## `xkey ssh keys`

| Command | Purpose |
|---|---|
| `generate` | Generate a new SSH key |
| `import [file]` | Import a PEM-encoded private key |
| `list` (`ls`) | List keys |
| `get` | Show metadata for one key |
| `delete` (`rm`, `remove`) | Delete a key |
| `export` | Print the `authorized_keys`-format public half |

Shared flags (`generate`, `import`, `list`, `get`, `delete`, `export`):
`--scope` (default `user`), `--owner` (default `$USER`/`$LOGNAME`).

| Flag | Applies to | Default | Description |
|---|---|---|---|
| `--name` | `generate`, `get`, `delete`, `export` | *(required)* | Key name |
| `--name` | `import` | *(basename of the imported file)* | Key name |
| `--type` | `generate` | `ed25519` | `ed25519`, `rsa`, `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521` |
| `--bits` | `generate` | `0` (server default; `4096` for `rsa`) | RSA key size |
| `--comment` | `generate`, `import` | *(empty)* | Free-form key comment |
| `--backend` | `generate` | *(empty — server/embedded default)* | Crypto backend: `software`, `tpm2`, `pkcs11`, cloud |

```bash
xkey ssh keys generate --name laptop --type ecdsa-p256 --backend tpm2
xkey ssh keys import ~/.ssh/id_ed25519 --name imported
xkey ssh keys list
xkey ssh keys get --name laptop
xkey ssh keys export --name laptop >> ~/.ssh/authorized_keys
xkey ssh keys delete --name laptop
```

`import` reads an encrypted PEM's passphrase without echo from a TTY, or
from stdin otherwise (see `sshPassphraseProvider`, `ssh.go`).

## `xkey ssh host-keys` (alias `known-hosts`)

| Command | Purpose |
|---|---|
| `add` | Pin a host key |
| `list` (`ls`) | List pinned host keys |
| `remove` (`rm`, `delete`) | Remove a pin |

Shared flags: `--scope` (default `user`), `--owner` (default `$USER`).

| Flag | Applies to | Default | Description |
|---|---|---|---|
| `--host` | `add`, `remove` | *(required)* | Target host |
| `--key` | `add` | *(empty)* | Host key as an `authorized_keys`-format line (required unless `--file`) |
| `--file` | `add` | *(empty)* | Read the host key from a file instead of `--key` |
| `--source` | `add` | *(empty)* | Provenance tag (e.g. `manual`, `cert`) |

```bash
xkey ssh host-keys add --host bastion.example.com --key "ssh-ed25519 AAAA..."
xkey ssh host-keys add --host bastion.example.com --file bastion_host_key.pub
xkey ssh host-keys list
xkey ssh host-keys remove --host bastion.example.com
```

**Exactly one of `--key`/`--file` is required** — `add` refuses to pin
from a fingerprint alone (`ErrSSHMissingHostKey`).

## `xkey ssh authorized-keys` (alias `authorized`)

| Command | Purpose |
|---|---|
| `add [line]` | Add an `authorized_keys` line under `--name` |
| `list` (`ls`) | List entries |
| `remove` (`rm`, `delete`) | Remove an entry by `--name` |

Shared flags: `--scope` (default `user`), `--owner` (default `$USER`).
`--name` is required on `add` and `remove`.

```bash
xkey ssh authorized-keys add "ssh-ed25519 AAAA... ci-runner" --name ci-runner
xkey ssh authorized-keys list
xkey ssh authorized-keys remove --name ci-runner
```

## `xkey ssh profile`

| Command | Purpose |
|---|---|
| `add` | Create a profile |
| `list` (`ls`) | List profiles (`--folder` to scope) |
| `get [name]` | Show a profile |
| `remove [name]` (`rm`, `delete`) | Delete a profile |
| `mv [name]` | Move a profile to a different folder |

| Flag | Default | Description |
|---|---|---|
| `--name` | *(required)* | Profile name |
| `--folder` | *(empty)* | Folder path, e.g. `work/prod` |
| `--host` | *(required unless `--ssh-config-alias`)* | Target host |
| `--port` | `22` | Target port |
| `--user` | *(empty)* | Remote user |
| `--key` | *(empty)* | xkey-managed key name |
| `--key-scope` | `user` | Key scope |
| `--key-owner` | *(empty — defaults to `local`)* | Key owner |
| `--key-source` | *(empty — xkey-managed)* | `""` or `local` |
| `--ssh-config-alias` | *(empty)* | `ssh_config(5)` `Host` alias (implies `--key-source local`) |
| `--identity` | *(empty)* | Identity file path or `agent:<SHA256-fingerprint>` (implies `--key-source local`) |
| `--persist-session` | `false` | Record embedded-console sessions from this profile in the persistent session store |
| `--notes` | *(empty)* | Free-form notes |

`list` additionally takes `--folder` (limit to a folder and its
subfolders); `mv` requires `--folder` (destination, `ErrSSHProfileMoveFolder`
if empty).

```bash
xkey ssh profile add --name prod-web --folder work/prod --host web1 --port 2222 --user deploy --key laptop
xkey ssh profile add --name bastion2 --ssh-config-alias prod-bastion
xkey ssh profile list --folder work
xkey ssh profile get prod-web
xkey ssh profile mv prod-web --folder work/staging
xkey ssh profile remove prod-web
```

## `xkey ssh connect [profile|user@host]`

Opens an SSH session in the **current terminal** using the system `ssh`
binary.

| Flag | Default | Description |
|---|---|---|
| `--key` | *(from profile)* | xkey-managed key name to authenticate with |
| `--key-scope` | `user` | Key scope |
| `--key-owner` | *(empty — defaults to `local` for GUI keys, `$USER` for CLI keys)* | Key owner |
| `--port` | `0` (→ `22`) | Target port |
| `--user` | *(empty)* | Remote user (for `user@host` targets without an inline user) |
| `--known-hosts-policy` | `barrier` | Where to record new pins: `barrier`\|`system`\|`both` |
| `--local` | `false` | Authenticate via the operator's own ssh-agent/`~/.ssh` identities — plain passthrough `ssh` |
| `--ssh-config-alias` | *(empty)* | `ssh_config(5)` `Host` alias (implies `--local`) |
| `--identity` | *(empty)* | Identity file path or `agent:<SHA256-fingerprint>` (implies `--local`) |

```bash
xkey ssh connect prod-web
xkey ssh connect deploy@web1 --key laptop
xkey ssh connect prod-web --known-hosts-policy both
xkey ssh connect --local --ssh-config-alias prod-bastion
xkey ssh connect deploy@web1 --identity agent:SHA256:pNYoqv...
xkey ssh connect deploy@web1
```

With no `--key` and no profile key, `connect` falls through to a plain
passthrough (the system agent or an interactive password prompt
authenticates). See [architecture.md](architecture.md#shape-chosen-three-ways-to-reach-a-host-chosen-by-key-source).

## `xkey ssh console [profile|user@host]`

Opens an interactive SSH PTY **in-process** (no `ssh` subprocess), through
the same capability the embedded GUI console uses.

| Flag | Default | Description |
|---|---|---|
| `--key` | *(from profile)* | xkey-managed key name |
| `--key-scope` | `user` | Key scope |
| `--key-owner` | *(empty — defaults to `local`)* | Key owner |
| `--port` | `0` (→ `22`) | Target port |
| `--user` | *(empty)* | Remote user |
| `--local` | `false` | Authenticate via the operator's own ssh-agent/`~/.ssh` identities |
| `--identity` | *(empty)* | Identity file path or `agent:<SHA256-fingerprint>` (implies `--local`) |

```bash
xkey ssh console prod-web
xkey ssh console deploy@web1 --key laptop
xkey ssh console deploy@web1 --local
xkey ssh console deploy@web1 --identity agent:SHA256:pNYoqv...
```

With no `--key` and no profile key, `console` also falls back to
`--local`, matching the GUI's embedded console. Terminal size/type are
read from the local TTY (`$TERM`, default `xterm-256color`); `SIGWINCH` is
forwarded to resize the remote PTY.

## `xkey ssh local`

Read-only discovery of the operator's existing OpenSSH tooling. Backed by
`xkey/pkg/sshlocal` — the same package the GUI's local-source toggle
calls.

| Command | Purpose |
|---|---|
| `hosts` (`ls`) | List `Host` aliases resolved from `ssh_config(5)` |
| `keys` | List keys visible via the system ssh-agent and `~/.ssh` |

```bash
xkey ssh local hosts
xkey ssh local keys
```

## `xkey ssh sessions` (alias `session`)

Manages persistent embedded-console session records the GUI restores as
tabs after a reload/restart.

| Command | Purpose |
|---|---|
| `list` (`ls`) | List persistent sessions (ID, title, origin, last connected) |
| `remove [id]` (`rm`, `delete`) | Delete a persistent session record |

```bash
xkey ssh sessions list
xkey ssh sessions remove <id>
```

## See also

- [Architecture](architecture.md) — the shared store, transport
  selection, and key-source resolution these verbs build on
- [API](api.md) — the GUI equivalents of this surface
- [User Guide](user.md) — task-oriented usage
