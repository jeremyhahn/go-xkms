# SSH

xkey's SSH surface — key management, host-key pins, authorized_keys, saved
connections, and two ways to open a shell — is a thin CLI/GUI layer over
go-xkms's canonical `pkg/ssh/*`, reached exclusively through
`sdk/go/client/ssh` (`xkey/CLAUDE.md`: no `pkg/ssh` imports in `xkey/`). The
GUI and CLI share one key/profile/host-key store, so a key generated in one
front end is immediately usable from the other.

There is no standalone SSH agent daemon (`xkey ssh agent ...` does not
exist). Connections either run through the native OS `ssh` client (system
terminal mode) or an in-process PTY console streamed into the app (embedded
mode) — see [Connecting](#connecting-system-terminal-vs-embedded-console).

## Quick start

```bash
# Generate an ed25519 key (embedded store, backend-bound; software by default)
xkey ssh keys generate --name laptop

# List / export for a remote authorized_keys file
xkey ssh keys list
xkey ssh keys export --name laptop >> ~/.ssh/authorized_keys

# Save a profile and connect (system terminal, native ssh first-contact prompt)
xkey ssh profile add --name prod-web --host web1 --user deploy --key laptop
xkey ssh connect prod-web

# Or connect through the operator's own ssh_config/ssh-agent instead of an xkey key
xkey ssh connect --local --ssh-config-alias prod-bastion
```

Every key/profile/host-key subcommand accepts `--server <url>` (any of
`http(s)://`, `grpc(s)://`, `unix://<path>`, `quic://`, `mcp(s)://`) plus
`--tls-ca` to operate against a remote `xkmsd` instead of the local store; see
[Remote xkmsd](#remote-xkmsd).

## Storage: one shared, barrier-routed store

`xkey/pkg/sshstore` is the single construction point for SSH keys, profiles,
and host-key pins — the GUI and CLI both call it, so they never diverge on
where data lives or how it's protected.

| xkey barrier state | Where SSH data lives |
|---------------------|----------------------|
| Initialized (encrypted at rest) | Namespaced under the barrier via a `"ssh/"` prefix backend — keys, profiles, and pins are encrypted at rest with everything else in the barrier. |
| Not initialized | A plain engine store at `<data-dir>/ssh` (file/pebble/memory, per the configured storage engine). |

There is no migration between the two forms: a plaintext store from before
the barrier was initialized is not imported into the barrier-encrypted
store. Initialize the barrier first, then re-add SSH keys, profiles, and
host-key pins through the CLI or GUI. The old hardcoded `~/.xkey-store/ssh`
default path is gone; the shared resolver always derives its root from the
app's data directory.

The CLI has no barrier-unlock flow of its own. If the store is
barrier-encrypted, SSH commands fail with:

```
ssh: local store is barrier-encrypted; unlock via the xkey app
```

Unlock through the xkey GUI (TPM/PCR-policy auto-unseal or manual unlock),
then retry the CLI command.

## Commands

### `xkey ssh keys`

| Command | Purpose |
|---------|---------|
| `generate` | Generate a new SSH key. |
| `import [file]` | Import a PEM-encoded private key (passphrase prompted on a TTY, read from stdin otherwise). |
| `list` (`ls`) | List keys. |
| `get` | Show metadata for one key. |
| `delete` (`rm`, `remove`) | Delete a key. |
| `export` | Print the `authorized_keys`-format public half. |

| Flag | Applies to | Default | Description |
|------|-----------|---------|-------------|
| `--scope` | all | `user` | Scope (`tenant`\|`user`\|`service`). |
| `--owner` | all | `$USER`/`$LOGNAME` | Owner identifier. |
| `--name` | generate, get, delete, export | (required) | Key name. |
| `--type` | generate | `ed25519` | `ed25519`, `rsa`, `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`. |
| `--bits` | generate | `4096` for `rsa` | RSA key size. |
| `--comment` | generate, import | — | Free-form comment. |
| `--backend` | generate | (server/embedded default) | Crypto backend to generate on: `software`, `tpm2`, `pkcs11`, cloud. |

```bash
xkey ssh keys generate --name laptop --type ecdsa-p256 --backend tpm2
xkey ssh keys import ~/.ssh/id_ed25519 --name imported
xkey ssh keys export --name laptop > ~/.ssh/id_xkey.pub
xkey ssh keys delete --name laptop
```

### `xkey ssh connect`

```
xkey ssh connect [profile|user@host] [flags]
```

Opens an SSH session in the **current terminal** using the system `ssh`
binary. The argument is a saved profile name or a `user@host` target.

| Flag | Default | Description |
|------|---------|-------------|
| `--key` | (from profile) | xkey-managed key name to authenticate with. |
| `--key-scope` | `user` | Key scope. |
| `--key-owner` | `local` | Key owner. |
| `--port` | `22` | Target port. |
| `--user` | — | Remote user (for a bare-host target). |
| `--known-hosts-policy` | `barrier` | Where to record new pins: `barrier`\|`system`\|`both`. |
| `--local` | `false` | Authenticate via the operator's own ssh-agent/`~/.ssh` identities — plain passthrough `ssh`, no xkey key, no in-process agent, no `known_hosts` override. |
| `--ssh-config-alias` | — | An `ssh_config(5)` `Host` alias to connect through; implies `--local`. |
| `--identity` | — | Pin one specific local key: an identity file path (passed to `ssh` as `-i`) or `agent:<SHA256-fingerprint>` for an agent-held key; implies `--local`. |

Without `--local`, xkey serves the chosen key over an **in-process SSH agent**
(`pkg/ssh/agent`) on a temp socket, seeds a temp `known_hosts` from its pins,
and execs `ssh` with `SSH_AUTH_SOCK` pointed at that agent — hardware-backed
keys never export private material. The native `ssh` client shows the classic
console first-contact prompt for an unpinned host; accepted keys are synced
back into the pin store when the session exits.

With no `--key` and no profile key, `connect` also falls through to the plain
passthrough — the system agent or an interactive password prompt
authenticates, exactly like typing `ssh user@host` yourself.

With `--local` (or `--ssh-config-alias` / `--identity`), xkey steps out of the
way entirely: it execs `ssh [alias]` or `ssh [-p port] [-i identity]
[user@]host` with nothing but the
inherited environment, so `ssh_config`, `ProxyJump`, and the operator's own
agent behave exactly as they would from a raw terminal.

```bash
xkey ssh connect prod-web                      # saved profile, xkey-managed key
xkey ssh connect deploy@web1 --key laptop       # one-time target, xkey-managed key
xkey ssh connect prod-web --known-hosts-policy both
xkey ssh connect --local --ssh-config-alias prod-bastion   # local ssh_config passthrough
xkey ssh connect deploy@web1 --local            # local ssh-agent/~/.ssh, one-time
```

### `xkey ssh console`

```
xkey ssh console [profile|user@host] [flags]
```

Opens an interactive SSH PTY **in-process**, through the same
`pkg/ssh/console` capability the embedded GUI terminal uses — unlike
`connect`, no `ssh` subprocess is spawned. The local terminal is put into raw
mode and `SIGWINCH` is forwarded to resize the remote PTY.

| Flag | Default | Description |
|------|---------|-------------|
| `--key` | (from profile) | xkey-managed key name. |
| `--key-scope` | `user` | Key scope. |
| `--key-owner` | `local` | Key owner. |
| `--port` | `22` | Target port. |
| `--user` | — | Remote user. |
| `--local` | `false` | Authenticate via the operator's own ssh-agent/`~/.ssh` identities (multi-signer, OpenSSH-style) instead of an xkey-managed key. |
| `--identity` | — | Pin one specific local key: an identity file path or `agent:<SHA256-fingerprint>`; implies `--local`. |

```bash
xkey ssh console prod-web
xkey ssh console deploy@web1 --key laptop
xkey ssh console deploy@web1 --local                          # agent + ~/.ssh identities
xkey ssh console deploy@web1 --identity agent:SHA256:pNYoqv…  # one agent-held key (e.g. sk-)
```

With no `--key` and no profile key, `console` falls back to `--local`
behavior, matching the GUI embedded console. Host-key pins still verify
against xkey's store either way.

### `xkey ssh profile`

`pkg/ssh/profile` stores profiles in the shared store under `ssh/profiles/`
(folder model identical to the password manager). A profile references a
key by name — never key material.

| Command | Purpose |
|---------|---------|
| `add` | Create a profile. |
| `list` (`ls`) | List profiles, optionally `--folder <path>`. |
| `get [name]` | Show a profile. |
| `remove [name]` (`rm`, `delete`) | Delete a profile. |
| `mv [name]` | Move a profile to a different folder (`--folder`, required). |

| Flag | Default | Description |
|------|---------|-------------|
| `--name` | (required) | Profile name. |
| `--folder` | — | Folder path, e.g. `work/prod`. |
| `--host` | (required unless `--ssh-config-alias`) | Target host. |
| `--port` | `22` | Target port. |
| `--user` | — | Remote user. |
| `--key` | — | xkey-managed key name. |
| `--key-scope` | `user` | Key scope. |
| `--key-owner` | `local` | Key owner. |
| `--key-source` | `""` (xkey-managed) | `""` or `local` — `local` makes `connect`/this profile use the operator's ssh-agent/`~/.ssh` instead of an xkey key. |
| `--ssh-config-alias` | — | `ssh_config(5)` `Host` alias; implies `--key-source local`. |
| `--identity` | — | Local identity pin: an identity file path or `agent:<SHA256-fingerprint>`; implies `--key-source local`. |
| `--persist-session` | `false` | Record embedded-console sessions from this profile in the persistent session store (GUI tabs restored after reload/restart; default memory-only). |
| `--notes` | — | Free-form notes. |

### `xkey ssh sessions`

Manages the persistent embedded-console session records the GUI restores as
tabs after a reload/restart. Only sessions explicitly started with
persistence enabled (New Connection checkbox or a `--persist-session`
profile) are recorded; a record carries the session title and reconnect
origin — never key material or live connection state.

| Command | Purpose |
|---------|---------|
| `list` (`ls`) | List persistent sessions (ID, title, origin, last connected). |
| `remove [id]` (`rm`, `delete`) | Delete a persistent session record. |

```bash
xkey ssh profile add --name prod-web --folder work/prod --host web1 --port 2222 --user deploy --key laptop
xkey ssh profile add --name bastion --ssh-config-alias prod-bastion   # local passthrough profile
xkey ssh profile list --folder work
xkey ssh profile mv prod-web --folder work/staging
```

### `xkey ssh host-keys`

Host-key pin management (`known-hosts` is an alias for the parent command).

| Command | Purpose |
|---------|---------|
| `add` | Pin a host-key fingerprint (`--host`, `--fingerprint` required; `--algorithm`, `--source` optional). |
| `list` (`ls`) | List pinned fingerprints. |
| `remove` (`rm`, `delete`) | Remove a pin (`--host` required). |

All three accept `--scope` (default `user`) and `--owner` (default `$USER`).

```bash
xkey ssh host-keys add --host bastion.example.com --fingerprint SHA256:abc... --algorithm ssh-ed25519
xkey ssh host-keys list
xkey ssh host-keys remove --host bastion.example.com
```

### `xkey ssh authorized-keys`

Authorized-key management (`authorized` is an alias for the parent command).

| Command | Purpose |
|---------|---------|
| `add [line]` | Add an `authorized_keys` line under `--name`. |
| `list` (`ls`) | List entries. |
| `remove` (`rm`, `delete`) | Remove an entry by `--name`. |

All three accept `--scope` (default `user`) and `--owner` (default `$USER`).

### `xkey ssh local`

Read-only discovery of the operator's **existing** OpenSSH tooling —
`ssh_config(5)` hosts and the identities visible via the system ssh-agent and
`~/.ssh` — backed by `pkg/ssh/local` via `sdk/go/client/ssh`. xkey never
writes `~/.ssh/config`, `/etc/ssh/ssh_config`, or anything under `~/.ssh`; the
same enumeration logic backs the GUI's local-source toggle (Keys tab) and
"From ~/.ssh/config" section (Connections tab), so the two front ends never
diverge.

| Command | Purpose |
|---------|---------|
| `hosts` (`ls`) | List `Host` aliases resolved from `~/.ssh/config` + `/etc/ssh/ssh_config` (`Include`, `HostName`/`User`/`Port`/`IdentityFile` resolved). |
| `keys` | List keys visible via the system ssh-agent (`$SSH_AUTH_SOCK`) and the default `~/.ssh` identity files (`id_rsa`, `id_ecdsa`, `id_ecdsa_sk`, `id_ed25519`, `id_ed25519_sk`). |

```bash
xkey ssh local hosts
xkey ssh local keys
```

Signing for a local identity prefers the system agent — required for FIDO2
`sk-` keys — and falls back to parsing an unencrypted identity file; an
encrypted file with no matching agent key fails with a clear
passphrase-required error rather than prompting (use `--local` connect, which
delegates entirely to the operator's own `ssh`/agent, for encrypted keys
outside the agent).

## Connecting: system terminal vs embedded console

A saved profile (or one-time target) can open in one of two places:

| Mode | How it runs | First-contact host-key handling |
|------|-------------|----------------------------------|
| **System terminal** | `xkey ssh connect` execs the native `ssh` client (in-process agent + temp `known_hosts` for xkey-managed keys, or a bare passthrough for `--local`). | The OS `ssh` client's own classic prompt; accepted keys sync back into xkey's pin store (unless `--local`, which never touches xkey's store). |
| **Embedded console** | `xkey ssh console` (CLI) or the in-app xterm.js terminal (GUI) streams a PTY in-process through `pkg/ssh/console`. | Governed by `ConsoleTarget.HostKeyPolicy`: `ask` (the GUI default — interactive Accept/Reject in the console, 60s timeout), `yes` (strict, no prompt — dial fails on an unpinned host; the CLI `ssh console` behavior), or `accept-new` (auto-accept + notify). A changed, already-pinned key always fails, regardless of policy. The GUI's Settings → SSH host-key policy is persisted and re-applied at startup. See `docs/ssh/README.md` for the wire protocol. |

Both modes honor the same **host-key store policy** (Settings → SSH in the
GUI, `--known-hosts-policy` on `connect`): `barrier` (xkey's encrypted store
only, default), `system` (`~/.ssh/known_hosts`), or `both`.

The GUI's embedded console panel is **tabbed**: each embedded connection
opens its own session tab (`user@host` title, live/ended status dot,
per-tab close, `+` for a new connection). Background tabs keep their
sessions and scrollback alive; an ended tab offers an in-place Reconnect.
See `docs/ssh/README.md` → *Embedded console tabs* for details.

## Remote xkmsd

Every `keys`/`host-keys`/`authorized-keys`/`connect`/`console` command
accepts `--server <url>` to operate against a remote `xkmsd` instead of the
local store, dispatched by URL scheme (shared with the rest of the xkey CLI):

| Scheme | Transport |
|--------|-----------|
| `http(s)://` | REST |
| `grpc(s)://` | gRPC |
| `unix://<path>` | gRPC over a Unix domain socket |
| `quic://` | HTTP/3 |
| `mcp(s)://` | MCP JSON-RPC |

```bash
xkey ssh keys list --server grpcs://host:9443 --tls-ca ca.crt
```

`--tls-ca` verifies the server. `XKMSD_TOKEN` supplies an auth token when set.
Without `--server`, `XKMSD_URL` (or the `xkmsd_url` config key) selects REST;
otherwise the command falls back to the local shared store described above.

## See also

`docs/ssh/README.md` (go-xkms root) covers the underlying `pkg/ssh/*`
architecture, backend-native key generation, the embedded-console wire
protocol in full, and the GUI's Keys/SSH-application layout.
