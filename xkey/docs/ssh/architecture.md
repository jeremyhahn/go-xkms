# SSH — Architecture

> **Status: NORMATIVE** · Feature: `ssh` · Module: `go-xkms/xkey` · Last verified: 2026-09-27

## Scope

This folder covers xkey's SSH **product layer**: the `xkey ssh …` CLI
verbs, the GUI's SSH services, and the two small packages
(`xkey/pkg/sshstore`, `xkey/pkg/sshlocal`) that make the CLI and GUI share
one store and one view of the operator's local SSH tooling. It does not
cover `pkg/ssh/*` (key lifecycle, host-key pinning, sessions, the console
wire protocol) or `sdk/go/client/ssh` (the transport-agnostic client) —
both are root-owned and documented at
[`../../../docs/ssh/README.md`](../../../docs/ssh/README.md). Agent-only
signing sessions (no connection target — `git commit -S`,
`ssh-keygen -Y sign`) are a separate, already-converted feature: see
[`../../../docs/ssh-agent-sessions/`](../../../docs/ssh-agent-sessions/),
which is NORMATIVE for that capability.

## The problem

xkey exposes SSH key/profile/host-key/console management through **two**
front ends — the `xkey` CLI and the desktop GUI — that must never diverge
on where SSH data lives, how it is protected at rest, or what the
operator's already-configured `ssh_config`/`ssh-agent` setup looks like.
A key generated from one front end has to be immediately usable from the
other; a host-key pin accepted in one has to be honored by the other.

## Shape chosen: one shared storage resolver, routed by barrier state

`xkey/pkg/sshstore.ResolveBackend(dataDir, engineKind, barrierBackend)` is
the single construction point for the SSH key/profile/host-key-pin
`xkmssdk.StorageBackend` both front ends build their `sdk/go/client/ssh`
store types on top of (`NewProfileStore`, `NewHostKeyStore`,
`NewConsoleSessionStore`, and the key store the embedded `Client` uses):

- **Barrier initialized** — `barrierBackend != nil` selects
  `xkmssdk.NewStoragePrefixBackend(barrierBackend, "ssh/")`: SSH data is
  namespaced under the barrier and encrypted at rest with everything else
  the barrier protects.
- **Barrier not initialized** — a plain engine store (file/pebble/memory,
  per the configured storage engine) rooted at `<dataDir>/ssh`.

There is **no migration** between the two forms: a plaintext store from
before the barrier was initialized is not imported into the
barrier-encrypted store when the barrier is later initialized (this
repository's pre-release, no-backward-compatibility policy — see the
package doc comment in `xkey/pkg/sshstore/store.go`). The operator
re-adds keys, profiles, and pins after initializing the barrier.

## Shape chosen: the CLI has no unlock flow, and fails closed

`xkeySSHBackend()` (`xkey/cmd/xkey/cmd/ssh.go`) resolves the CLI's SSH
backend by checking whether a barrier root key exists at the resolved
data directory. If it does, every SSH command returns
`ErrSSHStoreBarrierEncrypted` — a typed sentinel naming the fix ("unlock
via the xkey app") — rather than guessing at a passphrase prompt or
re-implementing the GUI's TPM/PCR-policy auto-unseal machinery a second
time. Barrier-encrypted SSH data is managed through the GUI until the CLI
gains an unlock flow of its own; this is a documented, deliberate gap, not
an oversight — see [engineering.md](engineering.md#known-gaps).

## Shape chosen: identical transport selection, one helper per front end

Both front ends resolve an `sshsdk.Client` through the same three-step
precedence, driven by the same SDK dispatch
(`sshsdk.NewClientForServer` / `NewREST` / `NewEmbedded`):

1. An explicit `--server <url>` (CLI) selects a transport by URL scheme —
   `http(s)`, `grpc(s)`, `unix://`, `quic://`, `mcp(s)` — so one command
   works unmodified against every protocol xkmsd serves.
2. `XKMSD_URL` (env) or the `xkmsd_url` config key falls back to REST.
3. Otherwise, the local embedded client is built on the shared
   `sshstore`-resolved backend described above.

The CLI's `sshClient(cmd)` (`ssh.go`) and the GUI's `SSHService` /
`SSHConnectService` / `SSHConsoleService` (each taking an already-built
`sshclient.Client` at construction, via `SetEmbeddedClient` /
`SetSSHClient`) both terminate at the same three SDK constructors — there
is no second transport-selection implementation.

## Shape chosen: three ways to reach a host, chosen by key source

`ssh connect` / `ssh console` (CLI) and the New Connection / Profile
dialogs (GUI) all resolve to one of three authentication paths, keyed off
the same `KeySource` concept (`Profile.KeySource`,
`SSHConnectParams.KeySource`: `""` vs. `"local"`) plus an optional pinned
`Identity`:

1. **xkey-managed key** (`KeySource == ""`, a key name given) — the chosen
   key's signer is served over an in-process SSH agent (system terminal
   mode) or resolved directly (embedded console mode), so a
   hardware-backed key's private material never leaves its backend. See
   root docs for the agent/console mechanics.
2. **Local, pinned** (`KeySource == "local"` with `--identity` or
   `--ssh-config-alias`) — one specific operator-owned key (an identity
   file, an agent-held fingerprint, or an `ssh_config` alias) is used.
3. **Local, unpinned / no key** — a plain passthrough `ssh` invocation
   with no xkey involvement at all: no in-process agent, no temporary
   `known_hosts`, no injected options. `ssh_config`, `ProxyJump`, and the
   system agent behave exactly as they would from a raw terminal. This is
   also the fallback when no key and no profile key are given, matching
   what typing `ssh user@host` yourself would do.

`buildLocalSSHArgs` (`ssh_connect.go`) is the one function that builds
that plain-passthrough argv for the CLI; the GUI's
`SSHConnectService.launchPassthrough` is its GUI-side counterpart. Both
exist so path 3 can never accidentally acquire agent/known-hosts
side effects that belong to path 1.

## Shape chosen: `xkey/pkg/sshlocal` — one read-only presentation package

Read-only discovery of the operator's *existing* `ssh_config(5)` hosts and
`ssh-agent`/`~/.ssh` identities (`ssh local hosts`/`keys` on the CLI, the
Keys-tab local toggle and "From ~/.ssh/config" section on the GUI) is
implemented once, in `xkey/pkg/sshlocal`, and called directly by both the
CLI (`ssh_local.go`) and the GUI (`SSHLocalService`). The package itself
does no SSH protocol or config parsing — it calls the SDK's
`LoadLocalSSHConfig` / `DiscoverLocalIdentities` / `DialLocalAgent`
(`sdk/go/client/ssh`, documented at the root) and reshapes the results for
display, deduplicating an agent-held key against its on-disk identity
file by fingerprint. `xkey/pkg/sshlocal` never imports `go-xkms/pkg`
directly (package doc comment, `hosts.go`) — matching the boundary
`xkey/CLAUDE.md` sets for the rest of this module: only through the SDK.
xkey never writes `~/.ssh/config`, `/etc/ssh/ssh_config`, or anything
under `~/.ssh`; this package only reads.

## Shape chosen: persistent console sessions are opt-in, and share the same store

The embedded console panel's tab strip (GUI) is memory-only by default; a
session started with **Persistent session** enabled (or a profile added
with `--persist-session`) is additionally recorded through
`sshclient.ConsoleSessionStore`, built on the same `sshstore`-resolved
backend as keys/profiles/pins (`xkeySessionStore()` in `ssh_sessions.go`;
`SSHConsoleService.SaveSession`/`ListSessions`/`DeleteSession` in the
GUI). A record carries only a title and reconnect origin — never key
material or live connection state — so restoring it after a reload or
restart leaves the tab disconnected, with Reconnect one click away.
`xkey ssh sessions list|rm` is the CLI's read/delete parity for the same
records.

## Rejected alternative: a CLI-native barrier unlock

The CLI could implement its own TPM/PCR-policy auto-unseal or a
passphrase prompt so barrier-encrypted SSH data is reachable without the
GUI running. That would duplicate unlock logic this repository already
owns once, in the GUI's seal feature (see
[`../seal/`](../seal/)) — and the CLI's headless, scriptable design (no
`Connect`-style GUI dialogs) has no natural place for the interactive
ceremony auto-unseal sometimes requires. Failing closed with a clear
error, rather than half-implementing unlock a second time, was chosen
instead.

## See also

- [Engineering](engineering.md) — exported surface, invariants, errors, tests
- [CLI](cli.md) — every `xkey ssh` verb and flag
- [API](api.md) — GUI bindings and the local package surface
- [User Guide](user.md) — task-oriented usage
- Root SSH library and SDK: [`../../../docs/ssh/README.md`](../../../docs/ssh/README.md)
- Agent-only sessions (no connection target): [`../../../docs/ssh-agent-sessions/`](../../../docs/ssh-agent-sessions/)
