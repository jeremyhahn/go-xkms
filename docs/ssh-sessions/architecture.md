# SSH Connect & Console Sessions — Architecture

> **Status: NORMATIVE** · Feature: `ssh-sessions` · Repo: `go-xkms` · Last verified: 2026-10-12

## Scope of this folder

This folder covers the part of go-xkms's SSH subsystem that opens an
**outbound connection to a target host**, as opposed to storing keys
(`ssh-keys`) or serving a hostless signing socket (`ssh-agent-sessions`):

- `pkg/ssh/console` — an interactive PTY session over SSH, plus the
  reusable WebSocket↔SSH-console bridge handler.
- `pkg/ssh/session` — a non-interactive session (`Run`, upload) dialed
  directly from the calling process.
- `pkg/ssh/connect` — launches the operator's system `ssh` binary against
  a host, backed by an in-process signing agent.
- `pkg/ssh/sessions` — persisted records of embedded-console sessions, for
  GUI tab restore. Never key material or live connection state.
- `pkg/ssh/profile` — saved, foldered connection profiles (host/port/user
  plus a key reference), the input `connect`/`console` are usually
  launched from.
- `pkg/ssh/local` — read-only discovery of the operator's own
  `ssh_config(5)` chain, default identity files, and running `ssh-agent`.

[`../ssh-keys/architecture.md`](../ssh-keys/architecture.md) names this
exact package set as "the xkey desktop application's connection-profile
manager... which is a consumer of this feature and of
[`ssh-agent-sessions`](../ssh-agent-sessions/), not part of either" —
this is that folder. The legacy `ssh/README.md` it replaces was absorbed
and deleted (go-xkms#1433).

## The problem: xkms is a vault, not an SSH relay

xkms holds SSH private key material (or a handle to it, for hardware
backends) and signs with it. It never terminates or proxies an SSH
session itself, on any transport. `sdk/go/client/ssh`'s gRPC client states
the reason directly, at the point it refuses:

> "the xkms server is a key vault and CA and never terminates an SSH
> session. Terminating SSH there would let an authenticated caller make
> the appliance open outbound connections to arbitrary hosts and proxy an
> interactive shell through them. The client (xkey) runs the SSH protocol
> itself and asks the server only to sign the authentication challenge
> with the stored key, which never leaves the vault."
> (`sdk/go/client/ssh/grpc.go:103-108`)

`sdk/go/client/ssh/console.go:105-108`'s `NewConsoleWSHandler` doc comment
states the same boundary from the other side, for anyone tempted to mount
the bridge on the daemon: "Do not mount this on the xkms server. The
process serving the handler is the one that dials the target host, so
mounting it on the vault would let an authenticated caller proxy an
interactive shell to any reachable host through the appliance."

Every package in this folder exists downstream of that one rule: the
**calling process** (embedded Go program, `xkey` CLI, or `xkey`'s desktop
GUI) opens the TCP connection and speaks the SSH protocol; xkms is asked
only to produce a signature or hand out an `ssh.Signer`.

## Three ways to open a connection, three different transport reaches

| Mechanism | What it needs from xkms | Client transports it works over |
|---|---|---|
| `SessionClient.Dial` (`pkg/ssh/session.Dial`) — non-interactive `Run`/upload | One `ssh:sign` call + one known-hosts verify, both already-existing `ssh-keys` endpoints | embedded, REST, gRPC, MCP (QUIC reuses REST — `sdk/go/client/ssh/quic.go:44-64`) |
| `Client.Console` (`pkg/ssh/console.Dial`) — interactive PTY | A resolved `ssh.Signer` | embedded only; every network client (REST, gRPC, MCP, QUIC) returns `*ConsoleUnsupportedError` |
| `pkg/ssh/connect.Start` — spawn the system `ssh` binary | A resolved `ssh.Signer`, served over an in-process agent socket | Not an SDK transport at all — a process launcher used by the `xkey` CLI/GUI |

### Why `Dial` reaches every transport and `Console` does not

`SessionClient.Dial` needs exactly two things from the server: a
signature over the SSH auth challenge (the same `POST
/xkms/v1/ssh/keys/{scope}/{owner}/{name}/sign` route `ssh-keys` already
documents) and a known-hosts pin (the same `GET/POST
/xkms/v1/ssh/known-hosts` routes). `restSessionClient.Dial`'s doc comment
is explicit that this is composition, not a new endpoint: "resolves the
authentication key to a forward-signing proxy and the target host to a
wire-verified callback, both over REST, then dials the SSH connection
directly from this process" (`sdk/go/client/ssh/rest.go:577-583`). Once
the signer and the pin are in hand, dialing the target is a pure
client-side operation — the same reasoning applies unchanged to the gRPC
and MCP clients, so all three implement it, and grepping
`pkg/api/rest/routes.go`, `pkg/api/grpc/service_ssh.go`, and
`pkg/api/mcp/authz.go`'s `ssh.*` tool table confirms none of them carry a
`connect`/`console`/`session`/`dial` route, RPC, or tool — only
`keys`/`knownHosts`/`authorizedKeys`.

`Client.Console` cannot be built the same way: an interactive PTY is a
long-lived, bidirectional **byte stream** the calling process must relay
keystrokes into and terminal output out of, in real time, for the
lifetime of the shell. There is no request/response endpoint that
expresses that, and building one server-side would mean the *xkms server*
dials the target host and proxies the shell — exactly the capability the
grpc.go comment above refuses to add. So `Client.Console` is implemented
exactly once, in `sdk/go/client/ssh/embedded.go:108`, which calls
`pkg/ssh/console.Dial` directly in the caller's own process. Every other
transport's `Console` method — `restClient` (`rest.go:103`), `grpcClient`
(`grpc.go:111`), `mcpClient` (`mcp.go:157`) — is a two-line stub that
returns `&ConsoleUnsupportedError{Transport: "..."}`
(`sdk/go/client/ssh/errors.go:66-73`). QUIC inherits the REST behavior
(`quic.go`). Note the error message's parenthetical ("use embedded/gRPC,
or the WebSocket bridge for REST/QUIC") overstates gRPC's support — the
gRPC client returns the identical unsupported error; only the embedded
client and the WebSocket bridge below ever construct a working
`ConsoleSession`.

### The WebSocket bridge is real, but it is not an xkms server route

`pkg/ssh/console/handler.go:146`'s `NewWSHandler` (re-exported as
`sdk/go/client/ssh.NewConsoleWSHandler`, `console.go:108`) is a reusable
`http.Handler` that bridges a WebSocket connection to an interactive SSH
session. It exists to give a **local** process that renders a terminal in
a browser or webview something to mount. Its only current caller is
`xkey`'s desktop GUI, `xkey/pkg/gui/services/ssh_console_service.go:369`,
which serves it on xkey's own loopback HTTP server and consumes it from
`sdk/ts`'s `ssh-console.ts` WebSocket client, entirely inside the
operator's own machine.
[`../web-console/architecture.md`](../web-console/architecture.md)
already documents the other side of this boundary: `web/app` (the SPA
`xkmsd` itself serves at `/ui/`) imports none of `ssh-console.ts` and the
SSH screen there manages stored keys only — grepping `web/app/src` for
`ssh-console` or `WebSocket` returns nothing
(`docs/web-console/api.md:6-13`). No `pkg/api/rest` route ever calls
`NewWSHandler` on the `xkmsd` process; searching the whole repository for
`ConsoleWSHandler` finds exactly the definition, the REST client's doc
comment referencing it, and the xkey GUI's one call site.

## `pkg/ssh/connect` — launching the system `ssh` client

`connect.Start` (`pkg/ssh/connect/connect.go:177`) takes a different
approach again: rather than speaking the SSH protocol itself, it starts
an in-process signing agent — built on the same primitive
`ssh-agent-sessions` exposes, per that folder's own note that "`pkg/ssh/connect`
is now a **consumer of this session**, not a second copy of it"
(`docs/ssh-agent-sessions/architecture.md:44`) — seeds a temporary
`known_hosts` file from the caller's pins, and returns the argv/env for
the operator's *own* `ssh` binary
(`connect.Request`/`connect.Session`, `pkg/ssh/connect/connect.go:41-90`).
The caller (the `xkey` CLI or GUI) execs that command in a real terminal;
hardware-backed keys never leave the agent socket because the native
`ssh` client authenticates through it exactly as it would through any
other `SSH_AUTH_SOCK`. `Session.Sync`/`SyncAndStop`
(`connect.go:309,514`) merge any newly-accepted host keys back into the
configured `known_hosts.Store` once the native client exits.

## `pkg/ssh/local` — reading, never writing, the operator's own SSH setup

`pkg/ssh/local` (package doc, `pkg/ssh/local/doc.go`) is a read-only view
of `$HOME/.ssh/config`, `/etc/ssh/ssh_config`, the conventional default
identity files, and a running `ssh-agent` (`$SSH_AUTH_SOCK`). It exists so
a `profile.Profile` can set `KeySource: "local"`
(`pkg/ssh/profile/types.go:60-63`) and resolve a signer from whatever the
operator already has configured, instead of requiring every connection to
go through an xkey-managed key. The package "never writes to `$HOME/.ssh`
or `/etc/ssh`" (`pkg/ssh/local/doc.go`) — every exported entry point
(`LoadConfig`, `DialAgent`, `ResolveSigner`, `pkg/ssh/local/config.go:79`,
`agent.go:45`, `signer.go:61`) only reads state that already exists on
disk or is exposed by a running agent.

## `pkg/ssh/profile` and `pkg/ssh/sessions` — the two stores connect/console build on

`profile.Profile` (`pkg/ssh/profile/types.go:33`) is a saved, foldered
connection target: `Host`/`Port`/`User` plus either an xkey-managed key
reference (`KeyScope`/`KeyOwner`/`KeyName`) or, with `KeySource: "local"`,
an `SSHConfigAlias` resolved through `pkg/ssh/local` instead. It never
stores key material — the doc comment on the package draws the parallel
directly: "mirroring the static-password manager (`pkg/staticpw`)"
(`pkg/ssh/profile/profile.go` package doc). `profile.Store`
(`store.go:43`) is a full folder tree (`ListByFolder`, `MoveToFolder`,
`CreateFolder`/`RemoveFolder`/`RenameFolder`, `Search`) whose profiles and
folders are go-qrdb DAO entities in the `ssh` database.

`sessions.Session` (`pkg/ssh/sessions/types.go:25`) is the *record* of an
already-open embedded-console tab, not a live connection — "a session's
display title and its reconnect origin — never any key material or live
connection state" (package doc, `pkg/ssh/sessions/sessions.go`). Exactly
one origin group is set (`Validate`, `types.go:57`): a raw
host/port/user/key tuple, a `ProfileID`, or an `Alias` into the local
`ssh_config`. A session opened without persistence enabled is
memory-only and never touches this store.

## Rejected alternative: proxying SSH through the xkms server

An earlier shape considered for the web console screen was a server-side
proxy — `xkmsd` dials the target host and relays bytes to a browser
WebSocket, the same shape `NewConsoleWSHandler` implements for xkey's
*local* loopback server. This was rejected for the reason both doc
comments above state: it would let any caller holding an `ssh:use` grant
turn the appliance into an open SSH relay to any host it can reach,
collapsing the "vault signs, never dials" boundary this whole folder is
built to preserve. The rejection is not a temporary gap — see
`docs/web-console/architecture.md`'s own "What this feature deliberately
does not do" section, which states the appliance "never terminates an SSH
session, on any transport."

## See also

- [`../ssh-keys/`](../ssh-keys/) — the key, known-hosts, and
  authorized-keys data these packages consume; also the backend bridge
  (`pkg/ssh/backend`) and shared key-ID layout (`pkg/ssh/scope`).
- [`../ssh-agent-sessions/`](../ssh-agent-sessions/) — the hostless signing
  socket `pkg/ssh/connect` builds on.
- [`../web-console/`](../web-console/) — documents the SPA's SSH screen and
  why it never imports the console bridge.
