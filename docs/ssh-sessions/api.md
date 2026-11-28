# SSH Connect & Console Sessions — API

> **Status: NORMATIVE** · Feature: `ssh-sessions` · Repo: `go-xkms` · Last verified: 2026-09-24

## No REST, gRPC, QUIC, or MCP surface for connect/console/profile/sessions/local

Unlike [`ssh-keys`](../ssh-keys/api.md), which documents real
`/xkms/v1/ssh/{keys,known-hosts,authorized-keys}` REST routes, gRPC RPCs,
and MCP tools, **none of the packages this folder covers have a server-side
route, RPC, or tool.** This is confirmed by grep, not by absence of
effort — see [`engineering.md`](engineering.md) §"Transport surface (none,
by design)" for the exact files checked. If a future PR adds one, this
file is the place its route table goes; today there is nothing to list.

The reason is architectural, not a gap to be filled: `xkmsd` is a key
vault and CA that signs on request and never dials or proxies an SSH
session itself. See [`architecture.md`](architecture.md) for the full
reasoning and the two doc comments (`sdk/go/client/ssh/grpc.go:103-108`,
`console.go:105-108`) that state it directly in the source.

## What *is* reachable over the network: signing, through `ssh-keys`

`SessionClient.Dial` (non-interactive `Run`/upload) works over every SDK
transport — embedded, REST, gRPC, MCP (and QUIC, which reuses the REST
client) — but it does so by calling the existing `ssh-keys` sign and
known-hosts-verify endpoints from the client process, then dialing the
target host directly from there. It adds no endpoint of its own. See
[`../ssh-keys/api.md`](../ssh-keys/api.md) for:

- `POST /xkms/v1/ssh/keys/{scope}/{owner}/{name}/sign`
- `GET /xkms/v1/ssh/known-hosts`, `POST /xkms/v1/ssh/known-hosts/{host}/verify`

and their gRPC/MCP equivalents. `Client.Session().Dial(ctx,
SessionDialRequest)` (`sdk/go/client/ssh/client.go`) is the Go-SDK entry
point that composes them; there is no wire format specific to `Dial`
itself.

## `Client.Console` — embedded only

`Client.Console(ctx, ConsoleConnectRequest, ConsoleConfig)
(ConsoleSession, error)` is part of the `sdk/go/client/ssh.Client`
interface every transport implements, but only the embedded client
(`sdk/go/client/ssh/embedded.go:108`) returns a working `ConsoleSession`.
The REST, gRPC, MCP, and QUIC clients all return
`*ConsoleUnsupportedError` (see [`engineering.md`](engineering.md)
§"Errors"). There is no wire-level fallback for `Console` on those
transports — a caller that needs an interactive shell over one of them
must use the WebSocket bridge below instead of `Client.Console`.

## The WebSocket bridge (`NewConsoleWSHandler`) is SDK infrastructure, not an xkms server route

`sdk/go/client/ssh.NewConsoleWSHandler` (wrapping
`pkg/ssh/console.NewWSHandler`) is an `http.Handler` a **local** process
can mount to bridge a browser/webview terminal to an SSH session. It is
not part of `xkmsd`'s REST API — `pkg/api/rest` never registers it — and
its doc comment says explicitly not to mount it there (quoted in full in
[`architecture.md`](architecture.md)). Its one caller today is xkey's
desktop GUI (`xkey/pkg/gui/services/ssh_console_service.go:369`), which
serves it on xkey's own loopback HTTP listener, consumed by
`sdk/ts`'s `ssh-console.ts` from xkey's own webview — never from `xkmsd`'s
served SPA. See
[`../web-console/api.md`](../web-console/api.md) for the confirmation
that `web/app` (the SPA `xkmsd` serves at `/ui/`) imports none of
`ssh-console.ts`.

## `pkg/ssh/connect` is a process launcher, not a client transport

`connect.Start` does not call any xkms transport itself once it has a
signer — it starts a local signing-agent socket and returns argv/env for
the operator's *own* `ssh` binary to exec against. There is no request or
response shape to document here; the "API" is the Go function signature
covered in [`engineering.md`](engineering.md).

## Migrating the pre-DAO session and profile stores

`sdkssh.MigrateLegacyStores(ctx, legacy, daos)`
(`sdk/go/client/ssh/stores.go:82`) moves the sessions (`ssh/sessions/<id>`),
profiles (`ssh/profiles/<id>.json`) and folder markers
(`ssh/profiles/__folders__/<path>`) the pre-DAO stores kept in a sealed-KV
`storage.Backend` into the DAO catalogs, along with the SSH keys, pins and
authorized entries (see `../ssh-keys/api.md` §"Migrating the pre-DAO
stores"). The consumer calls it at store open, before the session and profile
stores serve requests. Sessions and profiles under a tenant prefix are
counted as skipped and left in place, because these catalogs have no tenant
partition. A second call migrates nothing and reports zero.
