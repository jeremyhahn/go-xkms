# SSH Connect & Console Sessions — CLI

> **Status: NORMATIVE** · Feature: `ssh-sessions` · Repo: `go-xkms` · Last verified: 2026-09-24

## No `xkmsctl` surface

`cmd/xkmsctl/ssh.go` defines only `keys`, `known-hosts`, and
`authorized-keys` command groups (see
[`../ssh-keys/cli.md`](../ssh-keys/cli.md)). It has no `connect`,
`console`, `profile`, `sessions`, or `local` subcommand, matching the
transport gap documented in [`api.md`](api.md) — there is nothing in
`xkmsctl` for these packages to wire into, because `xkmsd` never dials a
target host on the operator's behalf.

## The CLI surface for this capability lives in `xkey`

`connect.Start`, `console.Dial`, `pkg/ssh/profile`, `pkg/ssh/sessions`,
and `pkg/ssh/local` are consumed by the `xkey` CLI, in
`xkey/cmd/xkey/cmd/ssh_connect.go`, `ssh_console_cmd.go`, `ssh_local.go`,
and `ssh_sessions.go`. The full flag reference for these verbs is
normative in [`../../xkey/docs/ssh/cli.md`](../../xkey/docs/ssh/cli.md);
this section lists only the verbs and the go-xkms package each maps to,
so a reader tracing from the root packages can find the command without
re-deriving it:

| `xkey` command | Backed by |
|---|---|
| `xkey ssh connect [profile\|user@host]` (`ssh_connect.go:48`) | `pkg/ssh/connect.Start` |
| `xkey ssh console [profile\|user@host]` (`ssh_console_cmd.go:32`) | `pkg/ssh/console.Dial` |
| `xkey ssh profile add\|list\|get\|remove\|mv` (`ssh_connect.go:61-94`) | `pkg/ssh/profile.Store` |
| `xkey ssh sessions list\|remove` (`ssh_sessions.go:26-43`) | `pkg/ssh/sessions.Store` |
| `xkey ssh local hosts\|keys` (`ssh_local.go:31-44`) | `pkg/ssh/local` |

`xkey`'s desktop GUI exposes the same capabilities through its SSH
services; see [`../../xkey/docs/ssh/`](../../xkey/docs/ssh/) for the GUI
surface and the shared storage resolver both front ends build on.

## No `xkmsctl Console`-over-network workaround

Because `Client.Console` is embedded-only (see [`api.md`](api.md)), there
is no `xkmsctl ssh console --server ...` verb to add against a remote
`xkmsd` — an interactive shell requires the calling process to hold the
signer locally (embedded SDK) or to run xkey's own loopback WebSocket
bridge. This is a deliberate consequence of the architecture in
[`architecture.md`](architecture.md), not an oversight to file an issue
against.
