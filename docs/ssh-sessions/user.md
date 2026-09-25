# SSH Connect & Console Sessions — User Guide

> **Status: NORMATIVE** · Feature: `ssh-sessions` · Repo: `go-xkms` · Last verified: 2026-09-24

## Who this is for

This folder documents `go-xkms` library packages, not an end-user tool by
itself. If you are an operator who wants to connect to a host with an
xkey-managed SSH key, use the `xkey` CLI or desktop GUI — see
[`../../xkey/docs/ssh/user.md`](../../xkey/docs/ssh/user.md) for the
task-oriented walkthrough (`xkey ssh connect`, `xkey ssh console`, saved
profiles, and local `ssh_config`/agent discovery).

This page is for an application developer embedding `go-xkms` directly
through the Go SDK.

## Opening a non-interactive session (works against any server transport)

```go
client, _ := sshsdk.NewREST(sshsdk.RESTOptions{BaseURL: "https://kms.example.com:8443"})

key, _ := client.Keys().Get(ctx, sshsdk.KeyRef{Scope: "user", Owner: "alice", Name: "laptop"})
sess, err := client.Session().Dial(ctx, sshsdk.SessionDialRequest{
    Host: "app01.example.com",
    Port: 22,
    User: "deploy",
    KeyScope: "user", KeyOwner: "alice", KeyName: "laptop",
})
if err != nil {
    // *NotFoundError, *MismatchError (unpinned or changed host key), ...
}
defer sess.Close()

stdout, stderr, err := sess.Run(ctx, "systemctl status myapp")
```

This works whether `client` was constructed with `NewREST`, `NewGRPC`,
`NewMCP`, or `NewQUIC` — see [`api.md`](api.md) for why.

## Opening an interactive console (embedded only)

```go
client, _ := sshsdk.NewEmbedded(sshsdk.EmbeddedOptions{ /* ... */ })

session, err := client.Console(ctx, sshsdk.ConsoleConnectRequest{
    KeyScope: "user", KeyOwner: "alice", KeyName: "laptop",
    Host: "app01.example.com", Port: 22, User: "deploy",
}, sshsdk.ConsoleConfig{Term: "xterm-256color", Rows: 40, Cols: 120})
if err != nil {
    // A *ConsoleUnsupportedError here means client was built with
    // NewREST/NewGRPC/NewMCP/NewQUIC instead of NewEmbedded.
}
defer session.Close()
io.Copy(os.Stdout, session)
```

A REST, gRPC, MCP, or QUIC client returns `*ConsoleUnsupportedError` from
`Console` unconditionally — there is no retry or fallback that makes it
succeed on those transports. An application that needs an interactive
shell from outside the process holding the key must build its own
WebSocket bridge with `sshsdk.NewConsoleWSHandler`, the way xkey's desktop
GUI does, and serve it locally to a browser/webview — never expose it on
a network-reachable listener, since the process serving it is the one
that dials the target host (see [`architecture.md`](architecture.md)).

## Saved connection profiles and session history

`pkg/ssh/profile` and `pkg/ssh/sessions` are storage-only packages — they
have no CLI or REST surface of their own. An application embeds them
through the SDK re-exports (`sshsdk.NewProfileStore` /
`sshsdk.NewConsoleSessionStore`), which exist specifically so callers
never need to import `pkg/ssh/profile` or `pkg/ssh/sessions` directly:

```go
store, _ := sshsdk.NewProfileStore(backend)
store.Add(&sshsdk.Profile{
    Name: "prod-app01", FolderPath: "work/prod",
    Host: "app01.example.com", Port: 22, User: "deploy",
    KeyScope: "user", KeyOwner: "alice", KeyName: "laptop",
})
```

is the same operation `xkey ssh profile add` performs on the operator's
behalf. See [`engineering.md`](engineering.md) for the full `Store`
interfaces and the re-exported error sentinels.

## What this folder does not give you

- **No remote interactive shell over REST/gRPC/MCP/QUIC.** If your
  application needs that, it must run the embedded SDK (or xkey's local
  bridge) in the same process/host that will terminate the session — see
  [`architecture.md`](architecture.md) for why this is a deliberate
  security boundary, not a missing feature.
- **No `xkmsd`-side connection profile or session-history storage.** These
  stores are constructed directly against a `storage.Backend` by the
  embedding application; there is no REST resource for them.
