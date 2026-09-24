# Seal & Auto-Unseal — API

> **Status: NORMATIVE** · Feature: `seal` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

No network-transport API surface. The Barrier, barrier auto-unseal, and the
named PCR policy store are all local-only: reachable through the CLI (see
[cli.md](cli.md)), and for the GUI, through direct Go method calls on
`pkg/gui/services.BarrierService`/`BarrierAutoUnsealService` over Wails
bindings. Neither is served over REST, gRPC, or any other transport, and
neither requires (or talks to) an `xkmsd` server.

This is not to be confused with `xkey platform-store`
(`xkey/docs/architecture/platform-store.md`), a same-named but unrelated
key-value secret store served by a remote `xkmsd` process — that command
group does require `--xkmsd-url` and does cross the network. Nothing in
this feature folder does.
