# LUKS (root module) — API

> **Status: NORMATIVE** · Feature: `luks` · Repo: `go-xkms` · Last verified: 2026-09-30

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped".

**No REST, gRPC, QUIC, Unix, or MCP surface.** Verified: no case-insensitive
match for `luks` anywhere under `pkg/api` or `pkg/server` (the packages that
register routes and RPCs for every other transport-facing feature in this
repository).

This tracks the finding in [`architecture.md`](architecture.md#consumers):
`pkg/luks` has exactly one in-tree importer, `sdk/go/luks`, which is a
type-and-value alias re-export with no service layer, no RPC definitions,
and no route registration of its own. There is nothing behind an API surface
to expose — a route would have no server-side implementation to call.

The only network-reachable path today is embedding `pkg/luks` (through its
`sdk/go/luks` re-export) directly into a Go binary and calling `Manager` /
`TPMSealer` in-process — exactly what `xkey` does, as of go-xkms#917, for
its `xkey luks2 *` commands (documented at
[`../../xkey/docs/luks/api.md`](../../xkey/docs/luks/api.md), which likewise
has no server-transport surface — it operates entirely through the local
`xkey` CLI and GUI processes).
