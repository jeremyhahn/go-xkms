# Key Escrow — API

> **Status: NORMATIVE** · Feature: `escrow` · Repo: `go-xkms` · Last verified: 2026-09-23

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped".

## Capability matrix

| Capability | REST / gRPC / Unix / QUIC / MCP / USB | Embedded (`EscrowService.`) | Permission |
|---|---|---|---|
| Escrow a key | not implemented | `EscrowKey` | **unresolved — see below** |
| Recover a key | not implemented | `RecoverKey` | **unresolved — see below** |
| List escrowed keys | not implemented | `ListEscrowed` | **unresolved — see below** |
| Revoke an escrowed key | not implemented | `RevokeEscrow` | **unresolved — see below** |

**BREAKING (go-xkms#692):** `transport.EscrowService` (`pkg/api/transport/client.go`)
and `transport.EscrowServicer` (`pkg/api/transport/servicer.go`) are no longer
embedded in `Client` / `XKMSServicer`. Escrow's RBAC model is still unresolved
— see below — and carrying four methods that every network transport could
only ever answer with `ErrNotSupported` on the interface every transport must
satisfy misrepresented the six network transports as "escrow-capable, just not
wired up yet." They are not: nothing about REST, gRPC, QUIC, Unix, MCP or USB
routes to escrow, and none of the six implements the four methods any more —
they were deleted, not left as stubs.

`embedded.XKMSServicer` (`pkg/api/transport/embedded/servicer.go`) is now the
one place in the stack that still composes `EscrowServicer` into the wider
servicer surface it requires from its backing service, and
`*embedded.Transport` is the one concrete type satisfying
`transport.EscrowService` (`pkg/api/transport/embedded/transport.go` delegates
each method straight to the injected service). A caller holding a generic
`transport.Client` that needs escrow type-asserts it to `transport.EscrowService`
and handles the "not this transport" case; there is no route to reach it
through the umbrella interfaces.

## Embedded Go SDK works today

Any Go program that embeds `pkg/xkms.XKMSService` directly, or obtains a
`sdk/go` `Client` via `xkms.NewEmbedded(service)` /
`xkms.New(&BackendConfig{Protocol: xkms.ProtocolEmbedded, Service: service})`,
can call escrow today with no additional wiring:

```go
receipts, err := client.EscrowKey(ctx, &transport.EscrowRequest{
	KeyID:             "backup-root-key",
	WrappedKey:        wrappedKeyBytes, // already wrapped with AES-KW or RSA-OAEP
	WrappingAlgorithm: "AES-KW",
	Purpose:           "backup",
})

resp, err := client.RecoverKey(ctx, &transport.RecoverRequest{KeyID: "backup-root-key"})

records, err := client.ListEscrowed(ctx)

err = client.RevokeEscrow(ctx, receipts[0].EscrowID)
```

`transport.EscrowRequest`, `EscrowReceipt`, `RecoverRequest`,
`RecoverResponse`, and `EscrowRecord` are aliases of the `pkg/escrow` domain
types (`pkg/api/transport/types_escrow.go`), re-exported again under
`sdk/go` (`xkms.EscrowRequest`, …) and `sdk/go/transport`
(`transport.EscrowRequest`, …) for external consumers.

The embedded transport carries **no permission check** — it is a same-process
call into whichever `*xkms.XKMSService` the embedding program constructed,
which is also true of every other embedded-only capability (`SealStore*`,
`CustodianGroup*`, …). This is why embedded reachability does not require
resolving the open question below: the embedding process is already the
trust boundary.

## Why no network transport implements it

Every existing key-material REST route (`keys:*`, `certs:*`, `barrier:*`,
`frost:*` in `pkg/api/rest/routes.go`) is gated by an RBAC
`resource:action` pair from `pkg/auth/permissions.go`, which is documented as
the only authorization vocabulary in the xkms process and mirrors, pair for
pair, go-qrdb's canonical permission registry
(`go-qrdb/pkg/permission/constants.go`). That registry has no `escrow`
resource as of `v0.16.3-alpha`, so there is no RBAC pair to gate a route with
— and adding one unilaterally, or silently reusing an existing one (the
closest candidates are `keys:export` for escrowing and `keys:import` for
recovery), is a security-policy decision this change does not make on its
own. See [`architecture.md`](architecture.md#what-is-not-wired-yet-and-why)
for the full reasoning and the two concrete paths to resolve it.

Once resolved, wiring a transport back in is mechanical but no longer a stub
edit: add the four `EscrowKey`/`RecoverKey`/`ListEscrowed`/`RevokeEscrow`
methods to that transport's `Transport` type (delegating to the wire call,
exactly as every other implemented capability does), four `perm(...)` entries
to `pkg/api/rest/routes.go` calling `s.escrowHandlers.*Handler` (a new
`EscrowHandlers` type following `pkg/api/rest/handlers_custodian.go`), and the
equivalent gRPC/QUIC/Unix/MCP dispatch entries — the servicer, request/response
types, and error handling underneath are already in place and tested. Adding
those four methods back to a transport is also what makes it implement
`transport.EscrowService` again (go-xkms#692); until then it deliberately does
not.
