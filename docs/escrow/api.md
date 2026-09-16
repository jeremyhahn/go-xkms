# Key Escrow — API

> **Status: NORMATIVE** · Feature: `escrow` · Repo: `go-xkms` · Last verified: 2026-09-15

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped".

## Capability matrix

| Capability | REST | gRPC / Unix / QUIC / USB | MCP | Embedded (`EscrowService.`) | Permission |
|---|---|---|---|---|---|
| Escrow a key | not supported (`ErrNotSupported`) | not supported | not supported | `EscrowKey` | **unresolved — see below** |
| Recover a key | not supported | not supported | not supported | `RecoverKey` | **unresolved — see below** |
| List escrowed keys | not supported | not supported | not supported | `ListEscrowed` | **unresolved — see below** |
| Revoke an escrowed key | not supported | not supported | not supported | `RevokeEscrow` | **unresolved — see below** |

`transport.EscrowService` (in `pkg/api/transport/client.go`, part of the
`Client` interface every transport implements) and the equivalent
`transport.EscrowServicer` (server side, part of `XKMSServicer`) exist and are
fully implemented by the embedded transport and the `pkg/xkms.XKMSService`
service layer. Every network transport (REST, gRPC, QUIC, Unix, MCP, USB)
implements the four methods as typed `ErrNotSupported` stubs — the same
pattern the pre-existing `SealStoreService` uses for a capability with no
route yet — purely so each transport's concrete type keeps satisfying
`Client` / `XKMSServicer`. No route exists on any network transport.

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

## Why every network transport returns `ErrNotSupported`

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

Once resolved, registering the routes is mechanical: add four `perm(...)`
entries to `pkg/api/rest/routes.go` calling `s.escrowHandlers.*Handler`
(a new `EscrowHandlers` type following `pkg/api/rest/handlers_custodian.go`),
and the equivalent gRPC/QUIC/Unix/MCP dispatch entries — the servicer,
request/response types, and error handling underneath are already in place
and tested.
