- **External key escrow's four methods are no longer part of
  `transport.XKMSServicer` or `transport.Client` — BREAKING.** Escrow's RBAC
  model is undecided (no `escrow` resource exists yet in go-qrdb's
  permission registry), so every network transport could only ever answer
  `EscrowKey`/`RecoverKey`/`ListEscrowed`/`RevokeEscrow` with
  `ErrNotSupported`, while the umbrella interfaces every transport must
  satisfy still forced each one to carry the four methods as dead stubs.
  `transport.EscrowServicer` (`pkg/api/transport/servicer.go`) and
  `transport.EscrowService` (`pkg/api/transport/client.go`) are now standalone
  interfaces outside that composition; REST, gRPC, QUIC, Unix, MCP, and USB no
  longer declare the four methods at all. `embedded.XKMSServicer`
  (`pkg/api/transport/embedded/servicer.go`) composes `EscrowServicer` back in
  for the one transport that still reaches escrow — the embedded transport,
  delegating to whichever `*xkms.XKMSService` backs it — and its `sdk/go`
  re-export (`sdk/go/transport/embedded/servicer.go`) follows it so
  `sdk/go.NewEmbedded` keeps compiling. A caller holding a generic
  `transport.Client` that needs escrow now type-asserts it to
  `transport.EscrowService`. No production caller reached escrow through
  `Client`/`XKMSServicer` before this change (confirmed across
  `cmd/xkmsctl`, `sdk/go`, `xkey`, and `pkg/server`), and no downstream
  consumer (`go-quicbaas`, `go-trusted-platform`) references the escrow
  methods through the SDK, so the practical migration is nil; the change
  closes the interface-shape gap for anyone who does. The service layer
  (`pkg/xkms/servicer_escrow.go`, `pkg/escrow/*`) is unchanged. Files:
  `pkg/api/transport/servicer.go`, `pkg/api/transport/client.go`,
  `pkg/api/transport/embedded/servicer.go`,
  `sdk/go/transport/embedded/servicer.go`,
  `pkg/api/transport/{rest,grpc,quic,unix,mcp,usb}/transport.go`,
  `pkg/api/transport/escrow_interface_split_test.go`, `docs/escrow/api.md`.
  Fixes go-xkms#692.
