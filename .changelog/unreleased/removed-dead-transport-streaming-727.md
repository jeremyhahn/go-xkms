- **Dead streaming surface removed from every transport layer, and ACME
  gRPC construction now refuses with a typed error — BREAKING for anyone
  importing the deleted symbols or relying on the default (gRPC) transport
  with `sdk/go/acme`.** `RequestStream` and `Stream` are deleted from the
  `pkg/api/transport.Transport` interface — itself deleted, since nothing in
  the tree ever held a value of that generic, unary-`Request` abstraction;
  every real caller goes through the service-specific `pkg/api/transport.
  Client` interface instead — along with every `RequestStream` implementation
  in `pkg/api/transport/{rest,mcp,quic,usb}` and their dedicated tests.
  `RequestStream`/`Stream` are likewise deleted from the ACME SDK's
  `sdk/go/acme/transport.Transport` (its `Request` method has real callers
  and is kept), from every implementation under `sdk/go/acme/transport/
  {rest,unix,quic,embedded,mcp,grpc}`, from the ACME SDK's own `Stream` type
  alias, and from the `sdk/go/transport` re-export of the `pkg/api/transport`
  pair. `grpcStream` — constructed only inside the now-deleted ACME gRPC
  `RequestStream`, and itself never exercised outside that dead path — and
  the `isACMEService` helper that existed solely to gate it are deleted with
  their tests. `RequestStream` had zero callers anywhere in the tree
  (including `sdk/go`, `xkey`, and `test/integration`) outside the tests
  removed alongside it; go-xkms#698's provenance investigation confirms the
  same was true at the go-trusted-ca origin, that no proto defines a
  streaming RPC, and that the generic `pkg/api` `Request` had zero callers.

  Separately: `sdk/go/acme.NewClient` (`trustedca` package) now refuses
  `TransportGRPC` — the zero-value default — with a typed `Unimplemented`
  error at construction. RFC 8555 defines ACME as HTTP+JWS; there is no gRPC
  binding for the protocol, and the gRPC transport's own `Request` already
  refused every ACME service at call time (`handleACMEUnsupported`). Refusing
  at construction means a caller who leaves the transport unset, or a caller
  who forgets `WithREST`/`WithQUIC`/`WithUnix`/`WithMCP`/`WithEmbedded`, gets
  one clear error immediately instead of a client whose `Account`, `Order`,
  `Directory`, `Nonce`, `Challenge`, `Authorization`, and `Certificate` calls
  would each fail individually on their first `Request`. The gRPC transport
  package itself is unchanged and still serves the Admin API; it can still be
  driven directly with `admin.NewClient` for callers who want gRPC Admin
  access outside this combined client — no real caller in this tree ever
  requested gRPC for ACME or Admin through `trustedca.NewClient` (every one
  passes `WithREST` or `WithEmbedded` explicitly). go-xkms#727.
