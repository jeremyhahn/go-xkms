# Continuous attestation: the verdict verbs on gRPC, Unix and MCP (row 2088, slice 3)

SPEC.md:81's verdict verbs were served on REST only (slice 2). This slice
serves the same three verbs on gRPC (and the Unix socket, which runs the same
Service), on MCP, and through the gRPC, Unix and MCP client transports.

## Pairs

| Verb | gRPC RPC | MCP method | Permission |
|------|----------|------------|------------|
| list | `ListAttestationVerdicts` | `attestation.verdict.list` | `attestation_verdicts:list` |
| latest | `GetLatestAttestationVerdict` | `attestation.verdict.latest` | `attestation_verdicts:get` |
| re-attest | `ReattestDevice` | `attestation.verdict.reattest` | `attestation_verdicts:create` |

Every RPC and method acts for `callerTenant(ctx)`; no request carries a tenant.
No new resource or action string.

## Files

- pkg/api/grpc/proto/xkmsv1/xkms.proto (+ regenerated xkms.pb.go, xkms_grpc.pb.go)
- pkg/api/grpc/service_attestation_verdicts.go (`verdictCall`, `mapVerdictError`)
- pkg/api/grpc/pbconv/attestation_verdicts.go (conversions, `AttestationVerdictClient`)
- pkg/api/transport/grpc/transport_attestation_verdicts.go
- pkg/api/transport/unix/transport_attestation_verdicts.go
- pkg/api/mcp/handlers_attestation_verdicts.go, pkg/api/mcp/server.go
- pkg/api/transport/mcp/transport_attestation_verdicts.go
- golden rows: pkg/api/grpc/authz_golden_test.go, pkg/api/mcp/authz_test.go,
  pkg/api/transport/mcp/transport_test.go; `restOnlyPermissions` emptied in
  pkg/apimodule/module_grants_test.go
- docs/attestation-verifier/api.md, architecture.md, changelog entry

## Order

1. Tests (fail to build until the proto lands).
2. Proto + `make proto`.
3. Service, pbconv, transports, MCP handlers.
4. Docs.

## Checks

- `go test -count=1 -race -tags "codec_cbor codec_json codec_msgpack"` on
  pkg/api/grpc, pkg/api/mcp, pkg/api/transport/{grpc,unix,mcp}, pkg/api/unix,
  pkg/apimodule, internal/authzscan
- `cd sdk/go && go build ./...`
- `make lint`

## Results

- Proto regenerated with `make proto` (protoc 36.2, protoc-gen-go v1.36.12,
  protoc-gen-go-grpc v1.6.2).
- `go test -count=1 -race -tags "codec_cbor codec_json codec_msgpack"` on the
  packages above: pass.
- `cd sdk/go && go build ./...`: pass.
- `make lint`: pass (0 issues in every module and tag set).
- Left: the QUIC transport, sdk/go and compose wiring.

## Out of scope

QUIC transport, sdk/go and compose wiring.
