# Signing — API

> **Status: NORMATIVE** · Feature: `signing` · Repo: `go-xkms` · Last verified: 2026-10-09

## Embedded Go SDK

The only transport this feature has. Import `github.com/jeremyhahn/go-xkms/pkg/xkms`
directly (in-process; see [`user.md`](user.md) for a full example):

```go
func Sign(ctx context.Context, kid string, data []byte, opts *SignOptions) ([]byte, error)
func Verify(ctx context.Context, kid string, data, signature []byte, opts *types.VerifyOpts) error
```

`SignOptions.BlobCN` and `types.VerifyOpts.{BlobCN,IntegrityCheck}` are Go
struct fields, not wire fields — there is no serialization format for them to
document.

## REST / gRPC / QUIC / Unix / MCP

Not reachable. `CryptoService.Sign`/`Verify` (`transport.SignRequest` /
`VerifyRequest`, implemented by `(*XKMSService).Sign`/`Verify` in
`pkg/xkms/servicer_crypto.go`) is the network-facing signing API and predates
this feature; it does not carry `BlobCN` or `IntegrityCheck` today and this
change does not add them there. See
[`key-management/api.md`](../key-management/api.md) for that surface.

Extending `SignRequest`/`VerifyRequest` with the wire fields to reach this
feature over the network is future work, tracked as a gap rather than
implemented speculatively here (YAGNI): no caller of the network transports
has asked for it yet, and adding wire fields nothing reads is exactly the
half-built-stub shape this project's conventions forbid.
