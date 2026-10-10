# Signing — CLI

> **Status: NORMATIVE** · Feature: `signing` · Repo: `go-xkms` · Last verified: 2026-10-09

No CLI surface: `SignOptions.BlobCN` and `VerifyOpts.IntegrityCheck` are
reachable only through the embedded Go SDK's package-level `xkms.Sign` /
`xkms.Verify` (`pkg/xkms/service.go`). `xkmsctl` has no `sign`/`verify` verb
today, and `CryptoService.Sign`/`Verify` (the network-transport RPCs `xkmsctl`
would eventually front) do not carry `BlobCN`/`IntegrityCheck` — see
[`key-management/cli.md`](../key-management/cli.md) for the CLI surface that
exists.
