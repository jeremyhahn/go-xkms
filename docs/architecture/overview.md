# Architecture Overview

> **Status: REFERENCE** · Last verified: 2026-10-12
> High-level map of go-xkms layers; each feature folder under `docs/<feature>/` is normative for its own design.

## Layers

```
 clients     xkmsctl · REST · HTTP/3 · gRPC · MCP · Unix socket · in-process SDK
                                   │
 transport   pkg/api/{rest,grpc,unix,mcp}  →  transport.XKMSServicer
                                   │
 service     pkg/xkms  XKMSService (servicer_*.go, one file per capability)
                                   │
 backends    pkg/backend/*  (xkms.Backend)    pkg/keyprovider/*  (types.KeyProvider)
                                   │
 storage     pkg/storage  (storage.Backend over the embedded qrdb datastore)
```

- Every transport converts its wire format and calls the one
  `transport.XKMSServicer` interface (`pkg/api/transport/servicer.go:36`).
- `XKMSService` (`pkg/xkms/service.go:68`) implements it. Each capability
  lives in its own `servicer_<capability>.go` file in `pkg/xkms`.
- Subsystems that are built after the service are injected with setters, for
  example `SetPINManager` (`service.go:259`) and `SetCA` (`service.go:371`).
  A subsystem that was never set returns `ErrNotConfigured`
  (`pkg/xkms/errors.go:337`).
- `sdk.NewEmbedded(service)` (`sdk/go/xkms.go:250`) runs the SDK in-process
  against the same servicer, with no network hop.

Barrier, bootstrap and the user model are consumed from go-qrdb; see
[sealing-and-barrier](../sealing-and-barrier/engineering.md) and
[datastore](../datastore/engineering.md).

## Backends and key providers

A **backend** implements the full `xkms.Backend` contract
(`pkg/xkms/keystore.go:39`). A **key provider** implements the narrower
`types.KeyProvider` (`pkg/types/types.go:1826`) and is composed into a backend.

Backends are registered in `pkg/xkms/registry.go` (`RegisterBackend`,
line 132; `RegisterBackendFactory`, line 198), with `register_<name>.go` files beside it; the cloud, Vault and PKCS#11
registrations carry the build tags below. The phone backend is not in the
registry.

| Backend | Package | Build tag | `SecurityLevel` |
|---|---|---|---|
| Software | `pkg/backend/software` | none | Low (`software.go:223`) |
| TPM 2.0 | `pkg/backend/tpm2` | none | VeryHigh (`backend.go:270`) |
| PKCS#11 | `pkg/backend/pkcs11` | `pkcs11` | High (`pkcs11.go:213`) |
| AWS KMS | `pkg/backend/awskms` | `awskms` | Medium (`awskms.go:581`) |
| GCP KMS | `pkg/backend/gcpkms` | `gcpkms` | Medium (`gcpkms.go:255`) |
| Azure Key Vault | `pkg/backend/azurekv` | `azurekv` | Medium (`azurekv.go:330`) |
| HashiCorp Vault | `pkg/backend/vault` | `vault` | Medium (`vault.go:175`) |
| Phone | `pkg/backend/phone` | none | High (`backend.go:204`) |

`SecurityLevel` runs from 0 (Low) to 3 (VeryHigh) (`pkg/types/types.go:1583-1603`)
and is read with `Capabilities.GetSecurityLevel()` (`types.go:1760`).

Key providers live in `pkg/keyprovider`: `pkcs8`, `symmetric`, `quantum` and
`frost`.

See [crypto-backends](../crypto-backends/engineering.md) for per-backend
detail.

## Build toggles

Every optional feature is compiled in by default. Pass `WITH_<X>=0` to drop
it (Makefile lines 16-48): `WITH_PKCS8`, `WITH_TPM2`, `WITH_AWS_KMS`,
`WITH_GCP_KMS`, `WITH_AZURE_KV`, `WITH_VAULT`, `WITH_PKCS11`, `WITH_FROST`,
and the object-storage toggles `WITH_AWS_S3`, `WITH_MINIO`,
`WITH_GCP_STORAGE`, `WITH_AZURE_BLOB`, `WITH_GLACIER`, `WITH_AZURE_ARCHIVE`.
The umbrellas `WITH_AWS`, `WITH_GCP` and `WITH_AZURE` set a provider's KMS and
storage toggles together. A binary built without a feature fails closed when
the configuration names it. See
[crypto-backends → Build toggles](../crypto-backends/engineering.md#build-toggles).

## Testing

- Unit tests: `make test`, or `make test-<pkg>` for one package.
- Integration tests run in the devcontainer: `make integration-test`, or
  per area, for example `integration-test-software`, `integration-test-pkcs11`,
  `integration-test-tpm2`, `integration-test-awskms`, `integration-test-gcpkms`,
  `integration-test-azurekv`, `integration-test-vault`.
- Suites live under `test/integration/<area>/`.

## See also

- [Architecture index](./README.md)
- [Datastore](../datastore/engineering.md)
- [PKCS#11 manager](../pkcs11-provider-module/engineering.md#pkgpkcs11manager)
- [Getting started](../../xkey/docs/usage/getting-started.md)
