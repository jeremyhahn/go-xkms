# Sealing and Barrier — API

> **Status: NORMATIVE** · Feature: `sealing-and-barrier` · Repo: `go-xkms` · Last verified: 2026-10-13 (#1227, #1228, #1244, #1415)

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped".

Barrier routes are `RouteAuthPermission` under `/api/v1/barrier`, gated on the
`pkg/auth` `seal` and `barrier` resources — the most tightly permissioned group
in the repo, because these operations control whether any key in the system is
usable.

## The barrier verbs are go-qrdb's

xkms does not re-expose the barrier on any transport (no initialize, unseal,
seal, status, rekey, recovery, Shamir or enable-encryption route, RPC or MCP
method). The barrier is the embedded go-qrdb node's; operate it through
go-qrdb's own surface. xkms contributes the hardware and cloud seal strategies
the node's registry resolves (see [`engineering.md`](engineering.md)).

The node seal's pre-barrier secrets — the PKCS#11 token PIN
(`platform/pkcs11-pin`) and the Vault token (`platform/vault-token`) — have no
transport surface either. They are sealed by `xkmsd seal-pkcs11-pin` and
`xkmsd seal-vault-token` on the host, released only inside the booting
process, and never sent over the wire. The SDK surface is embedded only: `sdk/go` `OpenPreseal`, `PresealStore`, `PresealPKCS11PIN`,
`PresealNotFoundError`, `PresealRefusedError`,
`BuildPKCS11StrategyWithSealedPIN`, `PKCS11StrategyBuildError` and
`ErrPKCS11StrategyNotCompiledIn` (`sdk/go/preseal.go`).

## Data-level sealing

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded (`SealService.`) | Permission |
|---|---|---|---|---|---|---|
| Seal data | `POST /api/v1/seal` | `Seal` | same as REST | `xkms.seal` | `Seal` | `keys:encrypt` |
| Unseal data | `POST /api/v1/unseal` | `Unseal` | same as REST | `xkms.unseal` | `Unseal` | `keys:decrypt` |
| Seal capability | `GET /api/v1/seal/capability` | `CanSeal` | same as REST | `xkms.canSeal` | `CanSeal` | `keys:get` |

### Data-level sealing is tenant-scoped (go-xkms#1228)

Seal and Unseal are thin adapters over `XKMSService.Seal` and
`XKMSService.Unseal` on every transport: REST `SealHandler` / `UnsealHandler`
(`pkg/api/rest/handlers.go:1554-1645`), gRPC `Seal` / `Unseal`
(`pkg/api/grpc/service.go:1686-1768`) and MCP `handleSeal` / `handleUnseal`
(`pkg/api/mcp/handlers.go:1653-1725`). Each fills the request's `TenantID`
from the authenticated identity, and the service resolves the backend through
that tenant (`pkg/xkms/servicer_seal.go:157`, `:237`).

- **Named key.** `key_id` is parsed as a key reference and its key name is
  resolved among the caller's tenant's keys (`sealingKey`,
  `pkg/xkms/servicer_seal.go:131`). Another tenant's key, or the platform's,
  is `ErrKeyNotFound` — the same response a key nobody holds gets
  (`404` / `NotFound` / Not found). A `key_id` containing `/` is malformed.
- **Default sealing key.** Without `key_id`, a key-based backend (software,
  PKCS#11, the cloud KMSs) seals under the deterministic key
  `xkms-sealing-key-<backend-type>` (`defaultSealingKeyAttributes`,
  `pkg/xkms/servicer_seal.go:89`), generated on first use
  (`ensureSealingKey`, `:105`). The tenant view stamps the caller's tenant on
  the key's attributes (`TenantScopedBackend.Seal` / `Unseal`,
  `pkg/xkms/backend_tenant.go:243`, `:258`), so each tenant has its own
  default key, stored under its own identifier, and a blob sealed under one
  tenant's default key does not unseal for another tenant or for the
  platform. A platform-scoped caller uses the untenanted default key.
- **TPM 2.0.** TPM sealing needs no key: the blob is a keyed-hash object
  under the platform storage root and unseals for anyone who presents it. A
  tenant-scoped caller is therefore refused on a TPM 2.0 backend, with or
  without a `key_id` (`sealBound`, `pkg/xkms/backend_tenant.go:227`;
  `ErrBackendUnsupported` carrying `ErrSealingNotSupported` and
  `ErrSealNotTenantBound`, `pkg/xkms/errors.go:318`): `400` on REST,
  `Unimplemented` on gRPC, Method not found on MCP. Platform-scoped TPM
  sealing is unchanged.

Wire changes: REST, gRPC and MCP now seal and unseal without a `key_id` on a
key-based backend (they used to fail, because no transport generated the
default key); an unknown backend is `404` / `NotFound`; a `key_id` of another
tenant's key is `keystore: key not found` on every transport (MCP used to say
`key not found: <id>`); an unparseable `key_id` is `invalid key ID: ...`.
Verified by `pkg/api/rest/handlers_certseal_crosstenant_test.go`,
`pkg/api/grpc/service_certseal_crosstenant_test.go`,
`pkg/api/mcp/handlers_certseal_crosstenant_test.go`,
`pkg/xkms/servicer_certseal_tenant_test.go` and
`pkg/xkms/backend_tenant_seal_test.go`.

### Unseal failures that blame the sealed data

In process — the embedded transport, the Go SDK, and any caller holding a
`types.Sealer` — an unseal error matches `ErrSealedDataAuthentication`
(`types.` or the SDK's `xkms.`) when the sealed value itself was forged,
modified, truncated, produced under another key or backend, malformed, or
presented with different AAD, and never when the device, KMS, permissions,
context or TPM authorization failed. The native cause stays reachable with
`errors.As`. A match is conclusive; no match is not: a backend whose native
signal cannot tell bad data from a failing device (SoftHSM before 2.7.0)
reports that failure without the sentinel. See [`engineering.md`](engineering.md) §"Sealed-data
authentication" for each backend's mapping. On REST, gRPC and MCP the status
an unseal failure maps to is unchanged; the error text begins
`sealed data failed authentication` for this class.

## go-enclave provider (embedded only)

The go-enclave provider bridge (`pkg/enclaveprovider`, go-xkms#1415) has no
REST, gRPC, QUIC, MCP or USB surface: it hands a go-enclave `Sealer` its keys
inside the process that holds them, so there is nothing to send over a wire.
It is a Go library seam over an already-constructed `types.Sealer`:

| Capability | Go |
|---|---|
| Per-operation provider | `enclaveprovider.NewKeyProtector(sealer, attrs)` → `enclave.WithKeyProtector` |
| Provision a sealed root | `enclaveprovider.ProvisionRoot(ctx, sealer, attrs)` |
| Root-key provider | `enclaveprovider.NewRootUnsealer(sealer, attrs, sealedRoot)` → `enclave.WithRootUnsealer` |

Errors and the envelope format: [`engineering.md`](engineering.md)
§"go-enclave provider bridge".

## TPM policies

Named TPM policies that TPM2 keys and sealed objects are bound to
(`pkg/tpm2/policy`) replaced the PCR snapshot store (`pkg/seal/policy`,
`/api/v1/policies/*`, `Policy*`, `policy.*`), which bound nothing. The
surface, its tenancy and its error mapping are in
[`../tpm-policies/api.md`](../tpm-policies/api.md). A TPM2 seal names its
policy in `SealRequest.TPMPolicy` on every transport.

## Request and response schemas

Go types in `pkg/api/transport/types.go`; the barrier types are aliases of
go-qrdb's (`BarrierStatus`, `ShamirConfig`, `ShamirInitResult`,
`QuorumProgress`, `RecoveryKeyResult`, `RootToken`, `SealedRootKey`) — go-xkms
does not define its own barrier vocabulary.

**Shares and recovery keys appear in exactly one response each** — the
initialization or generation response — and are never retrievable afterwards.
There is no "list shares" operation and there will not be one.

## Status and error mapping

| Condition | REST | gRPC / Unix | MCP |
|---|---|---|---|
| success | 200 | `OK` | `result` |
| barrier sealed (reported by `status`) | 200 | `OK` | `result` |
| operation requires an unsealed barrier | 409 | `FailedPrecondition` | error object |
| already initialized | 409 | `AlreadyExists` | error object |
| wrong credential / insufficient shares | 401 | `Unauthenticated` | error object |
| strategy hardware or provider unreachable | 503 | `Unavailable` | error object |
| sealed-blob format version unknown | 500 | `Internal` | error object |
| RBAC denial | 403 | `PermissionDenied` | error object |
| no barrier composed on the service | 503 | `Unavailable` | `ErrCodeServiceUnavailable` |

## Pagination

Not applicable.

## Versioning and deprecation

gRPC package `xkmsv1`. Nothing deprecated.

The real versioning surface here is not the wire but the blob:
`sealedRootKeyVersion` in `pkg/seal/strategy.go` governs the `SealedRootKey`
format. A root key that cannot be unsealed is unrecoverable, so that constant
must be bumped on any layout change and old versions must stay readable.
