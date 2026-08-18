# Sealing and Barrier — API

> **Status: NORMATIVE** · Feature: `sealing-and-barrier` · Repo: `go-xkms` · Last verified: 2026-08-19

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped".

Barrier routes are `RouteAuthPermission` under `/api/v1/barrier`, gated on the
`pkg/auth` `seal` and `barrier` resources — the most tightly permissioned group
in the repo, because these operations control whether any key in the system is
usable.

## Barrier capability matrix

| Capability | REST | gRPC / Unix (`KeystoreService.`) | QUIC | MCP | Embedded (`BarrierService.`) | Permission |
|---|---|---|---|---|---|---|
| Initialize | `POST /api/v1/barrier/initialize` | `BarrierInitialize` | same as REST | `barrier.initialize` | `BarrierInitialize` | `seal:bootstrap` |
| Unseal | `POST /api/v1/barrier/unseal` | `BarrierUnseal` | same as REST | `barrier.unseal` | `BarrierUnseal` | `seal:unseal` |
| Seal | `POST /api/v1/barrier/seal` | `BarrierSeal` | same as REST | `barrier.seal` | `BarrierSeal` | `seal:seal` |
| Status | `GET /api/v1/barrier/status` | `BarrierStatus` | same as REST | `barrier.status` | `BarrierStatus` | `seal:status` |
| Initialize Shamir | `POST /api/v1/barrier/shamir/initialize` | `BarrierInitializeShamir` | same as REST | `barrier.initializeShamir` | `BarrierInitializeShamir` | `seal:initialize-shamir` |
| Unseal with one share | `POST /api/v1/barrier/shamir/unseal-share` | `BarrierUnsealShare` | same as REST | `barrier.unsealShare` | `BarrierUnsealWithShare` | `barrier:unseal-share` |
| Unseal with shares | `POST /api/v1/barrier/shamir/unseal-shares` | `BarrierUnsealShares` | same as REST | `barrier.unsealShares` | `BarrierUnsealWithShares` | `seal:unseal` |
| Rekey | `POST /api/v1/barrier/rekey` | `BarrierRekey` | same as REST | `barrier.rekey` | `BarrierRekey` | `seal:rekey` |
| Generate recovery keys | `POST /api/v1/barrier/recovery/generate` | `BarrierGenerateRecoveryKeys` | same as REST | `barrier.generateRecoveryKeys` | `BarrierGenerateRecoveryKeys` | `seal:generate-recovery` |
| Recover with keys | `POST /api/v1/barrier/recovery/recover` | `BarrierRecoverWithKeys` | same as REST | `barrier.recoverWithKeys` | `BarrierRecoverWithKeys` | `seal:recover-with-keys` |
| Delete recovery keys | `DELETE /api/v1/barrier/recovery/keys` | `BarrierDeleteRecoveryKeys` | same as REST | `barrier.deleteRecoveryKeys` | `BarrierDeleteRecoveryKeys` | `seal:generate-recovery` |
| Has recovery keys | **MISSING — docs/13** | `BarrierHasRecoveryKeys` | **MISSING — docs/13** | `barrier.hasRecoveryKeys` | `BarrierHasRecoveryKeys` | — |
| Generate root token | `POST /api/v1/barrier/recovery/root-token` | `BarrierGenerateRootToken` | same as REST | `barrier.generateRootToken` | `BarrierGenerateRootToken` | `seal:rotate-root-key` |
| Enable encryption | `POST /api/v1/barrier/enable-encryption` | `BarrierEnableEncryption` | same as REST | `barrier.enableEncryption` | `BarrierEnableEncryption` | `seal:enable-encryption` |

**The barrier is the best-covered feature on MCP** — fourteen methods, the full
set. Contrast PIN (zero) and WebAuthn (zero).

The one gap is `BarrierHasRecoveryKeys`, which has a gRPC RPC and an MCP method
but no REST route. That is an inconsistency rather than a design decision:
`DELETE /api/v1/barrier/recovery/keys` exists, so a REST caller can destroy
recovery keys but cannot ask whether any exist.

## Data-level sealing

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded (`SealService.`) | Permission |
|---|---|---|---|---|---|---|
| Seal data | `POST /api/v1/seal` | `Seal` | same as REST | `xkms.seal` | `Seal` | `keys:encrypt` |
| Unseal data | `POST /api/v1/unseal` | `Unseal` | same as REST | `xkms.unseal` | `Unseal` | `keys:decrypt` |
| Seal capability | `GET /api/v1/seal/capability` | `CanSeal` | same as REST | `xkms.canSeal` | `CanSeal` | `keys:get` |

## Tenant barriers

Per-tenant barrier operations live under the tenant routes and are documented in
[`../multi-tenancy/api.md`](../multi-tenancy/api.md): `TenantBarrierInit`,
`TenantBarrierUnseal`, `TenantBarrierStatus`.

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

`GET /api/v1/barrier/status` returning "sealed" is **200, not an error**. A
client that treats a sealed barrier as a transport failure will retry forever.

## Pagination

Not applicable.

## Versioning and deprecation

`/api/v1/barrier/*`, gRPC package `xkmsv1`. Nothing deprecated.

The real versioning surface here is not the wire but the blob:
`sealedRootKeyVersion` in `pkg/seal/strategy.go` governs the `SealedRootKey`
format. A root key that cannot be unsealed is unrecoverable, so that constant
must be bumped on any layout change and old versions must stay readable.
