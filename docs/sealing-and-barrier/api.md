# Sealing and Barrier — API

> **Status: NORMATIVE** · Feature: `sealing-and-barrier` · Repo: `go-xkms` · Last verified: 2026-09-28 (#1227, #1228, #1244)

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

### The system barrier is platform-scoped

Every row above except enable-encryption operates the **system** barrier,
which protects every tenant. Each is refused to a tenant-scoped caller -- a
tenant-local Admin whose self-scoped `seal:*` / `barrier:*` grants pass the
RBAC gate included -- with the answer a missing tenant gets (go-xkms#1227):

| Transport | Answer | Mapping site |
|---|---|---|
| REST / QUIC | `404`, the unknown-tenant message | `pkg/api/rest/handlers_barrier_pin.go:504` |
| gRPC / Unix | `codes.NotFound` | `pkg/api/apierrors/tables.go:147` |
| MCP | `JSONRPCCodeNotFound` | `pkg/api/apierrors/tables.go:147` |
| ACME admin plane (`/admin/barrier/*`) | `403`, the admin gate's own denial body (the admin plane's platform-only convention) | `pkg/acme/admin/barrier_handlers.go:279` |

The refusal is raised in `XKMSService` (`pkg/xkms/servicer_barrier.go:89,117,
128,139,170,205,236,253,278,300,314,325,342`), and every transport reaches
the barrier only through it: REST `pkg/api/rest/handlers_barrier_pin.go`,
`handlers_barrier_shamir.go`; gRPC/Unix `pkg/api/grpc/service_barrier_pin.go`,
`service_barrier_shamir.go`; MCP `pkg/api/mcp/handlers_barrier_shamir.go`;
the ACME admin plane's `/admin/barrier/*` routes through `SystemBarrier`
(`pkg/acme/admin/barrier_service.go:199`), which xkmsd satisfies with the
server's `XKMSService` (`cmd/xkmsd/admin.go:186-194`, go-xkms#1244). The
admin plane translates the refusal into its `*PlatformScopeError`
(`pkg/acme/admin/barrier_service.go:245`) and answers it `403`, as it
answers its other platform-only routes (tenant creation, the audit trail);
see [`../acme-issuance/api.md`](../acme-issuance/api.md#admin-api-tenant-binding-responses).
Before this change gRPC and MCP held their own barrier reference that
production never set, so their barrier methods answered "not configured";
they now serve the service's barrier. A service with no barrier composed
answers `503` / `Unavailable` / `ErrCodeServiceUnavailable`.

**Enable encryption keeps its tenant binding** (`pkg/xkms/servicer_barrier.go:384`):
a tenant may migrate its own barrier; naming another tenant or the system
barrier (empty `tenant_id`) is refused as not-found. The per-tenant barrier
operations (`TenantBarrier*`, below) keep theirs.

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

## PCR policy management

TPM 2.0 PCR-bank sealed-secret authorization policies (`pkg/seal/policy`),
wired onto every network transport by go-xkms#691. All seven RPCs gate on
the `policy:*` permission family (`pkg/auth.ResourcePolicy`) — a resource
name go-qrdb's canonical registry does not declare, so xkms mints and
scopes it itself the way it already does for `bootstrap:read`
(`pkg/apimodule/module_scopes.go`).

| Capability | REST | gRPC / Unix (`KeystoreService.`) | QUIC | MCP | Embedded (`PolicyServicer.`) | Permission |
|---|---|---|---|---|---|---|
| Create | `POST /api/v1/policies/` | `PolicyCreate` | same as REST | `policy.create` | `PolicyCreate` | `policy:create` |
| Get | `GET /api/v1/policies/{name}` | `PolicyGet` | same as REST | `policy.get` | `PolicyGet` | `policy:get` |
| List | `GET /api/v1/policies/` | `PolicyList` | same as REST | `policy.list` | `PolicyList` | `policy:list` |
| Delete | `DELETE /api/v1/policies/{name}` | `PolicyDelete` | same as REST | `policy.delete` | `PolicyDelete` | `policy:delete` |
| Refresh | `POST /api/v1/policies/{name}/refresh` | `PolicyRefresh` | same as REST | `policy.refresh` | `PolicyRefresh` | `policy:refresh` |
| Verify | `POST /api/v1/policies/{name}/verify` | `PolicyVerify` | same as REST | `policy.verify` | `PolicyVerify` | `policy:verify` |
| Export | `GET /api/v1/policies/{name}/export` | `PolicyExport` | same as REST | `policy.export` | `PolicyExport` | `policy:export` |

**Not served over USB.** The USB transport's counterparty is the xkey
Android companion app — a Noise-encrypted JSON-RPC peer, not xkmsd, and one
with no TPM to read PCRs from — so the entire Password/SealStore/Escrow/
Policy administrative surface is out of scope there structurally, not by
omission.

**Escrow is a separate, open question.** `pkg/escrow`'s four operations
(`EscrowKey`, `RecoverKey`, `ListEscrowed`, `RevokeEscrow`) remain stubbed
`ErrNotSupported` on every transport pending go-xkms#692; they are unrelated
to policy management beyond sharing a file section header in the transport
source.

`pkg/api/rest/policy_handlers.go` predates the convention every other REST
handler group in this file follows (wiring `pkg/api/transport` request/
response types straight onto the HTTP body): its JSON field names
(`pcr_indices`, `pcr_values` as raw bytes) and its own local response types
diverge from `transport.Policy*` (`pcrs`, `values` as a hex-encoded map).
The REST and QUIC client transports translate between the two;
`pkg/api/rest/wire`'s PCR Policy types document the mapping in full so it
lives in exactly one place. The REST handlers now call the service and
decode its hex values back into that wire shape (`pcrValuesFromHex`,
`pkg/api/rest/policy_handlers.go`).

**PCR policies are platform-scoped** (go-xkms#1227). They bind the platform's
sealed secrets to its measured boot state, so every `Policy*` service method
refuses a tenant-scoped caller before the policy manager is touched
(`pkg/xkms/servicer_policy.go:42,66,84,106,120,138,160`); the REST handlers
hold only the service (`pkg/api/rest/policy_handlers.go`). The refusal is
REST `404` with the unknown-tenant message (`pkg/api/rest/policy_handlers.go:367`),
gRPC `NotFound` and MCP `JSONRPCCodeNotFound` (`pkg/api/apierrors/tables.go:192`).

The policy manager exists only where a PCR reader is supplied: an embedding
host passes one with `WithServiceModulePCRReader`
([`../host-embedding/`](../host-embedding/)); `xkmsd` uses its configured TPM
(`backends.tpm2.enabled`) through `tpm2.BankPCRReader`
(`pkg/tpm2/pcr_reader.go`, wired in `pkg/server/backend_tpm2.go`). Without a
TPM, `xkmsd` logs `xkms feature off feature=policies` with the
`compose.FeatureDisabledError` reason and the policy routes answer "not
configured". Definitions persist durably through
`policy.BackendPolicyStore` (`pkg/seal/policy/backend_store.go`).

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
| tenant-scoped caller (platform scope) | 404 (403 on the ACME admin plane's `/admin/barrier/*`) | `NotFound` | `JSONRPCCodeNotFound` |
| no barrier composed on the service | 503 | `Unavailable` | `ErrCodeServiceUnavailable` |

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
