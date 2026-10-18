# Platform Secrets — API

> **Status: NORMATIVE** · Feature: `platform-secrets` · Repo: `go-xkms` · Last verified: 2026-10-11 (#1465)

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped".

REST routes live under `/api/v1/platform` (`pkg/api/rest/routes.go`), carry
the `keys:*` pairs, and are mounted whenever an `XKMSService` is composed
(`pkg/api/rest/server.go`, the `platformHandlers` wiring).

## Capability matrix

| Capability | REST | gRPC / Unix (`KeystoreService.`) | QUIC | MCP | Embedded (`SealStoreServicer.`) |
|---|---|---|---|---|---|
| Put secret | `PUT /api/v1/platform/secrets/{name}` | `SealStorePut` | same as REST | `sealStore.put` | `SealStorePut` |
| Get secret | `GET /api/v1/platform/secrets/{name}` | `SealStoreGet` | same as REST | `sealStore.get` | `SealStoreGet` |
| Delete secret | `DELETE /api/v1/platform/secrets/{name}` | `SealStoreDelete` | same as REST | `sealStore.delete` | `SealStoreDelete` |
| List secret names | `GET /api/v1/platform/secrets` | `SealStoreList` | same as REST | `sealStore.list` | `SealStoreList` |
| Reseal a secret | `POST /api/v1/platform/secrets/{name}/reseal` | `SealStoreReseal` | same as REST | `sealStore.reseal` | `SealStoreReseal` |
| Store status | `GET /api/v1/platform/status` | `SealStoreStatus` | same as REST | `sealStore.status` | `SealStoreStatus` |

Every transport reaches the store only through the `XKMSService` methods
(`pkg/xkms/servicer_seal_store.go`): REST `pkg/api/rest/seal_store_handlers.go`,
gRPC/Unix `pkg/api/grpc/service_seal_store.go`, MCP
`pkg/api/mcp/handlers_seal_store.go`. The USB transport (a seventh,
product-specific transport) proxies the same six methods to the phone's
embedded xkmsd (`pkg/api/transport/usb/transport.go`).

## Platform scope

The store holds platform-global secrets -- the backend credentials live under
`credentials/<name>` (`pkg/server/credentials/service.go`) -- so every
operation is refused to a tenant-scoped caller, including a tenant-local
Admin whose `keys:*` grants pass the RBAC gate (go-xkms#1226). Each service
method checks `qrdbsdk.IdentityIsSystemTenant` before touching the store
(`pkg/xkms/servicer_seal_store.go:50,68,93,112,130,149`). The refusal reads
exactly as a missing tenant:

| Transport | Answer | Mapping site |
|---|---|---|
| REST | `404`, `{"error":"<unknown-tenant message>"}` | `pkg/api/rest/seal_store_handlers.go:268` |
| gRPC / Unix | `codes.NotFound` | `pkg/api/apierrors/tables.go:50` |
| MCP | `JSONRPCCodeNotFound` | `pkg/api/apierrors/tables.go:50` |

Only a platform (system-tenant) identity, or an in-process caller with no
identity, reaches the store.

## The backend-credential namespace

The `credentials/` namespace is not part of platform secrets (go-xkms#1465).
A backend credential's value is write-only: only the credentials service
reads it, in process. So Put, Get, Delete and Reseal refuse a name inside the
namespace with `xkms.ErrReservedSecretName`, before the store is touched, and
List and Status leave those names out
(`pkg/xkms/servicer_seal_store.go:56,74,99,120,136,156`). The name is cleaned
first, so `x/../credentials/db` is refused too
(`credentials.InNamespace`, `pkg/server/credentials/service.go`).

| Transport | Answer | Mapping site |
|---|---|---|
| REST | `403`, `{"error":"Secret name is reserved for backend credentials"}` | `pkg/api/rest/seal_store_handlers.go:261` |
| gRPC / Unix | `codes.PermissionDenied` | `pkg/api/apierrors/tables.go:45` |
| MCP | `ErrCodeForbidden` | `pkg/api/apierrors/tables.go:45` |

Embedded and USB return the service's error as is. Credential names are
listed through the credential API (`xkmsctl credential list`), never here.

## Request and response schemas

`pkg/api/transport/types.go`: `SealStorePutRequest`, `SealStoreGetRequest`,
`SealStoreGetResponse`, `SealStoreDeleteRequest`, `SealStoreListResponse`,
`SealStoreResealRequest`, `SealStoreStatusResponse`.

Values are opaque bytes. `SealStoreListResponse` carries **names only** —
listing never returns values, and names are not treated as secret.

Note the shape difference between the layers: the Go `PlatformStore` interface
has `Exists(ctx, name)`, the transport has `SealStoreStatus(ctx)`. They answer
different questions — per-name presence versus store state — and are not
substitutes.

## Status and error mapping

| Condition | REST |
|---|---|
| success | 200 |
| secret stored / resealed | 200 |
| `ErrSecretNotFound` | 404 |
| sealed value cannot be opened in the current platform state | **409** |
| `ErrResealFailed` | 500 |
| tenant-scoped caller (platform scope) | 404 with the unknown-tenant message |
| no platform store composed on the service | 503 |
| no `XKMSService` composed | route absent (404) |

The 404-versus-409 distinction is the important one. A TPM-sealed secret that
will not open because the PCRs changed is **not** a missing secret, and a client
that collapses the two will report a state change as a configuration error.

## Sealing is the backend's, not the route's

These routes call `PlatformStore`, which delegates to its `storage.Backend`. On
a `sealed.Backend` values are protected by the barrier's strategy; on a plain
file or memory backend they are stored as-is. **The API surface is identical
either way**, so no response tells a client whether the deployment it is talking
to actually seals anything. That is a server configuration fact, not an API one.

## Pagination

`SealStoreList` returns all names. The platform secret set is small by
construction — this is not a general secret manager.

## Versioning and deprecation

`/api/v1/platform/*`. Nothing deprecated. There is no gRPC surface to version.

`Put` over an existing name overwrites with a fresh seal; there is no version
history and no API to retrieve a previous value.
