# Platform Secrets — API

> **Status: NORMATIVE** · Feature: `platform-secrets` · Repo: `go-xkms` · Last verified: 2026-09-23

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped".

Routes are `RouteAuthSession` under `/api/v1/platform`, registered on the
`hasPlatform` predicate.

## Capability matrix

| Capability | REST | gRPC / Unix (`KeystoreService.`) | QUIC | MCP | Embedded (`SealStoreService.`) |
|---|---|---|---|---|---|
| Put secret | `PUT /api/v1/platform/secrets/{name}` | **MISSING — docs/13** | same as REST | **MISSING — docs/13** | `SealStorePut` |
| Get secret | `GET /api/v1/platform/secrets/{name}` | **MISSING — docs/13** | same as REST | **MISSING — docs/13** | `SealStoreGet` |
| Delete secret | `DELETE /api/v1/platform/secrets/{name}` | **MISSING — docs/13** | same as REST | **MISSING — docs/13** | `SealStoreDelete` |
| List secret names | `GET /api/v1/platform/secrets` | **MISSING — docs/13** | same as REST | **MISSING — docs/13** | `SealStoreList` |
| Reseal a secret | `POST /api/v1/platform/secrets/{name}/reseal` | **MISSING — docs/13** | same as REST | **MISSING — docs/13** | `SealStoreReseal` |
| Store status | `GET /api/v1/platform/status` | **MISSING — docs/13** | same as REST | **MISSING — docs/13** | `SealStoreStatus` |

**This feature exists on REST, QUIC and embedded only.** Twelve gaps across gRPC,
Unix and MCP — proportionally the weakest transport coverage of any feature in
this repo. There is no `SealStore*` RPC in `xkmsv1` and no `platform.*` MCP
method. The USB transport (a seventh, product-specific transport, not part of
the six above) is the exception: it proxies all six `SealStoreService` methods
to the phone's embedded xkmsd instance over the Noise-encrypted USB channel
(`pkg/api/transport/usb/transport.go`), using the servicer's own method names
verbatim (`SealStorePut`, `SealStoreGet`, ...).

Recorded as gaps rather than presented as a design choice, because nothing in
the code argues for the omission — unlike, say, the absence of a Unix-socket
ACME adapter, which has a reason.

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
| platform store not configured | route absent (404) |

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
