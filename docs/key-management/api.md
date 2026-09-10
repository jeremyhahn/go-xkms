# Key Management — API

> **Status: NORMATIVE** · Feature: `key-management` · Repo: `go-xkms` · Last verified: 2026-09-10

## How the six transports are shaped

Read this once; every feature folder's `api.md` uses the same convention.

| Transport | Wire form | Where it is served | Client |
|---|---|---|---|
| **embedded** | direct Go call, no wire | `pkg/xkms.XKMSService` | `sdk/go`, `transport.Client` |
| **unix** | gRPC `xkmsv1.KeystoreService` over a Unix domain socket | `pkg/api/unix/grpc_server.go` | `pkg/api/transport/unix` |
| **rest** | HTTP/1.1+HTTP/2 JSON, route table in `pkg/api/rest/routes.go` | `pkg/api/rest` | `pkg/api/transport/rest` |
| **grpc** | gRPC `xkmsv1.KeystoreService` over TCP | `pkg/api/grpc` | `pkg/api/transport/grpc` |
| **quic** | **HTTP/3 over the same REST paths** | the REST handler set | `pkg/api/transport/quic` |
| **mcp** | JSON-RPC 2.0, dotted method names | `pkg/api/mcp` | `pkg/api/transport/mcp` |

A seventh, product-specific transport — **usb** (`pkg/api/transport/usb`) — carries
the phone/CTAP path. It is a Noise-XX-encrypted JSON-RPC channel over USB AOA
and deliberately implements only `Connect`/`Close`/`Healthy`/`Request`; every
service method on it returns `ErrNotSupported` and `RequestStream` returns
`ErrStreamNotSupported`. The "all six transports" completeness rule does not
apply to it.

gRPC, QUIC, Unix and MCP each assert conformance to the full client contract at
compile time (`var _ transport.Client = (*Transport)(nil)`).

REST authorization is data: every route carries a `RouteSpec` with a
`RouteAuth` classification (`RouteAuthPublic`, `RouteAuthSession`,
`RouteAuthPermission`) and, for permission routes, a `Resource:Action` pair
from the `pkg/auth` vocabulary. The same table drives the legacy in-process
server and the unified-API-server `ServiceModule` in `pkg/apimodule`, so a
route exists on both paths with the same permission by construction.

## Capability matrix

| Capability | REST | gRPC / Unix (`KeystoreService.`) | QUIC (HTTP/3) | MCP | Embedded | Permission |
|---|---|---|---|---|---|---|
| List backends | `GET /api/v1/backends` | `ListBackends` | same as REST | `xkms.listBackends` | `ListBackends` | `backends:list` |
| Get backend | `GET /api/v1/backends/{id}` | `GetBackendInfo` | same as REST | `xkms.getBackend` | `GetBackend` | `backends:read` |
| Algorithms | `GET /api/v1/algorithms` | `Algorithms` | same as REST | `xkms.algorithms` | `Algorithms` | public |
| Generate key | `POST /api/v1/keys` | `GenerateKey` | same as REST | `xkms.generateKey` | `GenerateKey` | `keys:create` |
| List keys | `GET /api/v1/keys` | `ListKeys` | same as REST | `xkms.listKeys` | `ListKeys` | `keys:list` |
| Get key | `GET /api/v1/keys/{id}` | `GetKey` | same as REST | `xkms.getKey` | `GetKey` | `keys:get` |
| Delete key | `DELETE /api/v1/keys/{id}` | `DeleteKey` | same as REST | `xkms.deleteKey` | `DeleteKey` | `keys:delete` |
| Sign | `POST /api/v1/keys/{id}/sign` | `Sign` | same as REST | `xkms.sign` | `Sign` | `keys:sign` |
| Verify | `POST /api/v1/keys/{id}/verify` | `Verify` | same as REST | `xkms.verify` | `Verify` | `keys:verify` |
| Rotate | `POST /api/v1/keys/{id}/rotate` | `RotateKey` | same as REST | `xkms.rotateKey` | `RotateKey` | `keys:rotate` |
| Encrypt (AEAD) | `POST /api/v1/keys/{id}/encrypt` | `Encrypt` | same as REST | `xkms.encrypt` | `Encrypt` | `keys:encrypt` |
| Decrypt (AEAD) | `POST /api/v1/keys/{id}/decrypt` | `Decrypt` | same as REST | `xkms.decrypt` | `Decrypt` | `keys:decrypt` |
| Encrypt asym (OAEP) | `POST /api/v1/keys/{id}/encrypt-asym` | `EncryptAsym` | same as REST | `xkms.asymmetricEncrypt` | `EncryptAsym` | `keys:encrypt` |
| Decrypt asym (OAEP) | via `POST /api/v1/keys/{id}/decrypt` | `Decrypt` | same as REST | `xkms.asymmetricDecrypt` | `Decrypt` | `keys:decrypt` |
| Import params | `POST /api/v1/keys/import-params` | `GetImportParameters` | same as REST | `xkms.getImportParameters` | `GetImportParameters` | `keys:import` |
| Import key | `POST /api/v1/keys/import` | `ImportKey` | same as REST | `xkms.importKey` | `ImportKey` | `keys:import` |
| Export key | `POST /api/v1/keys/{id}/export` | `ExportKey` | same as REST | `xkms.exportKey` | `ExportKey` | `keys:export` |
| Export raw material | `POST /api/v1/keys/{id}/export-material` | `ExportKeyMaterial` | same as REST | `xkms.exportKeyMaterial` | `ExportKeyMaterial` | `keys:export` |
| Copy key | `POST /api/v1/keys/copy` | `CopyKey` | same as REST | `xkms.copyKey` | `CopyKey` | `keys:create` |
| Wrap (material in) | `POST /api/v1/keys/wrap` | `WrapKey` | same as REST | `xkms.wrapKey` | `WrapKey` | `keys:encrypt` |
| Unwrap (material in) | `POST /api/v1/keys/unwrap` | `UnwrapKey` | same as REST | `xkms.unwrapKey` | `UnwrapKey` | `keys:decrypt` |
| Wrap by ID | `POST /api/v1/keys/wrap-by-id` | `WrapKeyByID` | same as REST | `xkms.wrapKeyByID` | `WrapKeyByID` | route-level session |
| Unwrap by ID | `POST /api/v1/keys/unwrap-by-id` | `UnwrapKeyByID` | same as REST | `xkms.unwrapKeyByID` | `UnwrapKeyByID` | route-level session |
| Derive (ECDH) | `POST /api/v1/keys/derive-ecdh` | `DeriveKeyECDH` | same as REST | `xkms.deriveKeyECDH` | `DeriveKeyECDH` | route-level session |
| Derive (KDF) | **MISSING — docs/13** | `DeriveKey` | **MISSING — docs/13** | **MISSING — docs/13** | `DeriveKey` | — |
| Derive ECDH (secure) | **MISSING — docs/13** | `DeriveKeyECDHSecure` | **MISSING — docs/13** | **MISSING — docs/13** | — | — |
| Attest key | `POST /api/v1/attest` | `AttestKey` | same as REST | `xkms.attestKey` | `AttestKey` | `keys:get` |
| Health | `GET /health`, `/health/live`, `/health/ready`, `/health/startup` | `Health` | same as REST | `xkms.health` | `Health` | public |
| Capabilities | `GET /api/v1/capabilities` | **MISSING — docs/13** | same as REST | **MISSING — docs/13** | — | public |

### MCP names some import/export fields differently from the request struct

The MCP params structs and the `transport.*Request` structs are two views of
the same call, and three fields are spelled differently on purpose. The MCP
vocabulary is the one every params struct on that transport shares.

| Call | `transport.*Request` | MCP params | Note |
|---|---|---|---|
| Import | `wrapped_key_material` (bytes) | `wrapped_key` (bytes) | name only |
| Unwrap | `wrapped_key_material` (bytes) | `wrapped_key` (bytes) | name only |
| Wrap | `wrapping_public_key` (**DER** bytes) | `wrapping_public_key_pem` (**PEM** text) | name *and* encoding |
| Unwrap | `wrapping_public_key` (**DER** bytes) | `wrapping_public_key` (**PEM** text) | encoding only |

`pkg/api/transport/mcp` builds each params struct by name and PEM-encodes the
wrapping key on the way out, so the two sides are linked at compile time. Before
#159 and #255 it marshalled the request struct directly, and every import,
wrap and unwrap over that transport arrived unusable — the material or the
wrapping key simply absent.

Watch the encoding, not just the name: a DER `[]byte` assigned into the PEM
`string` field marshals as base64, which is non-empty and looks correct right up
until the handler calls `pem.Decode` and gets `nil`.

`backend` and `key_spec` reach the MCP wrap and unwrap params as of #255; before
that both ran against the process-default keystore whatever the caller named.
`tenant_id` is **not** an MCP field on any of these calls — the tenant comes
from the authenticated identity, and supplying one on the wire is an error.

Still outstanding: `CopyKeyParams` carries `hash` and `aes_key_size` that
`transport.CopyKeyRequest` cannot express, so no caller of this transport can
set them (#155).

### Import names the key's algorithm, on every transport

`ImportKey` takes the algorithm of the key being imported in a `key_type` field
— `"rsa"`, `"ecdsa"`, `"ed25519"`, `"symmetric"`/`"aes"` — with `key_size` and
`curve` as its parameters. It is **required**: the algorithm cannot be recovered
from wrapped material at the service layer, and guessing one stores the key
under an identifier that does not describe it.

Do not confuse it with `algorithm`, which on every import request names the
**wrapping** algorithm the material arrived under.

| Transport | field |
|---|---|
| REST | `key_type` in `ImportKeyRequest`, with `key_size`, `curve`, `hash`, `aes_key_size` |
| gRPC | `key_type` in `ImportKeyRequest`, with `key_size`, `curve` |
| MCP | `key_type` in `xkms.importKey` params, with `key_size`, `curve`, `hash`, `aes_key_size`, `partition` |

The MCP tool carried no such field until go-xkms#53: it built attributes from
the key ID alone, so the key was stored describing no algorithm and the
backend's check of material against its declared type had nothing to check
against.

`hash`, `aes_key_size` and `partition` reached the MCP params only in
go-xkms#159; before that the params struct could not represent them, so a
symmetric import over MCP failed on a zero key size and any requested digest or
partition was discarded.

**The MCP field carrying the key material is `wrapped_key`**, not the
`wrapped_key_material` the REST and embedded `ImportKeyRequest` use. The name
is the one every params struct on that transport uses for wrapped material.
`pkg/api/transport/mcp` builds the params struct by name so the two cannot
drift apart silently again — which they had, and every import over that
transport arrived with no key material at all until go-xkms#159.

`tenant_id` is deliberately **not** an MCP import field: the MCP handlers take
the tenant from the authenticated caller and reject a wire-supplied one.

### Key versioning — declared, unserved

`xkmsv1.KeystoreService` declares `ListKeyVersions`, `EnableKeyVersion`,
`DisableKeyVersion`, `EnableAllKeyVersions` and `DisableAllKeyVersions`. **No
production server implements them.** `pkg/api/grpc.Service` embeds
`pb.UnimplementedKeystoreServiceServer` (`pkg/api/grpc/service.go:90`), so every
call falls through to `codes.Unimplemented`. The only implementations in the
tree are test mocks under `pkg/api/transport/{grpc,unix}/*_test.go`. There is no
REST route, no MCP method, no CLI verb, and no SDK accessor.

This is an API surface that lies: a generated client lists five methods that can
never succeed. Resolving it means either implementing versioning or removing the
RPCs (a breaking change) — an owner decision, recorded in the report rather than
taken here.

### Additional gRPC-only surface

`UseResidentKey`, `DestroyResidentKey` and `GenerateEphemeralECDH` exist on
`KeystoreService` with no REST/QUIC/MCP counterpart and no CLI verb. Recorded as
**MISSING — docs/13** on the other transports.

## Request and response schemas

Schemas are the Go request/response types in `pkg/api/transport/types.go`
(re-exported by `sdk/go/transport`) and their protobuf counterparts in
`pkg/api/grpc/proto/xkmsv1/xkms.proto`. REST and QUIC serialise those Go types
directly as JSON; MCP carries them as the JSON-RPC `params` and `result`. There
is one shape per capability across all transports — that is the point of the
shared type set.

## Status and error mapping

| Condition | REST | gRPC / Unix | MCP |
|---|---|---|---|
| success | 200 | `OK` | `result` |
| malformed request | 400 | `InvalidArgument` | JSON-RPC `-32602` |
| unauthenticated | 401 | `Unauthenticated` | error object |
| RBAC denial | 403 | `PermissionDenied` | error object |
| `ErrKeyNotFound` | 404 | `NotFound` | error object |
| `ErrKeyAlreadyExists` | 409 | `AlreadyExists` | error object |
| unknown method | 404 | `Unimplemented` | JSON-RPC `-32601` |
| backend failure | 500 | `Internal` | error object |
| subsystem not configured | 501 | `Unimplemented` | error object |
| backend name not registered, or failing name validation (MCP-side check) | — | — | JSON-RPC `-32602`, `ErrInvalidBackend` |

The mapping is implemented once per transport in `errors_keyops.go`
(`pkg/api/rest`, `pkg/api/grpc`, `pkg/api/mcp`, `pkg/xkms`).

## Pagination

`ListKeys`, `ListBackends` and `ListCertificates` take `ListOption` values and
return paged results; the REST side is `pkg/api/rest/pagination.go`, the client
side `pkg/api/transport/pagination.go`. Unbounded result sets are not returned.

## Port conflicts — as-shipped reality

Three independent disagreements exist in the tree. Documented as they ship;
picking canonical values is a config-contract decision for the owner.

| Surface | Shipped config (`configs/xkmsd*.yaml`) | Library / SDK default |
|---|---|---|
| REST | `rest_port: 8443` | `sdk/go/options.go` `DefaultRESTAddress = "http://localhost:8443"` — agrees |
| gRPC | `grpc_port: 9443` | `DefaultGRPCAddress = "localhost:9443"` — agrees |
| QUIC | `quic_port: 8444` | `DefaultQUICAddress = "localhost:8444"` — agrees |
| **MCP** | `mcp_port: 8445` | `DefaultMCPAddress = "localhost:9444"`, and `pkg/api/mcp/server.go:175` defaults to `localhost:9444` — **disagree** |
| **Noise bootstrap** | `noise_port: 8447` in `configs/xkmsd-local.yaml` only | `pkg/trust/bootstrap/bootstrap.go:98` `DefaultNoisePort = "8445"` — **collides with the shipped MCP port**, which is why the local config moves it to 8447 |
| **ACME QUIC** | — | `pkg/acme/api/server/server.go:49` `DefaultQUICPort = 9444` — **collides with the SDK's MCP default** |

Use explicit ports in configuration until this is settled.

## Versioning and deprecation

REST routes are under `/api/v1` (SSH is under `/xkms/v1/ssh`; trust bootstrap
is `/v1/ca/bootstrap`). gRPC is package `xkmsv1`. No route in this feature is
deprecated. The SDK module is tagged with a **path-prefixed** tag
(`sdk/go/vX.Y.Z-alpha`), not a bare `vX.Y.Z`.
