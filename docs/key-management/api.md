# Key Management — API

> **Status: NORMATIVE** · Feature: `key-management` · Repo: `go-xkms` · Last verified: 2026-09-23

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
compile time (`var _ transport.Client = (*Transport)(nil)`). MCP's `FIDO2Service`
methods (`BeginRegistration`, `FinishRegistration`, `BeginAuthentication`,
`FinishAuthentication`) satisfy that contract but are a deliberate, permanent
exclusion rather than a real implementation: an MCP tool-call surface is
agent-facing and must not mint sessions or enrol credentials, so those four
methods always return the typed `pkg/api/transport/mcp.ErrIdentityCeremonyExcluded`
(issue #193). See [`../webauthn/api.md`](../webauthn/api.md) §Capability matrix
for the full rationale and the capability-discovery mechanism
(`pkg/api/mcp.ModuleMethods` never lists a tool for these methods).

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

### The REST body spells the same fields the same way as MCP

The REST bodies of the ceremony (`POST /api/v1/keys/import-params`, `/wrap`,
`/unwrap`, `/import`) carry the material as `wrapped_key` and the wrapping key
as PEM text under `wrapping_public_key_pem`, and the import-parameters response
returns the wrapping key as PEM. Those bodies are defined once, in
`pkg/api/rest/wire`, which the REST handlers alias and the REST and QUIC
client transports build **by name**: `wire.NewImportKeyRequest`,
`NewWrapKeyRequest`, `NewUnwrapKeyRequest`, `NewGetImportParametersRequest`,
and `Transport()` on the two responses, which PEM-encode the wrapping key on
the way out and decode it on the way back. A wrapping key that is not DER
PKIX is refused locally with `wire.ErrWrappingPublicKeyNotDER` before any
request is sent. The contract test in that package pins every field of every
body against `transport.*Request`, so a field one side can express and the
other drops cannot come back.

Before this the two transports marshalled the contract struct straight onto
the route: the material arrived under a name the handler did not read, the
wrapping key arrived as base64 where PEM was expected, the import-parameters
response came back with no wrapping key, and `partition`, `metadata` and
`key_spec` were dropped. No import, wrap or unwrap over REST or QUIC could
have worked; the REST body also now carries `partition`, `metadata` and
`key_spec`, and `GenerateKeyRequest` carries `partition`.

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
| REST | `key_type` in `ImportKeyRequest`, with `key_size`, `curve`, `hash`, `aes_key_size`, `exportable`, `sensitive` |
| gRPC | `key_type` in `ImportKeyRequest`, with `key_size`, `curve`, `hash`, `partition`, `exportable` (optional), `sensitive` |
| MCP | `key_type` in `xkms.importKey` params, with `key_size`, `curve`, `hash`, `aes_key_size`, `partition`, `exportable`, `sensitive` |

The first half of the ceremony takes the same vocabulary: `key_type` (with
`key_size` and `curve`) on `POST /api/v1/keys/import-params`, gRPC
`GetImportParametersRequest` and the `xkms.getImportParameters` params tells
the backend what the caller intends to import, and the response's `key_spec`
names what it will accept (`RSA_2048`, `AES_256`, `ECC_NIST_P256`, ...). A
request that declares nothing gets `UNKNOWN`, and the caller learns the
intended algorithm only at import time. The MCP params carried no such field
until now, so every MCP answer was `UNKNOWN`; the MCP handler now resolves
the request through the service, as the import does, and the MCP client
transport builds the params by name and decodes the PEM wrapping key in the
result back to the DER the contract carries.

`exportable` and `sensitive` are the same controls `GenerateKeyRequest`
carries. `exportable` is optional on every transport: absent, the import keeps
the write-once default (symmetric material exportable, asymmetric not);
`false` imports non-extractable secret material that `export-material` and
`export` refuse for the key's whole lifetime. `sensitive` marks the key
CKA_SENSITIVE independently of `exportable`.

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

### `GetTLSCertificate`'s response is one canonical type on every transport

`GetTLSCertificate`'s response is `pkg/api/transport.GetTLSCertificateResponse`
(`key_id`, `certificate_pem`, `chain_pem`) — the same struct every server
handler builds and every client transport decodes, with no per-transport
variant. `chain_pem` is a JSON array, one PEM-encoded certificate per chain
entry, leaf excluded (matching `GetTLSCertificateResponse.cert_chain_pem` in
`pkg/api/grpc/proto/xkmsv1/xkms.proto`). The private key never travels on
this response, on any transport (go-xkms#627), and does not come back.

Before go-xkms#656, REST and MCP each carried their own response type for
this one call, and both disagreed with `transport.GetTLSCertificateResponse`:
REST's `chain_pem` was a JSON array while the transport type's was a single
string under the same tag, so the REST and QUIC client transports (QUIC
reuses the REST handler set) failed to decode any certificate that had a
chain; MCP's result used different field names entirely
(`cert_pem`/`chain_pems` against `certificate_pem`/`chain_pem`), so every MCP
call decoded to a zero-value response. Both local types are deleted; REST and
MCP now build `transport.GetTLSCertificateResponse` directly, the one type
this call has ever needed.

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
