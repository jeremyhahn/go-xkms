# Key Management — API

> **Status: NORMATIVE** · Feature: `key-management` · Repo: `go-xkms` · Last verified: 2026-09-24

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
| `ErrKeyNotFound` | 404 | `NotFound` | JSON-RPC `-32001` (`sdkssh.JSONRPCCodeNotFound`) |
| `ErrBackendNotFound` | 404 | `NotFound` | JSON-RPC `-32001` (`sdkssh.JSONRPCCodeNotFound`) |
| `ErrKeyAlreadyExists` | 409 | `AlreadyExists` | error object |
| unknown method | 404 | `Unimplemented` | JSON-RPC `-32601` |
| backend failure | 500 | `Internal` | error object |
| subsystem not configured | 501 | `Unimplemented` | error object |
| backend name not registered, or failing name validation (MCP-side check) | — | — | JSON-RPC `-32602`, `ErrInvalidBackend` |

The mapping is implemented once per transport in `errors_keyops.go`
(`pkg/api/rest`, `pkg/api/grpc`, `pkg/api/mcp`, `pkg/xkms`).

**MCP's not-found code (go-xkms#814)**: `pkg/api/mcp`'s own JSON-RPC
vocabulary (the eight `ErrCode*` constants in `types.go`) has no dedicated
NotFound member. Rather than mint a ninth, `errors_keyops.go`'s
`keyOpSentinelCodes` and `handlers_user.go`'s `mapUserError` reuse
`sdkssh.JSONRPCCodeNotFound` (`-32001`, `sdk/go/client/ssh/mcp_status.go`) —
the code this package's SSH sub-system already defined in the reserved
`-32000..-32099` range for the identical outcome (`errors_ssh.go`'s
`mapSSHError`). It covers `xkms.ErrKeyNotFound`, `xkms.ErrBackendNotFound`,
and a `*qrdbsdk.UserNotFoundError` surfaced by `user.get`,
`user.listCredentials`, or any other `user.*` method that resolves a
username — matching go-qrdb's own gRPC/QUIC/MCP-wire classification of that
type ("lower layers win"). `pkg/apimodule/module_mcp_errors.go`'s
`keyOpCodeToWire` already carried the `sdkssh.JSONRPCCodeNotFound →
wire.CodeNotFound` row (added for SSH); no new row was needed once the
key/backend/user paths started producing that code too.

### The real MCP tool surface carries go-qrdb's wire classification (#791)

The MCP column above is the JSON-RPC dispatch core, `pkg/api/mcp.Server`. The
unified API server never speaks that JSON-RPC-over-the-wire shape directly:
`pkg/apimodule.RegisterMCP` registers one real mcp-go tool per JSON-RPC
method, and `mcpToolHandler` calls `Server.InvokeMethod` and adapts its
answer. Per the Model Context Protocol specification, a failure *inside* a
tool is an ordinary tool result (`isError: true`), never a JSON-RPC protocol
error, so the code has nowhere to ride except that result.

Before #791, `mcpToolHandler` rendered every `InvokeMethod` failure as prose
only (`err.Error()`) — none of the codes `pkg/api/mcp`'s handlers and gates
compute (`*KeyOpError.Code`; see `errors_keyops.go`, `authz.go`, `tenant.go`)
reached the caller. `mcpToolHandler` now unwraps a `*KeyOpError` (`errors.As`)
and renders it as go-qrdb's own MCP wire contract instead of inventing a
parallel one: the tool result's `structuredContent` carries a
`wire.ErrorEnvelope` (`code`, `status`, `message`, `tool`) — the exact shape
go-qrdb's own MCP server produces for its own tools
(`go-qrdb/pkg/api/mcp/status.go`'s `toolErrorResult`) and the shape go-qrdb's
own SDK client (`sdk/go/transport/mcp`) already decodes. An `InvokeMethod`
failure that is not a `*KeyOpError` renders as a generic, undetailed internal
fault (`wire.CodeInternal`, message `"xkms: internal error"`) rather than
leaking its text to the caller.

| `KeyOpError.Code` (`pkg/api/mcp`, JSON-RPC numbering) | go-qrdb `wire.Code` |
|---|---|
| `ErrCodeParseError` (-32700) | `CodeInvalidArgument` (-32012) |
| `ErrCodeInvalidRequest` (-32600) | `CodeInvalidArgument` (-32012) |
| `ErrCodeMethodNotFound` (-32601) | `CodeUnimplemented` (-32014) |
| `ErrCodeInvalidParams` (-32602) | `CodeInvalidArgument` (-32012) |
| `ErrCodeInternalError` (-32603) | `CodeInternal` (-32603) |
| `ErrCodeUnauthorized` (-32002) | `CodeUnauthenticated` (-32001) |
| `ErrCodeForbidden` (-32003) | `CodePermissionDenied` (-32003) |
| `ErrCodeServiceUnavailable` (-32004) | `CodeUnavailable` (-32006) |
| `sdkssh.JSONRPCCodeNotFound` (-32001; `sdk/go/client/ssh/mcp_status.go`, reused outside the SSH sub-system since go-xkms#814 — see "Status and error mapping" above) | `CodeNotFound` (-32004) |

**Closed (#797)**: xkms's own SDK client for this surface
(`pkg/api/transport/mcp.Transport`) now reads `structuredContent` instead of
classifying a tool failure by matching keywords in the error text. `rpcCall`
runs every failing tool result through `classifyToolError` (`status.go`),
which decodes the envelope with `wire.DecodeErrorPayload` and maps its
`wire.Code` back onto the JSON-RPC error codes `*RPCError.Code` has always
carried — the same fail-open pattern go-qrdb's own SDK client replaced with
this envelope (go-qrdb#438), adopted here rather than reinvented. The
previous `newToolError`/`toolErrorCode` keyword matcher, and the legacy
"`JSON-RPC error <code>: <message>`" text-embedded-code fallback it also
carried, are both deleted; there is no text fallback left.

| go-qrdb `wire.Code` | `*RPCError.Code` (`pkg/api/mcp`, JSON-RPC numbering) |
|---|---|
| `CodeUnauthenticated` (-32001) | `ErrCodeUnauthorized` (-32002) |
| `CodePermissionDenied` (-32003) | `ErrCodeForbidden` (-32003) |
| `CodeNotFound` (-32004) | `sdkssh.JSONRPCCodeNotFound` (-32001) |
| `CodeUnavailable` (-32006) | `ErrCodeServiceUnavailable` (-32004) |
| `CodeInvalidArgument` (-32012) | `ErrCodeInvalidParams` (-32602) |
| `CodeUnimplemented` (-32014) | `ErrCodeMethodNotFound` (-32601) |
| `CodeInternal` (-32603) | `ErrCodeInternalError` (-32603) |
| any other code (`CodeDeadlineExceeded`, `CodeResourceExhausted`, `CodeFailedPrecondition`, `CodeCanceled`, `CodeAlreadyExists`, `CodeAborted`, `CodeOutOfRange`, `CodeDataLoss`, `CodeUnknown`, or a number this build predates) | `ErrCodeInternalError` (-32603), same floor `mapKeyOpError` uses server-side |

**Closed (#814)**: `wire.CodeNotFound` used to join `CodeInvalidArgument` in
`ErrCodeInvalidParams` here, and no server code path actually produced it —
every not-found sentinel in `errors_keyops.go`'s `keyOpSentinelCodes` (and
every `user.*` failure, which had no classification at all; see below)
rendered as `ErrCodeInternalError`, so a missing key, backend, or user was
indistinguishable from a genuine server fault. `wire.CodeNotFound` now
classifies onto `sdkssh.JSONRPCCodeNotFound` instead: `xkms.ErrKeyNotFound`
and `xkms.ErrBackendNotFound` (`errors_keyops.go`'s `keyOpSentinelCodes`) and
a `*qrdbsdk.UserNotFoundError` (`handlers_user.go`'s `mapUserError`) all
produce it server-side, and this table's row renders it back for the SDK
client. `user.*` param-decode failures also stopped bypassing classification
in the same change: `handlers_user.go`'s `unmarshalUserParams` (a second,
non-`*KeyOpError`-producing decode helper) was deleted in favor of the
shared `decodeParams` (`utils.go`) every other handler already used, so a
malformed `user.*` request now reports `ErrCodeInvalidParams` like every
other method instead of `ErrCodeInternalError`.

A failing tool result whose `structuredContent` carries no envelope is not
degraded into a keyword guess. Per the project's no-backward-compatibility
rule it is reported as `*EnvelopeMissingError`, a protocol error: the unified
server stamps an envelope onto every failing xkms tool result
(`codedToolResult`), so a response with none did not come from that
contract.

### Cert, PIV, CA, barrier, password and wrap/unwrap now classify like every other MCP method (#912)

Before #912, the cert, PIV, CA, barrier, password and wrap/unwrap MCP
handlers (`pkg/api/mcp/handlers.go`, `handlers_piv.go`, `handlers_ca.go`,
`handlers_ca_tcg.go`, `handlers_barrier_shamir.go`, `handlers_password.go`)
returned service-layer errors as bare, unwrapped `error` values instead of
`*KeyOpError`. `pkg/apimodule/module_mcp.go`'s `mcpToolHandler` only unwraps
`*KeyOpError` (`errors.As`); anything else renders as the generic
`wire.CodeInternal` / `"xkms: internal error"` floor described above,
regardless of the actual condition. Every handler in these six families now
returns a `*KeyOpError` for every failure path.

**A shared classification table, not six duplicated ones.** `pkg/api/apierrors`
(`apierrors.go`, `tables.go`) holds `Class`, a transport-agnostic outcome
vocabulary (`ClassNotFound`, `ClassInvalidArgument`, `ClassUnimplemented`, …),
and three ordered `[]SentinelClass` tables — `ImportExportSentinelClasses`,
`PIVSentinelClasses`, `BarrierSentinelClasses` — that pair each domain
sentinel with its `Class`. `ClassOf` runs `errors.Is` against a table, first
match wins. Both `pkg/api/grpc` (`errors_keyops.go`'s `mapImportExportError`,
`service_piv.go`'s `mapPIVError`, `service_barrier_pin.go`'s
`mapBarrierError`) and `pkg/api/mcp` (`errors_shared.go`'s three
identically-named functions) call `apierrors.ClassOf` against these same
three tables and translate the resulting `Class` into their own wire
vocabulary with a small, total, package-local map (`classToGRPCCode` /
`classToJSONRPCCode`): the judgment of "which sentinel means what" is written
down once; only the mechanical `Class` → local-code step is duplicated.

CA (`errors_cert.go`'s `mapCAError`) and certificate storage
(`certOperationError`, `getCertError`) do **not** read a shared table: gRPC's
own classification for these two families (`pkg/api/grpc/service_ca.go`,
`service.go`'s `SaveCert`/`GetCert`/…) is not sentinel-driven — each RPC
pre-validates its own request fields and checks a package-level CA instance
for nil, then reports any servicer failure as a fixed `codes.Internal` (or,
for `GetCert` only, a fixed `codes.NotFound` regardless of cause). There is
no gRPC-side table to share; MCP's two functions reproduce the same wire
*outcome* by checking the sentinels its own call path can actually produce
(`xkms.ErrNotConfigured`, `*xkms.ErrValidation`, `xkms.ErrNilRequest`,
`xkms.ErrNilData`) instead.

| Family | Sentinel(s) | MCP code | gRPC code |
|---|---|---|---|
| wrap/unwrap/export | `backend.ErrExportNotSupported`, `ErrImportNotSupported` | `ErrCodeMethodNotFound` | `Unimplemented` |
| wrap/unwrap/export | `backend.ErrAsymmetricKeyExportNotAllowed` | `ErrCodeInvalidParams` | `InvalidArgument` |
| wrap/unwrap/export | `backend.ErrKeyNotExportable` | `ErrCodeForbidden` | `PermissionDenied` |
| PIV | `xkms.ErrPIVBackendNotFound`, `ErrPIVKeyNotFound` | `sdkssh.JSONRPCCodeNotFound` | `NotFound` |
| PIV | `xkms.ErrPIVInvalidAlgorithm`, `ErrPIVInvalidSlot`, `ErrPIVInvalidFormat` | `ErrCodeInvalidParams` | `InvalidArgument` |
| PIV | `xkms.ErrPIVNotInitialized` | `ErrCodeInternalError` (no JSON-RPC FailedPrecondition) | `FailedPrecondition` |
| barrier | `seal.ErrAlreadyInitialized`, `ErrAlreadyUnsealed`, `ErrShamirDuplicateShare` | `sdkssh.JSONRPCCodeDuplicate` | `AlreadyExists` |
| barrier | `seal.ErrStrategyNotFound`, `ErrShamirShareNotFound`, `ErrShamirNoSharesFound`, `ErrRecoveryKeysNotFound` | `sdkssh.JSONRPCCodeNotFound` | `NotFound` |
| barrier | `seal.ErrInvalidCredentials`, `ErrDecryptionFailed`, `ErrRootTokenVerificationFailed` | `ErrCodeInvalidParams` (no JSON-RPC Unauthenticated) | `Unauthenticated` |
| barrier | `seal.ErrNoAvailableStrategy` | `ErrCodeServiceUnavailable` | `Unavailable` |
| barrier | `seal.ErrSealed`, `ErrNotInitialized`, `ErrStrategyMismatch`, `ErrEncryptorNotAvailable`, `ErrShamirNotConfigured`, `ErrShamirQuorumIncomplete` | `ErrCodeInternalError` (no JSON-RPC FailedPrecondition) | `FailedPrecondition` |
| barrier | `seal.ErrShamirThresholdInvalid` | `ErrCodeInvalidParams` | `InvalidArgument` |
| barrier | `seal.ErrCorruptRootKey`, `ErrShamirVerificationFailed` | `ErrCodeInternalError` (no JSON-RPC DataLoss) | `DataLoss` |
| barrier | `seal.ErrShamirQuorumExpired` | `ErrCodeInternalError` (no JSON-RPC DeadlineExceeded) | `DeadlineExceeded` |
| CA / cert | `xkms.ErrNotConfigured` (`mapCAError`) | `ErrCodeServiceUnavailable` | `Unavailable` (nil CA instance check) |
| CA / cert | `*xkms.ErrValidation`, `xkms.ErrNilRequest`, `xkms.ErrNilData` (`mapCAError`) | `ErrCodeInvalidParams` | `InvalidArgument` (pre-validated request field) |
| cert | any `GetCert` failure (`getCertError`) | `sdkssh.JSONRPCCodeNotFound` | `NotFound` (unconditional) |
| cert | any other cert-storage failure (`certOperationError`) | `ErrCodeInternalError` | `Internal` (unconditional) |

**`*xkms.ErrRoleLookup` now classifies as Not found, not Invalid params, on
MCP (#912)**, resolving a divergence from gRPC: `pkg/api/grpc/errors_keyops.go`'s
`mapKeyOpError` has always mapped `*xkms.ErrRoleLookup` to `codes.NotFound`
("a named role, backend, or key that does not resolve"). MCP's
`errors_keyops.go`'s `mapKeyOpError` mapped the same type to
`ErrCodeInvalidParams` — as if the caller's request were malformed rather
than the name it gave simply not resolving. go-qrdb's own MCP wire contract
(`pkg/api/mcp/status.go`'s `classifyToolError`, pinned by that package's
`status_test.go`'s "missing role" case) classifies its own
`*role.RoleNotFoundError` identically to its own gRPC transport — `wire.CodeNotFound`
— so "lower layers win" and gRPC agree: MCP now reports
`sdkssh.JSONRPCCodeNotFound` for `*xkms.ErrRoleLookup` too.

**`staticpw.ErrInvalidTenantID` now classifies as Invalid params on MCP
(#912)**, matching `pkg/api/grpc/service_password.go`'s `mapPasswordError`
(`codes.InvalidArgument`). `handlePasswordUnlock` and `handlePasswordLock`
used to return this sentinel bare for a cross-tenant caller (the reserved
`"system"` `TenantID`, or any identity whose tenant carries no per-tenant
password store); both now route it through `mapPasswordError`.
`handlers_password.go`'s `mapPasswordError` and `mapPasswordStoreError` were
also, more broadly, returning every case unwrapped — the whole `password.*`
family (add/get/list/update/delete/unlock/lock/generate/setAccessMode)
reported `ErrCodeInternalError` for every domain condition regardless of
cause; both functions now return `*KeyOpError`.

**Verification**: `pkg/api/mcp/errors_shared_test.go`,
`errors_cert_test.go`, `errors_keyops_test.go` and `handlers_password_test.go`
assert the JSON-RPC code for each family's domain sentinels directly;
`pkg/api/mcp/handlers_domain_sentinels_test.go` asserts a representative
sentinel per family through the real `Server.InvokeMethod` dispatch.
`pkg/api/grpc/apierrors_parity_test.go` and
`pkg/api/mcp/apierrors_parity_test.go` each walk
`apierrors.ImportExportSentinelClasses` / `PIVSentinelClasses` /
`BarrierSentinelClasses` and assert their own package's classification
function renders the wire outcome a shared, per-`Class` expectation table
(mirrored between the two files, since neither package can see the other's
unexported map) names for that `Class` — so a change to either package's
`Class` → local-code map that drifts from the other's intended outcome fails
one of the two tests.

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
