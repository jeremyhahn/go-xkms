# PIV Smartcard — API

> **Status: NORMATIVE** · Feature: `piv-smartcard` · Repo: `go-xkms` · Last verified: 2026-08-19

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped".

PIV routes are registered under `/api/v1/piv` with `RouteAuthSession` — an
authenticated identity, no specific RBAC permission.

## Capability matrix

| Capability | REST | gRPC / Unix (`KeystoreService.`) | QUIC (HTTP/3) | MCP | Embedded (`PIVService.`) | Auth |
|---|---|---|---|---|---|---|
| List slots | `GET /api/v1/piv/slots` | `ListPIVSlots` | same as REST | `xkms.listPIVSlots` | `ListPIVSlots` | session |
| Get certificate | `GET /api/v1/piv/slots/{slot}/certificate` | `GetPIVCertificate` | same as REST | `xkms.getPIVCertificate` | `GetPIVCertificate` | session |
| Store certificate | `POST /api/v1/piv/slots/{slot}/certificate` | `StorePIVCertificate` | same as REST | `xkms.storePIVCertificate` | `StorePIVCertificate` | session |
| Delete certificate | `DELETE /api/v1/piv/slots/{slot}/certificate` | `DeletePIVCertificate` | same as REST | `xkms.deletePIVCertificate` | `DeletePIVCertificate` | session |
| Generate key | `POST /api/v1/piv/slots/{slot}/generate` | `GeneratePIVKey` | same as REST | `xkms.generatePIVKey` | `GeneratePIVKey` | session |
| Import certificate | `POST /api/v1/piv/slots/{slot}/import` | `ImportPIVCertificate` | same as REST | `xkms.importPIVCertificate` | `ImportPIVCertificate` | session |
| Export certificate | `GET /api/v1/piv/slots/{slot}/export` | `ExportPIVCertificate` | same as REST | `xkms.exportPIVCertificate` | `ExportPIVCertificate` | session |
| Generate CSR | `POST /api/v1/piv/slots/{slot}/csr` | `GeneratePIVCSR` | same as REST | `xkms.generatePIVCSR` | `GeneratePIVCSR` | session |
| PIV login | `POST /api/v1/auth/login/piv` | **MISSING — docs/13** | same as REST | **MISSING — docs/13** | — | **public** |

**PIV is the best-covered hardware feature on MCP** — all eight slot operations
have methods, unlike PIN (zero) and WebAuthn (zero). The one gap is PIV login,
which is an authentication route rather than a slot operation.

`POST /api/v1/auth/login/piv` sits in `GroupAuthSession`, is `RouteAuthPublic`
(it *is* the authentication), is gated on `hasIssuer`, and runs behind the login
rate limiter.

## `{slot}` is a closed set

The path parameter accepts only defined PIV slots: `9a`, `9c`, `9d`, `9e`, `f9`,
and the retired range `82`–`95`. `ValidateSlot` rejects anything else, and the
rejection happens before any device access — so probing the API with arbitrary
slot values cannot advance a token's error counter.

Slot purposes are NIST SP 800-73-4's and are documented in
[`architecture.md`](architecture.md). A client choosing a slot programmatically
should allocate from the **retired** range unless it genuinely needs one of the
four standard purposes.

## Request and response schemas

Go types in `pkg/api/transport/types.go` and `types_piv_ops.go`:
`ListPIVSlotsRequest`/`Response`, `GetPIVCertificateRequest`/`Response`,
`StorePIVCertificateRequest`, `DeletePIVCertificateRequest`,
`GeneratePIVKeyRequest`/`Response`, `GeneratePIVCSRRequest`/`Response`.
Protobuf counterparts in `xkms.proto`.

Note the interface shape: `ImportPIVCertificate` takes a
`*StorePIVCertificateRequest` and `ExportPIVCertificate` takes a
`*GetPIVCertificateRequest` — import/store and export/get share request types
because they differ in storage semantics, not in payload.

Certificates are carried as PEM or DER per the request's format field.
**No response in this feature ever carries a private key.**

`ListPIVSlots` returns `SlotOccupancyInfo` per slot — metadata plus whether the
slot is occupied. That is the only reliable occupancy source; the three storage
types share no index.

## Status and error mapping

| Condition | REST | gRPC / Unix | MCP |
|---|---|---|---|
| success | 200 | `OK` | `result` |
| invalid slot identifier | 400 | `InvalidArgument` | JSON-RPC `-32602` |
| slot empty | 404 | `NotFound` | error object |
| slot occupied on generate | 409 | `AlreadyExists` | error object |
| certificate chain fails verification | 400 | `InvalidArgument` | error object |
| device absent / token locked | 503 | `Unavailable` | error object |
| PIN required | 401 | `Unauthenticated` | error object |
| TPM NV space exhausted | 507 | `ResourceExhausted` | error object |

`PIVStorageError` carries the operation and the slot; the transport preserves
the slot in the message, because "store failed" without it is not actionable.

## Pagination

`ListPIVSlots` returns the full slot set — bounded by the PIV standard at 25
slots, so it is deliberately unpaged.

## Versioning and deprecation

`/api/v1/piv/*`, gRPC package `xkmsv1`. Slot identifiers and certificate
encodings are NIST-defined and will not change.

The one local versioning hazard is not on the wire: TPM2 NV indices are derived
by `GetNVIndex(slot, baseIndex)`. Changing that derivation orphans every
NV-stored certificate, so it is a migration rather than a refactor.
