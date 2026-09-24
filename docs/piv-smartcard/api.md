# PIV Smartcard — API

> **Status: NORMATIVE** · Feature: `piv-smartcard` · Repo: `go-xkms` · Last verified: 2026-09-23

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped".

PIV routes are registered under `/api/v1/piv` with `RouteAuthPermission`: an
authenticated identity that also holds the route's `piv:*` permission when RBAC
is enabled — the pair gRPC and MCP enforce for the same operation. Reads are
`piv:read`, certificate and key provisioning `piv:write`, deletion
`piv:delete`, and CSR generation — a signature by a slot key that never leaves
the card — `piv:use`. Admin and Owner hold all four by default.

## Capability matrix

| Capability | REST | gRPC / Unix (`KeystoreService.`) | QUIC (HTTP/3) | MCP | Embedded (`PIVService.`) | Auth / permission |
|---|---|---|---|---|---|---|
| List slots | `GET /api/v1/piv/slots` | `ListPIVSlots` | same as REST | `xkms.listPIVSlots` | `ListPIVSlots` | `piv:read` |
| Get certificate | `GET /api/v1/piv/slots/{slot}/certificate` | `GetPIVCertificate` | same as REST | `xkms.getPIVCertificate` | `GetPIVCertificate` | `piv:read` |
| Store certificate | `POST /api/v1/piv/slots/{slot}/certificate` | `StorePIVCertificate` | same as REST | `xkms.storePIVCertificate` | `StorePIVCertificate` | `piv:write` |
| Delete certificate | `DELETE /api/v1/piv/slots/{slot}/certificate` | `DeletePIVCertificate` | same as REST | `xkms.deletePIVCertificate` | `DeletePIVCertificate` | `piv:delete` |
| Generate key | `POST /api/v1/piv/slots/{slot}/generate` | `GeneratePIVKey` | same as REST | `xkms.generatePIVKey` | `GeneratePIVKey` | `piv:write` |
| Import certificate | `POST /api/v1/piv/slots/{slot}/import` | `ImportPIVCertificate` | same as REST | `xkms.importPIVCertificate` | `ImportPIVCertificate` | `piv:write` |
| Export certificate | `GET /api/v1/piv/slots/{slot}/export` | `ExportPIVCertificate` | same as REST | `xkms.exportPIVCertificate` | `ExportPIVCertificate` | `piv:read` |
| Generate CSR | `POST /api/v1/piv/slots/{slot}/csr` | `GeneratePIVCSR` | same as REST | `xkms.generatePIVCSR` | `GeneratePIVCSR` | `piv:use` |
| Import **private key** | — | — | — | — | — (SDK only: `xkms.ImportPIVKey`) | session |
| **Verify** an attestation | — | — | — | — | — (SDK only: `xkms.VerifyPIVAttestation` / `ParsePIVAttestation`) | n/a |
| PIV login | `POST /api/v1/auth/login/piv` | **MISSING — docs/13** | same as REST | **MISSING — docs/13** | — | **public** |

**PIV is the best-covered hardware feature on MCP** — all eight slot operations
have methods, unlike PIN (zero) and WebAuthn (zero). The one gap is PIV login,
which is an authentication route rather than a slot operation.

`POST /api/v1/auth/login/piv` sits in `GroupAuthSession`, is `RouteAuthPublic`
(it *is* the authentication), is gated on `hasIssuer`, and runs behind the login
rate limiter. It accepts a certificate as smartcard-backed only when a presented
certificate chains to the configured PIV attestation anchor and carries the
login key's SubjectPublicKeyInfo; the token it mints records `attest_level`
(`hardware`, `software`, or `unattested` — `types.AttestLevel`, `pkg/types`,
the one vocabulary shared with go-quicbaas#379). The contract is in
[`../auth-factors/api.md`](../auth-factors/api.md).

**Precedence: a recorded enrollment level, when one exists, decides the
claim outright — the certificate chain is not consulted at all in that case.**
`PIVLoginOptions.RecordedLevel`
(`func(cert *x509.Certificate) (types.AttestLevel, bool)`) looks up the level
`pkg/xkms`'s `PIVKeyGenerator` implementations recorded on
`types.KeyAttributes.AttestLevel` when the login key was enrolled. `pkg/server`
wires it to `PIVManager.AttestLevelForCertificate`, which matches the login
certificate against every enrolled PIV slot on every registered backend by
SubjectPublicKeyInfo — the canonical qrdb SPKI SHA-256 thumbprint
(`qrdbsdk.ComputeSPKIThumbprint`, the one cert-binding algorithm already used
for admin cert binding), not a second algorithm invented for this lookup.
When `RecordedLevel` is nil (no PIV manager was initialized at server
composition) or reports not-found for the presented certificate, the
exchange falls back to the pre-existing chain-derived decision (an anchored
attestation chain proves `hardware`; `AllowUnattested` opts into minting
`unattested` otherwise). A recorded `hardware` is never downgraded by a
missing or invalid chain, and a recorded `software` or `unattested` is never
upgraded by a chain that happens to verify — RecordedLevel decides *what*
the key is; `AllowUnattested` still decides whether a non-hardware login may
proceed at all.

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

`ImportPIVKeyRequest`/`Response` (`types_piv_ops.go`) carry the private-key
import verb. It is **SDK-only and deliberately not on any network transport**:
its request field holds private key material, and the only transport-shaped
thing that could carry it is a wrap ceremony the caller would have to run
anyway. `ImportPIVKey` runs that ceremony internally — `GetImportParameters`,
`WrapKey`, `ImportKey` against the target backend — so key material is wrapped
to a backend-issued key before it crosses into the backend, rather than being
handed over in the clear.

Do not confuse it with `ImportPIVCertificate`, which imports a **certificate**
and shares `StorePIVCertificateRequest`. Passing a private key to that verb was
the defect that motivated adding this one: the key landed in a field named
`Certificate`.

Certificates are carried as PEM or DER per the request's format field.
**No response in this feature ever carries a private key** — `ImportPIVKeyResponse`
returns only the public half, so a caller can confirm what the slot holds.

`VerifyPIVAttestation` and `ParsePIVAttestation` read that material back —
firmware, serial, PIN and touch policy, form factor. They are SDK-only and take
their trust anchors from the caller; no vendor root ships with the SDK. A nil
error from the verifier means the **chain** verified, not that any policy is
satisfied.

**`AttestPIVSlot` refuses a slot whose key arrived by import**, with
`ErrPIVKeyImportedNotAttestable`, and returns no material. Nothing on the wire
could carry the residency-not-exclusivity distinction, so the attestation is
withheld rather than issued and misread. This matches YubiKey PIV, where
attestation is likewise available only for slot-generated keys. A key whose
origin was never recorded reads as unknown and still attests — see
[`architecture.md`](architecture.md).

`ListPIVSlots` returns `SlotOccupancyInfo` per slot — metadata plus whether the
slot is occupied. That is the only reliable occupancy source; the three storage
types share no index.

## Status and error mapping

| Condition | REST | gRPC / Unix | MCP |
|---|---|---|---|
| success | 200 | `OK` | `result` |
| caller lacks the route's `piv:*` permission | 403 | `PermissionDenied` | error object |
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
