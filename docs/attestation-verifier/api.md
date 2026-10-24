# Attestation Verifier — API

> **Status: NORMATIVE** · Feature: `attestation-verifier` · Module: `go-xkms` · Last verified: 2026-10-24

Transport shapes:
[`../key-management/api.md`](../key-management/api.md).

## Not a transport of its own

`pkg/attestation` has no REST route, gRPC method, QUIC handler or MCP tool
(its `appraisal` subpackage's signing-key verbs do; see
[below](#repository-signing-keys)).
It runs inside the handler for one existing capability — `SignCSR` — gating
whether that call succeeds, not exposing a new one. The route itself is
documented in [`../certificate-authority/api.md`](../certificate-authority/api.md):

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded | Auth |
|---|---|---|---|---|---|---|
| Sign CSR | `POST /api/v1/ca/sign-csr` | `SignCSR` | same as REST | **MISSING — docs/13** | `SignCSR` | `certs:generate` |

## The fields this feature reads on that request

`transport.SignCSRRequest` (`pkg/api/transport/types.go:1327-1333`) carries
four optional fields, present on every transport that reaches `SignCSR`
because they live on the shared request struct, not a REST-only body:

| Field | JSON | Meaning |
|---|---|---|
| `AttestationFormat` | `attestation_format` | wire format tag: `"tpm2"`, `"yubikey-piv"`, `"android-key-attestation"` |
| `AttestationChain` | `attestation_chain` | leaf-first DER certificate chain |
| `AttestationData` | `attestation_data` | format-specific evidence (carried through; not read by this feature — see below) |
| `AttestationSig` | `attestation_sig` | signature over `AttestationData` (likewise carried through, not read here) |
| `AttestationNonce` | `attestation_nonce` | the challenge `enforceAttestationInvariants` compares against the format's attested challenge |

A request with `AttestationChain` empty is `ErrAttestationVerificationFailed`
("empty attestation chain"); a request with `AttestationFormat` set to a
format with no configured verifier is `ErrAttestationFormatNotConfigured` if
*some* formats are configured, or `ErrAttestationNotConfigured` if *none*
are — the distinction exists so an operator can tell "this deployment has no
attestation anchors at all" from "this deployment has anchors, but not for
what you sent" (`servicer_ca.go:306-318`).

`AttestationData`/`AttestationSig` are accepted on the wire but not consumed
by `verifyCSRAttestation`/`enforceAttestationInvariants` — those two fields
belong to the `AttestationStatement.Signature` shape this feature's
`Verifier.Verify`/`VerifySignature` can check, which the CSR-gate path does
not call (see [`architecture.md`](architecture.md) §"Two checks belong to
different call paths"). Do not infer that setting them changes CSR-signing
behavior today.

## Repository signing keys

The repository signing-key verbs (#1697) are the one appraisal capability
served on every transport. Each acts on the caller's tenant. Without an
Appraiser wired, each returns `ErrNotConfigured`.

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded | Auth |
|---|---|---|---|---|---|---|
| Bind a repository | `PUT /api/v1/attestation/signing-keys` | `SetSigningKeyBinding` | same as REST | `attestation.signing_key.set` | `SetSigningKeyBinding` | `attestation_signing_keys:bind` |
| List bindings | `GET /api/v1/attestation/signing-keys` | `ListSigningKeyBindings` | same as REST | `attestation.signing_key.list` | `ListSigningKeyBindings` | `attestation_signing_keys:list` |
| Read a binding | `GET /api/v1/attestation/signing-keys/binding?repository=` | `GetSigningKeyBinding` | same as REST | `attestation.signing_key.get` | `GetSigningKeyBinding` | `attestation_signing_keys:get` |
| Remove a binding | `DELETE /api/v1/attestation/signing-keys/binding?repository=` (204) | `DeleteSigningKeyBinding` | same as REST | `attestation.signing_key.delete` | `DeleteSigningKeyBinding` | `attestation_signing_keys:bind` |
| Resolve a repository's key | `GET /api/v1/attestation/signing-keys/resolve?repository=` | `ResolveSigningKey` | same as REST | `attestation.signing_key.resolve` | `ResolveSigningKey` | `attestation_signing_keys:get` |

USB returns `ErrNotSupported`. A repository path contains slashes
(`"org/app"`), so the REST routes take it as the `repository` query
parameter (`pkg/api/rest/wire/signing_key.go:16`–`:27`). The gRPC methods
are `pkg/api/grpc/proto/xkmsv1/xkms.proto:1002`–`:1023`. MCP routes them in
`pkg/api/mcp/server.go:535`–`:539`. The TypeScript SDK serves them as
`client.signingKeys` (`sdk/ts/src/clients/signingKey.ts`).

Fields (JSON): a binding is `repository`, `key_id`, `backend` (omitted when
it is the default backend) and `updated_at`. A resolution is `repository`,
`key_id`, `backend` and `default`, where `default` is true when the key is
the release key `release-signing`.

| Condition | Sentinel | Class (HTTP) |
|---|---|---|
| no Appraiser wired | `ErrNotConfigured` | unavailable (503) |
| caller lacks the permission | `ErrSigningKeyForbidden` | permission denied (403) |
| bad repository path, key ID or backend; nil request | `ErrInvalidRepository`, `ErrInvalidSigningKey`, `ErrNilRequest` | invalid argument (400) |
| get or delete of an unbound repository | `ErrRecordNotFound` | not found (404) |

The classes come from `apierrors.SigningKeySentinelClasses`
(`pkg/api/apierrors/tables.go:330`).

## Generation is a separate capability, already documented

`AttestKey` (generating the statement this feature can verify) is a
`CryptoServicer` capability with its own full transport row —
`POST /api/v1/attest`, gRPC `AttestKey`, MCP `xkms.attestKey`, embedded
`AttestKey` — documented in
[`../key-management/api.md`](../key-management/api.md). This folder does not
repeat that row.

## Error mapping

| Condition | Sentinel | HTTP-equivalent shape |
|---|---|---|
| no attestation anchors configured for any format | `ErrAttestationNotConfigured` | 400-class, `errs.Detail` |
| anchors configured, but not for the requested format | `ErrAttestationFormatNotConfigured` | 400-class |
| empty attestation chain | `ErrAttestationVerificationFailed` | 400-class |
| chain fails to parse, or fails structural/anchoring validation | `ErrAttestationVerificationFailed` (wrapping `VerifyChainAnchored`'s cause, e.g. `ErrNoTrustAnchors`/`ErrChainNotAnchored`) | 400-class |
| evidence does not bind to the CSR's key | `ErrAttestationKeyNotBound` (wraps `attestation.ErrKeyNotBound`) | 400-class |
| challenge does not match / format cannot carry one but got one | `ErrAttestationStale` (wraps `attestation.ErrStaleEvidence`) | 400-class |
| format's binding mechanism cannot be checked with the evidence given | `ErrAttestationUnbindableFormat` (wraps `attestation.ErrBindingUnavailable`, unless `AllowUnboundAttestationFormats(true)` is set) | 400-class |
| a verifier registered with no trust anchors | `ErrAttestationVerifierInvalid` — refused at `SetAttestationVerifiers`, before any request can hit it | fatal at server startup, not a request-time error |

## A second route also calls this feature

`POST /api/v1/ca/tcg/sign-csr` (`SignTCGCSR`,
[`../certificate-authority/api.md`](../certificate-authority/api.md)) calls
`attestation.VerifyInvariants` too, for the TPM2 format specifically
(`pkg/ca/tcg.go:379-390`) — the TCG-CSR-IDEVID carrier and the generic
`SignCSR` carrier above both answer to the same gate, by design (see
[`architecture.md`](architecture.md)). Failures there surface as
`ca.ErrTCGCSRVerificationFailed` (`pkg/ca/errors.go:289`), not the
`ca:`-prefixed `pkg/xkms` sentinels in the table above — same underlying
`pkg/attestation` cause (`ErrKeyNotBound`/`ErrStaleEvidence`/
`ErrUnknownFormat`/`ErrBindingUnavailable`), different wrapper, because the
two routes live in different packages (`pkg/ca` vs `pkg/xkms`). This TCG
carrier supplies no `ExpectedChallenge` — its certification is produced when
the IDevID is created, before a CA picks a challenge; freshness there comes
from credential activation and the quote instead
(`pkg/ca/tcg.go:375-378`).

## Versioning

Nothing here is versioned independently — these fields ride on `SignCSR`'s
own request/response shape and its own compatibility rules
([`../certificate-authority/api.md`](../certificate-authority/api.md)). The
attestation format vocabulary (`tpm2`, `yubikey-piv`,
`android-key-attestation`) is additive: a new format needs a new
`formatProfile` entry in `pkg/attestation/invariants.go` and a config entry
in `attestation.formats`, not a wire-shape change.
