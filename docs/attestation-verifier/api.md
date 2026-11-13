# Attestation Verifier — API

> **Status: NORMATIVE** · Feature: `attestation-verifier` · Module: `go-xkms` · Last verified: 2026-10-25

Transport shapes:
[`../key-management/api.md`](../key-management/api.md).

## Not a transport of its own

`pkg/attestation` has no REST route, gRPC method, QUIC handler or MCP tool
(its `appraisal` subpackage's [Verifier](#attestation-verifier) and
[signing-key](#repository-signing-keys) verbs do).
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

## Attestation Verifier

The Verifier verbs (#1608) manage a tenant's trust anchors and signed
reference values and appraise a TPM quote against them. Each acts on the
caller's tenant.

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded | Auth |
|---|---|---|---|---|---|---|
| Store an endorsement | `PUT /api/v1/attestation/endorsements` | `PutAttestationEndorsement` | same as REST | `attestation.endorsement.put` | `PutAttestationEndorsement` | `attestation_endorsements:create` |
| List endorsements | `GET /api/v1/attestation/endorsements?kind=` | `ListAttestationEndorsements` | same as REST | `attestation.endorsement.list` | `ListAttestationEndorsements` | `attestation_endorsements:list` |
| Remove an endorsement | `DELETE /api/v1/attestation/endorsements/{name}` (204) | `DeleteAttestationEndorsement` | same as REST | `attestation.endorsement.delete` | `DeleteAttestationEndorsement` | `attestation_endorsements:delete` |
| Store reference values | `PUT /api/v1/attestation/reference-values` | `PutAttestationReferenceValues` | same as REST | `attestation.reference_values.put` | `PutAttestationReferenceValues` | `attestation_reference_values:create` |
| Read reference values | `GET /api/v1/attestation/reference-values/{name}` | `GetAttestationReferenceValues` | same as REST | `attestation.reference_values.get` | `GetAttestationReferenceValues` | `attestation_reference_values:get` |
| List reference values | `GET /api/v1/attestation/reference-values` | `ListAttestationReferenceValues` | same as REST | `attestation.reference_values.list` | `ListAttestationReferenceValues` | `attestation_reference_values:list` |
| Remove reference values | `DELETE /api/v1/attestation/reference-values/{name}` (204) | `DeleteAttestationReferenceValues` | same as REST | `attestation.reference_values.delete` | `DeleteAttestationReferenceValues` | `attestation_reference_values:delete` |
| Appraise a quote | `POST /api/v1/attestation/appraise` | `AppraiseAttestationQuote` | same as REST | `attestation.quote.appraise` | `AppraiseAttestationQuote` | `attestation_verifier:verify` |

USB returns `ErrNotSupported`. The REST routes are
`pkg/api/rest/routes.go:475`–`:482`, and the wire client is
`pkg/api/rest/wire/attestation_appraisal.go`. The gRPC methods are
`pkg/api/grpc/proto/xkmsv1/xkms.proto:1004`–`:1042`. MCP routes them in
`pkg/api/mcp/server.go:546`–`:553`; the two MCP deletes answer with the
request they removed. The TypeScript SDK serves them as `client.attestation`
(`sdk/ts/src/clients/attestationAppraisal.ts`). The eight permissions are
self-scoped (`pkg/apimodule/module_scopes.go`).

Fields (JSON) are those of `pkg/attestation/appraisal/verifier.go:95`–`:231`;
Go `[]byte` fields are base64. An endorsement is `name`, `kind` (`ak-root` or
`reference-signer`), and `certificate_pem` or `public_key_pem`. Reference
values are stored from `name`, `signed_corim` (a COSE_Sign1 CoRIM) and an
optional `repository`. A quote appraisal sends `ak_certificate_pem`, `quote`,
`signature`, `nonce`, `pcrs` (PCR index to value), an optional `event_log`
and the `reference_values` name. It answers with `verified`,
`cryptographic_failure` and one `checks` entry per check, each `pass`,
`forged`, `absent` or `skipped`. A quote that fails appraisal is a result
with `verified` false, not an error.

| Condition | Sentinel | Class (HTTP) |
|---|---|---|
| no Appraiser wired; store outage | `ErrNotConfigured`, `ErrStoreUnavailable` | unavailable (503) |
| nil request; bad name, repository, endorsement or AK intermediate; a CoRIM that no endorsement or repository key verifies | `ErrNilRequest`, `ErrInvalidName`, `ErrInvalidRepository`, `ErrEndorsementInvalid`, `ErrInvalidAKIntermediate`, `ErrReferenceValuesRejected`, `ErrSigningKeyRefused` | invalid argument (400) |
| get or delete of an absent record | `ErrRecordNotFound` | not found (404) |

The classes come from `apierrors.AttestationAppraisalSentinelClasses`
(`pkg/api/apierrors/attestation_appraisal.go:28`). A REST body or MCP
parameter object that does not decode is invalid argument before it reaches
the Verifier.

## Repository signing keys

The repository signing-key verbs (#1697) are served on every transport.
Each acts on the caller's tenant. Without an
Appraiser wired, each returns `ErrNotConfigured`.

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded | Auth |
|---|---|---|---|---|---|---|
| Bind a repository | `PUT /api/v1/attestation/signing-keys` | `SetSigningKeyBinding` | same as REST | `attestation.signing_key.set` | `SetSigningKeyBinding` | `attestation_signing_keys:bind` |
| List bindings | `GET /api/v1/attestation/signing-keys` | `ListSigningKeyBindings` | same as REST | `attestation.signing_key.list` | `ListSigningKeyBindings` | `attestation_signing_keys:list` |
| Read a binding | `GET /api/v1/attestation/signing-keys/binding?repository=` | `GetSigningKeyBinding` | same as REST | `attestation.signing_key.get` | `GetSigningKeyBinding` | `attestation_signing_keys:get` |
| Remove a binding | `DELETE /api/v1/attestation/signing-keys/binding?repository=` (204) | `DeleteSigningKeyBinding` | same as REST | `attestation.signing_key.delete` | `DeleteSigningKeyBinding` | `attestation_signing_keys:bind` |
| Resolve a repository's key | `GET /api/v1/attestation/signing-keys/resolve?repository=` | `ResolveSigningKey` | same as REST | `attestation.signing_key.resolve` | `ResolveSigningKey` | `attestation_signing_keys:get` |
| Sign a CoRIM with a repository's key | `POST /api/v1/attestation/signing-keys/sign-corim` | `SignCoRIM` | same as REST | `attestation.signing_key.sign_corim` | `SignCoRIM` | `attestation_signing_keys:sign` |

`SignCoRIM` resolves the repository's key like `ResolveSigningKey` and wraps
the unsigned CoRIM in a COSE_Sign1 with that key, draft-ietf-rats-corim-11
§4.2 (`XKMSService.SignCoRIM`, `pkg/xkms/servicer_signing_keys.go:219`;
`refvalue.Sign`, `pkg/attestation/refvalue/sign.go:69`). A malformed CoRIM or
signer metadata is a 400 / `InvalidArgument`; a missing key is a 503 /
`FailedPrecondition`. `sdk/go/evidence` re-exports the signer as `SignCoRIM`
(`sdk/go/evidence/refvalue.go:58`); `sdk/ts` posts it as `signingKeys.signCoRIM`.

USB returns `ErrNotSupported`. A repository path contains slashes
(`"org/app"`), so the REST routes take it as the `repository` query
parameter (`pkg/api/rest/wire/signing_key.go:16`–`:27`). The gRPC methods
are `pkg/api/grpc/proto/xkmsv1/xkms.proto:1052`–`:1073`. MCP routes them in
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

## Host and container evidence (embedded)

`AppraiseHost` and `AppraiseContainer` are Go calls with no wire form. Their
evidence takes the AK certificate in `AKCertificate` and, when an
intermediate CA issued it, those CA certificates in `AKIntermediates`
(issuer first, leaf excluded); the chain must reach a stored `ak-root`. A nil
entry in `AKIntermediates` is refused with `ErrInvalidAKIntermediate`.

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
