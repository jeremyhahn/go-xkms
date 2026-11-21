# Attestation Verifier over REST and the embedded transport (#1660)

Objective: serve the attestation appraisal verbs of `XKMSService`
(pkg/xkms/servicer_attestation.go) over REST and the embedded transport,
and expose them in sdk/go, so a client reaches a server's Verifier
(docs/SPEC.md:43, "the transport routes are not yet in").

The service has eight appraisal verbs (the brief counted nine): endorsement
put/list/delete, reference values put/get/list/delete, and quote appraisal.

## Routes

All paths are under /api/v1. Each route is `permIf`-gated on an existing
`auth.Resource*` / `auth.Action*` pair, and the guard reports whether the
server has the appraisal handlers wired (as `hasSigningKeys` does).

| Method | Path | Verb | resource:action |
|---|---|---|---|
| PUT | /attestation/endorsements | PutAttestationEndorsement | attestation_endorsements:create |
| GET | /attestation/endorsements?kind= | ListAttestationEndorsements | attestation_endorsements:list |
| DELETE | /attestation/endorsements?name= | DeleteAttestationEndorsement | attestation_endorsements:delete |
| PUT | /attestation/reference-values | PutAttestationReferenceValues | attestation_reference_values:create |
| GET | /attestation/reference-values | ListAttestationReferenceValues | attestation_reference_values:list |
| GET | /attestation/reference-values/entry?name= | GetAttestationReferenceValues | attestation_reference_values:get |
| DELETE | /attestation/reference-values/entry?name= | DeleteAttestationReferenceValues | attestation_reference_values:delete |
| POST | /attestation/appraise | AppraiseAttestationQuote | attestation_verifier:verify |

## Slices

1. Test commit: REST handler tests (a round trip for each verb, the tenant
   taken from the caller's identity, a caller without the permission
   refused, an unknown endorsement 404) and a parity test that the REST
   client and the embedded transport return the same result for each verb.
2. Feat commit: wire types, handlers, routes, transport interface, REST
   client, embedded transport, sdk/go exposure.
3. docs/attestation-verifier/api.md route list; changelog entry.

## Out of scope

gRPC, Unix, QUIC, USB and MCP: a later slice. No proto change, and no new
resource or action string.

## Permission scopes (lane att1660-scopes)

lane-verify gate 10 failed in pkg/apimodule: the 8 permissions had no
declared scope. module_scopes.go makes the 8 pairs ScopeSelf, like
attestation_signing_keys (every call is bound to the caller's tenant).

## Results (2026-11-16, HEAD bab0c9278, lane row1660a)

T="codec_cbor codec_json codec_msgpack", go test -count=1 -race -tags "$T":

- ./pkg/api/... ./pkg/apimodule/ ./pkg/auth/ ./cmd/xkmsctl/: pass.
- sdk/go: . ./transport/...: pass.
- xkey: ./pkg/gui/... ./pkg/pairing/... ./cmd/xkey/...: pass.
- make lint: pass (0 issues on every module and tag set; actionlint ok).

## SPEC text slice (lane rw2101a)

- Merge: main 852146763 merged into the row branch (0ac35e09d), ruling 1015.
- SPEC commit 1f08d126d: docs/SPEC.md row attestation-verifier names the REST, embedded, MCP, QUIC, gRPC and Unix socket transports, USB `ErrNotSupported`, `AttestationAppraisalService` in `transport.Client` and the xkmsctl verbs.
- Citations checked at HEAD: `pkg/api/rest/routes.go` `/attestation/*` routes, `pkg/api/mcp/server.go` `attestation.*` tools, gRPC `AppraiseAttestationQuote`, USB `transport_attestation_appraisal.go`, `pkg/api/transport/client.go` and the `sdk/go/transport/client.go` alias, `attestationAppraiseCmd` with the endorsement and reference-values commands.
- The xkey clause (`device_attest.go:261`, `tpm_ek.go:402`) stays: those calls build trust pools and verify chains in-process; they are not appraisals.
- Open question for the coordinator: must xkey appraise through the remote Client before the row ships?
- `refs/fold/attestation-verifier/lane/test/1794-attestation` (3707b8bca41f) is not in the lane clone, so the fold is left to the coordinator.
