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

## Checks

- go test -count=1 -tags "codec_cbor codec_json codec_msgpack"
  ./pkg/api/rest/... ./pkg/api/transport/... ./pkg/xkms/...
- go build ./... in sdk/go
- make lint

## Out of scope

gRPC, Unix, QUIC, USB and MCP: a later slice. No proto change, and no new
resource or action string.

## Remaining transports

SPEC.md:43 still lists gRPC, Unix, QUIC, USB and MCP for these 8 verbs. The
brief counted 9 verbs; the service has 8.

## Results

- go test -count=1 -tags "codec_cbor codec_json codec_msgpack" ./pkg/api/rest/... ./pkg/api/transport/... ./pkg/xkms/...: pass (14 packages ok).
- go build ./... in sdk/go: pass.
- make lint: pass (0 issues on every tag set and module).

## Permission scopes (lane att1660-scopes)

lane-verify gate 10 failed in pkg/apimodule: the 8 permissions had no
declared scope and were on no gRPC or MCP surface.

- module_scopes.go: the 8 pairs are ScopeSelf, like attestation_signing_keys
  (the service binds every call to the caller's tenant).
- module_grants_test.go: the 8 pairs are in restOnlyPermissions, reason row
  1660 (REST and embedded only; gRPC and MCP are a later slice, which must
  drop them from that set).
- go test -count=1 -tags "codec_cbor codec_json codec_msgpack"
  ./pkg/apimodule/ ./pkg/api/rest/: pass (both packages ok).
