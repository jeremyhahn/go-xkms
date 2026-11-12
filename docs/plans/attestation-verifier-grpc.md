# Attestation verifier: the appraisal verbs on gRPC and the Unix socket (row 1660, slice 3)

Objective: serve the 8 attestation appraisal verbs from slices 1-2
(docs/plans/attestation-verifier-rest.md, docs/plans/attestation-verifier-mcp.md)
as gRPC RPCs in pkg/api/grpc/proto/xkmsv1/xkms.proto, served by the gRPC Service
(also served on the Unix socket by pkg/api/unix/grpc_server.go) and called by the
gRPC and Unix client transports, gated by the same resource:action pair as each
REST/MCP route. No new resource or action string.

## RPCs

| RPC | resource:action |
|---|---|
| PutAttestationEndorsement | attestation_endorsements:create |
| ListAttestationEndorsements | attestation_endorsements:list |
| DeleteAttestationEndorsement | attestation_endorsements:delete |
| PutAttestationReferenceValues | attestation_reference_values:create |
| GetAttestationReferenceValues | attestation_reference_values:get |
| ListAttestationReferenceValues | attestation_reference_values:list |
| DeleteAttestationReferenceValues | attestation_reference_values:delete |
| AppraiseAttestationQuote | attestation_verifier:verify |

## Proto messages

Mirroring pkg/api/transport/types_attestation_appraisal.go field for field
(bytes for DER/CBOR blobs): AttestationEndorsement,
PutAttestationEndorsementRequest/Response, ListAttestationEndorsementsRequest/Response,
DeleteAttestationEndorsementRequest/Response, AttestationReferenceValues,
PutAttestationReferenceValuesRequest/Response, GetAttestationReferenceValuesRequest/Response,
ListAttestationReferenceValuesRequest/Response, DeleteAttestationReferenceValuesRequest/Response,
AppraiseAttestationQuoteRequest/Response, AttestationResult.

## Tests

- pkg/api/grpc/service_attestation_appraisal_test.go: round trip per resource,
  one appraise call, PermissionDenied without the pair, NotFound for an unknown
  name, no appraiser maps to the not-configured code.
- pkg/api/grpc/pbconv/attestation_appraisal_test.go: round trip per message, nil in nil out.
- pkg/api/transport/grpc and pkg/api/transport/unix transport_attestation_appraisal_test.go:
  nil request refused, not connected returns ErrNotConnected.
- pkg/api/grpc/authz_golden_test.go: the 8 rows.

## Checks

- go test -count=1 -tags "codec_cbor codec_json codec_msgpack" ./pkg/api/grpc/...
  ./pkg/api/transport/grpc/... ./pkg/api/transport/unix/... ./pkg/api/unix/... ./pkg/apimodule/...
- cd sdk/go && go build ./...
- make lint

## Results

- go test (grpc, pbconv, transport/grpc, transport/unix, api/unix, apimodule): pass, at feat 2ef6f7964.
- cd sdk/go && go build ./...: pass.
- make lint: pass (actionlint, then golangci-lint 0 issues on every module and tag set).

Generated with protoc 36.2 (libprotoc 36.2), protoc-gen-go v1.36.12 and
protoc-gen-go-grpc v1.6.2 via make proto.

Notes:

- The appraisal error table now has three copies: REST, MCP and gRPC
  (pkg/api/grpc/service_attestation_appraisal.go:40-51). Moving it into
  pkg/api/apierrors, as SigningKeySentinelClasses already is, is a follow-up.
- The Unix socket serves the same gRPC Service (pkg/api/unix/grpc_server.go:338),
  so it needs no handler of its own.

## Out of scope (remaining)

USB (pkg/api/transport/usb) is the only transport left; password-vault-usb is blocked.
