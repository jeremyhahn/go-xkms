# Attestation verifier: the appraisal verbs on MCP and QUIC (row 1660, slice 2)

Objective: serve the 8 attestation appraisal verbs from slice 1
(docs/plans/attestation-verifier-rest.md) over MCP (server handlers and client
transport) and through the QUIC client transport, gated by the same
resource:action pair as each REST route, so `restOnlyPermissions` is empty again.

## Methods

| MCP method | resource:action |
|---|---|
| attestation.endorsement.put | attestation_endorsements:create |
| attestation.endorsement.list | attestation_endorsements:list |
| attestation.endorsement.delete | attestation_endorsements:delete |
| attestation.reference_values.put | attestation_reference_values:create |
| attestation.reference_values.get | attestation_reference_values:get |
| attestation.reference_values.list | attestation_reference_values:list |
| attestation.reference_values.delete | attestation_reference_values:delete |
| attestation.appraise | attestation_verifier:verify |

## Tests

- pkg/api/mcp/handlers_attestation_appraisal_test.go: round trip per resource,
  one appraise call, refusal without the pair, unknown name maps to not-found,
  no appraiser fails with the unsupported error.
- pkg/api/transport/mcp/transport_attestation_appraisal_test.go: tool names,
  server refusal surfaces, not connected returns ErrNotConnected.
- pkg/api/transport/quic/transport_attestation_appraisal_test.go: nil request
  refused, not connected returns ErrNotConnected.
- pkg/apimodule/module_grants_test.go: `restOnlyPermissions` empty.

## Checks

- go test -tags "codec_cbor codec_json codec_msgpack" on pkg/api/mcp,
  pkg/api/transport/mcp, pkg/api/transport/quic, pkg/apimodule
- cd sdk/go && go build ./...
- make lint

## Results

Results to follow.

## Out of scope (remaining slice)

gRPC and the Unix socket (proto change, pbconv) and USB.
