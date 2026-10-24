- **Attestation Verifier and reference-values store (go-xkms#1608).** The
  go-quicbaas Verifier moved here with its history, as
  `pkg/attestation/appraisal`. It appraises TPM quotes (`AppraiseQuote`),
  hosts (`AppraiseHost`) and container launches (`AppraiseContainer`) against
  a tenant's endorsements (AK roots and reference-value signers) and signed
  CoRIM reference values, kept per tenant in the qrdb DAO database
  `attestation`. `XKMSService` serves the endorsement, reference-value and
  appraisal verbs scoped to the caller's tenant. They are gated by the new
  permissions `attestation_endorsements`, `attestation_reference_values` and
  `attestation_verifier`, and return `ErrNotConfigured` until
  `SetAttestationAppraiser` wires an Appraiser. `sdk/go` re-exports the
  package as `NewAttestationAppraiser`, `NewAttestationAppraisalStore`, the
  request and result types and the `ErrAttestation*` errors, so go-quicbaas
  can consume it. The REST, gRPC and MCP routes are not yet in. Code:
  `pkg/attestation/appraisal`, `pkg/xkms/servicer_attestation.go`; docs:
  `docs/attestation-verifier/architecture.md#appraisal-the-rfc-9334-verifier`.
