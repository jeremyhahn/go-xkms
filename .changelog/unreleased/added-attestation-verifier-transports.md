- **Attestation Verifier on every transport (go-xkms#1608).** The endorsement,
  reference-value and quote-appraisal verbs are now served over REST
  (`/api/v1/attestation/endorsements`, `/api/v1/attestation/reference-values`,
  `POST /api/v1/attestation/appraise`), gRPC (`PutAttestationEndorsement` …
  `AppraiseAttestationQuote`) and MCP (`attestation.endorsement.*`,
  `attestation.reference_values.*`, `attestation.quote.appraise`). Every
  `sdk/go` client transport carries them, so a remote caller can appraise
  through the server's Verifier; USB returns `ErrNotSupported`. The
  TypeScript SDK adds `client.attestation`. The eight permissions are
  self-scoped. A server with no Appraiser answers unavailable. Code:
  `pkg/api/transport/types_attestation_appraisal.go`,
  `pkg/api/{rest,grpc,mcp}/*attestation_appraisal*.go`,
  `sdk/ts/src/clients/attestationAppraisal.ts`; docs:
  `docs/attestation-verifier/api.md#attestation-verifier`.
