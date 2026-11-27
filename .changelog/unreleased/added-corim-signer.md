- **CoRIM signer (owner ruling 134).** `XKMSService.SignCoRIM` signs an
  unsigned CoRIM with the repository's resolved signing key: the tenant's
  release key (`release-signing`) by default, or the key a binding names. The
  result is a COSE_Sign1 signed CoRIM (draft-ietf-rats-corim-11 §4.2), signed
  by `refvalue.Sign`. It is served on the caller's tenant over REST
  (`POST /api/v1/attestation/signing-keys/sign-corim`), gRPC, Unix, QUIC, MCP
  (`attestation.signing_key.sign_corim`) and embedded. USB returns
  `ErrNotSupported`. The call is gated by the new permission
  `attestation_signing_keys:sign`. `sdk/go` re-exports the request types and
  `evidence.SignCoRIM`, and the TypeScript SDK adds `signingKeys.signCoRIM`.
  Code: `pkg/attestation/refvalue/sign.go`,
  `pkg/xkms/servicer_signing_keys.go`; docs:
  `docs/attestation-verifier/architecture.md#repository-signing-keys`.
