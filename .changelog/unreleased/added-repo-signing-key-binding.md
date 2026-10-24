- **Per-repository signing keys (go-xkms#1697).** A tenant's images and
  signed CoRIM verify under its release key (`release-signing`) unless a
  binding names another tenant key for the repository. The bindings are kept
  in the qrdb DAO database `attestation`. A CoRIM that names a repository,
  and an image verified with `image.VerifierConfig.SigningKeys`, must be
  signed by that repository's key. Anything else is refused with
  `ErrSigningKeyRefused` or `image.ErrSigningKeyMismatch`. `XKMSService`
  serves set, get, list, delete and resolve on the caller's tenant over REST
  (`/api/v1/attestation/signing-keys`), gRPC, Unix, QUIC, MCP
  (`attestation.signing_key.*`) and embedded. They are gated by the new
  permissions `attestation_signing_keys:{bind,get,list}`, which the service
  enforces as well as the wire gate. `sdk/go` re-exports the types under an
  `Attestation` prefix, and the TypeScript SDK adds `client.signingKeys`.
  Code: `pkg/attestation/appraisal/signing_keys.go`,
  `pkg/xkms/servicer_signing_keys.go`; docs:
  `docs/attestation-verifier/architecture.md#repository-signing-keys`.
