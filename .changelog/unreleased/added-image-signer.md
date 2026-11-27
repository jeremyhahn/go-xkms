- **Image signing with the repository's key (owner ruling 134).**
  `XKMSService.SignImage` signs a container image with the key its repository
  resolves to in the caller's tenant, the tenant's release key
  (`release-signing`) unless a binding names another. The service CA issues
  the key a code-signing certificate in the tenant for each call, and the
  DSSE attestation is pushed as an OCI 1.1 referrer and to the cosign `.att`
  tag with the registry credentials in the request, which are used for that
  call only and wiped. It is served over REST
  (`POST /api/v1/attestation/signing-keys/sign-image`), gRPC, Unix, QUIC, MCP
  (`attestation.signing_key.sign_image`) and embedded, gated by
  `attestation_signing_keys:sign`; USB refuses it. The system tenant never
  signs images and is refused with `ErrSystemTenantImageSigning` (owner
  ruling 165); a deployment that must sign its first image creates a data
  tenant for it.
  `sdk/go` re-exports `SignAttestationImageRequest` and
  `SignedAttestationImage`, and the TypeScript SDK adds
  `client.signingKeys.signImage`. Code: `pkg/xkms/servicer_signing_keys.go`;
  docs: `docs/image-signing/architecture.md#the-signing-service`.
