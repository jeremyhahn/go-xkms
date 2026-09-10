- **BREAKING (Go SDK): `IAKAttributesFromConfig`, `IDevIDAttributesFromConfig` and `LDevIDAttributesFromConfig` no longer take a policy digest (#398).**
  The `*tpm2.TPM2BDigest` parameter only ever fed an EK template nothing
  read, and since the dead assignment went it was blank-named and documented
  as retained for signature stability. It is gone from the three builders in
  `pkg/tpm2` and therefore from their `sdk/go` re-exports; platform policy
  is still conveyed by the `PlatformPolicy` field and applied by
  `CreateIAK`/`CreateIDevID`, which compute the digest themselves. The two
  in-repo callers no longer compute a digest they did not use. Consumers
  that pass a digest (go-trusted-platform) drop the argument when they adopt
  the release that carries this.
