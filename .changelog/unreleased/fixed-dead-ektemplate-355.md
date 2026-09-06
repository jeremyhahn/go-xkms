- **The IAK, IDevID and LDevID attribute builders no longer assign a dead
  Endorsement Key template into `TPMAttributes.Template`** (#355).
  `pkg/tpm2/config.go`. `IAKAttributesFromConfig`, `IDevIDAttributesFromConfig`
  and `LDevIDAttributesFromConfig` copied `RSAEKTemplate`/`ECCEKTemplate`
  (Restricted, `SignEncrypt: false`) — plus the platform-policy `AuthPolicy` —
  into a field nothing on those key types' creation paths ever reads:
  `CreateIAK` builds its restricted signing template from scratch and
  `CreateIDevID` selects the dedicated unrestricted IDevID/LDevID template
  constants, while only the EK and SRK creation paths consume
  `TPMAttributes.Template`. No key was ever created from the stale value, but
  the contradiction between descriptor and code is exactly what produced the
  #355 misdiagnosis of restricted, non-signing identity keys — this closes
  that misdiagnosis vector. `EKAttributesFromConfig` keeps its template, which
  `CreateEK` genuinely consumes; function signatures (including the now
  compatibility-only `policyDigest` parameters) and the `PlatformPolicy`
  field are unchanged. Verified by tracing every `TPMAttributes.Template`
  reader in the repository to EK/SRK/seal-path attributes only, by a new
  regression test asserting the three builders leave `Template` as the zero
  `TPMTPublic` (red when the assignment is re-introduced) while the EK builder
  still bakes the policy digest into its template, and by the full `pkg/tpm2`
  simulator suite.
