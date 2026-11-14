- **`pkg/factor/fido2`'s tests test each behaviour by one path** (#1794). Four
  tests that repeated another kept test's path and assertions are removed:
  `TestLocalCeremony_Enroll_UnwiredSubsystem` (kept:
  `TestNewLocalCeremony_NilHandlerRefuses`),
  `TestCredentialFromAttestation_MalformedDocument` (kept:
  `TestLocalCeremony_SelectsByHint`, whose `assertStubParseFailure` asserts the
  parse failure through `Enroll`), `TestLocalCeremony_AvailableRequiresAuthenticator`
  and `TestFIDO2Factor_Name` (kept: `TestNewWithLocalCeremony_DelegatesAvailability`).
  Every refusal, decoy, PIN, origin, relying-party and hint-selection test
  stays. No production code changes.
