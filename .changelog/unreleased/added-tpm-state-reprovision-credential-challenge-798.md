- **`TrustedPlatformModule` gains `State`, `ClearForReprovision`, and a
  software-verifiable EK credential challenge, so consumers (go-trusted-platform)
  no longer need their own private copies.** `State() (*ProvisioningState, error)`
  (`pkg/tpm2/provisioning_state.go`) is one classification: the TPMA_PERMANENT
  `ownerAuthSet`/`endorsementAuthSet`/`lockoutAuthSet` bits, which of
  EK/SSRK/IAK/IDevID/Platform SRK's configured persistent handles exist, and
  whether the Platform SRK's `authPolicy` matches the current
  `PlatformPolicyDigest`. `ClearForReprovision() (rebootRequired bool, err error)`
  (`pkg/tpm2/provision.go`) tries `TPM2_Clear` via the LOCKOUT hierarchy, then
  the PLATFORM hierarchy (for firmware that leaves it open, e.g. U-Boot and
  Raspberry Pi UEFI), then UEFI PPI `ForceClear`; `rebootRequired` is true only
  for the PPI path, and each refusal gets its own typed error
  (`ErrClearLockoutRefused`, `ErrClearPlatformRefused`). `ForceClear`'s single
  sysfs write now goes through an injectable seam (`ppiRequestWriter`) instead
  of `os.WriteFile` directly, so it is never exercised against a real host in
  a test. `NewCredentialChallenge(ekPub crypto.PublicKey, activationKeyName []byte)`
  and `ActivationKeyName(publicArea []byte)` (`pkg/tpm2/credential_challenge.go`)
  build a `TPM2_MakeCredential` challenge entirely in software, using go-tpm's
  own `tpm2.CreateCredential`/`tpm2.ImportEncapsulationKey`/`tpm2.ObjectName`
  rather than a hand-rolled KDFa/AES-CFB/HMAC construction, so a verifier (a CA,
  or an installer proving device possession before any identity key exists)
  needs no TPM of its own. `CreateActivationKey()` and
  `AnswerCredentialChallenge(key, challenge)` (`pkg/tpm2/activation_key.go`)
  are the device-side counterpart: a transient, unrestricted key in the null
  hierarchy (no hierarchy auth) that generalises `ActivateCredential`'s
  previously hardcoded IAK path — both now share one `activateCredential`
  helper (`pkg/tpm2/attestation.go`). `pkg/ca`'s `VerifyTCG_CSR_IDevIDBytes`
  is refactored onto `NewCredentialChallenge`/`ActivationKeyName` and no
  longer requires `SetTPM` to have been called; enroll-01's wire behaviour
  and existing tests are unchanged. All five are re-exported through `sdk/go`
  (type aliases and direct function re-exports). Simulator tests cover `State`
  on a fresh, provisioned and owned TPM; `ClearForReprovision` on all three
  paths (the PPI path through its seam); that a challenge built against one EK
  or one activation key's Name cannot be answered by a different EK or a
  different key on the same TPM; and that the software-built challenge is
  answered correctly by the real IAK-bound `ActivateCredential` path. Documented
  in `docs/tpm2/` and `docs/certificate-authority/engineering.md`. go-xkms#798.
