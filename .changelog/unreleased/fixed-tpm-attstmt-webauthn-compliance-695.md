- **xkey's `tpm` FIDO2 attestation statement is now WebAuthn L2 §8.3 compliant,
  so a relying party no longer rejects it.** The TPM2 key backend now
  implements `keybackend.FIDO2AttestingKeyBackend` directly
  (`keybackend.TPM2AttestingBackend`), certifying each credential key with a
  real `TPM2_Certify` under the device's Initial Attestation Key (IAK) instead
  of leaving `certInfo` as the only populated field. The emitted `attStmt` now
  carries the full required set: `ver` ("2.0"), `alg` (the IAK signature's COSE
  algorithm — including the RSA/RSA-PSS families `EncodeCOSEPublicKey` did not
  previously encode), `x5c` (the IAK certificate), `sig` (the IAK's ordinary
  signature over `certInfo`), `certInfo` (the TPMS_ATTEST TPM2_Certify
  produced, with `extraData` set to the hash of `authData‖clientDataHash`
  using the IAK's own hash algorithm) and `pubArea` (the credential key's
  TPMT_PUBLIC, whose Name TPM2_Certify's `certInfo` attests to). A statement
  missing any required field now degrades to `"none"` rather than being sent
  incomplete. `keybackend.FIDO2AttestationStatement.TPMData` is removed —
  BREAKING for any direct caller — replaced by structured `Ver`, `CertInfo`
  and `PubArea` fields. Verified end to end against go-webauthn's own `tpm`
  format verifier (the library `pkg/webauthn`'s RP already embeds) using the
  TPM simulator: a real IAK-issued statement verifies, a tampered `pubArea`
  fails the Name binding check, and a `clientDataHash` the authenticator never
  signed for fails the `extraData` check. Files:
  `xkey/pkg/authenticator/keybackend/tpm_attestation.go`,
  `xkey/pkg/authenticator/keybackend/keybackend.go`,
  `xkey/pkg/authenticator/keybackend/cose.go`,
  `xkey/pkg/authenticator/keybackend/tpm_attestation_simulator_test.go`,
  `xkey/pkg/authenticator/cmd_makecredential.go`,
  `xkey/pkg/authenticator/cmd_makecredential_test.go`,
  `xkey/cmd/xkey/cmd/fido2.go`. Follow-up filed: xkms's IAK certificate
  issuance path (`xkey tpm iak csr` + CA countersign) does not yet emit a
  certificate conformant to WebAuthn L2 §8.3.1 / the TCG EK-Profile AIK
  requirements (empty Subject, TCG-manufacturer SAN, `tcg-kp-AIKCertificate`
  EKU) — until it does, a real device's `tpm` attestation is structurally
  correct but its AIK certificate will fail a strict relying party's
  certificate-profile check. Issue #695.
