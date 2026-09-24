- **TCG endorsement and attestation key certificates now carry their
  `tcg-kp-EKCertificate` / `tcg-kp-AIKCertificate` markers inside the
  certificate's standard ExtKeyUsage extension, and AK/IAK certificates now
  explicitly assert `BasicConstraints CA:false`.** `IssueEKCertificate`,
  `IssueAKCertificate` and the TCG-CSR-IDEVID IAK path (`SignTCGCSRIDevID` via
  `buildIAKExtensions`) previously wrote `tcg-kp-EKCertificate` (2.23.133.8.1)
  and `tcg-kp-AIKCertificate` (2.23.133.8.3) as standalone extensions under
  the OID's own `Id`. Both OIDs are Extended Key Usage purposes (RFC 5280
  section 4.2.1.12); a standalone extension is not where a conformant relying
  party looks, including go-webauthn's `"tpm"` attestation format verifier
  and this CA's own `requireTCGEKCertificateEKU` check run against a device's
  EK chain before IAK/IDevID issuance. Both OIDs are now carried in
  `UnknownExtKeyUsage` via the `tcg-ek`, `tcg-ak` and `tcg-iak` profiles
  (`tcgEKCertificateExtKeyUsage`, `tcgAIKCertificateExtKeyUsage`), and the
  `tcg-ak` / `tcg-iak` profiles now assert `BasicConstraintsValid` with
  `IsCA` false, satisfying WebAuthn L2 §8.3.1 requirements 4 and 5. The
  Subject-field requirement of that same profile (§8.3.1 requirement 2, "MUST
  be set to empty") is **not** addressed here: it directly conflicts with TCG
  TPM 2.0 Keys for Device Identity and Attestation v1.00 r12 §8's mandatory
  non-empty Subject, and with `pkg/certstore.CertStore` being keyed by
  `Subject.CommonName` — an architecture decision pending the owner's review,
  documented in `docs/ca/certificate-types.md`. Also fixed the same
  standalone-extension mistake in `ImportEndorsementKeyCertificate` and
  `EndorsementKeyCertificate`'s EK-OID presence check, which now shares
  `hasTCGEKCertificateEKU` with `requireTCGEKCertificateEKU`. Files:
  `pkg/ca/tcg.go`, `pkg/ca/profiles.go`, `pkg/ca/tcg_ek_trust.go`,
  `pkg/ca/tcg_test.go`, `pkg/ca/tcg_iak_certstore_test.go`,
  `pkg/ca/tcg_webauthn_profile_test.go`, `pkg/ca/certpolicy_test.go`,
  `test/integration/acme-tpm/ca_tcgcsr_integration_test.go`,
  `test/integration/acme-tpm/attestation_integration_test.go`,
  `docs/ca/certificate-types.md`. Refs go-xkms#715.
