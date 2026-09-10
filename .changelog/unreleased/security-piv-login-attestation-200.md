- **SECURITY: the module's PIV login proves the key is on a smartcard (#200).**
  `POST /api/v1/auth/login/piv` authenticated on a TLS client-certificate
  binding plus an optional issuer-DN string match, and a DN is not evidence:
  a self-signed software key could assert any issuer. The exchange now accepts
  a certificate as hardware-backed only when some certificate the client
  presents chains to the operator-configured PIV attestation anchor
  (`auth.piv_login.attestation_roots`, with optional
  `attestation_intermediates`; `AttestationRoots` / `AttestationIntermediates`
  on `PIVLoginOptions` and the SDK's `ServiceModulePIVLoginOptions`) AND
  carries the login certificate's SubjectPublicKeyInfo, so a genuine
  attestation borrowed from another card launders nothing; presented
  certificates are chain material, never anchors. **BREAKING for
  configuration**: with no anchor the exchange refuses every login, and a
  config with `piv_login.enabled` and neither `attestation_roots` nor
  `allow_unattested: true` no longer validates. The minted token records
  `attest_level` (`hardware` or `unattested`, carried through refresh) and the
  audit event for `auth.login.piv` carries the operator-facing reason for a
  refusal. A bundle that does not load fails the daemon at composition.
