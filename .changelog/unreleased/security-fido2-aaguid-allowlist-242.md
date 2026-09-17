- **The `fido2-attestation` profile certifies only authenticator models the
  operator has vouched for (#242).** The profile copied `id-fido-gen-ce-aaguid`
  out of the request verbatim, so any device that cleared the provisioning
  ceremony — physical possession plus the Security Officer PIN — could name any
  AAGUID it liked and the CA would certify it. That made an xkms-issued
  attestation certificate useless as evidence of *model*: a policy such as
  "only this authenticator may register as an administrator" was unenforceable,
  because an insider holding an SO PIN could provision a software device
  claiming a hardware AAGUID and receive a certificate saying so.
  `NewFIDO2AttestationProfile` now takes the AAGUIDs it may certify and refuses
  every other one with `ErrFIDO2AttestationAAGUIDNotPermitted`, naming the
  refused AAGUID in RFC 4122 form and pointing at the profile to register to
  admit it. Both routes into the extension are covered: the device's
  `CSRExtensions` and a direct caller's `ExtraExtensions`, which the issuer
  would otherwise append unchecked.

  Called with no arguments the profile permits exactly `ca.XKeyAAGUID`, the one
  authenticator this project ships, which is what `NewDefaultProfileRegistry`
  installs; there is no argument that permits every AAGUID, so the control
  cannot be switched off by leaving it unconfigured. The listed AAGUIDs are the
  whole policy and `ca.XKeyAAGUID` is not unioned into an operator's list. An
  operator running other models registers a profile built with the full set
  under `ProfileNameFIDO2Attestation` — a deliberate administrative act,
  distinct from provisioning, which is how the first device of a newly approved
  model is admitted. Files: `pkg/ca/profile_fido2.go`, `pkg/ca/errors.go`,
  `pkg/ca/profile_fido2_test.go`, `docs/ca/architecture.md`. Verified by
  `go test ./pkg/ca/...`: the shipped model issues, an unlisted model is
  refused by both routes, an explicit list admits exactly what it names, and
  the refusal text carries the AAGUID.
