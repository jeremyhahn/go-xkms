- **`xkey device enroll-phone` requested certificate profile "idevid", which
  no registry entry matches, so phone enrolment could not issue a certificate
  at all** (#241). `xkey/cmd/xkey/cmd/device_enroll_phone_ca.go`,
  `xkey/cmd/xkey/cmd/ca.go`.

  The string travelled untouched from `enrollmentCertProfile` through
  `SignCSRRequest.Profile` to `ca.Profiles().Get`, which correctly fails
  closed with `ErrProfileNotFound` — there is no fallback profile, so the
  command errored instead of issuing something wrong. The path is behind
  `//go:build ble`, which is why no default build caught it.

  The constant now names the `client` profile. The credential is an LDevID in
  the IEEE 802.1AR sense presented by the phone as a client of the enterprise
  CA, and `client` supplies exactly what that needs: DigitalSignature key
  usage, ClientAuth EKU, finite validity — the device identity travels in the
  CSR subject and the re-attestation cadence in `ValidityDays`. `tcg-idevid`
  was rejected deliberately: it stamps TCG policy OIDs asserting TPM residency
  a phone's Android Keystore key does not have, and models a never-expiring
  manufacturer IDevID where this credential's expiry is the re-attestation
  cadence. `fido2-attestation` certifies an authenticator attestation key, not
  an identity key. Registering a new "idevid" profile would have duplicated
  `client` under a second name.

  The audit of the other profile names `cmd/` hardcodes found one more dead
  one: `xkey ca issue --help` advertised "idevid" as an available profile, so
  a user who followed the help hit the same `ErrProfileNotFound`. The help
  now lists only registered profiles.

  Tests now resolve `enrollmentCertProfile`, every profile `ca issue` help
  advertises, and the `cert request` / `agent` profile defaults against the
  same default registry the CA constructs, so an unregistered profile name in
  this package can never again survive to runtime; a semantics test pins
  DigitalSignature + ClientAuth + CA:false on the phone credential. The
  ble-gated tests are named in the CI gate that runs `cmd/xkey/cmd` under
  `-tags ble`, since that package is otherwise compiled but never run there.
