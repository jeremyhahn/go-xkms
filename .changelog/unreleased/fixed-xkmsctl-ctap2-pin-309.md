- **`xkmsctl` WebAuthn login and registration could not supply a CTAP2 PIN,
  so neither completed against a PIN-protected authenticator** (#309). The
  identical gap #299 closed for `xkey auth register`/`login`: the fido2 layer
  already carried `WebAuthnRegistrationOptions.PIN` and (since #299)
  `WebAuthnAuthenticationOptions.PIN`, but `xkmsctl user register`,
  `xkmsctl user login` and `xkmsctl admin create` never set either field, and
  offered no way to take a PIN in.

  The three verbs now accept the same three PIN sources, in the same
  precedence order, as the xkey verbs: `--pin-stdin` (preferred — the PIN
  stays out of the process list), the `XKMS_FIDO2_PIN` environment variable,
  then `--pin`. The resolver is re-stated in `cmd/xkmsctl/pin_input.go`
  because `xkmsctl` cannot import the xkey binary's command package; the flag
  names, precedence and empty-PIN semantics mirror xkey's exactly. The PIN is
  resolved before anything reaches the network, an empty `--pin-stdin` is
  rejected as operator input to correct, `CTAP2_ERR_PIN_REQUIRED` with no PIN
  supplied is reported as `ErrWebAuthnPINRequired` naming the sources rather
  than as a device fault, and a wrong PIN keeps its
  `fido2.PINAttemptsError` attempts-remaining annotation so a looming lockout
  is visible. `sdk/go/fido2` additionally re-exports `WebAuthnAssertion` so
  SDK callers can name `AuthenticateWebAuthn`'s result type.

  Files: `cmd/xkmsctl/pin_input.go` (new), `cmd/xkmsctl/user.go`,
  `cmd/xkmsctl/admin.go`, `cmd/xkmsctl/errors.go`, `sdk/go/fido2/fido2.go`.
  Verified by ceremony tests driving the real `pkg/fido2` stack against the
  real virtual authenticator with a PIN installed — registration and login
  complete with the PIN, fail named without it, and report remaining attempts
  on a wrong one — plus resolver-precedence and before-the-network guard
  tests; each fails on the unfixed code.

