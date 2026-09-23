- **`xkey/pkg/authenticator.ErrNotImplemented` renamed to
  `ErrCommandNotSupported` — BREAKING.** The sentinel is returned for three
  CTAP 2.1 commands this software authenticator declines:
  `authenticatorBioEnrollment` (no fingerprint sensor to enroll against),
  and `authenticatorClientPIN` / `authenticatorLargeBlobs` when disabled by
  `Config.EnablePIN` / `Config.EnableLargeBlobs`. All three are optional per
  CTAP 2.1, `authenticatorGetInfo` never advertises the corresponding
  capability (`bioEnroll`, `clientPin`/`pinUvAuthProtocols`, `largeBlobs`)
  when declined, and `Config.SetDefaults` forces `EnablePIN` whenever
  credential management is enabled — the only feature here that mints
  pinUvAuthTokens for UV without a PIN — so declining
  `authenticatorClientPIN` with `EnablePIN=false` never blocks a required
  capability. `CTAP1_ERR_INVALID_COMMAND` (`StatusInvalidCommand`) is the
  spec-correct response in all three cases; the rename only replaces the
  inaccurate "not implemented" name with one that says so. Files:
  `xkey/pkg/authenticator/authenticator.go`,
  `xkey/pkg/authenticator/cmd_clientpin.go`,
  `xkey/pkg/authenticator/cmd_largeblobs.go`,
  `xkey/pkg/authenticator/authenticator_test.go`,
  `xkey/pkg/authenticator/cmd_largeblobs_test.go`,
  `xkey/docs/fido2/authenticator-api.md`. Fixes go-xkms#663.
