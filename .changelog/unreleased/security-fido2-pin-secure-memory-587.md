- **BREAKING: the CTAP2 authenticator PIN carried through the FIDO2 WebAuthn
  ceremonies, the local enrollment driver, and the init ceremony's passkey
  enrollment is now sealed in protected memory (`*secure.Secret`) instead of
  held as a plaintext `string`.** `pkg/fido2.WebAuthnAuthenticationOptions.PIN`,
  `WebAuthnAssertionRequest.PIN`, `WebAuthnRegistrationOptions.PIN`,
  `pkg/factor/fido2.LocalEnrollRequest.PIN`, `xkey/cmd/xkey/cmd.CeremonyRequest.PIN`,
  `pkg/init.AdminEnrollmentConfig.PasskeyPIN` and
  `pkg/init.AdminEnrollmentContext.PasskeyPIN` all change from `string` to
  `*secure.Secret` (`go-xkms/sdk/go/secure`); a nil secret replaces the empty
  string as "no PIN configured". `fido2.Authenticator.AuthorizeWithPIN` and
  `GetPINToken` now take the PIN as `*secure.Secret` and open it only for the
  instant the CTAP 2.1 6.5.5.7 pinHashEnc computation needs its bytes, then
  destroy the buffer — the plaintext PIN is never held in a struct. Every
  caller is updated: `cmd/xkmsctl` (`resolvePINInput` now seals the resolved
  PIN, `webAuthnRegistration`/`loginAssertion`/`ceremonyFailure` take
  `*secure.Secret`), `xkey/cmd/xkey/cmd` (`sealCeremonyPIN` seals the PIN
  `resolvePINInput` resolves before it reaches `CeremonyRequest`;
  `ceremonyFailure` takes `*secure.Secret`), `pkg/init`/`pkg/factor/fido2`
  (the passkey enrollment plumbing), and `cmd/xkmsd` (`resolvePasskeyPIN`
  now seals the resolved passkey PIN). The `pre-existing` deferred-review
  allowlist lines for these fields are removed from
  `scripts/secure-analyzer-allowlist.txt`.
