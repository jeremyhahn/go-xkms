- **`pkg/webauthn/client` is now the single headless WebAuthn ceremony driver
  in the stack, re-exported at `sdk/go/webauthnclient`** (go-xkms#721),
  consolidating three prior implementations. It gained a `RelyingParty` seam
  (`RelyingParty` interface, `BeginResult`, `AvailabilityChecker`) with two
  implementations — `HTTPRelyingParty` (the pre-existing browser-shaped
  `pkg/webauthn/http` routes, now `Client`'s default) and
  `TransportRelyingParty` (the SDK transport routes
  `/api/v1/webauthn/sdk/...`, driven over any `pkg/api/transport.Client`
  protocol binding) — and a `HardwareAdapter` `AuthenticatorAdapter`
  implementation that drives a real CTAP2 authenticator over HID through
  `pkg/fido2`, alongside the existing `SoftwareAdapter`. `pkg/fido2` gained
  the matching canonical options parser, `ParseWebAuthnRegistrationOptions`
  (mirroring the assertion-side `parseRequestOptions`), re-exported at
  `sdk/go/fido2`. `AuthenticatorAdapter.MakeCredential`/`GetAssertion` now
  take a `context.Context` and a `*CeremonyOptions` (options JSON, origin,
  CTAP2 PIN) instead of a bare `[]byte` — **BREAKING** for any direct caller
  of the pre-#721 `pkg/webauthn/client` interface, though none shipped
  before this change. `xkey`'s `fido2Ceremony`
  (`xkey/cmd/xkey/cmd/webauthn_ceremony.go`) and `xkmsctl`'s
  `webAuthnRegistration`/`loginAssertion` (`cmd/xkmsctl/user.go`,
  `admin.go`) now drive their local CTAP2 authenticator through this one
  `HardwareAdapter` instead of separately reimplementing WebAuthn
  options-JSON parsing and `pkg/fido2.FIDO2Handler` calls; xkey and xkmsctl
  keep their own server-side ceremony glue (SDK transport `BeginRegistration`
  / `FinishRegistration` / `BeginAuthentication` / `FinishAuthentication`
  calls) and PIN-failure classification. The hardware adapter now opens the
  local authenticator lazily, after the server-side ceremony calls have
  already succeeded, so a missing security key is never mistaken for a
  server-side failure and is never checked before it. Both modules still
  import only `sdk/go` (and its `fido2`/`secure`/`webauthnclient`
  subpackages), never `go-xkms/pkg`.