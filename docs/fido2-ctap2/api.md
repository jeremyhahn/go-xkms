# FIDO2 / CTAP2 Client — API

> **Status: NORMATIVE** · Feature: `fido2-ctap2` · Repo: `go-xkms` · Last verified: 2026-08-19

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped".

## This is a client-side library

`pkg/fido2` speaks CTAP2 over USB HID to a physical authenticator attached to
the machine running the code. **Its wire protocol is CTAP2, not one of the six
portfolio transports**, and it has no server surface of its own — a remote
FIDO2 endpoint would be a request to touch someone else's security key.

What appears on the six transports is (a) the WebAuthn ceremonies the relying
party serves, and (b) the FIDO2 auth factor. Both are documented elsewhere:
[`../webauthn/api.md`](../webauthn/api.md) and
[`../auth-factors/api.md`](../auth-factors/api.md).

## In-process surface

| Capability | Embedded call | Wire |
|---|---|---|
| Construct a handler | `fido2.NewHandler(cfg, enumerator)` · `NewHandlerWithLogger(...)` | — |
| List authenticators | `Handler.ListDevices()` | CTAPHID enumeration |
| Wait for insertion | `Handler.WaitForDevice(ctx)` | HID hotplug |
| Enroll a credential | `Handler.EnrollKey(cfg)` | CTAP2 `authenticatorMakeCredential` |
| Assert + derive a key | `Handler.UnlockWithKey(cfg)` | CTAP2 `authenticatorGetAssertion` + `hmac-secret` |
| Release the device | `Handler.Close()` | — |

Config builders: `DefaultEnrollmentConfig(userName)`,
`DefaultAuthenticationConfig(credentialID, salt)`.

Device layer: `HIDDevice`, `HIDDeviceEnumerator`, `CTAPHIDDevice`,
`NewCTAPHIDDevice(device, config)`.

## The CTAP2 commands used

| Command | Package file | Purpose |
|---|---|---|
| `authenticatorGetInfo` | `ctap2.go` | capabilities, backing `xkmsctl fido2 info` |
| `authenticatorMakeCredential` | `ctap2.go` | enrollment |
| `authenticatorGetAssertion` | `ctap2.go` | authentication and `hmac-secret` derivation |
| `authenticatorClientPIN` | `pinuvauth.go` | PIN token exchange for user verification |

Extension used: **`hmac-secret`**. It is what makes `UnlockWithKey` return key
bytes rather than a boolean. Authenticator data parsing — flags, signature
counter, attested credential data — is `authdata.go`.

## The related wire surfaces

For completeness, the places FIDO2 does reach the network:

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| WebAuthn registration ceremony | `POST /api/v1/webauthn/registration/begin` · `/finish` | `BeginRegistration` · `FinishRegistration` | same as REST | **MISSING — docs/13** | `FIDO2Service.*` |
| WebAuthn authentication ceremony | `POST /api/v1/webauthn/login/begin` · `/finish` | `BeginAuthentication` · `FinishAuthentication` | same as REST | **MISSING — docs/13** | `FIDO2Service.*` |

The SDK also exposes `sdk/go/fido2` and `sdk/go/fido2_hid.go` for callers that
want the local-device surface through the SDK rather than the package.

## Error mapping

CTAP2 status codes surface as typed Go errors; there is no HTTP mapping because
there is no HTTP. The categories are in
[`engineering.md`](engineering.md) §Error semantics. Where these do reach a
transport — through the auth factor — they collapse into a uniform 401, so a
remote caller cannot tell "no device" from "wrong PIN".

## Pagination

Not applicable. `ListDevices()` returns the devices attached to this machine.

## Versioning and deprecation

CTAP2 is a FIDO Alliance standard; version negotiation is
`authenticatorGetInfo`, not something go-xkms defines.

**BREAKING (2026-09-22):** the `hmac-secret` derivation used to have a second,
insecure form selected by `--legacy-hmac-derivation`. That mode, the flag, and
`DerivationModeLegacyInsecure` have been deleted outright; the CTAP 2.1 §12.5
derivation is the only one. `hmac_secret_derivation_test.go` is the suite that
keeps it honest.
