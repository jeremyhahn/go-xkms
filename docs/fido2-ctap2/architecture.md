# FIDO2 / CTAP2 Client — Architecture

> **Status: NORMATIVE** · Feature: `fido2-ctap2` · Repo: `go-xkms` · Last verified: 2026-08-19

## The problem

A browser talks to a security key for you. A daemon, a CLI, an agent or a CI
job has no browser — but still needs to make a credential on a key, get an
assertion from it, and derive a secret from it. `pkg/fido2` is the CTAP2 client
that does that directly over USB HID.

The second, less obvious need: **key derivation**. The `hmac-secret` extension
turns a security key into a source of a stable secret that only exists when the
key is present and the user touches it. That is what makes a FIDO2 key usable to
unlock a barrier, not just to log in.

## Shape chosen: a `Handler` over a pluggable HID enumerator

```go
type Handler interface {
	EnrollKey(config *EnrollmentConfig) (*EnrollmentResult, error)
	UnlockWithKey(config *AuthenticationConfig) ([]byte, error)
	ListDevices() ([]Device, error)
	WaitForDevice(ctx context.Context) (*Device, error)
	Close() error
}
```

Four methods, and the names say what this package is for: **enroll a key, and
unlock with it.** `UnlockWithKey` returns `[]byte` — a derived key, not a
boolean — which is the `hmac-secret` path.

Hardware access is behind `HIDDeviceEnumerator` / `HIDDevice`
(`device.go`), with a Linux implementation (`hid_linux.go`) and a stub
elsewhere (`hid_stub.go`). Tests inject a mock enumerator; nothing in the
ceremony logic knows whether the device is real.

Rejected alternatives:

- **Shelling out to `libfido2`.** Rejected: a CGO dependency on every consumer,
  and no way to inject a test device.
- **Returning a boolean from authentication.** Rejected: it would throw away the
  derived secret, which is half the point.
- **Requiring a browser for the WebAuthn path.** Rejected — that is exactly what
  agents and CI cannot have. The headless relying-party client lives in
  [`../webauthn/`](../webauthn/engineering.md) and bridges to this package.

## Component boundaries

| Piece | File | Purpose |
|---|---|---|
| `Handler`, `FIDO2Handler` | `fido2.go` | the ceremony surface |
| CTAP2 protocol | `ctap2.go` | command encoding, CBOR |
| Authenticator data parsing | `authdata.go` | attested credential data, flags, counters |
| `hmac-secret` derivation | `hmac_secret.go` | the derived-key path |
| PIN/UV auth protocol | `pinuvauth.go` | PIN token exchange |
| HID transport | `device.go`, `hid_linux.go`, `hid_stub.go` | `CTAPHIDDevice`, enumerator |
| Configuration | `config.go` | timeouts, RP identity, vendor/product allowlists |

Consumers: `xkmsctl fido2`, the FIDO2 auth factor
([`../auth-factors/`](../auth-factors/architecture.md)), the headless WebAuthn
client ([`../webauthn/`](../webauthn/architecture.md)), and xkey's virtual
authenticator, which is the mirror image — this package *drives* an
authenticator, xkey *is* one.

## Data flow

```
enroll:
  DefaultEnrollmentConfig(userName)  →  EnrollKey
    → enumerate HID devices, select one (or Config.DevicePath)
    → CTAP2 authenticatorMakeCredential  (user presence; PIN if required)
    → parse authenticator data, extract credential id + public key
    ← EnrollmentResult

unlock:
  DefaultAuthenticationConfig(credentialID, salt)  →  UnlockWithKey
    → CTAP2 authenticatorGetAssertion with the hmac-secret extension
    → key computes HMAC over the salt with its credential-bound secret
    ← derived key bytes
```

The salt is the caller's; the secret never leaves the device. The same salt and
the same key always yield the same output, and no other key can produce it.

## Trust boundaries

- **User presence is the point.** A touch is a human asserting intent. Anything
  that removes it removes the security property.
- **`RequireUserVerification` escalates from presence to identity** — a PIN or
  biometric, not just a touch.
- **`AllowedVendors` / `AllowedProducts` are an allowlist of USB VID/PIDs.**
  Empty means any key. Populating it is how a deployment refuses unknown
  hardware — but note it filters by identifier, not by attestation, so it is a
  policy control, not a cryptographic one.
- **The derived key is as secret as the device.** `UnlockWithKey` output must be
  treated as key material: never logged, never written unprotected.
- **`Debug` logs protocol detail** including material you do not want in a log.
  Off in production.

## What this feature deliberately does not do

- **It is not the relying party.** Verification of attestations and assertions
  server-side is [`../webauthn/`](../webauthn/architecture.md).
- **It is not an authenticator.** It drives one. xkey's virtual authenticator is
  the other side.
- **It does not persist enrollments.** Credential ids and public keys are
  returned to the caller, who decides where they live.
- **It does not do NFC or BLE.** USB HID only in this package; BLE transport for
  the phone path is xkey's.
