# FIDO2 / CTAP2 Client — Engineering Contract

> **Status: NORMATIVE** · Feature: `fido2-ctap2` · Repo: `go-xkms` · Last verified: 2026-09-06

## Exported surface — `pkg/fido2`

```go
type Handler interface {
	EnrollKey(config *EnrollmentConfig) (*EnrollmentResult, error)
	UnlockWithKey(config *AuthenticationConfig) ([]byte, error)
	ListDevices() ([]Device, error)
	WaitForDevice(ctx context.Context) (*Device, error)
	Close() error
}

type Logger interface { Printf(format string, v ...interface{}) }

type PromptWriter interface { /* user-presence prompting */ }

type FIDO2Handler struct{ /* implements Handler */ }

func NewHandler(config *Config, enumerator HIDDeviceEnumerator) (*FIDO2Handler, error)
func NewHandlerWithLogger(config *Config, enumerator HIDDeviceEnumerator, logger Logger) (*FIDO2Handler, error)

func DefaultEnrollmentConfig(userName string) *EnrollmentConfig
func DefaultAuthenticationConfig(credentialID, salt []byte) *AuthenticationConfig
```

Device layer (`device.go`):

```go
type HIDDevice interface           { /* raw report I/O */ }
type HIDDeviceEnumerator interface { /* device discovery */ }
type CTAPHIDDevice struct          { /* CTAPHID framing over a HIDDevice */ }
func NewCTAPHIDDevice(device HIDDevice, config *Config) (*CTAPHIDDevice, error)
```

`hid_linux.go` supplies the real enumerator; `hid_stub.go` is the non-Linux
build. Tests inject their own — `mock_test.go`.

## `Config` (`config.go`)

| Field | YAML key | Default / meaning |
|---|---|---|
| `Timeout` | `timeout` | overall operation timeout |
| `UserPresenceTimeout` | `user-presence-timeout` | how long to wait for a touch |
| `RetryCount` | `retry-count` | retries on transient HID errors |
| `RetryDelay` | `retry-delay` | delay between retries |
| `Debug` | `debug` | verbose protocol logging — **off in production** |
| `DevicePath` | `device-path` | pin to a specific device; empty enumerates |
| `RelyingPartyID` | `relying-party-id` | RP id recorded on credentials |
| `RelyingPartyName` | `relying-party-name` | display name |
| `RequireUserVerification` | `require-user-verification` | require PIN/biometric, not just presence |
| `AllowedVendors` | `allowed-vendors` | `[]uint16` USB vendor allowlist; empty = any |
| `AllowedProducts` | `allowed-products` | `[]uint16` USB product allowlist; empty = any |

`AllowedVendors`/`AllowedProducts` filter by USB identifier. That is a policy
control against unknown hardware, not a cryptographic one — a VID/PID is
asserted by the device. For a cryptographic control, verify attestation at the
relying party.

## Invariants

- **Every ceremony requires user presence.** There is no flag that removes it,
  and none that fabricates verification. xkey's unattended path supplies the
  gesture rather than skipping it: a scripted `xkey touch` answers the daemon's
  presence request, or a verified CTAP2 PIN stands in for the touch when the
  daemon runs with `--require-touch=false`.
- **`UnlockWithKey` is deterministic** for a fixed credential and salt: the same
  inputs always yield the same derived key, and no other authenticator can
  produce it. That is what makes it usable as a key source.
- **The derived key is key material.** Never log it, never write it unprotected,
  zeroize it when done.
- **A credential is bound to its RP id.** Changing `RelyingPartyID` makes
  existing credentials unusable — the authenticator will not find them.
- **`WaitForDevice` respects context cancellation**; it does not spin.
- **`Close()` releases the HID handle.** A leaked handle blocks the next open on
  some platforms.
- **Concurrency.** A `FIDO2Handler` drives one device at a time; the CTAPHID
  channel is not multiplexed. Do not share a handler across concurrent
  ceremonies.

## Error semantics

Typed errors throughout. The categories a caller must distinguish:

| Category | Meaning | Caller's move |
|---|---|---|
| no device found | nothing enumerated, or the allowlist excluded everything | prompt to insert; check udev permissions |
| user-presence timeout | nobody touched the key | retry with a prompt |
| PIN required | `RequireUserVerification`, or the key demands it | collect the PIN |
| PIN invalid / retries remaining | wrong PIN | surface the remaining count — the key locks out |
| credential not found | wrong RP id, or the credential is not on this key | do not retry blindly |
| CTAP protocol error | transport or firmware level | `RetryCount`/`RetryDelay` cover transients |

**Fail closed:** an absent device, a timed-out touch, a failed PIN or a missing
credential all return an error. Nothing degrades to a software key.

## Configuration

Injected as `*Config` at handler construction; the same fields appear in
`xkmsctl fido2` flags (`--rp-id`, `--rp-name`, `--timeout`, `--device`,
`--user-verification`). Precedence: flag → config file → struct default.

**`--legacy-hmac-derivation`** on `xkmsctl fido2 authenticate` selects an older
derivation of the `hmac-secret` output. It exists for credentials enrolled
before the current derivation; a credential enrolled under one derivation
produces a different key under the other, so the flag is not cosmetic — using
the wrong one yields a wrong key with no error.

## Persistence

None. `EnrollmentResult` carries the credential id and public key back to the
caller; storing them is the caller's job — the auth factor stores them in
go-qrdb's user store, xkey stores them locally.

## Test strategy

- **Unit** — `fido2_test.go`, `ctap2_test.go`, `authdata_test.go`,
  `device_test.go`, `device_edge_cases_test.go`, `hmac_secret_test.go`,
  `hmac_secret_derivation_test.go` (the derivation-compatibility suite — this is
  what protects the legacy path), `hid_linux_test.go`, `coverage_test.go`,
  `coverage_boost_test.go`.
- **Mock device** — `mock_test.go` supplies a `HIDDeviceEnumerator`, so the
  whole ceremony path runs with no hardware.
- **Integration** — `test/integration/fido2` (real devices),
  `test/integration/webauthn-browser`, `test/integration/logins`.
- **Fault injection** — `device_edge_cases_test.go` covers short reads, framing
  errors and disconnects mid-ceremony.

## Observability

`Logger` is a minimal `Printf` interface so a caller can route CTAP traffic
wherever it already logs. `Debug` adds full protocol detail and must stay off
outside development. `PromptWriter` is how the user-presence prompt reaches a
human — a CLI writes to the terminal, a GUI raises a dialog; without one, a
ceremony that is waiting for a touch looks like a hang.
