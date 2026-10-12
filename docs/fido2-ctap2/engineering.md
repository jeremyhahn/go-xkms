# FIDO2 / CTAP2 Client — Engineering Contract

> **Status: NORMATIVE** · Feature: `fido2-ctap2` · Repo: `go-xkms` · Last verified: 2026-10-12

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

// DeriveHMACSecret returns the raw hmac-secret output, HMAC-SHA-256(CredRandom,
// salt) (CTAP 2.1 12.5): AuthenticationResult.HMACSecret (and HMACSecret2 for
// Salt2). UnlockWithKey is this output run through GenerateDerivedKey.
func (h *FIDO2Handler) DeriveHMACSecret(config *AuthenticationConfig) (*AuthenticationResult, error)

// WebAuthnPRFSalt returns SHA-256(UTF8("WebAuthn PRF") || 0x00 || salt): the
// hmac-secret salt a browser sends for a WebAuthn prf evaluation of salt.
func WebAuthnPRFSalt(salt []byte) []byte

// EnrollmentConfig.PIN and AuthenticationConfig.PIN (*secure.Secret, optional)
// authorize MakeCredential / GetAssertion with a pinUvAuthToken; the "uv"
// option is cleared, since the token is the verification (CTAP 2.1 6.1.2).

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
- **`UnlockWithKey` and `DeriveHMACSecret` are deterministic** for a fixed
  credential, salt and user-verification state: the same inputs always yield
  the same output, and no other authenticator can produce it. That is what
  makes them usable as a key source. **User verification is an input:** CTAP
  2.1 keys the output with `CredRandomWithUV` when the assertion is
  user-verified (a PIN was supplied) and `CredRandomWithoutUV` otherwise, so a
  caller that must reproduce an output supplies a PIN every time or never.
- **A browser's prf output is the hmac-secret of the transformed salt.** To
  match a browser's WebAuthn prf evaluation of `salt`, a direct CTAP2 caller
  evaluates `WebAuthnPRFSalt(salt)`, never `salt` itself. The vectors in
  `pkg/fido2/testdata/webauthn_prf_salt_vectors.json` pin the transform; the
  Go tests and `sdk/ts` (WebCrypto, the browser computation) both check them.
- **The derived key is key material.** Never log it, never write it unprotected,
  zeroize it when done.
- **A credential is bound to its RP id.** Changing `RelyingPartyID` makes
  existing credentials unusable — the authenticator will not find them.
- **A server-supplied rpId must be covered by the caller's origin.** Every
  WebAuthn ceremony entry point (`ParseWebAuthnRegistrationOptions`,
  `RegisterWebAuthn`, `AuthenticateWebAuthn`, and the options parser behind
  `Assert`/`AssertWithOptionsAndOrigin`) runs `ValidateRPID`
  (`rpid.go:37`; called at `webauthn_attestation.go:314,360`,
  `webauthn_assertion.go:195,314`) before the authenticator is touched: the
  rpId must equal the origin's host or be a registrable-domain suffix of it
  (WebAuthn L2 §5.1.3 step 8, §5.1.4.1 step 7). A suffix that is itself a
  public suffix (`com`, `co.uk`, `github.io`, per `golang.org/x/net/publicsuffix`)
  or any suffix of an IP-literal host is refused (`rpid.go:63`). The origin is
  required and is never derived from the rpId: an empty origin fails with
  `ErrOriginRequired`.
- **`WaitForDevice` respects context cancellation**; it does not spin.
- **`Close()` releases the HID handle.** A leaked handle blocks the next open on
  some platforms.
- **Concurrency.** A `FIDO2Handler` drives one device at a time; the CTAPHID
  channel is not multiplexed. Do not share a handler across concurrent
  ceremonies.

## The `hmac-secret` derivation (CTAP 2.1 §12.5)

`HMACSecretExtension.deriveSecretCTAP2` (`hmac_secret.go:197`) runs the
exchange:

1. `EstablishPINUVAuthSession` (`pinuvauth.go:595`) fetches the
   authenticator's key agreement key and derives the PIN/UV auth shared secret
   by ECDH. `PINUVAuthProtocolVersion` (`pinuvauth.go:581`) picks protocol two
   when `authenticatorGetInfo` advertises it, protocol one otherwise.
2. The salt (or `Salt` ‖ `Salt2`) is encrypted under that secret (`saltEnc`),
   authenticated (`saltAuth`), and sent with the platform key and protocol
   version as the `hmac-secret` input of `authenticatorGetAssertion`.
3. `hmacSecretOutput` (`hmac_secret.go:280`) finds the encrypted output in the
   CBOR extension map that ends the authenticator data.
   `ParseAuthDataExtensions` (`authdata.go:124`) honours the ED and AT flags
   (`authdata.go:133,138`) and measures the attested credential data instead of
   assuming a fixed offset. It then decrypts the output and checks its length
   against the salts.

`DeriveHMACSecret` returns the 32-byte output as `HMACSecret`, and the second
32 bytes as `HMACSecret2` when `Salt2` was set. `UnlockWithKey`
(`fido2.go:222`) uses only `HMACSecret`: it runs it through
`GenerateDerivedKey` (`hmac_secret.go:382`), two domain-separated SHA-256
digests concatenated into a 64-byte key, and clears the raw output.

Any failure to get the genuine output is a typed error and returns no key:
`ErrInvalidExtensions` (`types.go:78`) for a malformed extension map,
`ErrHMACSecretMissing` (`types.go:95`) when there is no `hmac-secret` entry,
and `ErrHMACSecretOutputInvalid` (`types.go:96`) for a wrong type, a failed
decryption or a wrong length.

## Error semantics

Typed errors throughout. The categories a caller must distinguish:

| Category | Meaning | Caller's move |
|---|---|---|
| no device found | nothing enumerated, or the allowlist excluded everything | prompt to insert; check udev permissions |
| user-presence timeout | nobody touched the key | retry with a prompt |
| PIN required | `RequireUserVerification`, or the key demands it | collect the PIN |
| PIN invalid / retries remaining | wrong PIN | surface the remaining count — the key locks out |
| credential not found | wrong RP id, or the credential is not on this key | do not retry blindly |
| `ErrOriginRequired` / `ErrInvalidOrigin` / `ErrRPIDOriginMismatch` | no origin, a malformed one, or a server rpId the origin does not cover | supply the real origin; a mismatch is a hostile or misconfigured relying party — do not retry |
| CTAP protocol error | transport or firmware level | `RetryCount`/`RetryDelay` cover transients |

**Fail closed:** an absent device, a timed-out touch, a failed PIN or a missing
credential all return an error. Nothing degrades to a software key.

## Configuration

Injected as `*Config` at handler construction; the same fields appear in
`xkmsctl fido2` flags (`--rp-id`, `--rp-name`, `--timeout`, `--device`,
`--user-verification`). Precedence: flag → config file → struct default.

**BREAKING (2026-09-22):** `--legacy-hmac-derivation` on
`xkmsctl fido2 authenticate`, the `DerivationModeLegacyInsecure` mode it
selected, and the pre-fix `hmac-secret` derivation itself have been deleted
outright. `DerivationModeCTAP2` (CTAP 2.1 §12.5) is the only mode.

## Persistence

None. `EnrollmentResult` carries the credential id and public key back to the
caller; storing them is the caller's job — the auth factor stores them in
go-qrdb's user store, xkey stores them locally.

## Test strategy

- **Unit** — `fido2_test.go`, `ctap2_test.go`, `authdata_test.go`,
  `device_test.go`, `device_edge_cases_test.go`, `hmac_secret_test.go`,
  `hmac_secret_derivation_test.go` (pins the CTAP2 derivation against the
  authenticator simulator), `hid_linux_test.go`, `coverage_test.go`,
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
