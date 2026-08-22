# Phone as HSM — Engineering Contract

> **Status: NORMATIVE** · Feature: `phone-hsm` · Module: `go-xkms/xkey` · Last verified: 2026-08-19

## Exported surface — `xkey/pkg/pairing`

### Noise session

```go
const (
	// XX pattern: mutual authentication, public keys transmitted in handshake.
	NoiseProtocolName = "Noise_XX_25519_ChaChaPoly_SHA256"
	NoiseKeySize        = noiseproto.KeySize
	NoiseMaxMessageSize = noiseproto.MaxMessageSize
)

type NoiseSession struct{ … }  // wraps noiseproto.Session with phone-domain errors
```

Built on `go-truststrap/pkg/noiseproto`. `NoiseSession` adds phone-domain error
mapping and a backward-compatible `RemoteStaticPublicKey` accessor.

### Protocol and bridges

One pair per concern: `protocol.go`/`bridge.go` (core),
`protocol_attestation.go`/`bridge_attestation.go`,
`protocol_piv.go`/`bridge_piv.go`, `protocol_oath.go`/`bridge_oath.go`,
`protocol_backup.go`/`bridge_backup.go`,
`protocol_sharing.go`/`bridge_sharing.go`, `protocol_sync.go`/`bridge_sync.go`,
plus `protocol_device_enrollment.go`, `protocol_idevid.go`,
`protocol_local.go`, `protocol_remote.go`.

Supporting: `device.go`, `attestation.go`, `bridge_attestation.go`,
`biometric_handler.go`, `device_enrollment_evidence.go`,
`device_enrollment_policy.go`, `fragmentation.go`, `handshake_common.go`,
`message_loop.go`, `sharing_policy.go`, `tcp_transport.go`, `tpm_enroller.go`,
`transport.go`, `constants.go`, `errors.go`.

### USB transport — `go-xkms/pkg/api/transport/usb`

```go
func New(opts ...transport.Option) (*Transport, error)
func NewWithConfig(cfg *transport.Config) (*Transport, error)
func (t *Transport) WithNoiseConfig(cfg *NoiseConfig) *Transport

func (t *Transport) Connect(ctx context.Context) error
func (t *Transport) Close() error
func (t *Transport) Healthy(_ context.Context) bool
func (t *Transport) Conn() interface{}
func (t *Transport) Request(ctx context.Context, method string, req, resp interface{}) error
func (t *Transport) RequestStream(...) (transport.Stream, error)   // ErrStreamNotSupported
func (t *Transport) Config() *transport.Config

var ErrNotSupported = errors.New("operation not supported by this protocol")
```

`NoiseConfig` carries `LocalStaticPrivateKey`, `ExpectedRemoteStatic` and
`ExpectedDeviceFingerprint`. `Connect` **fails without touching the bus** when no
pairing keys are configured (`ErrNoiseNotConfigured`).

## Invariants

- **Noise XX, both ends authenticated.** Not NK. The initiator verifies
  `ExpectedRemoteStatic` and `ExpectedDeviceFingerprint`.
- **The identity exchange runs on every connection.** The phone's stream
  responder always expects it, and it binds the attestation fingerprint into the
  Noise prologue.
- **Requests are serialised.** The transport holds a mutex across
  encrypt→send→receive→decrypt because a Noise cipherstate advances a monotonic
  nonce per message: concurrent senders would emit frames out of nonce order and
  the phone would reject them. **Do not remove that mutex to gain parallelism.**
- **`Connect` fails closed with no pairing keys**, before any bus access.
- **No streaming.** `RequestStream` returns `ErrStreamNotSupported`; USB AOA is
  request/response.
- **Every non-transport service method returns `ErrNotSupported`.** The USB
  channel implements `PasswordService`, `SealStoreService` and `PolicyService`
  method sets and supports none of them — the phone path carries the pairing
  protocol, not the general API.
- **Private keys never cross the channel.** No protocol message can export one.
- **Wire compatibility with xkey-android is binding.** Any protocol change is
  made on both sides in the same change.

## The cipher suite is fixed, and not FIPS-approved

`NoiseProtocolName` is a constant: `Noise_XX_25519_ChaChaPoly_SHA256`.
ChaChaPoly is not FIPS-approved, there is **no AES-GCM alternative in this
package**, and no `fips` reference anywhere under `xkey/pkg/pairing/`. The suite
is also fixed in the Android compatibility tests, and the separate `Noise_NK`
bootstrap path delegates to `go-truststrap/pkg/noiseproto`.

Under the portfolio FIPS mandate this is an open gap requiring coordinated
cross-repo work. It is recorded here rather than glossed.

## Error semantics

`xkey/pkg/pairing/errors.go`; transport-side, `ErrNoiseNotConfigured`,
`ErrNotConnected`, `ErrNotSupported`, `ErrStreamNotSupported`, `ErrRequestFailed`,
wrapped in `errs.Detail` with `transport.ErrConnectionFailed`,
`ErrInvalidRequest` or `ErrInvalidResponse`.

A failed send marks the transport disconnected — the next call returns
`ErrNotConnected` rather than retrying on a broken session, which is correct: a
Noise session cannot be resumed mid-nonce-sequence.

**Fail closed:** unconfigured keys, a handshake whose remote static or device
fingerprint does not match, a decrypt failure, or a JSON-RPC error from the
phone. None degrade to an unencrypted or unauthenticated path.

**A malformed stored fingerprint also fails closed.** `DecodeDeviceFingerprint`
distinguishes three states, and the distinction is the point:

| stored value | result |
|---|---|
| empty | `(nil, nil)` — no fingerprint policy configured, the legitimate unbound case |
| valid hex, exactly `DeviceFingerprintSize` bytes | the decoded fingerprint |
| anything else | `*InvalidDeviceFingerprintError`, and **no bytes** — never `(nil, nil)` |

Returning `nil` for a malformed value would hand the handshake the same "no
expected fingerprint" signal an unconfigured device gives it, downgrading an
identity-bound handshake to an unbound one. Corrupted authorization material
must never be less restrictive than the policy it corrupts.

Length is checked **before** decoding: the device always presents exactly
`DeviceFingerprintSize` bytes, so a wrong-length record can never match, and
refusing it here reports the stored record as unusable instead of letting the
handshake report a "mismatch" and accuse the device. It also bounds the work —
a corrupted config carrying a megabyte of valid hex is refused without
allocating half its size.

`InvalidDeviceFingerprintError` retains only a bounded prefix of the offending
value plus its true length, so holding the error does not hold the megabyte.
Its `Error` and `Unwrap` are nil-safe: the type is exported, so a downstream
package can construct one by hand, and an error that panics while being logged
converts a handled failure into an outage.

## Configuration

Pairing keys and the expected device fingerprint, from a completed pairing.
Transport selection is USB AOA, TCP relay (`tcp_transport.go`) or BLE.
`transport.Config.Timeout` maps to the USB operation timeout.

Device-side policy: `device_enrollment_policy.go`, `sharing_policy.go`.

## Persistence

The pairing — both static public keys and the device fingerprint — is persisted
on both sides. Everything else is session state and does not survive a
disconnect.

## Test strategy

- **Unit** — `xkey/pkg/pairing` per-protocol suites.
- **Transport** — `go-xkms/pkg/api/transport/usb/transport_test.go`.
- **Android compatibility** — the compat suites that fix the cipher suite; these
  are what make a unilateral protocol change fail loudly.
- **End to end** — `xkey/docs/testing/phone-e2e.md` in the legacy tree describes
  the manual procedure, which needs real hardware.

## Observability

The USB transport logs under `component=sdk_usb_transport` and reports a
successful connect. The events worth surfacing are the handshake outcome and a
fingerprint mismatch — the second is a security event, not a connectivity
problem, and it looks like a connection failure if nothing distinguishes it.
