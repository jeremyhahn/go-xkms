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

- **Noise XX, both ends authenticated.** Not NK. The initiator *verifies*
  `ExpectedRemoteStatic` cryptographically and *compares* the peer-supplied
  `ExpectedDeviceFingerprint` for equality — two different strengths, see
  "What the fingerprint proves" below.
- **The identity exchange runs on every connection.** The phone's stream
  responder always expects it, and it binds the device fingerprint into the
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

**What the fingerprint proves — and what it does not.** `DeviceFingerprint` is
the SHA-256 of the attestation chain's **root** certificate. Three independent
limits apply, and together they are narrower than the name suggests:

1. **Not device-unique.** On a verified chain that root is a *configured*
   Android-hardware trust anchor, shared by every handset issued under it.
   "Configured" is broader than "embedded": `Verifier.buildTrustPool` merges the
   local trust store's `PurposeAndroidHardware` certificates with
   `truststore.LoadEmbeddedRoots`, so a chain can verify under a root an
   operator installed with `xkey trust` and never appear in the embedded set at
   all. `findMatchingTrustRoot` searches only the embedded roots and is a
   display lookup — it can return `nil` for a chain that verified perfectly
   well, so it does not establish provenance and is not evidence for this
   point.
2. **Not an attestation, at connect time.** The handshake compares the stored
   value against bytes **the peer sends** in its identity ack:

   ```go
   receivedFingerprint := ack[1:]                       // peer-supplied
   bytes.Equal(receivedFingerprint, cfg.ExpectedDeviceFingerprint)
   ```

   No chain is presented or verified there.

3. **Not necessarily derived from a verified attestation either.**
   `performPairingAttestation` (`cmd/xkey/cmd/device_pair.go`) sends a nonce,
   takes the last certificate of whatever chain the phone returns, hashes it
   and stores it. It does **not** call `VerifyAndroidKeyAttestation`, does not
   check the nonce against the attestation extension, and does not verify the
   chain against any trust anchor. Every failure on that path is a warning
   that does not stop pairing.

   So on the CLI pairing path the stored value is the hash of a certificate
   **the phone chose**, not of a verified trust anchor. The chain is verified
   only on flows that actually invoke `VerifyAndroidKeyAttestation` — the GUI
   attestation flow does; pairing does not.

The value is also the hash of a **public** certificate, so it is not a shared
secret. Taken together, what the reconnect check establishes is: **the peer
echoed the same value it supplied when pairing.** That is a continuity check on
an attacker-suppliable value — it notices a peer that changed its answer, and
nothing more. It is not device identity, not live attestation, and not proof
that any attestation was ever verified.

The check that is actually proven rather than echoed is `ExpectedRemoteStatic`,
the peer's pinned Noise static public key: `noiseproto.Session` returns
`ErrStaticKeyMismatch` when the key presented in the handshake is not the
pinned one, so completing the handshake proves the peer holds the
corresponding private key. Note the limit on that too, since overstating it
would repeat the error this section corrects: it proves **possession of the
key paired earlier**, not the identity of a handset. Nothing in this
repository establishes that the key is hardware-bound or non-exportable, so a
key copied off the phone is indistinguishable here. Whether the fingerprint
check adds anything on top of that — and whether pairing should verify the
chain before persisting anything — is tracked as go-xkms issue **#93**,
*"DeviceFingerprint binds to the attestation ROOT CA, not the device"*.

Everything below is correct regardless: it concerns whether the check is
APPLIED, which is independent of what the check proves.

**A malformed stored fingerprint also fails closed.** `DecodeDeviceFingerprint`
distinguishes three states, and the distinction is the point:

| stored value | result |
|---|---|
| empty | `(nil, nil)` — no fingerprint policy configured, the legitimate first-pairing case |
| valid hex, exactly `DeviceFingerprintSize` bytes | the decoded fingerprint |
| anything else | `*InvalidDeviceFingerprintError`, and **no bytes** — never `(nil, nil)` |

Returning `nil` for a malformed value would hand the handshake the same "no
expected fingerprint" signal an unconfigured device gives it, silently omitting
the comparison instead of failing it. Corrupted authorization material must
never be less restrictive than the policy it corrupts.

Be precise about the size of that downgrade. `ExpectedRemoteStatic` is enforced
by Noise independently of the fingerprint, so dropping the fingerprint check
does **not** open the handshake to any device: it removes one of two checks,
leaving the pinned Noise key. The downgrade is from *pinned key plus matching
peer-asserted continuity data* to *pinned key alone*. Silently dropping a
configured check is worth refusing on its own terms — it does not need to be
the larger thing to justify failing closed.

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
