# Phone as HSM — Engineering Contract

> **Status: NORMATIVE** · Feature: `phone-hsm` · Module: `go-xkms/xkey` · Last verified: 2026-08-23

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
the SHA-256 of the device's persistent **attested key**'s
`SubjectPublicKeyInfo` (#93/#129). Two of the three limits that used to apply
are closed; read this section as the history of how, because each was a real
defect and the shape of the fix is what the current design is for.

1. **Device-unique (was: not device-unique).** The value used to be the hash of
   the attestation chain's **root** — on a verified chain a *configured*
   Android-hardware trust anchor, shared by every handset issued under it. It
   identified a vendor, not a device, and two handsets of the same family
   produced the same value. It is now the attested key itself, generated inside
   **this** handset's TEE/StrongBox and certified by the chain.

   Hashing the **SPKI** rather than the leaf DER is deliberate: re-attesting the
   same key reissues the leaf with a fresh serial and validity window, so an
   SPKI hash is stable across honest re-attestation and moves only on a genuine
   key rotation — which is exactly the event a pairing must be re-established
   for.

   The anchor is still read back out of the chain x509 built
   (`verifiedTrustAnchor`), but only for display. "Configured" is broader than
   "embedded": `Verifier.buildTrustPool` merges the local trust store's
   `PurposeAndroidHardware` certificates with `truststore.LoadEmbeddedRoots`, so
   a chain can verify under a root an operator installed with `xkey trust` and
   never appear in the embedded set at all. `findMatchingTrustRoot` is called
   with whatever root list its caller passes; the GUI passes the embedded roots
   alone, so there it is a display lookup that can return `nil` for a chain that
   verified perfectly well under an operator-installed root.

2. **Live attestation at connect time (was: not an attestation).** The identity
   ack still compares the stored value against bytes **the peer sends**:

   ```go
   receivedFingerprint := ack[1:]                       // peer-supplied
   bytes.Equal(receivedFingerprint, cfg.ExpectedDeviceFingerprint)
   ```

   That comparison is unchanged and still proves only continuity — it runs
   before the handshake, so there is nothing else it *could* be. What changed is
   that it is no longer the last word: since #129 a connection to a device bound
   under protocol version 2 runs a **challenge-response re-attestation** once
   the Noise session is up (`attestOverSession` with purpose `reattest`), and
   the device must present its attestation chain **and** a fresh signature by
   the attested key over this session's challenge. See *Challenge-response
   attestation* below.

3. **It is derived from a verified attestation — on every path.** This
   was the third limit until #95, and it was the largest: pairing sent a nonce,
   took the last certificate of whatever chain the phone returned, hashed it
   and stored it, without calling `VerifyAndroidKeyAttestation`, without
   comparing the nonce to the attestation extension, and without checking the
   chain against any anchor. Every failure was a warning that let pairing
   complete, so the stored value was the hash of a certificate **the phone
   chose**.

   `performPairingAttestation` (`cmd/xkey/cmd/device_pair.go`) now **fails
   closed**. It builds the trust material before it asks for evidence, and
   `verifyPairingAttestation` refuses unless the chain verifies against those
   anchors AND the device signs this pairing's challenge with the key that
   chain certifies.

   **What happens on a refusal is policy; what is recorded is not.** By the
   owner ruling of 2026-08-23 on #95, whether pairing *aborts* on an
   unattestable device is a setting, defaulting to abort. Whether an
   **unverified claim may be written down** is not a setting and never becomes
   one: that was the #95 defect itself. When policy allows an unattestable
   pairing to proceed, `newPairedDeviceRecord` writes the pairing half of the
   record — name, address, Noise keys, timestamp — and **nothing** about the
   device's hardware: no `SecurityLevel`, no `BootStateVerified`, no
   `DeviceBootHashHex`, no `DeviceFingerprint`, and no
   `LastDeviceAttestationTime`. Not zeroed versions of them; absent. The device
   reads as never attested because it has not been, the CLI says so in as many
   words, and the first `device attest-device` is what fills them in.

   The setting resolves across two planes (`allowUnattestablePairing`):

   | Plane | Where | Key |
   |---|---|---|
   | User | `devices.yaml` | `attestation_policy.allow_unattestable_devices` |
   | Enterprise / SO | the `policy:` section | `pairing_allow_unattestable_devices`, gated by `lock_pairing_attestation_policy` |

   **The enterprise plane is monotone: it may only make the answer stricter.**
   That is a limitation of what the CLI can honestly enforce, not a design
   preference. `config` has the integrity machinery (`VerifyPolicyHMAC` over
   `PolicyCanonicalJSON`, keyed from the SO PIN), but **no CLI path calls it**,
   and a pairing command has no SO PIN to call it with. Treating the section as
   authoritative in both directions therefore meant that anyone who could edit
   `xkey.yaml` could write

   ```yaml
   policy:
     lock_pairing_attestation_policy: true
     pairing_allow_unattestable_devices: true
   ```

   and pair an unattestable device over a `devices.yaml` that refuses — a
   fail-open reached by editing an unauthenticated file, which is worse than
   having no enterprise plane at all because it looks like enforcement.

   So `lock_pairing_attestation_policy: true` with
   `pairing_allow_unattestable_devices: false` **refuses**, whatever
   `devices.yaml` says — the direction no attacker wants, and the same answer an
   absent section already gives. The permissive direction is **ignored** until
   the policy can be authenticated, which is **#118**.

   **Every absent value means refuse**, and that is reached by the Go zero
   value rather than by a defaults table. The reason is measured, not stylistic:
   a config file carrying a *partial* `policy:` block resolves every key it
   omits to false rather than to `config.DefaultPolicy()` (#114), so a design
   whose secure state came from that table would be insecure for exactly the
   deployments that write a minimal policy file.

   One migration note that follows from `PolicyCanonicalJSON`: adding fields to
   `PolicySection` changes the canonical encoding, so an enterprise deployment
   must **re-seal** its policy after upgrading to a build with a different field
   set. An unsealed upgrade reads as tampered — the correct direction to fail,
   but a step someone has to take.

   The stored fingerprint is the **anchor x509 actually verified under**, read
   back out of the chain the verifier built (`verifiedTrustAnchor`), never
   `chain[len-1]`. The distinction is not cosmetic: verification proves the
   leaf chains to some certificate in the pool and says nothing about what the
   peer appended after it, so a valid chain with a trailing certificate still
   verifies while `chain[len-1]` is attacker-chosen. An appended certificate is
   therefore what it is — an unused extra — and cannot become the record.

   Reading the anchor back is also why there is no second list of roots. The
   first version of this fix kept a flat root list beside the pool and matched
   by fingerprint; the list was built from the store's certificates for **every
   purpose** while the pool held the Android-hardware ones alone, so a peer
   could append a certificate stored under an unrelated purpose and have it
   named as the anchor. Two sets that must agree are two sets that can
   disagree. There is one pool, and the anchor comes from the verification.

   `device attest-device` was corrected the same way — it verifies the chain
   properly but hashed `chain[len-1]`, and `recordDeviceAttestation` overwrites
   the pairing record, so it could have rewritten the value one command later.

   Pairing verifies at the same bar `device attest-device` enforces —
   `MinSecurityLevel: TrustedEnvironment` and `VerifyBootState: true` — which
   is alignment rather than new policy. Without it pairing ADMITTED a device
   that its own first re-attestation would refuse, so the weaker of the two
   gates was the one establishing the binding.

   **`VerifyBootState` is not sufficient on its own**, and pairing no longer
   relies on it alone. The SDK's contract is *"if a `RootOfTrust` is present, it
   must say verified"*, so an extension carrying **none** passes it. A trusted,
   nonce-matching, StrongBox chain with no `RootOfTrust` was therefore reported
   as `Chain Status: VERIFIED`, got a security level and an attestation
   timestamp written to the record, and paired — having claimed nothing
   whatsoever about its boot chain. For a phone-as-HSM pairing that claim *is*
   the product.

   `requireAttestedBootState` enforces the missing half at the **point of
   consumption**, and refuses unless the extension carries a `RootOfTrust`, the
   bootloader is **locked**, and the state is **verified**. It lives in the CLI
   rather than in `pkg/attestation/android` because absence-versus-refusal is
   the consumer's policy: the SDK's "verify what is claimed" contract is
   deliberate and other callers depend on it. `device attest-device` inherits
   the SDK's looser reading and is **not** changed here — pairing being the
   stricter of the two is the safe direction, since anything that pairs also
   passes re-attestation.

   A device that fails any of those is **unattestable**, which is a policy
   question with the policy answer above — not a silent admission.

   `SecurityLevel`, boot state and the boot hash now come from the parsed
   extension of the **verified** leaf. They used to be copied from the RPC
   result's sibling JSON fields, which nothing binds to the certificates — a
   device reporting `bootState == 0` was recorded as having a verified boot
   state on its own say-so. A verified chain carrying no `RootOfTrust` records
   no boot claim rather than a favourable default.

   The `Nonce` echoed in the RPC result is deliberately **not** checked: it is
   an unsigned field the peer controls, so matching it would prove only that
   the peer can copy. Freshness rests on the challenge signature (below).

## Challenge-response attestation (#129)

Under protocol version 2 a device proves two separate things, and neither is
worth much without the other:

| Claim | Evidence | What it would be alone |
|---|---|---|
| This key lives in that handset's secure hardware | the attestation chain, verified to a trusted Android hardware root at TEE-or-better on a locked, verified boot state | a public document; anyone who watched one pairing can replay it |
| The party on **this** connection holds it, right now | a live ECDSA-P256 signature by the attested key over a transcript carrying this exchange's nonce | possession of a key nobody vouched for |

The device's attestation key (the **DAK**) is **persistent**: generated once,
attested once, and never regenerated for a pairing. That is what makes the
fingerprint a stable identity, and it is why freshness cannot come from the
certificate. Android Keystore fixes the attestation challenge at key
*generation* (`setAttestationChallenge`) and offers no way to re-attest an
existing key, so a per-pairing challenge forces a per-pairing key — a stable
identity and an embedded-challenge freshness proof are mutually exclusive on
that platform. Version 1 chose the embedded challenge and therefore could not
have a stable identity; version 2 moves freshness to a live signature and keeps
both.

**The transcript** (`pairing.BuildAttestTranscript`), fixed-width except for the
length-prefixed purpose:

```
"xkey-attest-transcript-v1" || len8(purpose) || purpose
                            || nonce(32) || channelBinding(32) || fingerprint(32)
```

signed as `SHA256withECDSA`, ASN.1 DER, algorithm `ES256`. Each field earns its
place: the **domain** separates this signature from any other use of the key;
the **purpose** (`pair` / `reattest`) stops a signature gathered during pairing
from satisfying a reconnect; the **nonce** is the verifier's fresh random
challenge; the **channel binding** ties the answer to the connection it was
produced on; the **fingerprint** makes the signature commit to the identity
being claimed.

**The channel binding** is the anti-relay term
(`pairing.ComputeAttestChannelBinding`): `SHA-256` over the two Noise static
public keys in **initiator-then-responder** order plus the length-prefixed
prologue. Without it, an attacker completing its own Noise session with the
desktop could forward the desktop's challenge to a genuine phone on a second
session and pass that phone's answer off as its own; with it, the phone signs
the binding of the session it is actually speaking on. The Noise **handshake
hash** would be strictly stronger — it commits to the ephemerals too, making
the value unique per session rather than per key pair — and is not used because
`noiseproto.Session` keeps its `*noise.HandshakeState` unexported (filed
upstream on go-truststrap) and because depending on a hand-written Kotlin Noise
implementation agreeing byte-for-byte with flynn/noise at one point in the
transcript is an interop hazard on a value that must match exactly. Both
derivations rest on the same thing — key possession, proved by the XX
handshake — so the residual gap is two concurrent sessions between the same
pair of keys, where the fresh nonce is what keeps a signature from moving.

**The genesis challenge.** The DAK's certificate carries the challenge it was
*generated* under, which version 2 must never compare against a live nonce. It
is still checked for what it can say: it must begin with
`xkey-device-attestation-v1`, so a chain minted for an unrelated Android
attestation cannot be presented to this protocol. Trailing bytes are reserved,
so a prover may append install-unique material without a version bump.

**Downgrade is a refusal, not a fallback.** A version 2 challenge answered with
anything but a version 2 response is `ErrAttestProtocolDowngrade`. The pairing
record carries `attestation_protocol_version`, which only ever moves up
(`recordDeviceAttestation`), so a device bound under challenge-response cannot
shed the liveness proof by claiming it cannot produce one — otherwise the
protocol version would be chosen at connect time by the party being checked.
Records established before #129 keep the weaker mode until the device is
re-paired, and are not reported as though they had the stronger binding.

**Rotation.** The fingerprint changes only when the device regenerates its DAK.
`device attest-device` refuses fail-closed on a change
(`validateAttestedKeyMatch` → `ErrDeviceIdentityChanged`) rather than silently
rebinding: it *revalidates* an existing binding, and a peer holding the paired
Noise key plus a valid attestation of its own device would otherwise turn the
operator's revalidation into a rebind. Legitimate rotation is an explicit
re-pair.

The stored value is the hash of a **public** key, so it is not a shared secret,
and the identity ack remains a continuity check. What has changed is that it is
no longer the strongest thing the connection establishes.

The other check that is proven rather than echoed is `ExpectedRemoteStatic`,
the peer's pinned Noise static public key: `noiseproto.Session` returns
`ErrStaticKeyMismatch` when the key presented in the handshake is not the
pinned one, so completing the handshake proves the peer holds the
corresponding private key. Note its limit, since overstating it would repeat
the error this section exists to correct: it proves **possession of the key
paired earlier**, not the identity of a handset — nothing about that key is
established to be hardware-bound, so a key copied off the phone is
indistinguishable there. The challenge-response step is what supplies the
hardware-bound half, on a key the chain vouches for.

Everything below concerns whether the check is APPLIED, which is independent of
what the check proves.

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
