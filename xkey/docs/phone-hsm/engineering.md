# Phone as HSM — Engineering Contract

> **Status: NORMATIVE** · Feature: `phone-hsm` · Module: `go-xkms/xkey` · Last verified: 2026-09-25

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

### Bridge collaborators are optional, and say so honestly

`remote.oathAdd`/`remote.oathGenerate`, `remote.pivListSlots`/`pivGetCert`, and
`remote.syncTrustStore`/`syncOATH`/`syncPasswords`/`syncAll` each delegate to a
real xkey service the CLI layer wires into `BridgeConfig` when it constructs
the `Bridge`, the same pattern `BridgeConfig.TPM` already established for TCG
enrollment:

| Method family | `BridgeConfig` field | Delegates to |
|---|---|---|
| `remote.oath*` | `OATHStore oath.Store` | `xkey/pkg/oath` (`Store.Add`/`Get`, `Generator`) |
| `remote.pivListSlots`, `remote.pivGetCert` | `PIVStorage PIVStorageProvider` | `xkms.PIVCertificateStorage` for the named backend |
| `remote.pivSign` | *(none — see below)* | `Client.Sign`, the same generic key-signing path `remote.sign` uses |
| `remote.sync*` | `SyncService *sync.Service` | `xkey/pkg/sync` (`ApplyXDelta`/`ComputeLocalXDelta`) |

`remote.pivSign` needs no PIV-specific collaborator: a PIV slot's private key
is stored under `KeyID == slot` in the same key backend every other key
lives in, so signing reaches it through `Client.Sign` exactly like
`remote.sign` does. Only certificate storage (list/get-cert) is PIV-specific,
because `Client` (the generic `transport.Client`) has no certificate-storage
verbs.

Every field above is optional. When one is `nil`, its methods answer with a
typed "not configured" sentinel (`ErrOATHNotConfigured`, `ErrPIVNotConfigured`,
`ErrSyncNotConfigured`, all mapped to JSON-RPC `ErrorCodeFeatureUnavailable`)
instead of a fabricated empty success — the same "unavailable here, not
broken" distinction `ErrTPMNotConfigured` already draws for a host with no
TPM. `remote.syncStatus` is the one exception: with no `SyncService` it
reports an empty status (nothing has been synced yet) rather than an error,
since that is a legitimate status, not a missing feature.

`cmd/xkey/cmd/device_listen.go`'s `buildListenBridgeConfig` is the one place
that wires all three: it opens the OATH store through `openOATHStore` and the
sync service through `openSyncService` — the exact constructors `xkey oath`
and `xkey device sync` themselves call — and builds the PIV storage provider
from the same `createPIVStorage` construction `xkey piv` uses, so a
credential, certificate, or trust store entry the phone reaches through the
bridge is the same one those commands read and write. A collaborator that
fails to open there (no barrier password reachable, a missing PKCS#11
library, ...) is logged and left `nil` rather than aborting the daemon: the
host still pairs and serves every other method, with only that one method
family reporting itself unconfigured.

**`remote.createBackup`/`restoreBackup`/`listBackups` are unimplemented**
(go-xkms#690) pending an owner decision `bridge_backup.go` documents in
detail: `backup.Service` encrypts every archive with a caller-supplied
32-byte key, and neither the wire params nor the wire results for these three
methods carry one, so the key has to come from a source the bridge does not
yet have (a passphrase/key file the CLI supplies at `xkey device listen`
start, or something derived from material the bridge does not currently
hold) — and `remote.listBackups` additionally presumes a persistence
location and ID/label scheme for phone-initiated backups that has no
convention anywhere in this codebase yet. All three handlers return
`ErrBackupNotConfigured` until that is decided; they never fabricate success
or silently discard the phone's data.

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
- **No streaming.** The transport implements only `Connect`/`Close`/`Healthy`/
  `Request`; USB AOA is request/response.
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
`ErrNotConnected`, `ErrNotSupported`, `ErrRequestFailed`,
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

   The setting resolves across two planes, in ONE function both pairing
   surfaces call — `attestation.AllowUnattestablePairing` (see *Two pairing
   surfaces, one gate* below):

   | Plane | Where | Key |
   |---|---|---|
   | User | `devices.yaml` | `attestation_policy.allow_unattestable_devices` |
   | Enterprise / SO | the `policy:` section | `pairing_allow_unattestable_devices`, gated by `lock_pairing_attestation_policy` |

   **The enterprise plane is consulted only once it can be trusted, and is
   then honoured in both directions.** `allowUnattestablePairing` takes a
   `config.VerifiedPolicy`, never a raw `*config.Config`, and
   `resolvePairingPolicy` is the only thing that produces one:

   | Config directory | SO PIN supplied | What the pairing sees | Lock honoured |
   |---|---|---|---|
   | Unsealed (personal mode) | — | the section, state `unsealed` | both directions: it is the user's own file, no different from `devices.yaml` |
   | Sealed, verifies | yes | the section, state `sealed-verified` | both directions: it carries the SO's authority |
   | Sealed | no | `nil` — the plane exists but is unknown | **refuse**, whatever `devices.yaml` says |
   | Sealed, does not verify | yes | nothing: `ErrPairingPolicyRefused` | the pairing does not run |

   This is the #118 contract and it replaced the monotone mitigation of #110.
   That mitigation let an unverified section make the answer stricter and
   never wider, which closed the fail-open Codex found — anyone who could
   edit `xkey.yaml` could write

   ```yaml
   policy:
     lock_pairing_attestation_policy: true
     pairing_allow_unattestable_devices: true
   ```

   and pair an unattestable device over a `devices.yaml` that refuses — but
   it could not honour a deployment that legitimately locks the setting
   **open** (a fleet that pairs development handsets). Now the same edit is
   refused outright when the SO PIN is supplied and ignored when it is not,
   and a sealed policy that verifies is obeyed in the permissive direction.

   The SO PIN is never demanded: an ordinary pairing has no SO at the
   keyboard, and the price of not supplying it is the fail-closed answer.
   When it is wanted it comes from the same three sources as the user PIN —
   `--so-pin-stdin`, `XKEY_SO_PIN`, `--so-pin`, in that precedence
   (`soPINUsage`). Where an SO PIN might live for a command with no operator
   is an open owner decision on #290 and is not answered here.

   **Every absent value still means refuse.** Both policy fields are designed
   so that the zero value is the safe one — "not locked, not allowed" — and a
   `nil` policy is refuse by construction. That was originally forced by a
   partial `policy:` block zeroing the keys it omitted (#114); with that
   fixed it remains the right shape, because a default that means refuse and
   a zero that means refuse agree.

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

   **`requireAttestedKeyOrigin` requires the TEE's own claim that the key was
   generated in place, not merely held there (#132).** Everything above this
   point — the chain, the security level, the boot state, and (below) the live
   challenge signature — is equally consistent with a device attestation key
   generated elsewhere and **imported** into the TEE: the chain still
   certifies it, the security level still reads `strongbox`, and the
   signature still verifies. Only the TEE-enforced `Origin` claim inside the
   attestation extension rules that out.

   `RequireAttestedKeyOrigin` (`xkey/pkg/attestation/device.go`) refuses
   unless the leaf's `TeeEnforced` authorization list claims `Origin ==
   GENERATED` **and** its `Purpose` set includes `SIGN` — the one operation
   this protocol performs with the key. It reads `TeeEnforced` exclusively,
   never `SoftwareEnforced`: a software-enforced claim is the calling
   application's word, the same reason `requireAttestedBootState` above does
   not trust a software-enforced boot claim either. `pkg/attestation/android`
   parses both fields out of the extension's ASN.1 (`Origin` tag 702,
   `Purpose` tag 1) and defaults an **unclaimed** origin to `OriginUnknown`
   rather than the bare zero value — zero is also `OriginGenerated`'s value,
   so an attestation that never asserts an origin at all must not read as
   asserting `GENERATED`. An authorization list making neither claim — an
   absent extension, or evidence from a device with no TEE at all — therefore
   fails closed exactly as a wrong value would.

   A device that fails any of those is **unattestable**, which is a policy
   question with the policy answer above — not a silent admission.

   **Two pairing surfaces, one gate (#115, #131).** The desktop GUI pairs
   phones too, through `PhoneService.Pair` in `xkey/pkg/gui/services`, and
   until #115 that path ran the handshake, sent `pairing.confirm` and wrote
   the record without requesting an attestation at all. It was not the
   pre-#95 defect repeated — it wrote no unverified claim, because it obtained
   none — but the **gate** was missing: an unattestable device paired from the
   GUI without anything noticing, and its record carried no fingerprint, so
   the reconnect fingerprint check was inert for it. `Pair` now splits into
   the BLE half and `pairOverTransport`, and the latter runs, in order:
   handshake, `pairing.confirm`, `attestation.AttestOverSession` with purpose
   `pair` against the GUI's trust store, the policy, and only then the record.
   The decision, the record projection (`attestation.ApplyVerifiedAttestation`,
   shared with the CLI's `recordDeviceAttestation` rather than duplicated
   field for field — see *The paired-device record* below) and the policy
   resolution are the CLI's; what is the GUI's is which trust store to open
   and what the frontend is told (an `EventAttestationResult`). A GUI pairing supplies no
   SO PIN, so in a sealed deployment the enterprise plane is not consulted and
   the shared decision refuses; locking the setting open is proved through
   `xkey device pair` with the SO PIN (#118). A refusal is
   `ErrPhonePairAttestationRefused`, joined with the cause, and writes
   nothing. No trust store configured, or an `xkey.yaml` that exists but
   cannot be read, both **refuse** rather than admit — absent authorization
   material must never be less restrictive than the policy it implements.
   Both surfaces are tested against the same in-memory phone,
   `attesttest.Phone`: a real Noise XX responder with a persistent attested
   key that derives its own channel binding and lays out its own transcript.

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
Records established before #129 are refused outright (BREAKING, go-xkms
compat cleanup PR5, removing the original grace period that kept them
connecting in the weaker mode) -- `DeviceBinding.Validate` rejects any
`ProtocolVersion` below 2 with `ErrDeviceAttestationVersionUnsupported`, and
the device must be re-paired.

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
`transport.Config.Timeout` maps to the USB operation timeout. The relay
server's bind address is `phone.relay_listen_address` in the unified config
(`pkg/config`, validated as `host:port`; `XKEY_PHONE_RELAY_LISTEN_ADDRESS`),
resolved by `xkey device relay` as flag (`--listen`) over configuration over
the built-in `phone.DefaultTCPListenAddr` (`:8444`) (#140).

Device-side policy: `device_enrollment_policy.go`, `sharing_policy.go`.

## Persistence

The pairing — both static public keys and the device fingerprint — is persisted
on both sides. Everything else is session state and does not survive a
disconnect.

### The paired-device record — one owned type (#130)

`pairing.PairedDevice` (`xkey/pkg/pairing/device.go`) is the **one** record
type for a paired device, and it is what the CLI's `devices.yaml` and the
GUI's mirror of that same file both read and write. Before #130 the CLI
(`cmd/xkey/cmd/device.go`), the GUI's file mirror
(`pkg/gui/services/phone_service.go`) and this package each hand-maintained
their own struct for the same record, and the drift between the first two
silently dropped `attestation_protocol_version` from the GUI's copy — three
separate times (#95, #124 round 1, and the GUI mirror's own omission before
this unification) — so a CLI-paired challenge-response device reconnected
through the GUI as if it had never been attested.

`cmd.PairedDevice` and `services.phoneConfigDevice` are now type aliases to
`pairing.PairedDevice`, not separate definitions, so there is nothing left to
drift. Every persisted field carries both a `yaml` and a `json` tag; the
`yaml` tags are byte-compatible with the pre-unification CLI record (see the
round-trip test in `cmd/xkey/cmd/device_record_roundtrip_test.go`), because
`PairedDevice`'s field order was carried forward from the CLI's struct. The
GUI's writer used a different field order for the same conceptual record —
compare `device_record_roundtrip_test.go` (byte-identical) against
`pkg/gui/services/phone_record_roundtrip_test.go` (content-identical; see
that file's comment for why byte order cannot match both historical writers
at once).

Two fields exist only because the GUI populates them —
`PairedDeviceAttestationSnapshot` (`LastAttestation`, the last successful
attestation result, kept for auto-refresh and "pin as policy" without a fresh
BLE round trip) and `PairedDeviceAttestationPolicy` (`AttestationPolicy`, a
per-device baseline the GUI pins later attestations against) — and `IsBackend`
marks a device usable as a key backend. The CLI does not set any of the
three; it round-trips them unchanged, which is the point: before the
unification these three fields existed on the GUI's mirror alone, and a
CLI-driven save (pairing, re-attestation) had no way to preserve them because
it did not know they existed.

The GUI's Wails-facing view model (`services.PairedDevice`, JSON only — never
the persisted YAML shape) is a pure projection, `services.deviceView(d
pairing.PairedDevice, connected bool) PairedDevice`, never a parallel
definition. `pkg/gui/services/device_view_fieldset_test.go` reflects both
types' field sets and fails if a field is added to either one without an
explicit decision recorded for it — either a projection into the view or an
entry on the reviewed persisted-only allowlist — which is the general
mechanism #130 asked for, not a pin on today's field list.

`attestation.DeviceBindingFor(d pairing.PairedDevice) DeviceBinding` and
`attestation.ApplyVerifiedAttestation(d *pairing.PairedDevice, result
*Result)` (`xkey/pkg/attestation/device.go`) are the two functions that used
to be duplicated per surface as `attestationBinding()` and
`recordVerifiedAttestation`/`recordDeviceAttestation`. They live in
`pkg/attestation` rather than as methods on `pairing.PairedDevice` because
`pkg/attestation` already imports `pkg/pairing` to build `DeviceBinding`'s
contents (#95, #129); the reverse import would cycle. Neither function reads
or writes `LocalNoisePrivateKey`, sealed or not (#42) — the binding is built
from the public identity fields only.

### `LocalNoisePrivateKey` custody — sealed, never plaintext (#42)

The field holds one of two forms, told apart by a prefix and nothing else:

```go
const NoiseKeySealedPrefix = "xkey-noise-sealed-v1:"  // xkey/pkg/pairing/noise_key_seal.go

func IsSealedNoiseKey(stored string) bool
func SealLocalNoiseKey(barrier NoiseKeyBarrier, priv []byte) (string, error)
func UnsealLocalNoiseKey(barrier NoiseKeyBarrier, stored string) (*secure.Buffer, error)

type NoiseKeyBarrier interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}
```

- **Sealed** (current): `NoiseKeySealedPrefix` + base64 of the private scalar
  encrypted under the barrier's master key. `*sdk/go.Barrier` (go-qrdb's
  `StorageBarrier`) satisfies `NoiseKeyBarrier` directly — the same two
  methods its own `Put`/`Get` call to encrypt a KV entry at rest, so a key
  sealed this way is protected exactly like every other secret this stack
  keeps under the barrier, without going through the KV-store surface (the
  private scalar stays embedded in the `devices.yaml` record rather than
  becoming its own storage entry).
- **Legacy** (no barrier on this host): raw base64 of the private scalar, no
  prefix.

`UnsealLocalNoiseKey` picks which form it expects from barrier presence
alone, not from the stored value: a non-nil barrier means the record must be
sealed, a nil barrier means it must be legacy plaintext. A record in the
other form is refused with `ErrNoiseKeyFormMismatch` — there is no migration
between the two forms (BREAKING, go-xkms compat cleanup PR5, removing the
reseal-on-use path #42 originally shipped); the operator re-pairs the device
so a fresh record is written in the form that matches this host's current
barrier state. The unsealed material never exists as a Go string:
`SealLocalNoiseKey` takes the raw scalar as `[]byte` (typically
`phone.StaticKey.Private`, itself memguard-backed) and `UnsealLocalNoiseKey`
returns an `sdk/go/secure.Buffer`, mlocked and wiped on `Destroy`.

#### The barrier-absent case degrades, it does not refuse (owner ruling, recorded on #42)

`SealLocalNoiseKey`/`UnsealLocalNoiseKey` above are about one *value*: given a
barrier or not, seal or read accordingly, refuse a sealed value with no
barrier. What a **whole host** does when it has never run `xkey barrier init`
is a policy question one level up, decided per surface:

- **No barrier initialized on this host at all**: never refused. `Pair`
  writes the legacy plaintext form and logs `slog.Warn` once, pointing at
  `xkey barrier init`; `Connect`/`device listen`/`device attest-device` read
  a (necessarily legacy) record the same way, with the same warning.
- **A barrier exists but cannot currently be opened** (sealed — an app lock
  — or the CLI wasn't given a working password): still refused
  (`ErrPhoneBarrierRequired` / `ErrDeviceBarrierUnsealFailed`). The operator
  chose to protect this key by initializing a barrier; a locked one is not
  consent to fall back to plaintext.

The GUI's `PhoneService.resolveNoiseKeyBarrier()` and the CLI's
`openDeviceBarrier` are what draw this line, each returning a three-way
result — open, none-configured, or exists-but-unavailable — rather than the
two-way "have a barrier or don't" that `SealLocalNoiseKey` itself sees:

```go
// pkg/gui/services/phone_service.go
func (s *PhoneService) resolveNoiseKeyBarrier() (barrier pairing.NoiseKeyBarrier, noBarrierConfigured bool)
func (s *PhoneService) sealOrWarnLocalNoiseKey(deviceName string, priv []byte) (string, error)

// cmd/xkey/cmd/device_barrier.go
func openDeviceBarrier(cmd *cobra.Command) (pairing.NoiseKeyBarrier, func(), error)
func sealOrWarnLocalNoiseKey(logger *slog.Logger, deviceName string, barrier pairing.NoiseKeyBarrier, priv []byte) (string, error)
```

`resolveNoiseKeyBarrier`/`openDeviceBarrier` tell "none configured" apart from
"exists but sealed" using `BarrierService.IsInitialized()` (root key present
on disk, regardless of seal state) and `IsUnsealed()` (root key present *and*
currently open) together — `GetBarrier()` alone cannot: `BarrierService`
keeps its underlying `*xkms.Barrier` object across a `Seal()` call so a later
`Unseal()` can reuse it, so `GetBarrier()` stays non-nil for a sealed barrier
too. `noiseKeyBarrier()` (the read-only accessor `Connect` uses) checks
`IsUnsealed()` for the same reason, even though it does not need to
distinguish *why* a barrier is unavailable the way `resolveNoiseKeyBarrier`
does.

**Custody per surface:**

| Surface | Where | Barrier source | No barrier configured | Exists but sealed |
|---|---|---|---|---|
| GUI `Pair`/`Connect` | `pkg/gui/services/phone_service.go` | `PhoneService.SetBarrierService`, re-resolved on every use so an app lock/unlock is honoured | legacy plaintext + one `slog.Warn` | refuses (`ErrPhoneBarrierRequired`) |
| CLI `device pair`, `device listen`, `device attest-device` | `cmd/xkey/cmd/device_barrier.go` (`openDeviceBarrier`) | `--barrier-password`/`--barrier-password-file` flags, then `XKEY_BARRIER_PASSWORD`; resolved before the devices file is even read | legacy plaintext + one `slog.Warn` | refuses (`ErrDeviceBarrierUnsealFailed`) |
| Every other device-backed command (OATH sync, backup, sharing, re-attest, phone enrollment, FIDO2 phone backend) | `cmd/xkey/cmd/device_session.go` (`unsealDeviceLocalKey`, behind `openDeviceSession`/`newPairedDeviceBackendConfig`) | `XKEY_BARRIER_PASSWORD` only, opened and closed around the one unseal | unaffected — a legacy record already needed no barrier | refuses (only reached for an already-sealed record, which always needs a barrier) |

**No migration.** A device's record stays in whichever form it was written
in until the operator re-pairs it. There is no reseal-on-use: a legacy
plaintext record on a host that later gets a barrier initialized is not
transparently upgraded to the sealed form by `Connect`, `device listen`, or
`device attest-device` — those now return `ErrNoiseKeyFormMismatch`
(surfaced as `ErrPhoneMissingKeys` on the GUI side) once the barrier is
open, telling the operator to re-pair. Re-pairing (`xkey device pair` /
the GUI pairing flow) always writes the form that matches the barrier state
at pairing time, via `sealOrWarnLocalNoiseKey`.

## Test strategy

- **Unit** — `xkey/pkg/pairing` per-protocol suites.
- **Transport** — `go-xkms/pkg/api/transport/usb/transport_test.go`.
- **Android compatibility** — the compat suites that fix the cipher suite; these
  are what make a unilateral protocol change fail loudly.
- **Command flow** — `xkey/cmd/xkey/cmd/device_pair_flow_test.go` (build tag
  `ble`) drives `runDevicePair` itself against an `attesttest.Phone` on a
  memory transport, through the command's seams (`pairingSeams`: transport,
  devices file, attestation trust). It proves the wiring the helper tests
  cannot: under the default policy a failed attestation returns before the
  devices file is written; with the user plane opted in, the record is saved
  with the Noise identity and no attestation claim; a verified attestation
  is recorded with the phone's own fingerprint.
- **End to end** — `xkey/docs/testing/phone-e2e.md` in the legacy tree describes
  the manual procedure, which needs real hardware.

## Observability

The USB transport logs under `component=sdk_usb_transport` and reports a
successful connect. The events worth surfacing are the handshake outcome and a
fingerprint mismatch — the second is a security event, not a connectivity
problem, and it looks like a connection failure if nothing distinguishes it.
