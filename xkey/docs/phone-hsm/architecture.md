# Phone as HSM — Architecture

> **Status: NORMATIVE** · Feature: `phone-hsm` · Module: `go-xkms/xkey` · Last verified: 2026-09-25

## The problem

Every modern phone contains a hardware security element — a TEE, or StrongBox on
Android — that generates keys in hardware, refuses to export them, and can
attest to that. It is an HSM most people already carry, and it is idle.

The obstacle is the channel. A phone is not on the USB bus in any useful sense,
it moves between networks, and the connection has to be mutually authenticated
before a single key operation crosses it.

## Shape chosen: Noise XX over several transports, one protocol above

The wire protocol is **Noise XX** — mutual authentication with both static
public keys exchanged during the handshake:

```go
// pkg/trust/bootstrap/noise_session.go:29
NoiseXXProtocolName = "Noise_XX_25519_ChaChaPoly_SHA256"
```

XX rather than NK because both ends must authenticate: the desktop needs to know
it is talking to the paired phone, and the phone needs to know it is talking to
the paired desktop.

Above the session sits a JSON-RPC protocol split by concern. The wire types
are in `pkg/pairingproto/`; xkey's bridges that serve them are in
`xkey/pkg/pairing/`:

| Concern | Protocol file | Bridge |
|---|---|---|
| core | `protocol.go` | `bridge.go` |
| attestation | `protocol_attestation.go` | `bridge_attestation.go` |
| PIV | `protocol_piv.go` | `bridge_piv.go` |
| OATH | `protocol_oath.go` | `bridge_oath.go` |
| backup | `protocol_backup.go` | `bridge_backup.go` |
| sharing | `protocol_sharing.go` | `bridge_sharing.go` |
| sync | `protocol_sync.go` | `bridge_sync.go` |
| device enrollment | `protocol_device_enrollment.go` | — |
| IDevID | `protocol_idevid.go` | — |
| local / remote modes | `protocol_local.go`, `protocol_remote.go` | — |

The PIV, OATH, and sync bridges delegate to real xkey services
(`xkey/pkg/oath`, `xkey/pkg/sync`, and PIV certificate storage) that the CLI
wires into `BridgeConfig` per host; the backup bridge does not yet, pending
an open key-sourcing and persistence decision. See
[`engineering.md`](engineering.md) §"Bridge collaborators are optional, and
say so honestly" for the wiring contract and what each unconfigured method
reports.

Transports: USB AOA (`go-xkms/pkg/api/transport/usb`), TCP relay
(`xkey/pkg/pairing/tcp_transport.go`), and BLE. `pkg/pairingproto/fragmentation.go`
exists because none of these carry arbitrarily large frames.

Rejected alternatives:

- **A cloud relay holding the session.** Rejected: the session is
  end-to-end between two devices that authenticated each other; a relay that
  could read it would be a third party in the trust model.
- **Noise NK.** Rejected — NK authenticates only the responder. Both ends matter
  here.
- **Reusing the CTAP2 path.** Rejected: this is a general key-operation channel,
  not an authenticator protocol, and it carries PIV, OATH, backup and sync too.

## Component boundaries

| Piece | Where | Owner |
|---|---|---|
| Pairing wire protocol | `go-xkms/pkg/pairingproto` | go-xkms |
| Noise XX session | `go-xkms/pkg/trust/bootstrap` | go-xkms |
| Bridges, pairing record, TCP relay | `xkey/pkg/pairing` | go-xkms |
| Phone key backend | `go-xkms/pkg/backend/phone` | go-xkms |
| USB AOA transport | `go-xkms/pkg/api/transport/usb` | go-xkms |
| Android attestation verification | `go-xkms/pkg/attestation/android` | go-xkms |
| Phone-side implementation | **xkey-android** — a separate repo | xkey-android |

Capability rows: **"Phone-as-HSM pairing (wire contract)"** in the ownership
register, and **"Phone pairing (xkey-android)"** under the xkey product surface.

**The persisted pairing record also has one owner.** `pairing.PairedDevice`
(`xkey/pkg/pairing/device.go`) is the single type for the record `devices.yaml`
holds; the CLI (`cmd/xkey/cmd`) and the GUI (`pkg/gui/services`) both read and
write it directly rather than each keeping their own mirror of the file, and
the GUI's Wails-facing view model is a projection of it, never a second
definition. This closed a repeated defect: with two independent mirrors, a
field one surface added and the other did not — `attestation_protocol_version`
— silently reset a device's challenge-response binding on the surface that
lacked it (#95, #124 round 1, #130). See *The paired-device record — one owned
type (#130)* in `engineering.md` for the field-level detail.

**Coupling is by wire compatibility, not by import.** xkey-android is a Kotlin
application; there is no Go dependency in either direction. The consequence is a
hard rule: **a change to the pairing protocol must stay wire-compatible with
xkey-android, or be made on both sides in the same change.** The canonical wire
contract lives in the company documentation, not here.

## Data flow

```
pair:    xkey device pair
           → discover (BLE / USB / relay)
           → Noise XX handshake: both static keys exchanged and verified
           → identity exchange; the phone's attestation fingerprint enters the prologue
           → the pairing is persisted on both sides

use:     xkey fido2 --backend phone
           → key operations travel as JSON-RPC over the Noise session
             → the phone's TEE / StrongBox performs them
           ← results only; **private keys never leave the phone**

verify:  xkey device attest <key-id>
           → Android hardware attestation → go-xkms/pkg/attestation/android
```

The USB transport's `Connect` shows the model precisely: it loads the local
static key, opens the AOA channel, runs the identity exchange **on every
connection** — the phone's stream responder always expects it — and binds the
phone's attestation fingerprint into the Noise prologue.

## Trust boundaries

- **Both ends authenticate.** Noise XX, with `ExpectedRemoteStatic` and
  `ExpectedDeviceFingerprint` checked by the initiator.
- **The attestation fingerprint is in the prologue**, so a session cannot be
  established with a device whose attestation identity differs from the paired
  one — the binding is cryptographic, not a post-hoc check.
- **Keys never leave the phone.** The channel carries operations and results.
- **Nonces are monotonic per session, so requests are serialised.** The USB
  transport takes a mutex and says why: *"a Noise cipherstate advances a
  monotonic nonce per message, so concurrent senders would put frames on the
  wire out of nonce order and the phone would reject them."*
- **Pairing is the moment of trust.** Everything afterwards rests on the keys
  exchanged then; re-pairing is a deliberate act (`--force`).
- **A lost phone is a lost credential holder.** Unpair it; keys inside it cannot
  be extracted, which is the point and also the recovery constraint.
- **Enterprise policy is consulted only once authenticated.** The pairing
  command reads the SO-controlled `policy:` section through
  `config.LoadVerifiedPolicy`, which returns it only when the config directory
  is unsealed or the section verifies under the SO PIN, and fails closed
  otherwise. An unverified sealed policy is a value any local user could have
  written, and it grants nothing (#118).
- **This host's own Noise static private key is sealed in the barrier when
  this host has one** (#42). It is the credential that authenticates this
  host to the paired phone, so its exposure is symmetric with "keys never
  leave the phone" above: a copy of it lets a peer impersonate the host, the
  same way a copy of the phone's key would let a peer impersonate the phone.
  A host with **no barrier initialized at all** is not refused for that
  reason — it pairs and connects exactly as xkey always did, with the key in
  the legacy plaintext form and one warning logged per operation. A barrier
  that **exists** but cannot currently be opened (sealed, or an unattended
  command given no password) is a different case and does refuse: choosing to
  protect this key is not undone by a locked barrier. See
  *`LocalNoisePrivateKey` custody* in `engineering.md` for the sealed format
  and the per-surface decision, and `user.md` for what an operator sees.

## Known constraint: the cipher suite is fixed and not FIPS-approved

`NoiseXXProtocolName` (go-xkms `pkg/trust/bootstrap`, reached through
`sdk/go/bootstrap`) is a constant. ChaChaPoly is not a FIPS-approved cipher,
there is no AES-GCM alternative, and the suite is also fixed in
the Android compatibility tests. Under the portfolio's FIPS mandate that is a
real gap, and it is a **cross-repo** one: changing the suite requires
xkey-android to change in the same release, and the `Noise_NK` bootstrap path
additionally delegates to go-truststrap's `noiseproto`.

Documented here as shipped reality; the remedy is coordinated work, not a
documentation change.

## Where the SO PIN comes from for policy verification

The policy HMAC is keyed from the SO PIN, so verifying it needs the PIN, and a
pairing command has no SO at the keyboard. The choice made for #118 is that
the SO PIN is **supplied at the point of use, never demanded**: through the
same three sources as the user PIN (`--so-pin-stdin`, `XKEY_SO_PIN`,
`--so-pin`), and a command run without one fails closed. It is the only source
that exists in the product today, and it adds no secret at rest.

Rejected, or rather deferred, because each creates a new secret whose custody
is the open owner question on #290 (where a generated SO PIN may live):

| Alternative | Why not here |
|---|---|
| A TPM-sealed policy key (`PolicyHMAC.TPMNVIndex` exists and is unused) | A symmetric key any local process can ask the TPM to release can also forge the HMAC; it needs an authorization policy design of its own. |
| An SO-signed policy, verified with a public key | Removes the PIN from verification entirely, but replaces the sealing format and every writer of it; an architecture change, not a fix. |
| An escrowed SO PIN (platform keychain, separate sealed blob) | Exactly #290, and explicitly left to the owner there. |

Nothing in this feature precludes any of them: `LoadVerifiedPolicy` takes the
SO PIN as a string, so a future source plugs in without changing a consumer.

## What this feature deliberately does not do

- **It does not implement the phone side** — that is xkey-android.
- **It does not extract keys.** There is no operation that could.
- **It does not negotiate the cipher suite.** One constant, both sides.
- **It does not carry the password vault.** The USB transport implements the
  `PasswordService` methods and returns `ErrNotSupported` for every one.
