# Phone Backend — Architecture

> **Status: NORMATIVE** · Feature: `phone` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

## Scope: this folder vs. [phone-hsm](../phone-hsm/)

Two folders cover the phone integration and they split at a specific seam:

- **[phone-hsm](../phone-hsm/)** documents `xkey/pkg/pairing` — the Noise XX
  session, the JSON-RPC protocol and its desktop-side bridges
  (`protocol*.go`/`bridge*.go`), and the `xkey device *` CLI group (`scan`,
  `pair`, `list`, `status`, `unpair`, `listen`, `relay`, `attest-device`, and
  more).
- **This folder** documents `xkey/pkg/phone` — the package that turns a
  paired phone into a `keybackend.FIDO2KeyBackend` (`PhoneKeyBackend`,
  `xkey/pkg/phone/phone.go`), the transports that package owns (BLE central
  and peripheral roles, USB AOA, a TCP relay responder), device-fingerprint
  continuity checking, and the GUI's `PhoneService`
  (`xkey/pkg/gui/services/phone_service.go`) that drives pairing and
  attestation from the desktop UI.

Where the two overlap — the Noise session, the wire protocol, the `device`
CLI verbs — this folder links to phone-hsm rather than restating it. BLE GATT
characteristics and the Android app are covered by
[../ble/](../ble/architecture.md); this folder links there too.

## The problem `xkey/pkg/phone` solves

`xkey fido2` needs a `keybackend.FIDO2KeyBackend` to generate and use
credential keys. Three backends exist: software, TPM 2.0, and phone
(`xkey/cmd/xkey/cmd/fido2.go:265` validates exactly those three names).
`xkey/pkg/phone.PhoneKeyBackend` is the phone one: it holds a
`pairing.Transport` and a `pairing.NoiseSession` and turns
`GenerateCredentialKey`/`Sign`/`LoadKey`/`DeleteKey` into encrypted JSON-RPC
round trips against the connected phone
(`xkey/pkg/phone/phone.go:190-243`, `:848-1105`).

Private key material never crosses the wire in either direction: keys are
generated inside the phone's TEE/StrongBox and the backend's
`Capabilities()` reports `SupportsExport: false`, `SupportsImport: false`
(`xkey/pkg/phone/phone.go:441-455`).

## Package shape

```
xkey/pkg/phone/
    phone.go              PhoneKeyBackend: keybackend.FIDO2KeyBackend impl
    transport.go           BLECapableTransport (extends pairing.Transport)
    ble_transport.go        BLE central role (build tag: ble)
    ble_transport_stub.go    stub for builds without "ble" (ErrBLEUnavailable)
    ble_peripheral.go       BLE peripheral/GATT-server role (build tag: ble)
    ble_peripheral_stub.go   stub for builds without "ble"
    usb_transport.go        USB Accessory Mode (AOA) client (build tag: usb)
    usb_transport_stub.go   stub for builds without "usb" (ErrUSBUnavailable)
    aoa.go                  AOA protocol constants (build tag: usb)
    tcp_server.go           TCP relay responder: TCPPairingServer
    fingerprint.go          device-fingerprint continuity check
    errors.go               sentinel errors (most re-exported from pairing)
```

`ble_notify.go` carries desktop-notification wiring for pending biometric
approvals. Everything under `pairing.Transport` is one of four concrete
transports; `PhoneKeyBackend` is transport-agnostic and is constructed either
with a BLE transport it manages itself (`NewPhoneKeyBackend`,
`xkey/pkg/phone/phone.go:248-280`) or with any pre-connected
`pairing.Transport` (`NewPhoneKeyBackendWithTransport`,
`xkey/pkg/phone/phone.go:287-302`) — which is how USB and TCP get used.

## Two build tags gate two hardware dependencies

| Tag | Enables | Why gated |
|---|---|---|
| `ble` | `BLETransport` (central), `BLEPeripheral` (peripheral) | `tinygo.org/x/bluetooth` and BlueZ D-Bus are Linux/BlueZ-specific |
| `usb` | `USBTransport`, AOA constants (`aoa.go`) | `google/gousb`'s libusb cgo dependency has no static/`CGO_ENABLED=0` build, so static release and FIPS-lane binaries exclude it (`xkey/pkg/phone/usb_transport_stub.go:16-21`) |

Without a tag, the corresponding type still compiles (stub files mirror the
real exported surface field-for-field) but every method returns
`ErrBLEUnavailable` or `ErrUSBUnavailable`
(`xkey/pkg/phone/ble_transport_stub.go`, `xkey/pkg/phone/usb_transport_stub.go`).
This is why `xkey fido2 --backend phone` on a build without `ble` fails with
`ErrFIDO2BLENotAvailable` rather than a panic
(`xkey/cmd/xkey/cmd/fido2_phone_stub.go:24-30`).

## Bidirectional roles, not a fixed client/server split

Nothing here is a fixed "phone is always the server" design:

- **Desktop as BLE central, phone as GATT peripheral** — the ordinary case.
  `BLETransport` scans, connects, and drives the Noise XX handshake as
  initiator (`xkey/pkg/phone/phone.go:457-616`).
- **Desktop as BLE peripheral, phone as GATT central** — `BLEPeripheral`
  advertises and accepts a connection, driving the handshake as responder.
  Wired into `xkey device listen` (`xkey/cmd/xkey/cmd/device_listen.go:305`);
  see phone-hsm's [cli.md](../phone-hsm/cli.md) for the verb.
- **TCP relay** — `TCPPairingServer` is this host's Noise responder over a
  plain TCP listener (default `:8444`,
  `xkey/pkg/phone/tcp_server.go:55`), for networks where BLE does not reach.
  Wired into `xkey device relay`; also covered in phone-hsm's cli.md.
- **USB AOA** — `USBTransport` is the desktop acting as USB host while the
  phone switches into Android Open Accessory mode
  (`xkey/pkg/phone/usb_transport.go`, `aoa.go`). The same low-level
  transport is wrapped by the SDK-facing `go-xkms/pkg/api/transport/usb`
  package that xkmsd uses to reach a phone directly (see phone-hsm's
  api.md, "The seventh transport").

Every one of these is a `pairing.Transport`; the Noise session and JSON-RPC
framing above the transport are identical regardless of which one carries
it (phone-hsm's [architecture.md](../phone-hsm/architecture.md)).

## Device-fingerprint continuity vs. live attestation

Two distinct checks bind a connection to the phone it was paired with, and
this package owns only the first:

1. **Fingerprint continuity** (`xkey/pkg/phone/fingerprint.go`) —
   `DecodeDeviceFingerprint` decodes the SHA-256 of the paired device's
   attestation leaf SubjectPublicKeyInfo, stored from pairing time, into the
   bytes the pre-handshake identity exchange compares against what the peer
   presents. It fails closed: a non-empty value that does not decode to
   exactly `DeviceFingerprintSize` (32) bytes returns
   `*InvalidDeviceFingerprintError`, never a silent "no fingerprint
   configured" (`xkey/pkg/phone/fingerprint.go:129-196`). This is a
   continuity check, not a live proof — the value is a public key hash and
   the connection has no verified chain at the moment it is compared.
2. **Live attestation** (`PhoneKeyBackendConfig.RequireLiveAttestation`
   and `.LiveAttest`, `xkey/pkg/phone/phone.go:136-157`) — the #129
   challenge-response proof that the peer currently holds the attested key,
   run once per connection via `proveLiveness`
   (`xkey/pkg/phone/phone.go:680-728`) immediately after the Noise
   handshake and before the backend serves any request. A device whose
   pairing record requires this and supplies no verifier gets
   `ErrLiveAttestationUnavailable` rather than a silently skipped check
   (`xkey/pkg/phone/errors.go:24-33`) — a deliberate fail-closed choice: the
   whole point of `RequireLiveAttestation` is that a missing verifier must
   never look like "no live-attestation policy".

The attestation protocol itself (`local.attestKey`, `remote.attestDevice`,
the certificate-chain verification) is `xkey/pkg/pairing`'s
`protocol_attestation.go`/`bridge_attestation.go`, documented in phone-hsm's
engineering.md.

## Bidirectional key sharing at the FIDO2-daemon layer

`xkey fido2 --backend phone` can additionally bridge the phone to this
host's own xkmsd, so the phone can also act as a client against this
machine's key backends:

1. `createFIDO2PhoneKeyBackend` (`xkey/cmd/xkey/cmd/fido2_device.go`)
   resolves the paired device from `devices.yaml`, builds a
   `PhoneKeyBackendConfig` (with the stored fingerprint and
   `RequireLiveAttestation` wired in via `newPairedDeviceBackendConfig`),
   connects, then calls `connectXKMSdBridge`.
2. `connectXKMSdBridge` (`xkey/cmd/xkey/cmd/fido2_phone_bridge.go:177-224`)
   is a no-op unless `xkmsd.enabled` is set in config. When enabled it
   dials xkmsd with the SDK client, builds a `pairing.Bridge`
   (`pairing.NewBridge`), and calls
   `PhoneKeyBackend.EnableBidirectional` — starting a `pairing.MessageRouter`
   goroutine that routes outbound `local.*` requests to the phone and
   dispatches inbound `remote.*` requests from the phone to the Bridge
   (comment at `fido2_phone_bridge.go:214-217`).
3. The returned backend is `phoneBackendWithBridge`, which embeds
   `*phone.PhoneKeyBackend` and additionally closes the xkmsd SDK client and
   any TPM handle opened for device-enrollment support on `Close()`
   (`xkey/cmd/xkey/cmd/fido2_phone_bridge.go:139-165`).

See [engineering.md](engineering.md) for the full `xkmsd.*` configuration
key list this depends on; there are no CLI flags for it.

## GUI layer: PhoneService

`xkey/pkg/gui/services/phone_service.go` is the Wails-bound service behind
the desktop GUI's **Pairing** view
(`xkey/frontend/src/views/Pairing.svelte`, `PairingDetail.svelte`,
`xkey/frontend/src/lib/components/PairBLEDialog.svelte`). It composes:

- `phone.BLETransport` for scan/connect (GUI pairing is BLE-only; USB AOA
  and TCP relay are CLI-only paths today — verified by the absence of any
  `USBTransport`/`TCPPairingServer` construction in
  `xkey/pkg/gui/services/phone_service.go`).
- `xkey/pkg/pairing` for the Noise session and attestation policy types.
- `xkey/pkg/attestation` (imported as `xkeyAttestation`) for attestation
  verification.
- The GUI's `BarrierService`, through `pairing.NoiseKeyBarrier`, to seal the
  local Noise static private key at rest rather than write it in plaintext
  (`SetBarrierService`, `resolveNoiseKeyBarrier`,
  `xkey/pkg/gui/services/phone_service.go:364-461`) — the same #42 barrier
  rule phone-hsm's engineering.md documents for the CLI path.
- `xkey/pkg/gui/events` to push connection/pairing/attestation events to the
  Svelte frontend, and a `PhoneStatusChangeFunc` hook the systray uses to
  reflect connection state (`xkey/pkg/gui/app.go:2376-2383`).

See [engineering.md](engineering.md) for the exported method groups and
[api.md](api.md) for the Wails-facing surface.

## What is out of scope here

- `go-xkms/pkg/backend/phone` — the xkmsd-side `types.KeyProvider`
  implementation that lets an xkmsd server offer phone-backed keys through
  the general Backend API, proxying to the phone over `local.*` JSON-RPC
  (`pkg/backend/phone/backend.go:53-62`). It is a `go-xkms` root capability,
  documented (thinly, "no backend guide written yet") at
  [`../../../docs/backends/README.md`](../../../docs/backends/README.md);
  phone-hsm's architecture.md also places it in its component table. This
  folder only names it as the destination on the other end of the
  bidirectional bridge above.
