# BLE Transport — Architecture

> **Status: NORMATIVE** · Feature: `ble` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

## Scope

This folder documents xKey's **Bluetooth Low Energy transport** for the
phone-as-HSM pairing protocol: the GATT wire shape, the two roles the
desktop can take (BLE central and BLE peripheral), BlueZ integration, and
the boundary with the Android app. It does not restate the pairing
protocol itself — the Noise XX session, the JSON-RPC method set, and the
other two transports (USB AOA, TCP relay) that carry the same protocol are
`xkey/docs/phone-hsm/`. Read that folder first; this one is the BLE-specific
layer underneath it.

There is no `xkey/pkg/ble` package. BLE support lives in two places:

- `xkey/pkg/phone` — the BLE-specific code, gated behind the `ble` build
  tag: `ble_transport.go` (central/client role), `ble_peripheral.go`
  (peripheral/server role), `ble_notify.go` (GATT-notify fragment writer).
  Each has a `!ble` stub (`ble_transport_stub.go`, `ble_peripheral_stub.go`)
  that returns `ErrBLEUnavailable` for every method, so a binary built
  without the tag still links and the CLI verbs that need it still exist
  (`cli.md`).
- `pkg/pairingproto`, `pkg/trust/bootstrap` and `xkey/pkg/pairing` — the
  transport-agnostic machinery BLE shares with the USB AOA and TCP relay
  transports: `Fragmenter`/`Reassembler` (`pkg/pairingproto/fragmentation.go`),
  the `Transport` interface (`pkg/pairingproto/transport.go`), the Noise XX
  session (`pkg/trust/bootstrap/noise_session.go`) and the `NoiseKeyBarrier`
  type (`xkey/pkg/pairing/noise_key_seal.go`). None of these files carry a
  build tag; they compile into every xkey binary.

## Two roles, one GATT service

**Central** (`BLETransport`, `xkey/pkg/phone/ble_transport.go`): the
desktop scans for and connects to a phone advertising the xKey service,
using `tinygo.org/x/bluetooth` over BlueZ's D-Bus API. `xkey device pair`
and `xkey device scan` use it (`cli.md`).

**Peripheral** (`BLEPeripheral`, `xkey/pkg/phone/ble_peripheral.go`): the
desktop advertises the xKey service itself and waits for a *phone* to
connect — the reverse role, used when the phone needs to initiate (for
example, to ask the laptop to re-attest itself). `xkey device listen` uses
it (`cli.md`).

Both roles expose the same GATT service and three characteristics, defined
once in `ble_transport.go:32-56` and reused by the peripheral's
`setupGATTService` (`ble_peripheral.go:432-469`):

| Characteristic | UUID | Central's use | Peripheral's permission flags |
|---|---|---|---|
| `XKeyServiceUUID` | `f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d0f1d0` | service filter for scanning | — |
| `ControlPointUUID` | `...f1d0f1d00001` | write requests | `CharacteristicWritePermission \| CharacteristicWriteWithoutResponsePermission` |
| `ResponseUUID` | `...f1d0f1d00002` | subscribe for responses | `CharacteristicNotifyPermission \| CharacteristicReadPermission` |
| `StatusUUID` | `...f1d0f1d00003` | subscribe for status | `CharacteristicNotifyPermission \| CharacteristicReadPermission` |

No characteristic is configured with an encrypted-permission flag in
either role (`ble_peripheral.go:438-456`) — see "Security model" below.

## Fragmentation

Both roles use the same 7-byte wire header from `pkg/pairingproto/
fragmentation.go`: `[1 byte flags][2 bytes sequence][2 bytes
total][2 bytes length]`, flags `0x01` first / `0x02` last / `0x03` single /
`0x00` middle. `MinMTU = 23` (`pairingproto`) and the central's
`DefaultMTU = 247` (`xkey/pkg/phone/phone.go:66`) come straight from BLE 4.0's floor and
the ATT default negotiated MTU. The peripheral cannot read back the ATT
MTU the central actually negotiated — `tinygo.org/x/bluetooth`'s
`DeviceCharacteristic.GetMTU` exists only on the central side — so it
reserves 7 bytes of headroom per notification rather than the strict
3-byte `ATT_HANDLE_VALUE_NTF` header cost, documented in
`xkey/pkg/phone/ble_notify.go:26-38`.

## Security model — what the code actually establishes

The **one** cryptographic layer this code establishes is the Noise XX
session (`Noise_XX_25519_ChaChaPoly_SHA256`, `pkg/trust/bootstrap/noise_session.go:29`)
documented in `xkey/docs/phone-hsm/`. Two things worth stating plainly,
because they correct a claim in the superseded `xkey/docs/ble/`
documentation (see this repo's docs conventions on legacy-vs-code
conflicts, and the disagreement list in this feature's handoff report):

- **The central deliberately does not perform OS-level BLE
  pairing/bonding.** `Connect` calls `trustBlueZDevice` before connecting
  "to avoid pairing prompts", with the comment *"For BLE, the pairing
  happens at the application level (Noise handshake)"*
  (`ble_transport.go:364-366`), and classic-Bluetooth bonding state is
  explicitly called "irrelevant for BLE" (`ble_transport.go:393`) — the
  code trusts the device and connects without ever calling BlueZ's pairing
  API.
- **No characteristic carries an encrypted-permission flag.** The
  peripheral's `CharacteristicConfig.Flags` (table above) use only the
  plain Write/WriteWithoutResponse/Notify/Read permissions
  `tinygo.org/x/bluetooth` exposes; there is no
  `CharacteristicEncryptRequiredPermission` (or equivalent) in use.

So there is exactly one layer of confidentiality and authentication over
the air: Noise XX. Whatever protection BlueZ's own link layer happens to
apply is opportunistic, not something this code configures, checks, or
depends on. Document threats against that model, not against a two-layer
one.

## BlueZ integration quirks

`ble_transport.go` carries real operational complexity for BlueZ's D-Bus
object lifecycle, worth keeping in mind when reading or changing it:

- **Android RPA rotation**: Android rotates its BLE resolvable private
  address periodically. `ConnectWithBondedAddress` accepts both the
  current scanned address and the last-bonded address so it can clean up
  the stale D-Bus object for the old address (`ble_transport.go:355-362`).
- **Stale D-Bus objects**: `isBlueZCacheError` recognizes BlueZ's
  `org.freedesktop.DBus.Properties` "doesn't exist" error and triggers a
  full `bluetoothctl remove` + rescan rather than a retry
  (`ble_transport.go:382-410`), returning the sentinel `ErrDBusStaleObject`
  to the caller so it knows to rescan.
- **`connEpoch`**: every new connection increments an atomic counter;
  notification callbacks captured at registration time compare against the
  live epoch and silently drop fragments from a stale, un-deregistered
  D-Bus signal handler (`ble_transport.go:118-124, 556-561`) — TinyGo/BlueZ
  is documented as failing to unregister these on disconnect.
- All of this shells out to `bluetoothctl` directly
  (`trustBlueZDevice`, `removeBlueZDevice`, `disconnectBlueZDevice`,
  `isDevicePaired`, `ble_transport.go:961-1034`), which is BlueZ-specific.
  **Cross-platform (macOS/Windows) BLE central support is not verifiable
  from this code**: every recovery path assumes `bluetoothctl` is on
  `PATH`, which is Linux/BlueZ-only. Treat a superseded claim of macOS or
  Windows support as unconfirmed rather than repeating it here.

## The Android app is out of scope for this repository

The phone side is **xkey-android**, a separate Kotlin repository with no Go
import in either direction (`xkey/docs/phone-hsm/architecture.md`
"Component boundaries" and "The cross-repo wire contract" already state
this for the whole pairing protocol; it applies equally to BLE). This
folder does not — and, since the code isn't in this repository, cannot —
document xkey-android's Gradle build, signing, or Kotlin GATT-server
implementation. What is verifiable and documented here is the wire shape
(GATT UUIDs, fragment header, JSON-RPC methods) that any phone-side
implementation must match; a change to any of it is a coordinated,
wire-compatible change on both sides.

## Where BLE sits in the build

`Makefile` includes `ble` in `BUILD_TAGS` (used by `make build`, which
produces the one combined GUI+CLI binary, run as CLI with `--no-gui`) and
in `DEV_TAGS`, but deliberately excludes it from
`TEST_TAGS`: `bluetooth.DefaultAdapter.Enable()` under the real `ble` tag
blocks for roughly 25 seconds on a machine with no BLE hardware, so `make
test` builds against the `!ble` stub instead and gets fast, hardware-free
runs (`xkey/Makefile:23-27, 88-95`). Real-hardware and virtual-HCI coverage
runs separately under `make integration-test-ble`, in a privileged
container (`xkey/Makefile:609-618`, `xkey/test/integration/ble`).

## Naming collision to avoid

`xkey usb` (`xkey/docs/usb/`) and the phone-hsm USB **AOA** transport
(`pkg/pairingproto/usb_transport.go`, gated by a *different* build tag,
`usb`) are unrelated features that happen to share the word "USB": one is
a virtual CCID reader and portable disk image, the other is a wired
alternative to this BLE transport for the same pairing protocol. Neither
is part of this folder.
