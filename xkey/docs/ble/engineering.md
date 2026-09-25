# BLE Transport — Engineering

> **Status: NORMATIVE** · Feature: `ble` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

## Exported surface

### `xkey/pkg/phone` — central (`ble_transport.go`, build tag `ble`)

| Symbol | Kind | Notes |
|---|---|---|
| `phone.BLETransportConfig` | type | `DeviceAddress`, `ScanTimeout`, `ConnectTimeout`, `OperationTimeout`, `MTU`, `Logger` |
| `phone.DefaultBLETransportConfig()` | func | `ScanTimeout=30s`, `ConnectTimeout=10s`, `OperationTimeout=60s`, `MTU=247` (`phone.go:63-73`) |
| `phone.NewBLETransport(cfg)` | func | enables the default adapter; returns `ErrBLEUnavailable` if it can't |
| `phone.BLETransport` | type | implements `pairing.Transport` and the package-local `BLECapableTransport` |
| `(*BLETransport).Scan/ScanAll/ScanWithOptions(ctx, ...)` | methods | `Scan` stops on first match, `ScanAll` runs the full timeout |
| `phone.ScanResult` | type | `Address`, `LocalName`, `RSSI`; `DisplayName()` falls back to `"xKey (<last 5 of address>)"` |
| `(*BLETransport).Connect(ctx, address)` / `ConnectWithBondedAddress(ctx, address, bondedAddress)` | methods | see architecture.md "BlueZ integration quirks" |
| `(*BLETransport).Send/Receive/SendAndReceive(ctx, ...)` | methods | fragment, write with a 10s per-fragment timeout, reassemble |
| `(*BLETransport).Disconnect()` / `DisconnectAndRemove()` | methods | the latter also removes the BlueZ device object to clear stale GATT handles |
| `(*BLETransport).IsConnected/ConnectedAddress/StatusChannel/SetMTU/MTU/Close` | methods | — |
| `(*BLETransport).CleanStaleBlueZEntry(address)` | method | removes a stale classic-BT cache entry before a scan |

### `xkey/pkg/phone` — peripheral (`ble_peripheral.go`, build tag `ble`)

| Symbol | Kind | Notes |
|---|---|---|
| `phone.BLEPeripheralConfig` | type | `LocalStaticKey *pairing.StaticKey`, `OwnsStaticKey bool`, `ExpectedRemoteStatic []byte`, `DeviceName string`, `MTU int`, `AdapterID string`, `Logger *slog.Logger`, `RequestHandler PeripheralRequestHandler` |
| `phone.PeripheralRequestHandler` | interface | `HandleRequest(ctx, request []byte) ([]byte, error)` |
| `phone.NewBLEPeripheral(cfg)` | func | — |
| `phone.BLEPeripheral` | type | GATT server; advertises `XKeyServiceUUID` |
| `(*BLEPeripheral).Start(ctx)` / `Stop()` | methods | `Start` is exclusive — a second concurrent `Start` fails (`reserveStart`) |
| `(*BLEPeripheral).AcceptConnection(ctx)` | method | performs the Noise handshake, then serves requests until disconnect |
| `(*BLEPeripheral).IsConnected()` / `LocalStaticPublicKey()` | methods | — |

### `xkey/pkg/phone` — stubs (`ble_transport_stub.go`, `ble_peripheral_stub.go`, build tag `!ble`)

Same type and method signatures as above; every method returns
`ErrBLEUnavailable` (transport) or the equivalent peripheral error. This is
what `make test` links against (architecture.md "Where BLE sits in the
build").

### `xkey/pkg/pairing` — shared, no build tag

| Symbol | Kind | Notes |
|---|---|---|
| `pairing.Transport` | interface | `Send(ctx, []byte) error`, `Receive(ctx) ([]byte, error)`, `Close() error` — satisfied by `*BLETransport` and the USB/TCP transports alike |
| `pairing.Fragmenter` / `NewFragmenter(mtu)` | type/func | `Fragment(message) ([][]byte, error)` |
| `pairing.Reassembler` / `NewReassembler()` | type/func | `AddFragment`, `Assemble`, `Reset`, `IsComplete`, `Progress` |
| `pairing.DecodeFragment(data)` | func | wire → `*Fragment` |
| `pairing.FragmentHeaderSize` / `MinMTU` | const | `7`, `23` |
| `pairing.NoiseProtocolName` | const | `"Noise_XX_25519_ChaChaPoly_SHA256"` |
| `pairing.StaticKey` | type alias | → `noiseproto.StaticKey` |
| `pairing.NoiseKeyBarrier` | interface | how the local Noise static private key is sealed/unsealed (#42; full detail in `xkey/docs/phone-hsm/engineering.md`) |

## Errors

BLE-only sentinels, from `xkey/pkg/phone/errors.go`:

| Sentinel | Meaning |
|---|---|
| `phone.ErrBLEUnavailable` | adapter could not be enabled, or built without the `ble` tag |
| `phone.ErrBLEPeripheralStopped` | peripheral was stopped |
| `phone.ErrAdapterDisabled` | Bluetooth adapter disabled |
| `phone.ErrServiceNotFound` / `ErrCharacteristicNotFound` | xKey GATT service/characteristics not found on the remote device |
| `phone.ErrDBusStaleObject` | BlueZ D-Bus cache conflict; caller should rescan |
| `phone.ErrShutdownIncomplete` | `Stop`/`Close` could not confirm every in-flight handler finished — see `OwnsStaticKey` above |
| `phone.ErrPeripheralAlreadyRunning` / `ErrPeripheralNotRunning` / `ErrPeripheralStartFailed` | peripheral lifecycle |
| `phone.ErrClientDisconnected` | the connected phone disconnected mid-session |
| `phone.ErrNotifyUnavailable` | GATT service not registered, or the Response characteristic handle never bound (`ble_notify.go`) |
| `phone.ErrUSBUnavailable` | **not a BLE error** — "phone: usb transport not built (build with `-tags usb`)"; the AOA transport's sentinel, listed here only to disambiguate it from BLE (architecture.md "Naming collision to avoid") |

Every generic pairing-session error (`ErrNotConnected`, `ErrConnectionFailed`,
`ErrDeviceNotFound`, `ErrTimeout`, `ErrBackendClosed`, `ErrNoiseHandshakeFailed`,
and the rest of `pairing.Err*`) is re-exported by value from `xkey/pkg/pairing`
so `errors.Is` matches identically regardless of transport
(`xkey/pkg/phone/errors.go:37-107`); the full list belongs to
`xkey/docs/phone-hsm/engineering.md`, not duplicated here.

## Configuration

No dedicated config schema for BLE itself. There is no `--transport`
selector for the phone pairing protocol (unlike `xkey usb device start`'s
`--transport uhid|gadget`, a different feature): BLE is simply what
`device pair`, `device scan`, and `device listen` construct directly
(`cmd/xkey/cmd/device_pair.go:120-127`, `device_listen.go`). The USB AOA
and TCP relay alternatives are separate commands/flags documented in
`xkey/docs/phone-hsm/`.

## Tests

| Layer | File | What it proves |
|---|---|---|
| `pkg/phone` | `ble_stub_test.go` | `!ble` stub fails closed with `ErrBLEUnavailable` for both transport and peripheral; `ScanResult.DisplayName` fallback |
| `pkg/phone` | `ble_peripheral_test.go` | request/response notify path, large-response fragmentation, send-failure propagation, MTU selection, fragment reassembly, malformed-fragment handling, `IsConnected`, `LocalStaticPublicKey` |
| `pkg/phone` | `ble_peripheral_advertising_test.go`, `ble_peripheral_shutdown_test.go` | advertising lifecycle; shutdown / `OwnsStaticKey` release semantics |
| `pkg/phone` | `phone_connect_ble_test.go` | central `Connect` retry logic: handshake retry, stale D-Bus recovery, scan-failure fallback to a saved address |
| `pkg/pairing` | `fragmentation_test.go`, `noise_test.go`, `noise_android_compat_test.go` | wire-format round-trips; Noise handshake compatibility with the Android app's expected byte sequences |
| `test/integration/ble` | `ble_integration_test.go` (build tags `integration linux ble`) | a virtual-HCI harness (`TestVirtualHCIHarness`) and full peripheral round-trip/repeated-request tests against it — no physical hardware, but a real BlueZ stack |

`make test` links the `!ble` stub (fast, no adapter) per architecture.md;
`make integration-test-ble` runs the virtual-HCI suite in a privileged
container.

## Non-goals

- No BLE-level pairing/bonding management — deliberately not used
  (architecture.md "Security model").
- No cross-platform (macOS/Windows) BLE central implementation verified in
  this codebase — every recovery path shells out to `bluetoothctl`.
- No REST/gRPC surface — BLE is a local transport between this host and a
  paired phone; see `api.md`.
