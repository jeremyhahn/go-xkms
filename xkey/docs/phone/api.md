# Phone Backend — API

> **Status: NORMATIVE** · Feature: `phone` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

`xkey/pkg/phone` has no network-facing API of its own — it is a Go library
consumed by the `xkey fido2` daemon and by the GUI. The two surfaces below are
where it becomes reachable from outside a Go process.

## The wire protocol (JSON-RPC over Noise XX)

`PhoneKeyBackend` and the phone's Android responder exchange the same
JSON-RPC-over-Noise protocol documented in phone-hsm's
[api.md](../phone-hsm/api.md) and [engineering.md](../phone-hsm/engineering.md)
— including the bare methods (`generateKey`, `sign`, `loadKey`, `deleteKey`,
`getInfo`, `ping`, `pairing.confirm`) that `PhoneKeyBackend` itself sends
(`pkg/pairingproto/protocol.go:35-41`), and the `local.*`/`remote.*` bridge
methods used once `EnableBidirectional` is active. This document does not
restate that catalog.

## GUI: `PhoneService` (Wails-bound)

`xkey/pkg/gui/services/phone_service.go`'s `*PhoneService` is registered in
the Wails `Bind` list (`xkey/pkg/gui/app.go:2581`), so every exported method
below is callable directly from the Svelte frontend
(`xkey/frontend/wailsjs/go/services/PhoneService`) — backing the **Pairing**
view (`xkey/frontend/src/views/Pairing.svelte`, `PairingDetail.svelte`,
`xkey/frontend/src/lib/components/PairBLEDialog.svelte`).

| Method | Signature | Line |
|---|---|---|
| `IsConnected` | `() bool` | `phone_service.go:462` |
| `ConnectedDeviceName` | `() string` | `phone_service.go:468` |
| `ListDevices` | `() ([]PairedDevice, error)` | `phone_service.go:474` |
| `GetDeviceStatus` | `(name string) (*DeviceStatus, error)` | `phone_service.go:496` |
| `Scan` | `(timeoutSeconds int) ([]DiscoveredDevice, error)` | `phone_service.go:504` |
| `Pair` | `(address string) (*PairedDevice, error)` | `phone_service.go:571` |
| `Unpair` | `(name string) error` | `phone_service.go:876` |
| `SetDeviceAsBackend` | `(name string, enabled bool) error` | `phone_service.go:972` |
| `GetBackendDevices` | `() ([]PairedDevice, error)` | `phone_service.go:999` |
| `Connect` | `(name string) error` | `phone_service.go:1024` |
| `Disconnect` | `(name string) error` | `phone_service.go:1239` |
| `AttestDevice` | `(name string) (*AttestationResult, error)` | `phone_service.go:1254` |
| `SetAttestationPolicy` | `(deviceName string) error` | `phone_service.go:1630` |
| `ClearAttestationPolicy` | `(deviceName string) error` | `phone_service.go:1662` |
| `GetAttestationPolicy` | `(deviceName string) (*pairing.PairedDeviceAttestationPolicy, error)` | `phone_service.go:1682` |
| `RetainedKeyCount` | `() int` | `phone_service.go:1849` |

`SetContext`, `SetEventEmitter`, `SetStatusChangeFunc`, `SetTrustStore`, and
`SetBarrierService` (`phone_service.go:334-386`) are wiring calls the app
makes during startup (`xkey/pkg/gui/app.go:755, 889-901, 2687, 2733`), not
part of the frontend-facing surface.

### View models (JSON-tagged, returned to the frontend)

```go
// phone_service.go:113-120 PairedDevice: Name, Address, PairedAt, LastSeen,
//                            Connected, IsBackend
// phone_service.go:141-148  DeviceStatus: Name, Address, Connected,
//                            BatteryLevel, RSSI, Firmware
// phone_service.go:151-155  DiscoveredDevice: Name, Address, RSSI
// phone_service.go:158-185  AttestationResult: DeviceName, Verified,
//                            ChainLength, AttestTime, ErrorMessage,
//                            SecurityLevel, BootState, BootHash,
//                            BootKeyHash, DeviceLocked, KeyAlgorithm,
//                            KeySize, KeyPurposes, ...
```

### Events

`PhoneEventEmitter` (`phone_service.go:105`) pushes `events.Event` values to
the frontend for pairing, connection, and attestation-policy-violation
outcomes (`emitPolicyViolationEvent`, `emitAttestationEvent`,
`phone_service.go:1383-1399, 1591-1601`). The event type itself is
`xkey/pkg/gui/events`, shared across every GUI service — not phone-specific.

### Not exposed through the GUI

USB AOA and the TCP relay (`pairingproto.USBTransport`, `phone.TCPPairingServer`)
have no `PhoneService` construction site — GUI pairing and connection are
BLE-only. Reaching a phone over USB or TCP relay today requires the CLI
(`xkey device relay`, or `NewPhoneKeyBackendWithTransport` from Go code).

## xkmsd-side: `pkg/backend/phone`

`go-xkms/pkg/backend/phone.Backend` implements `types.KeyProvider` for an
xkmsd server, proxying operations to a phone over the `local.*` methods via
a `Sender` interface any `pairingproto.Transport`-backed sender can satisfy
(`pkg/backend/phone/backend.go:36-62`). This is a `go-xkms` root capability
consumed by xkmsd, not something `xkey/pkg/phone` calls into directly — see
[`../../../docs/crypto-backends/engineering.md`](../../../docs/crypto-backends/engineering.md) and
phone-hsm's architecture.md for where it sits in the stack.
