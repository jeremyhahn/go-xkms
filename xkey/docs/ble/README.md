# xkey Phone Backend via BLE

> **Status: REFERENCE** · Last verified: 2026-10-13
> Quick-start overview of the BLE phone backend; the [ble](architecture.md) feature folder is normative.

Use an Android phone as a FIDO2 key backend over Bluetooth Low Energy. Key storage, biometric prompts and the GATT server live in the separate **xkey-android** app; this repository holds the desktop side (`xkey/pkg/phone`) and the wire contract the app must match (see [Architecture](architecture.md#the-android-app-is-out-of-scope-for-this-repository)).

## Overview

The phone backend enables xkey to use an Android phone as a remote signing device:

```
┌─────────────────┐      USB HID       ┌─────────────────┐
│     Browser     │◄──────────────────►│    xkey         │
│   (WebAuthn)    │                    │   (Desktop)     │
└─────────────────┘                    │   BLE Central   │
                                       └────────┬────────┘
                                                │
                                           BLE GATT
                                       (Noise XX session)
                                                │
                                       ┌────────▼────────┐
                                       │ Android Phone   │
                                       │ BLE Peripheral  │
                                       │  (GATT Server)  │
                                       └─────────────────┘
```

## Key Features

- **Application-layer encryption**: every exchange runs inside a Noise XX session (`Noise_XX_25519_ChaChaPoly_SHA256`, `pkg/trust/bootstrap/noise_session.go:29`). The desktop does not perform OS-level BLE pairing or require an encrypted link; Noise is the only confidentiality layer it relies on (`xkey/pkg/phone/ble_transport.go:506-507`).
- **No network required**: direct BLE connection, works offline.
- **Linux (BlueZ)**: the central's recovery paths shell out to `bluetoothctl` (`ble_transport.go:1161-1214`), so macOS and Windows support is unconfirmed.

## Quick Start

### Prerequisites

**Desktop (xkey):**
- Linux with BlueZ and `bluetoothctl` on `PATH`
- Bluetooth adapter with BLE support
- xkey built with the `ble` tag: `make build` includes it (`xkey/Makefile:90`), or `go build -tags ble ./cmd/xkey/` from `xkey/`

**Phone:**
- The xkey-android app installed

### Pairing

There is no `xkey phone pair` command; pairing is `xkey device pair`
(phone-hsm's [cli.md](../phone-hsm/cli.md) and [user.md](../phone-hsm/user.md)).

1. Open xkey app on your phone and start advertising
2. On desktop, run:
   ```bash
   xkey device pair
   ```
3. The desktop prints a short verification code derived from the Noise
   handshake (`xkey/cmd/xkey/cmd/device_pair.go:363`). The Android app does
   not yet display a matching code, so there is nothing to confirm against
   it today; treat the printed code as informational until it does.
4. Keys are exchanged for secure communication

### Usage

Start the virtual FIDO2 device with phone backend (`xkey/cmd/xkey/cmd/fido2.go:405`):

```bash
xkey fido2 --backend phone
```

`--phone-device <name-or-address>` selects a specific paired phone (`fido2.go:411`).

Then use WebAuthn sites normally. When authentication is needed:
1. Phone receives signing request
2. User confirms on the phone
3. Signature sent back to desktop
4. WebAuthn completes

## Documentation

- [Architecture](architecture.md) - System design and security model
- [Protocol](protocol.md) - BLE GATT and JSON-RPC protocol specification
- [Android App](android-app.md) - Where the phone-side app lives and what it must match
- [Testing](testing.md) - Unit, integration and virtual-HCI BLE tests

## Security Model

| Threat | Mitigation |
|--------|------------|
| BLE eavesdropping | Noise XX session encryption |
| BLE MITM | Noise XX against the phone's pinned static key (`ExpectedRemoteStatic`, required unless `TrustNewDevices`, `xkey/pkg/phone/phone.go:375`) |
| Compromised BLE stack | Noise layer still protects |
| Stolen laptop | No keys stored, just pairing info |
| Replay attacks | Noise transport nonces |

## Requirements

### Go Package

Build with BLE support:
```bash
go build -tags ble ./cmd/xkey/
```

Without the `ble` tag, the BLE transport is a stub (`xkey/pkg/phone/ble_transport_stub.go:13`) and phone operations return `ErrBLEUnavailable` (`xkey/pkg/phone/errors.go:122`).

### Linux

- BlueZ with `bluetoothctl` on `PATH`
