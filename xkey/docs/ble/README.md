# xkey Phone Backend via BLE

Use your Android phone as a secure FIDO2 key backend via Bluetooth Low Energy. Keys are stored in Android Keystore/StrongBox with biometric binding, providing hardware-backed security without dedicated hardware tokens.

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
                                        (encrypted link)
                                                │
                                       ┌────────▼────────┐
                                       │ Android Phone   │
                                       │ BLE Peripheral  │
                                       │  (GATT Server)  │
                                       │  ┌───────────┐  │
                                       │  │ StrongBox │  │
                                       │  └───────────┘  │
                                       └─────────────────┘
```

## Key Features

- **Hardware-backed security**: Keys stored in Android Keystore with StrongBox (hardware security module)
- **Biometric protection**: Every signing operation requires fingerprint or face authentication
- **Double encryption**: BLE link encryption + Noise protocol application layer
- **No network required**: Direct BLE connection, works offline
- **Cross-platform**: Linux (BlueZ), macOS, and Windows support

## Quick Start

### Prerequisites

**Desktop (xkey):**
- Linux with BlueZ 5.48+ (or macOS/Windows)
- Bluetooth adapter with BLE support
- xkey built with BLE support: `go build -tags ble ./cmd/xkey/`

**Phone:**
- Android 9+ (API 28) with biometric hardware
- xkey Android app installed

### Pairing

1. Open xkey app on your phone
2. On desktop, run:
   ```bash
   xkey phone pair
   ```
3. Confirm pairing on both devices
4. Keys are exchanged for secure communication

### Usage

Start the virtual FIDO2 device with phone backend:

```bash
xkey fido2 --backend phone
```

Then use WebAuthn sites normally. When authentication is needed:
1. Phone receives signing request
2. User confirms with biometric
3. Signature sent back to desktop
4. WebAuthn completes

## Documentation

- [Architecture](architecture.md) - System design and security model
- [Protocol](protocol.md) - BLE GATT and JSON-RPC protocol specification
- [Android App](android-app.md) - Building and using the Android app
- [Testing](testing.md) - Integration testing guide

## Security Model

| Threat | Mitigation |
|--------|------------|
| BLE eavesdropping | Link encryption + Noise app layer |
| BLE MITM | LE Secure Connections + Noise mutual auth |
| Compromised BLE stack | Noise layer still protects |
| Stolen phone (locked) | Biometric required for signing |
| Stolen laptop | No keys stored, just pairing info |
| Replay attacks | Noise counters + nonces |

## Requirements

### Go Package

Build with BLE support:
```bash
go build -tags ble ./cmd/xkey/
```

Without the `ble` tag, phone commands return `ErrBLEUnavailable`.

### Linux

- BlueZ 5.48+ (standard on modern distros)
- User in `bluetooth` group or root access

### Android

- Android 9+ (API 28)
- StrongBox or TEE for key storage
- Biometric hardware (fingerprint or face)
