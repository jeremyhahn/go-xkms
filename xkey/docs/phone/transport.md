# Phone Transport

> **Status: REFERENCE** · Last verified: 2026-10-13
> Transport background for the xkey phone link; superseded by [phone/architecture.md](architecture.md), [ble/](../ble/architecture.md) and [usb/](../usb/architecture.md). Where they disagree, the feature folders win. Phone-side (Android app) behaviour is unverified here.

## Overview

xkey reaches a paired phone over three transports. All carry the same Noise XX encrypted JSON-RPC 2.0 protocol, so `local.*` and `remote.*` methods work identically over each.

```
+----------------------------+
|   JSON-RPC 2.0 Protocol    |
+----------------------------+
|   Noise XX Encryption      |
+----------------------------+
|   Transport Abstraction    |
+------+----------+----------+
| BLE  | USB/AOA  | TCP      |
| GATT | (bulk)   | (relay)  |
+------+----------+----------+
```

| Transport | Code | Build tag |
|-----------|------|-----------|
| BLE GATT | `xkey/pkg/phone/ble_transport.go`, `ble_peripheral.go` | `ble` |
| USB (Android Open Accessory) | `xkey/pkg/phone/usb_transport.go`, `aoa.go` | `usb` |
| TCP | `xkey/pkg/phone/tcp_server.go` | none |

Without the tag, the BLE and USB files are replaced by stubs
(`ble_transport_stub.go`, `usb_transport_stub.go`).

---

## BLE Transport

### GATT Service

UUIDs from `xkey/pkg/phone/phone.go:52-61`:

```
xkey Service
UUID: f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d0f1d0

+-- Control Point
|   UUID: f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d00001
|   Purpose: Send encrypted requests to phone
|
+-- Response
|   UUID: f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d00002
|   Purpose: Receive encrypted responses from phone
|
+-- Status
    UUID: f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d00003
    Purpose: Connection status, device info, error signaling
```

### Fragmentation

Messages larger than the BLE MTU are fragmented before transmission and
reassembled on the receiver side (`xkey/pkg/pairing/fragmentation.go`).

**Fragment header (7 bytes, `FragmentHeaderSize`):**

```
+----------+----------+----------+----------+
|  Flags   | Sequence |  Total   | Length   |
|  1 byte  | 2 bytes  | 2 bytes  | 2 bytes  |
+----------+----------+----------+----------+
|  Payload                                  |
+-------------------------------------------+
```

| Field | Size | Description |
|-------|------|-------------|
| Flags | 1 byte | `0x01` first, `0x02` last, `0x03` single, `0x00` middle |
| Sequence | 2 bytes | Fragment index (0-based, big-endian) |
| Total | 2 bytes | Total number of fragments (big-endian) |
| Length | 2 bytes | Payload length in this fragment (big-endian) |

**Default MTU:** 247 bytes (`DefaultMTU`, `phone.go:64`)
**Minimum MTU:** 23 bytes (`MinMTU`, `xkey/pkg/pairing/constants.go:19`)

**Reassembly** (`Reassembler.AddFragment`, `fragmentation.go:210`):

1. Fragments are stored by sequence number, so arrival order does not matter
2. Duplicate fragments are ignored
3. A sequence number at or past `Total`, or a first fragment that changes `Total`, fails with `ErrSequenceNumber`
4. The message is complete when every fragment up to `Total` has arrived

### Connection Flow

```
Laptop (Central)                       Phone (Peripheral)
     |                                       |
     | 1. Scan for service UUID              |
     |-------- BLE Scan ------------------>  |  Phone advertising
     |                                       |
     | 2. Connect, discover services         |
     |-------- Connect -------------------> |
     |<------- Service + Characteristics ---|
     |                                       |
     | 3. Subscribe to Response + Status     |
     |                                       |
     | 4. Noise XX Handshake                 |
     |-------- e (ephemeral) -------------->| via Control Point
     |<------- e, ee, s, es ----------------| via Response
     |-------- s, se ---------------------->| via Control Point
     |                                       |
     | 5. Encrypted session established      |
     |<======= JSON-RPC Messages =========>|
```

The Noise XX handshake runs again on every reconnection, with new ephemeral keys.

---

## USB Transport (Android Open Accessory)

Built with the `usb` tag. The laptop switches the phone into accessory mode
and talks to it over USB bulk endpoints, with no ADB or debug mode. Accessory
devices are matched by Google's AOA IDs (`xkey/pkg/phone/aoa.go:30-36`):
vendor `0x18D1`, product `0x2D00` (accessory) or `0x2D01` (accessory + ADB).

Each message is framed with a 2-byte big-endian length prefix
(`usbFrameHeaderSize`, `usb_transport.go:46`). The default per-operation
timeout is 60 s (`DefaultUSBOperationTimeout`, `usb_transport.go:38`).

See [usb/architecture.md](../usb/architecture.md).

---

## TCP Transport

`xkey device relay` serves a paired phone's session over TCP instead of BLE
(`xkey/cmd/xkey/cmd/device_relay.go:44-45`). It listens on `--listen`, else
`phone.relay_listen_address`, else `127.0.0.1:8444`
(`DefaultTCPListenAddr`, `xkey/pkg/phone/tcp_server.go:69`). Each accepted
connection performs a Noise XX handshake and then serves JSON-RPC requests
(`TCPPairingServer`, `tcp_server.go:165`).

How the phone reaches the listener (for example ADB port forwarding over a USB
cable) is phone-side and not verified here.

### Framing over TCP

BLE fragmentation is not needed over TCP. Each Noise-encrypted message is
prefixed with a 2-byte big-endian length (`tcpFrameHeaderSize`,
`tcp_server.go:59`), so a message is at most 65535 bytes
(`maxTCPMessageSize`, `tcp_server.go:60`):

```
+----------+----------------------------+
|  Length  |  Noise Encrypted Payload   |
|  2 bytes |  (Length bytes)            |
+----------+----------------------------+
```

### Key Reuse

The same Noise static key pair is used on every transport. Pairing over one transport creates a trust relationship that works on the others.

---

## Transport Comparison

| Feature | BLE | USB (AOA) | TCP (relay) |
|---------|-----|-----------|-------------|
| Wireless | Yes | No | Depends on the network path |
| USB debug required | No | No | Only if the path is ADB |
| Fragmentation | Yes (MTU) | No (length prefix) | No (length prefix) |
| Build tag | `ble` | `usb` | none |

---

## Timeouts

| Constant | Value | Source |
|----------|-------|--------|
| `ScanTimeout` | 30s | `xkey/pkg/phone/phone.go:67` |
| `ConnectTimeout` | 10s | `phone.go:70` |
| `OperationTimeout` (includes biometric wait) | 60s | `phone.go:73` |
| `DefaultUSBOperationTimeout` | 60s | `usb_transport.go:38` |
| `DefaultHandshakeTimeout` (TCP) | 30s | `tcp_server.go:74` |
| `DefaultRequestTimeout` (TCP) | 30s | `tcp_server.go:80` |
| `DefaultIdleTimeout` (TCP) | 5m | `tcp_server.go:77` |
| `DefaultLiveAttestTimeout` | 120s | `xkey/pkg/phone/errors.go:31` |

Biometric operations share the same timeout regardless of transport, since the bottleneck is user interaction on the phone.

---

## See Also

- [Protocol Specification](protocol.md) - JSON-RPC method reference
- [BLE Architecture](../ble/architecture.md) - Detailed BLE GATT and Noise design
- [BLE Protocol](../ble/protocol.md) - FIDO2 BLE protocol
- [Phone Backend](backend/README.md) - xkmsd phone backend reference
