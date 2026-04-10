# Phone Transport

## Overview

The xkey binary supports two transports for phone communication. Both use the same Noise XX encrypted JSON-RPC 2.0 protocol. The transport layer is transparent to the protocol layer: all `local.*` and `remote.*` methods work identically over either transport.

```
+----------------------------+
|   JSON-RPC 2.0 Protocol   |
+----------------------------+
|   Noise XX Encryption      |
+----------------------------+
|   Transport Abstraction    |
+------+----------+----------+
| BLE  | USB/ADB  | USB/AOA  |
| GATT | (TCP)    | (Future) |
+------+----------+----------+
```

---

## BLE Transport

### Architecture

The laptop acts as a BLE central (client) connecting to the phone's GATT server (peripheral).

**GATT Service:**

```
xkey Service
UUID: f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d0f1d0

+-- Control Point
|   UUID: f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d00001
|   Properties: Write Without Response
|   Purpose: Send encrypted requests to phone
|
+-- Response
|   UUID: f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d00002
|   Properties: Notify
|   Purpose: Receive encrypted responses from phone
|
+-- Status
    UUID: f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d00003
    Properties: Read, Notify
    Purpose: Connection status, device info, error signaling
```

### Fragmentation

Messages larger than the BLE MTU are fragmented before transmission and reassembled on the receiver side.

**Fragment header (7 bytes):**

```
+----------+----------+----------+----------+
|  Flags   | Sequence |  Total   | Length   |
|  1 byte  | 2 bytes  | 2 bytes  | 2 bytes  |
+----------+----------+----------+----------+
|  Payload (MTU - 7 bytes)                  |
+-------------------------------------------+
```

| Field | Size | Description |
|-------|------|-------------|
| Flags | 1 byte | `0x01` first, `0x02` last, `0x03` single, `0x00` middle |
| Sequence | 2 bytes | Fragment index (0-based, big-endian) |
| Total | 2 bytes | Total number of fragments (big-endian) |
| Length | 2 bytes | Payload length in this fragment (big-endian) |
| Payload | variable | Fragment data (max MTU - 7 bytes) |

**Default MTU:** 247 bytes (negotiated during connection)
**Minimum MTU:** 23 bytes
**Max payload per fragment:** MTU - 7 bytes (240 bytes at default MTU)

**Reassembly rules:**

1. Fragments must arrive in sequence order
2. Out-of-order fragments cause message discard
3. If a fragment times out (5 seconds between fragments), partial message is discarded
4. Sequence numbers reset to 0 for each new message

### Connection Flow

```
Laptop (Central)                       Phone (Peripheral)
     |                                       |
     | 1. Scan for service UUID              |
     |-------- BLE Scan ------------------>  |  Phone advertising
     |                                       |
     | 2. Connect                            |
     |-------- Connect -------------------> |
     |<------- Connected ------------------|
     |                                       |
     | 3. Discover services                  |
     |-------- Discover GATT ------------->  |
     |<------- Service + Characteristics ---|
     |                                       |
     | 4. Negotiate MTU                      |
     |-------- MTU Request (512) ---------->|
     |<------- MTU Response (247) ----------|
     |                                       |
     | 5. Subscribe to Response + Status     |
     |-------- Enable Notifications ------->|
     |<------- Notifications Enabled -------|
     |                                       |
     | 6. Noise XX Handshake                 |
     |-------- e (ephemeral) -------------->| via Control Point
     |<------- e, ee, s, es ----------------| via Response
     |-------- s, se ---------------------->| via Control Point
     |                                       |
     | 7. Encrypted session established      |
     |<======= JSON-RPC Messages =========>|
     |                                       |
```

### Reconnection

When BLE connection drops:

1. Laptop detects disconnection via GATT callback
2. Laptop attempts reconnection using saved BLE address
3. If bonded, BLE link encryption resumes automatically
4. Noise XX handshake is performed again (new ephemeral keys)
5. JSON-RPC session resumes with fresh request ID counter

Reconnection timeout: 30 seconds (configurable)

---

## USB Transport (ADB Port Forwarding -- Stage 1)

### Architecture

The phone runs a TCP server on localhost. ADB port forwarding exposes the phone's TCP port to the laptop. The same Noise XX protocol runs over the TCP stream.

```
Laptop                            Phone
+------------------+              +------------------+
| xkey             |              | Android App      |
| TCP Client       |              | TCP Server       |
| localhost:8444   |              | localhost:8444   |
+--------+---------+              +--------+---------+
         |                                 |
         | TCP over ADB                    |
         +---- USB Cable ------------------+
```

### Setup

```bash
# 1. Enable USB debugging on phone
#    Settings > Developer options > USB debugging

# 2. Connect USB cable and authorize

# 3. Verify ADB connection
adb devices
# List of devices attached
# ABCD1234    device

# 4. Set up port forwarding
adb forward tcp:8444 tcp:8444

# 5. Pair phone over USB transport
xkey phone pair --transport usb
```

### Connection Flow

```
Laptop                                Phone
  |                                     |
  | 1. Verify ADB connection            |
  |     adb devices                     |
  |                                     |
  | 2. Set up port forwarding           |
  |     adb forward tcp:8444 tcp:8444   |
  |                                     |
  | 3. TCP connect                      |
  |-------- TCP SYN ------------------>|  localhost:8444
  |<------- TCP SYN-ACK --------------|
  |-------- TCP ACK ------------------>|
  |                                     |
  | 4. Noise XX Handshake               |
  |-------- e (ephemeral) ------------>|
  |<------- e, ee, s, es -------------|
  |-------- s, se ------------------->|
  |                                     |
  | 5. Encrypted session established    |
  |<======= JSON-RPC Messages =======>|
  |                                     |
```

### Framing over TCP

BLE fragmentation is not needed over TCP. Messages are framed with a 4-byte length prefix (big-endian uint32) followed by the Noise-encrypted payload:

```
+----------+----------------------------+
|  Length   |  Noise Encrypted Payload   |
|  4 bytes  |  (Length bytes)            |
+----------+----------------------------+
```

### Key Reuse

The same Noise static key pair is used for both BLE and USB transports. Pairing over one transport creates a trust relationship that works on either transport.

### Limitations

| Limitation | Details |
|------------|---------|
| USB debugging required | Phone must have developer options enabled |
| ADB authorization | Phone must authorize the laptop for ADB |
| USB cable | Physical cable connection required |
| Single host | ADB forwards to one laptop at a time |
| Manual setup | `adb forward` must be run before connecting |

---

## USB Transport (Custom Driver -- Stage 2, Future)

### Architecture (Planned)

A custom USB transport using Android USB Accessory Mode (AOA) or USB CDC-ACM will eliminate the ADB requirement.

```
Laptop                            Phone
+------------------+              +------------------+
| xkey             |              | Android App      |
| USB Driver       |              | USB Accessory    |
| (AOA or CDC-ACM) |              | Mode             |
+--------+---------+              +--------+---------+
         |                                 |
         +---- USB Cable ------------------+
         (no ADB, no debug mode)
```

**Key differences from ADB transport:**

- Phone acts as USB accessory (no debug mode needed)
- Direct USB bulk transfers (no TCP overhead)
- Automatic detection when cable is plugged in
- Same Noise XX + JSON-RPC protocol over USB bulk endpoints

### Planned Implementation

| Component | Laptop | Phone |
|-----------|--------|-------|
| USB mode | Host (sends accessory descriptor) | Accessory (AOA 2.0) |
| Endpoint | Bulk OUT (laptop to phone) | Bulk IN (phone to laptop) |
| Detection | USB VID/PID matching | Intent filter on USB accessory attach |
| Framing | 4-byte length prefix (same as TCP) | 4-byte length prefix |

---

## Transport Comparison

| Feature | BLE | USB (ADB) | USB (Custom, Future) |
|---------|-----|-----------|----------------------|
| Wireless | Yes | No | No |
| Range | ~10m | Cable length | Cable length |
| Throughput | ~1 Mbps | ~480 Mbps | ~480 Mbps |
| Latency | ~10ms | ~1ms | ~1ms |
| USB debug required | No | Yes | No |
| Setup | BLE pairing | `adb forward` | Plug in |
| Battery impact | Low (BLE) | Charges phone | Charges phone |
| Simultaneous | Yes | Yes | Yes |
| Fragmentation | Yes (MTU) | No (TCP framing) | No (USB bulk) |
| Reconnection | Auto (bonded) | Manual (`adb forward`) | Auto (USB attach) |

### When to Use Each

| Use Case | Recommended Transport |
|----------|----------------------|
| Daily wireless use | BLE |
| High-throughput operations | USB (ADB) |
| Low-latency signing | USB (ADB) |
| Charging while using | USB (ADB) |
| No USB debugging access | BLE |
| CI/CD automation | USB (ADB) |

---

## Simultaneous Transports

Both BLE and USB can run simultaneously. The phone maintains separate Noise sessions for each transport but routes to the same Android Keystore and JSON-RPC handlers.

```
Laptop
  |
  +-- BLE Transport --> Noise Session A --+
  |                                        |
  +-- USB Transport --> Noise Session B --+
                                           |
                                           v
                                    Phone Dispatcher
                                           |
                                    +------+------+
                                    |             |
                                 Keystore    JSON-RPC
                                 Handler     Router
```

**Session isolation:**

- Each transport has its own Noise session with independent keys
- Request IDs are scoped per session (no cross-session conflicts)
- One transport failing does not affect the other
- The phone does not bridge requests between transports

**Priority handling:**

When both transports are active, the laptop can route requests to either. By default, the xkey binary prefers USB when available (lower latency) and falls back to BLE:

```yaml
phone:
  transport_priority:
    - usb
    - ble
  fallback: true   # Auto-switch on transport failure
```

---

## Timeouts

| Operation | BLE | USB |
|-----------|-----|-----|
| Scan / discovery | 30s | N/A |
| Connection | 10s | 5s |
| Noise handshake | 10s | 5s |
| Key generation | 60s | 30s |
| Signing (with biometric) | 60s | 60s |
| Bulk operations | 120s | 60s |
| Reconnection | 30s | 10s |
| Fragment timeout | 5s | N/A |

Biometric operations share the same timeout regardless of transport, since the bottleneck is user interaction on the phone.

---

## See Also

- [Protocol Specification](protocol.md) - JSON-RPC method reference
- [BLE Architecture](../ble/architecture.md) - Detailed BLE GATT and Noise design
- [BLE Protocol](../ble/protocol.md) - Existing FIDO2 BLE protocol
- [Phone Backend](backend.md) - Full phone backend reference
