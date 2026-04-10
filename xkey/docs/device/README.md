# Unified Device Pairing

xKey supports pairing with multiple device types through a unified `xkey device` CLI namespace. All device types share a common pairing protocol, configuration store, and management interface.

## Supported Device Types

| Type | Value | Description | Transport |
|------|-------|-------------|-----------|
| Phone | `phone` | Android/iOS phone | BLE, USB (AOA), TCP |
| Agent | `agent` | Remote machine (server/workstation) | TCP (mTLS gRPC) |
| Desktop | `desktop` | Desktop-to-desktop pairing | TCP |
| USB | `usb` | Hardware device via USB | USB |

## Configuration

Paired devices are stored in `~/.xkey/devices.yaml`. Legacy `phone.yaml` files are automatically migrated on first access.

```yaml
devices:
  - name: "John's Pixel"
    address: "AA:BB:CC:DD:EE:FF"
    noise_public_key: "<base64>"
    local_noise_private_key: "<base64>"
    paired_at: "2025-01-15T10:30:00Z"
    security_level: "strongbox"
    device_fingerprint: "abc123..."

default_device: "John's Pixel"

attestation_policy:
  require_device_attestation: true
  min_security_level: "tee"
  verify_boot_state: true
  auto_attest_on_connect: true
  default_grace_period: "5m"
```

The `PairedDevice` struct tracks: Name, Address, NoisePublicKey, LocalNoisePrivateKey, PairedAt, SecurityLevel, DeviceFingerprint, BootStateVerified, DeviceBootHashHex, AttestationGracePeriod, and LastDeviceAttestationTime.

## CLI Commands

### Client-Side (Pairing and Enrollment)

```
xkey device pair                          # BLE scan and pair with phone
xkey device pair --device "Pixel"         # Pair with specific device
xkey device pair --timeout 60s            # Extended scan timeout
xkey device pair --force                  # Force re-pair (handles BLE address rotation)
xkey device scan                          # Scan for nearby xKey BLE devices
xkey device scan --timeout 10s            # Quick scan
xkey device enroll --server host:9443     # Enroll as agent with master
xkey device enroll --server host:9443 --code ABCD1234  # Enroll with one-time code
xkey device connect host:9443             # Connect to enrolled master
xkey device list                          # List all paired devices
xkey device unpair "John's Pixel"         # Remove a device
xkey device unpair "Pixel" --force        # Remove without confirmation
xkey device status                        # Device connection status
xkey device status --device "Pixel"       # Status of specific device
xkey device relay                         # Start TCP relay server on :8444
xkey device relay --listen :9443          # Custom listen address
xkey device relay --qr                    # Start relay with QR code display
xkey device listen                        # Listen for incoming phone connections
```

The `device` command is aliased as `phone` for backward compatibility.

### Server-Side (Agent Management)

```
xkey agent start                          # Start agent gRPC server
xkey agent start --listen :9443           # Custom listen address
xkey agent start --tls-cert server.pem --tls-key server-key.pem  # With mTLS
xkey agent stop                           # Stop agent server
xkey agent status                         # Show enrolled agents
```

## Pairing Protocols

### Noise XX Handshake

All device types authenticate via the Noise Protocol Framework using the XX pattern:

```
Noise_XX_25519_ChaChaPoly_SHA256
```

This provides mutual authentication with static public keys exchanged during the handshake, plus forward secrecy via ephemeral Curve25519 keys. After the handshake completes, all subsequent messages are encrypted with ChaChaPoly (ChaCha20-Poly1305).

### Transport Layer

| Transport | Framing | Use Case |
|-----------|---------|----------|
| BLE GATT | MTU-based fragmentation | Phone pairing (proximity) |
| USB AOA | Android Open Accessory protocol | Phone pairing (wired) |
| TCP | 2-byte big-endian length-prefix | Agent, desktop, relay, ADB-forwarded |

TCP framing uses a 2-byte big-endian length prefix per message, with a maximum message size of 65535 bytes. Default TCP address is `localhost:8444`.

### QR Code Pairing

The relay server can generate a QR code containing an `xkey-pair://` URI. The payload is base64url-encoded JSON:

```json
{
  "v": 1,
  "type": "xkey-pair",
  "noise_pub": "<base64url Noise static public key>",
  "addr": "192.168.1.10:8444",
  "transport": "tcp",
  "name": "my-desktop",
  "code": "ABCD1234"
}
```

The scanning device decodes the URI, extracts the Noise public key and address, and initiates a TCP connection followed by a Noise XX handshake.

## Security

- All communication is encrypted via Noise XX session keys (ChaChaPoly)
- Device attestation verifies hardware security level (TEE, StrongBox, software)
- Boot state verification detects tampered devices via `DeviceBootHashHex`
- Attestation grace period controls how frequently re-attestation is required
- Agent enrollment supports one-time codes, admin approval, and enterprise CA methods
- Agent connections use mTLS with certificates obtained during enrollment
- Configuration file (`devices.yaml`) is written with 0600 permissions (contains private keys)
- Android BLE address rotation (RPA) is handled by `--force` re-pairing

### Enrollment Methods

| Method | Value | Description |
|--------|-------|-------------|
| BLE | `ble` | Bluetooth Low Energy proximity pairing |
| USB | `usb` | USB wired connection |
| TCP | `tcp` | TCP network connection |
| One-Time Code | `one-time-code` | Pre-shared enrollment code |
| Admin Approval | `admin-approval` | Manual approval on master |
| Enterprise CA | `enterprise-ca` | CA-issued certificate |
| Noise Direct | `noise-direct` | Direct Noise handshake |
| QR | `qr` | QR code scan |

### Attestation Policy

The `AttestationPolicy` can enforce requirements on paired devices:

- `RequireTPM` -- hardware TPM attestation required
- `RequireSecureBoot` -- verified/secure boot must be enabled
- `RequireBiometric` -- biometric authentication support required
- `MinSecurityLevel` -- minimum acceptable level (`tee`, `strongbox`)
- `AllowedPCRBanks` -- restrict accepted PCR hash algorithms

## Architecture

```
xkey/pkg/pairing/       Protocol layer (transport-agnostic)
  device.go               PairedDevice, DeviceType, EnrollmentMethod, TransportType
  transport.go            Transport interface (Send, Receive, SendAndReceive)
  noise.go                Noise XX session management
  tcp_transport.go        TCP transport with length-prefixed framing
  protocol_local.go       Desktop-to-device RPC methods (local.*)
  protocol_remote.go      Device-to-desktop RPC methods (remote.*)
  attestation.go          Device attestation verification
  bridge.go               Bridge to xkmsd backends for remote.* calls

xkey/pkg/phone/         BLE/USB/TCP transport implementations
  ble_transport.go        BLE GATT transport (build tag: ble)
  usb_transport.go        USB AOA transport
  tcp_server.go           TCP pairing server
  phone.go                Phone key backend integration

xkey/pkg/agent/         Agent gRPC server/client
  server.go               gRPC server for agent connections
  client.go               gRPC client for connecting to master
  enrollment.go           Enrollment service (CSR, approval, certs)
  store.go                File-based enrollment data store

xkey/pkg/qrgen/         QR code generation
  qrgen.go                QR image and terminal rendering
  payload.go              PairingPayload encoding/decoding, xkey-pair:// URI

xkey/pkg/qrscan/        QR code scanning
  scanner.go              Screen capture QR scanning

xkey/cmd/xkey/cmd/      CLI commands
  device.go               Parent command, list, unpair, status
  device_pair.go          BLE pairing flow
  device_scan.go          BLE device discovery
  device_enroll.go        Agent enrollment and connect
  device_relay.go         TCP relay server with QR
  device_listen.go        Incoming connection listener
  agent.go                Agent server start/stop/status
```
