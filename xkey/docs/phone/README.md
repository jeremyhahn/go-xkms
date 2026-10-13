# Phone Integration

> **Status: REFERENCE** · Last verified: 2026-10-13
> Superseded background for the [phone](architecture.md) and [phone-hsm](../phone-hsm/architecture.md) feature folders; where they disagree, the feature folders win.

The xkey binary communicates with an Android phone over BLE, USB or TCP for cryptographic operations (`xkey/pkg/phone/ble_transport.go`, `usb_transport.go`, `tcp_server.go`). The phone can serve as a FIDO2 key backend, a general-purpose HSM, or a bidirectional key-sharing peer where each device uses the other's key backends.

## Documentation

| Document | Description |
|----------|-------------|
| [Protocol](protocol.md) | Bidirectional JSON-RPC 2.0 protocol specification |
| [Attestation](attestation.md) | Bidirectional attestation: Android + TPM2/PKCS#11 |
| [Bidirectional](bidirectional.md) | Bidirectional key sharing design |
| [Transport](transport.md) | BLE and USB transport layers |

## Architecture

```
+------------------+      USB HID       +------------------+
|     Browser      |<------------------>|     xkey          |
|    (WebAuthn)    |                    |    (Desktop)      |
+------------------+                    +--------+---------+
                                                 |
                                         Phone Backend
                                                 |
                                         Noise XX Channel
                                                 |
                                      BLE GATT / USB / TCP
                                                 |
                                        +--------v---------+
                                        |  Android Phone   |
                                        |  +-----------+   |
                                        |  | Keystore  |   |
                                        |  | TEE/SBox  |   |
                                        |  +-----------+   |
                                        +------------------+
```

The protocol is bidirectional. The laptop sends `local.*` methods to operate on phone keys (`xkey/pkg/pairing/protocol_local.go:28`), and the phone sends `remote.*` methods to operate on laptop xkmsd backends (`xkey/pkg/pairing/protocol_remote.go:20`). Both directions share the same Noise XX encrypted channel.

## Capabilities

| Capability | Description |
|------------|-------------|
| FIDO2 key storage | Phone as hardware-backed FIDO2 key backend |
| General-purpose HSM | Sign, encrypt, ECDH, HMAC via phone hardware |
| Bidirectional sharing | Phone uses laptop's xkmsd backends |
| Key attestation | Android Key Attestation and TPM2 Certify |
| FIDO2 credential sharing | Shared discoverable credentials across devices |

## Quick Start

Phone verbs live in the `xkey device` group (`xkey/cmd/xkey/cmd/device*.go`);
the full reference is [phone-hsm/cli.md](../phone-hsm/cli.md).

```bash
# Find and pair a phone
xkey device scan
xkey device pair --device "Pixel-8"

# Use the paired phone as the FIDO2 backend
xkey fido2 --backend phone --phone-device "Pixel-8"

# Serve this host's backends to the phone (remote.* methods)
xkey device listen

# List paired devices
xkey device list
```

## Configuration

The `phone:` section of the xkey config file maps to `PhoneConfig`
(`xkey/pkg/config/config.go:121`):

```yaml
phone:
  backend: ""
  server_address: ""
  server_protocol: ""
  server_tls_enabled: false
  device_filter: ""
  attestation_policy: ""
  relay_listen_address: "127.0.0.1:8444"   # `xkey device relay --listen`
  tpm_enrollment: false                    # serve TCG-CSR-IDEVID enrollment from this host's TPM
```

## See Also

- [xkey Phone Backend](backend/README.md) - Full phone backend reference
- [xkey Architecture](../architecture/README.md) - Component design
- [BLE Documentation](../ble/README.md) - BLE transport details
