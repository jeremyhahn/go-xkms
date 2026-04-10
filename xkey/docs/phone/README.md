# Phone Integration

The xkey binary communicates with an Android phone over BLE or USB for cryptographic operations. The phone can serve as a FIDO2 key backend, a general-purpose HSM, or a bidirectional key-sharing peer where each device uses the other's key backends.

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
                                      BLE GATT / USB (ADB)
                                                 |
                                        +--------v---------+
                                        |  Android Phone   |
                                        |  +-----------+   |
                                        |  | Keystore  |   |
                                        |  | TEE/SBox  |   |
                                        |  +-----------+   |
                                        +------------------+
```

The protocol is bidirectional. The laptop sends `local.*` methods to operate on phone keys, and the phone sends `remote.*` methods to operate on laptop xkmsd backends. Both directions share the same Noise XX encrypted channel.

## Capabilities

| Capability | Description |
|------------|-------------|
| FIDO2 key storage | Phone as hardware-backed FIDO2 key backend |
| General-purpose HSM | Sign, encrypt, ECDH, HMAC via phone hardware |
| Bidirectional sharing | Phone uses laptop's xkmsd backends |
| Key attestation | Android Key Attestation and TPM2 Certify |
| FIDO2 credential sharing | Shared discoverable credentials across devices |

## Quick Start

```bash
# Pair phone over BLE
xkey phone pair

# Use phone as FIDO2 backend
xkey fido2 --backend phone

# Use phone as HSM for signing
xkey phone sign --key my-key --input data.txt

# List keys on phone
xkey phone keys list

# Use phone over USB (ADB)
adb forward tcp:8444 tcp:8444
xkey phone pair --transport usb
```

## Configuration

Phone integration is configured in `~/.config/xkey/config.yaml`:

```yaml
phone:
  transport: ble          # ble or usb
  default_device: "Pixel"
  xkmsd:
    sharing:
      policy: "shared"
      allowed_backends: ["tpm2", "software"]
      denied_backends: ["vault"]
```

## See Also

- [xkey Phone Backend](backend.md) - Full phone backend reference
- [xkey Architecture](../architecture.md) - Component design
- [BLE Documentation](../ble/README.md) - BLE transport details
