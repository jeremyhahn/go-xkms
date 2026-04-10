# Phone Backend

## Overview

The phone backend enables an Android phone to function as a hardware security module (HSM) for xkmsd. Private keys are stored in the Android Keystore (TEE or StrongBox) and all cryptographic operations are performed on the phone. Communication occurs over BLE or USB using the Noise XX protocol for end-to-end encryption.

This is a **bidirectional** key sharing architecture: the laptop can use keys stored on the phone (via `local.*` JSON-RPC methods), and the phone can use keys stored on the laptop's xkmsd backends (via `remote.*` JSON-RPC methods).

## Architecture

```
+-------------------+         +-------------------+         +-------------------+
|     xkmsd     |         |   Phone Backend   |         |   Android Phone   |
|                   |         |                   |         |                   |
|  Backend Registry |-------->| Transport Layer   |-------->| Android Keystore  |
|  Service Layer    |         |  (BLE / USB)      |         |  (TEE/StrongBox)  |
|                   |         |                   |         |                   |
+-------------------+         +--------+----------+         +-------------------+
                                       |
                                       v
                              +-------------------+
                              |    Noise XX       |
                              |  (E2E Encryption) |
                              +-------------------+
```

### Data Flow

```
xkmsd                Phone Backend              Transport              Phone
   |                          |                        |                     |
   |--- GenerateKey() ------->|                        |                     |
   |                          |--- JSON-RPC req ------>|                     |
   |                          |                        |--- Noise XX enc --->|
   |                          |                        |                     |
   |                          |                        |    Android Keystore |
   |                          |                        |    generates key in |
   |                          |                        |    TEE/StrongBox    |
   |                          |                        |                     |
   |                          |                        |<-- Noise XX enc ----|
   |                          |<-- JSON-RPC resp ------|                     |
   |<-- public key -----------|                        |                     |
```

### Bidirectional Key Sharing

```
Laptop uses phone keys (local.* methods):
  xkmsd --> Phone Backend --> BLE/USB --> Phone --> Android Keystore

Phone uses laptop keys (remote.* methods):
  Phone --> BLE/USB --> Phone Backend --> xkmsd --> TPM2/PKCS#11/Software
```

## Features

| Feature | Supported | Notes |
|---------|-----------|-------|
| Asymmetric keys (EC P-256/384/521) | Yes | Hardware-backed ECDSA |
| Asymmetric keys (RSA 2048/3072/4096) | Yes | Hardware-backed RSA |
| Symmetric keys (AES-GCM 128/256) | Yes | Hardware-backed AES |
| HMAC (SHA-256/512) | Yes | Hardware-backed HMAC |
| Hardware-backed | Yes | TEE or StrongBox |
| Key attestation | Yes | Android Key Attestation |
| Signing (crypto.Signer) | Yes | Operations performed on phone |
| Decryption (crypto.Decrypter) | Yes | RSA only |
| ECDH key agreement | Yes | Hardware-backed ECDH |
| Key import | No | Hardware keys cannot be imported |
| Key export | Public key only | Private keys never leave hardware |
| Sealing | No | Not supported by Android Keystore |
| Key rotation | No | Generate new key + delete old |
| Biometric protection | Yes | Per-operation biometric verification |

## Quick Start

### Configuration

```yaml
backends:
  phone:
    enabled: true
    transport: ble          # "ble" or "usb"
    device_name: "My Phone" # BLE advertisement name
    noise:
      static_key_path: /var/lib/xkmsd/noise/phone.key
      known_peers_path: /var/lib/xkmsd/noise/known_peers.json
```

### Pairing

```bash
# Start xkmsd with phone backend enabled
xkmsd --config /etc/xkmsd/config.yaml

# Initiate pairing (displays QR code for the Android app)
xkmsctl phone pair --transport ble

# Verify pairing
xkmsctl phone status
```

After pairing, the Noise XX handshake establishes a shared secret. Subsequent connections use the cached static keys for mutual authentication without repeating the full handshake.

## Capabilities

The phone backend returns the following capabilities:

```go
types.Capabilities{
    Keys:                true,
    HardwareBacked:      true,
    Signing:             true,
    Decryption:          true,
    KeyRotation:         false,
    SymmetricEncryption: true,
    Sealing:             false,
    Import:              false,
    Export:              false,  // public key export only (via GetKey)
    KeyAgreement:        true,
    ECIES:               false,
}
```

## Interfaces Implemented

| Interface | Package | Notes |
|-----------|---------|-------|
| `types.Backend` | `pkg/types` | Core key management interface |
| `types.AttestingBackend` | `pkg/types` | Android Key Attestation support |
| `types.SymmetricBackend` | `pkg/types` | AES-GCM and HMAC operations |
| `types.KeyAgreementBackend` | `pkg/types` | ECDH key agreement |
| `backend.ImportExportBackend` | `pkg/backend` | Partial: public key export only |

## Security Properties

### Key Isolation

- Private keys are generated inside and never leave the TEE or StrongBox secure element
- All signing, decryption, and key agreement operations execute on the phone hardware
- The phone backend only receives operation results (signatures, ciphertext), never raw key material

### Transport Security

- All communication between xkmsd and the phone is encrypted end-to-end using the Noise XX handshake pattern
- Noise XX provides mutual authentication, forward secrecy, and identity hiding
- BLE link-layer encryption provides an additional defense-in-depth layer
- USB transport uses the same Noise XX encryption over a serial framing protocol

### Authentication

- Biometric verification (fingerprint or face) is required for each cryptographic operation on the phone
- Paired device identity is verified via Noise static keys on every connection
- Android Key Attestation proves keys are hardware-backed and provides a certificate chain rooted in Google's attestation CA

### Threat Model

| Threat | Mitigation |
|--------|------------|
| BLE eavesdropping | Noise XX end-to-end encryption |
| Rogue phone pairing | QR-code-based out-of-band verification during pairing |
| Lost/stolen phone | Biometric requirement prevents unauthorized key use |
| Compromised laptop | Private keys remain on phone hardware; attacker cannot extract them |
| Man-in-the-middle | Noise XX mutual authentication with cached static keys |
| Key attestation forgery | Android Key Attestation chain verified against Google root CA |

## See Also

- [Architecture](architecture.md) - Detailed architecture and transport protocol design
- [Configuration](configuration.md) - Full configuration reference
- [Attestation](attestation.md) - Android Key Attestation integration
- [API](api.md) - JSON-RPC method reference for `local.*` and `remote.*` methods
- [Security](security.md) - Threat model and security analysis
- [xKey Phone Protocol](../../xkey/phone-backend.md) - xKey-specific phone backend usage
