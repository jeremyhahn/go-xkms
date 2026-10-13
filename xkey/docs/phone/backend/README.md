# Phone Backend

> **Status: REFERENCE** · Last verified: 2026-10-13
> Background for the xkmsd phone backend (`pkg/backend/phone`); superseded by [phone-hsm/architecture.md](../../phone-hsm/architecture.md). Where they disagree, the feature folder wins.

## Overview

The phone backend (`pkg/backend/phone`) enables an Android phone to function as a hardware security module (HSM) for xkmsd. Private keys are stored in the Android Keystore (TEE or StrongBox) and all cryptographic operations are performed on the phone. The configured transport is BLE, or TCP for USB with ADB forwarding (`TransportBLE`, `TransportTCP`, `pkg/backend/phone/config.go:27-30`); the Noise XX connection itself is owned by the embedder and handed to the backend as a `Sender` (`pkg/backend/phone/backend.go:39`).

This is a **bidirectional** key sharing architecture: the laptop can use keys stored on the phone (via `local.*` JSON-RPC methods), and the phone can use keys stored on the laptop's xkmsd backends (via `remote.*` JSON-RPC methods).

## Architecture

```
+-------------------+         +-------------------+         +-------------------+
|       xkmsd       |         |   Phone Backend   |         |   Android Phone   |
|                   |         |                   |         |                   |
|  Backend Registry |-------->| Transport Layer   |-------->| Android Keystore  |
|  Service Layer    |         |  (BLE / TCP)      |         |  (TEE/StrongBox)  |
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
  xkmsd --> Phone Backend --> BLE/TCP --> Phone --> Android Keystore

Phone uses laptop keys (remote.* methods):
  Phone --> BLE/USB/TCP --> xkey bridge --> xkmsd --> TPM2/PKCS#11/Software
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
| Biometric protection | Yes | Per-key policy (`biometricRequired`) |

## Quick Start

### Configuration

The xkmsd `backends.phone` section maps to `PhoneConfig`
(`pkg/config/config.go:1267`); see [configuration.md](configuration.md):

```yaml
backends:
  phone:
    enabled: true
    transport: ble                 # "ble" or "tcp"
    device_address: "AA:BB:CC:DD:EE:FF"
    noise_static_key: "<secret reference>"
    phone_static_key: "<hex public key of the paired phone>"
    request_timeout: 30s
```

### Pairing

xkmsctl has no phone verbs; phones are paired from xkey
(`xkey device scan`, `xkey device pair --device <name>`), documented in
[phone-hsm/cli.md](../../phone-hsm/cli.md).

After pairing, the Noise XX handshake establishes a shared secret. Subsequent connections use the cached static keys for mutual authentication.

## Capabilities

The phone backend returns the following capabilities
(`pkg/backend/phone/backend.go:191`):

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
    Export:              false,
    KeyAgreement:        true,
    Attestation:         true,
    SecurityLevel:       types.SecurityLevelHigh,
}
```

## Interfaces Implemented

| Interface | Assertion |
|-----------|-----------|
| `types.KeyProvider` | `pkg/backend/phone/backend.go:111` |
| `types.AttestingKeyProvider` | `pkg/backend/phone/attestation.go:25` |
| `types.SymmetricKeyProvider` | `pkg/backend/phone/symmetric.go:27` |
| `types.KeyAgreementProvider` | `pkg/backend/phone/key_agreement.go:24` |
| `backend.ImportExportBackend` | `pkg/backend/phone/import_export.go:25` (public key export only) |

## Security Properties

### Key Isolation

- Private keys are generated inside and never leave the TEE or StrongBox secure element
- All signing, decryption, and key agreement operations execute on the phone hardware
- The phone backend only receives operation results (signatures, ciphertext), never raw key material

### Transport Security

- All communication between xkmsd and the phone is encrypted end-to-end using the Noise XX handshake pattern
- Noise XX provides mutual authentication, forward secrecy, and identity hiding
- BLE link-layer encryption provides an additional defense-in-depth layer

### Authentication

- Keys generated with `biometricRequired` need fingerprint or face verification on the phone
- Paired device identity is verified via Noise static keys on every connection
- Android Key Attestation proves keys are hardware-backed and provides a certificate chain rooted in Google's attestation CA

### Threat Model

| Threat | Mitigation |
|--------|------------|
| BLE eavesdropping | Noise XX end-to-end encryption |
| Rogue phone pairing | A desktop-displayed short authentication string (SAS) derived from the Noise channel binding; see [Security](security.md) |
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
