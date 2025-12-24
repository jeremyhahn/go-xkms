# CanoKey Architecture

## Overview

The CanoKey integration in go-keychain consists of two primary components:

1. **CanoKey PIV Backend** - PKCS#11-based key management via PIV smart card interface
2. **FIDO2 Handler** - CTAP2/HID-based credential management and authentication

```
┌─────────────────────────────────────────────────────────────────┐
│                        Application Layer                        │
├─────────────────────────────────────────────────────────────────┤
│  Keychain Service  │  FIDO2 Handler  │  WebAuthn Server        │
├─────────────────────────────────────────────────────────────────┤
│        CanoKey PIV Backend          │      FIDO2 Core          │
│        (pkg/backend/canokey)        │     (pkg/fido2)          │
├─────────────────────────────────────────────────────────────────┤
│           PKCS#11 Library           │     CTAP2/HID            │
│           (OpenSC)                  │     (libfido2)           │
├─────────────────────────────────────────────────────────────────┤
│                    CanoKey Hardware / QEMU                      │
└─────────────────────────────────────────────────────────────────┘
```

## CanoKey PIV Backend

### Location
`pkg/backend/canokey/`

### Components

| File | Purpose |
|------|---------|
| `canokey.go` | Main backend implementation |
| `config.go` | Configuration management |
| `slots.go` | PIV slot definitions and management |
| `canokey_sealer.go` | Data sealing operations |
| `canokey_symmetric.go` | Symmetric encryption (envelope) |
| `errors.go` | Error type definitions |

### PIV Slot Architecture

CanoKey supports 24 PIV slots:

| Slot | ID | Purpose | PIN Required |
|------|----|---------|--------------|
| Authentication | 0x9a | General authentication | Yes |
| Signature | 0x9c | Digital signatures | Always |
| Key Management | 0x9d | Encryption/decryption | Yes |
| Card Authentication | 0x9e | Card presence proof | No |
| Retired 1-20 | 0x82-0x95 | Additional key storage | Yes |

### Capabilities

```go
Capabilities: types.Capabilities{
    Keys:                true,   // Key generation/storage
    HardwareBacked:      true,   // Hardware security
    Signing:             true,   // Digital signatures
    Decryption:          true,   // RSA decryption
    SymmetricEncryption: true,   // Envelope encryption
    Sealing:             true,   // Hardware-bound sealing
    Import:              false,  // PIV keys non-exportable
    Export:              false,  // PIV keys non-exportable
}
```

### Algorithm Support by Firmware

| Algorithm | Firmware 2.0+ | Firmware 3.0+ |
|-----------|---------------|---------------|
| RSA 2048 | Yes | Yes |
| RSA 4096 | Yes | Yes |
| ECDSA P-256 | Yes | Yes |
| ECDSA P-384 | Yes | Yes |
| Ed25519 | No | Yes |
| X25519 | No | Yes |

## FIDO2 Handler

### Location
`pkg/fido2/`

### Components

| File | Purpose |
|------|---------|
| `fido2.go` | Main handler interface |
| `ctap2.go` | CTAP2 protocol implementation |
| `device.go` | HID device communication |
| `hmac_secret.go` | HMAC-secret extension |
| `config.go` | Configuration |
| `types.go` | Data types and constants |

### Handler Interface

```go
type Handler interface {
    EnrollKey(config *EnrollmentConfig) (*EnrollmentResult, error)
    UnlockWithKey(config *AuthenticationConfig) ([]byte, error)
    ListDevices() ([]Device, error)
    WaitForDevice(ctx context.Context) (*Device, error)
    Close() error
}
```

### CTAP2 Operations

1. **MakeCredential** - Create new credential
2. **GetAssertion** - Authenticate with credential
3. **GetInfo** - Query device capabilities

### HMAC-Secret Extension

The HMAC-secret extension enables deterministic key derivation:

```
Credential ID + Salt + Challenge → HMAC-SHA256 → Derived Key
```

Used for:
- Encryption key derivation
- Seed generation for hierarchical key systems
- Hardware-bound secret derivation

## CanoKey QEMU Integration

### Virtual Device Architecture

```
┌────────────────────────────────────────────────┐
│              Devcontainer                       │
├────────────────────────────────────────────────┤
│  ┌──────────────┐    ┌──────────────────────┐  │
│  │  Test Suite  │────│   CanoKey QEMU       │  │
│  │              │    │   (Virtual USB)      │  │
│  └──────────────┘    └──────────────────────┘  │
│         │                      │               │
│         ▼                      ▼               │
│  ┌──────────────┐    ┌──────────────────────┐  │
│  │   OpenSC     │    │   CTAP2/HID          │  │
│  │   PKCS#11    │    │   (Virtual)          │  │
│  └──────────────┘    └──────────────────────┘  │
└────────────────────────────────────────────────┘
```

### CanoKey QEMU Features

- Full PIV emulation
- FIDO2 CTAP2 support
- Persistent storage across runs
- CI/CD compatible (no physical hardware)

## Integration Points

### Server Protocols

All CanoKey operations are accessible via:
- **REST API** - HTTP/HTTPS endpoints
- **gRPC** - Protocol buffers RPC
- **QUIC** - HTTP/3 transport
- **MCP** - JSON-RPC 2.0
- **Unix Socket** - Local IPC

### CLI Commands

```bash
# PIV via keychain CLI
keychain key generate ...
keychain key sign ...
keychain cert create ...

# FIDO2 via keychain CLI
keychain fido2 list-devices
keychain fido2 register
keychain fido2 authenticate
```

## Security Model

### PIV Security
- Keys generated and stored on-device
- Never leave the security boundary
- PIN protection for sensitive operations
- Signed firmware updates only

### FIDO2 Security
- Credential bound to relying party
- User presence required (touch)
- Optional user verification (PIN)
- Attestation certificates

### Virtual Device Limitations

CanoKey QEMU is for **testing only**:
- No hardware security boundary
- Keys stored in software
- No physical user presence
- Suitable for CI/CD, not production
