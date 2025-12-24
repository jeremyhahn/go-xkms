# CanoKey Integration

go-keychain provides comprehensive integration with CanoKey security keys, supporting both PIV (Personal Identity Verification) and FIDO2/WebAuthn functionality.

## Overview

CanoKey is an open-source, multi-function hardware security key that supports:
- **PIV** - Smart card operations via PKCS#11
- **FIDO2/WebAuthn** - Passwordless authentication
- **OpenPGP** - Email encryption and signing
- **TOTP** - Time-based one-time passwords

go-keychain integrates with CanoKey's PIV and FIDO2 interfaces for:
- Hardware-backed key storage
- Cryptographic signing operations
- Credential registration and authentication
- HMAC-secret based key derivation

## Quick Start

### PIV Operations (PKCS#11)

```go
import "github.com/go-keychain/keychain/pkg/backend/canokey"

// Create CanoKey backend
config := &canokey.Config{
    Library:    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    PIN:        "123456",
    TokenLabel: "CanoKey PIV",
}

backend, err := canokey.NewBackend(config)
if err != nil {
    log.Fatal(err)
}
defer backend.Close()

// Generate ECDSA key in PIV Authentication slot
attrs := &types.KeyAttributes{
    CN:           "my-signing-key",
    KeyAlgorithm: x509.ECDSA,
    ECDSAAttributes: &types.ECDSAAttributes{
        Curve: elliptic.P256(),
    },
}
key, err := backend.GenerateECDSA(attrs)
```

### FIDO2 Operations

```go
import "github.com/go-keychain/keychain/pkg/fido2"

// Create FIDO2 handler
handler, err := fido2.NewHandler(&fido2.Config{
    RelyingPartyID:   "example.com",
    RelyingPartyName: "Example App",
})
if err != nil {
    log.Fatal(err)
}
defer handler.Close()

// List connected devices
devices, _ := handler.ListDevices()
for _, d := range devices {
    fmt.Printf("Found: %s %s\n", d.Manufacturer, d.Product)
}

// Register credential
result, err := handler.EnrollKey(&fido2.EnrollmentConfig{
    RelyingParty: fido2.RelyingParty{ID: "example.com", Name: "Example"},
    User:         fido2.User{ID: []byte("user123"), Name: "alice"},
})
```

### CLI Commands

```bash
# PIV operations via keychain CLI
keychain key generate my-key --backend canokey --key-type ecdsa --curve p256
keychain key sign my-key --input message.txt --output signature.bin
keychain key list --backend canokey

# FIDO2 operations
keychain fido2 list-devices
keychain fido2 register alice --rp-id example.com
keychain fido2 authenticate --credential-id <id> --salt <salt>
```

## Hardware Support

| Device | PIV | FIDO2 | Firmware |
|--------|-----|-------|----------|
| CanoKey Pigeon | Yes | Yes | 2.0+ |
| CanoKey STM32 | Yes | Yes | 2.0+ |
| CanoKey QEMU (Virtual) | Yes | Yes | Virtual |

## Documentation

- [Architecture](architecture.md) - System design and components
- [Configuration](configuration.md) - Configuration options
- [Usage](usage.md) - CLI command reference
- [API](api.md) - Go API documentation
- [Security](security.md) - Security considerations

## Development

- [Implementation Plan](implementation-plan.md) - Detailed implementation plan
- [Implementation Checklist](implementation-checklist.md) - Progress tracking
