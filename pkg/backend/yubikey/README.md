# YubiKey Backend

A specialized backend implementation for YubiKey hardware tokens using the PIV (Personal Identity Verification) application.

## Overview

The YubiKey backend provides optimized support for YubiKey hardware tokens while maintaining full compatibility with the standard `types.Backend` interface. It wraps PKCS#11 operations with YubiKey-specific features and constraints.

## Features

- **PIV Slot Management**: Support for all 24 PIV slots (4 primary + 20 retired)
- **Automatic Token Detection**: Discovers YubiKey devices automatically
- **CN-Based Slot Mapping**: Intelligent mapping of key names to PIV slots
- **Management Key Support**: Configuration for administrative operations
- **Hardware-Backed Security**: All cryptographic operations on-device
- **Full Backend Interface**: Drop-in replacement for other backends

## PIV Slots

YubiKey PIV supports specific slots for key storage:

| Slot | Name | PIN Required | Use Case |
|------|------|--------------|----------|
| 0x9a | Authentication | Yes | General authentication |
| 0x9c | Digital Signature | Yes (always) | Digital signatures |
| 0x9d | Key Management | Yes | Encryption/decryption |
| 0x9e | Card Authentication | No | Automatic authentication |
| 0x82-0x95 | Retired Key Management | Yes | Additional key storage (20 slots) |

## CN-to-Slot Mapping

The backend uses a convention-based approach to map key Common Names (CN) to PIV slots:

```go
// Slot mapping by CN prefix:
"auth-mykey"           -> SlotAuthentication (0x9a)
"authentication-mykey" -> SlotAuthentication (0x9a)
"sig-mykey"            -> SlotSignature (0x9c)
"signature-mykey"      -> SlotSignature (0x9c)
"keymgmt-mykey"        -> SlotKeyManagement (0x9d)
"keymanagement-mykey"  -> SlotKeyManagement (0x9d)
"card-mykey"           -> SlotCardAuth (0x9e)
"cardauth-mykey"       -> SlotCardAuth (0x9e)
"retired1-mykey"       -> SlotRetired1 (0x82)
// ... through retired20-mykey -> SlotRetired20 (0x95)
"mykey"                -> SlotAuthentication (0x9a) // Default
```

Mapping is case-insensitive.

## Usage

### Basic Setup

```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/backend/yubikey"
    "github.com/jeremyhahn/go-keychain/pkg/storage/memory"
)

// Create configuration
config := &yubikey.Config{
    PIN:           "123456",              // YubiKey PIN
    ManagementKey: yubikey.DefaultMgmtKey, // Or custom management key
    KeyStorage:    memory.NewKeyStorage(),
    CertStorage:   memory.NewCertStorage(),
}

// Create backend
backend, err := yubikey.NewBackend(config)
if err != nil {
    log.Fatal(err)
}
defer backend.Close()

// Initialize
err = backend.Initialize()
if err != nil {
    log.Fatal(err)
}
```

### Generate Keys

```go
// Generate RSA key in Authentication slot
attrs := &types.KeyAttributes{
    CN:           "auth-mykey",  // Maps to slot 0x9a
    KeyAlgorithm: x509.RSA,
    RSAAttributes: &types.RSAAttributes{
        KeySize: 2048,
    },
}

key, err := backend.GenerateRSA(attrs)
if err != nil {
    log.Fatal(err)
}

// Generate ECDSA key in Signature slot
attrs = &types.KeyAttributes{
    CN:           "sig-mykey",  // Maps to slot 0x9c
    KeyAlgorithm: x509.ECDSA,
    ECCAttributes: &types.ECCAttributes{
        Curve: elliptic.P256(),
    },
}

key, err = backend.GenerateECDSA(attrs)
if err != nil {
    log.Fatal(err)
}
```

### Sign and Verify

```go
// Get signer for key
signer, err := backend.Signer(attrs)
if err != nil {
    log.Fatal(err)
}

// Sign data
data := []byte("message to sign")
hashed := sha256.Sum256(data)

signature, err := signer.Sign(nil, hashed[:], crypto.SHA256)
if err != nil {
    log.Fatal(err)
}

// Verify signature
pubKey := signer.Public().(*rsa.PublicKey)
err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], signature)
if err != nil {
    log.Fatal(err)
}
```

## Configuration

### Environment Variables

- `YUBIKEY_PKCS11_LIBRARY`: Path to libykcs11.so (auto-detected if not set)
- `YUBIKEY_PIN`: YubiKey PIN (defaults to "123456")

### Default Values

```go
DefaultPIN        = "123456"
DefaultPUK        = "12345678"
DefaultMgmtKey    = 010203040506070801020304050607080102030405060708 (hex)
```

### Library Paths

The backend auto-detects the YubiKey PKCS#11 library from common locations:

- `/usr/lib/x86_64-linux-gnu/libykcs11.so` (Debian/Ubuntu)
- `/usr/lib/libykcs11.so` (Generic Linux)
- `/usr/local/lib/libykcs11.so` (Custom install)
- `/usr/local/lib/libykcs11.dylib` (macOS Intel)
- `/opt/homebrew/lib/libykcs11.dylib` (macOS ARM)

## Testing

### Unit Tests

```bash
# Run YubiKey backend unit tests
make test-yubikey
```

Tests include:
- Backend creation and configuration
- Type and capabilities reporting
- CN-to-slot mapping (all variants)
- Configuration validation
- Initialization and cleanup

### Integration Tests

```bash
# Run all YubiKey integration tests
make integration-test-yubikey-backend

# Or run individual test suites:
make integration-test-rand-yubikey          # crypto/rand tests
make integration-test-pkcs11-yubikey-piv    # PIV slot tests
```

## Requirements

- **Hardware**: YubiKey 4 or later with PIV support
- **Software**:
  - Yubico PIV Tool (`yubico-piv-tool`)
  - YubiKey PKCS#11 library (`libykcs11.so` or `libykcs11.dylib`)
- **Permissions**: USB access permissions for YubiKey device

### Installation (Ubuntu/Debian)

```bash
sudo apt-get install yubico-piv-tool ykcs11
```

### Installation (macOS)

```bash
brew install yubico-piv-tool
```

## Slot Management

### Check Slot Status

```bash
yubico-piv-tool -a status
```

### Delete Key/Certificate from Slot

```bash
yubico-piv-tool -a delete-certificate -s 9a  # Delete from auth slot
```

### Reset PIV Application

**WARNING**: This erases ALL PIV keys and certificates!

```bash
yubico-piv-tool -a reset
```

## Capabilities

The YubiKey backend reports the following capabilities:

```go
Capabilities{
    Keys:                true,   // Supports key operations
    HardwareBacked:      true,   // Hardware-backed security
    Signing:             true,   // Supports signing
    Decryption:          true,   // Supports decryption
    SymmetricEncryption: false,  // No symmetric encryption
    ImportExport:        false,  // Keys are non-exportable
}
```

## Limitations

1. **Non-Exportable Keys**: Keys generated on YubiKey cannot be exported
2. **Slot Capacity**: Limited to 24 key slots (4 primary + 20 retired)
3. **Key Types**: Supports RSA (1024-4096), ECDSA (P-256, P-384), Ed25519
4. **No Symmetric Encryption**: YubiKey PIV doesn't support symmetric operations directly
5. **Management Key Required**: Administrative operations require management key authentication

## Security Considerations

1. **Change Default PIN**: Always change the default PIN (123456) in production
2. **Protect Management Key**: Store management key securely (required for admin operations)
3. **PUK for PIN Recovery**: Keep PUK (12345678 default) secure for PIN recovery
4. **PIN Retry Counter**: Limited PIN attempts (default: 3) before blocking
5. **Slot Selection**: Use appropriate slots for their intended purpose (e.g., signature slot for signing)

## Troubleshooting

### "YubiKey not found" Error

1. Check USB connection
2. Verify libykcs11 is installed
3. Check permissions: `lsusb` should show YubiKey
4. Try: `sudo chmod 666 /dev/bus/usb/XXX/YYY`

### "Token not initialized" Error

This may occur if:
- Slot already contains a key
- Management key authentication failed
- PIN is incorrect

Solution: Delete existing key from slot or use different slot

### "PIN locked" Error

Too many failed PIN attempts. Use PUK to reset:

```bash
yubico-piv-tool -a unblock-pin
```

## References

- [YubiKey PIV Documentation](https://developers.yubico.com/PIV/)
- [NIST SP 800-73-4](https://csrc.nist.gov/publications/detail/sp/800-73/4/final) - PIV Standard
- [Yubico PIV Tool](https://github.com/Yubico/yubico-piv-tool)

## License

Copyright (c) 2025 Jeremy Hahn
SPDX-License-Identifier: AGPL-3.0
