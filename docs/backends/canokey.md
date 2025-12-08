# CanoKey Backend

The CanoKey backend provides hardware-backed cryptographic key management using CanoKey PIV (Personal Identity Verification) functionality.

## Overview

CanoKey is an open-source hardware security key that provides PIV-compatible cryptographic operations. The CanoKey backend wraps PKCS#11 operations with CanoKey-specific features including firmware version detection, virtual device support for CI/CD, and hardware random number generation.

## Features

- **Hardware-Backed Keys**: All keys stored and operated on CanoKey hardware
- **PIV Compliance**: Full PIV smart card standard support
- **Virtual Mode**: QEMU emulation support for CI/CD testing without physical hardware
- **Firmware Detection**: Automatic firmware version detection with feature capability checks
- **Hardware RNG**: Hardware random number generator
- **Multiple Algorithms**: RSA, ECDSA with firmware-dependent feature support
- **24 PIV Slots**: Support for all standard PIV slots (9a, 9c, 9d, 9e, 82-95)
- **Symmetric Encryption**: AES-GCM envelope encryption using PIV keys
- **Sealing Operations**: Hardware-backed data sealing/unsealing

## Supported Algorithms

### Current Firmware (2.0+)
- **RSA**: 2048, 4096 bits
- **ECDSA**: P-256, P-384 curves
- **Hardware RNG**: Up to 1024 bytes per call

### Advanced Firmware (3.0+)
- **Ed25519**: EdDSA signatures
- **X25519**: ECDH key agreement

## Configuration

```go
import "github.com/jeremyhahn/go-keychain/pkg/backend/canokey"

config := &canokey.Config{
    PIN:       "123456",     // Default CanoKey PIN
    IsVirtual: false,        // Set true for QEMU testing
}

backend, err := canokey.NewBackend(config)
if err != nil {
    log.Fatal(err)
}

if err := backend.Initialize(); err != nil {
    log.Fatal(err)
}
defer backend.Close()
```

### Configuration Options

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `Library` | string | No | Auto-detect | Path to OpenSC PKCS#11 library |
| `TokenLabel` | string | No | Auto-detect | CanoKey token label |
| `PIN` | string | Yes | "123456" | PIV PIN |
| `Slot` | *uint | No | Auto | PIV slot (0x9a, 0x9c, 0x9d, 0x9e, 0x82-0x95) |
| `IsVirtual` | bool | No | false | Enable for QEMU virtual CanoKey |
| `KeyStorage` | storage.Backend | No | - | Key metadata storage |
| `CertStorage` | storage.Backend | No | - | Certificate storage |

### PIV Slots

CanoKey PIV supports the standard PIV slots:

| Slot | Name | Purpose | PIN Required |
|------|------|---------|--------------|
| 0x9a | Authentication | General authentication | Yes |
| 0x9c | Digital Signature | Digital signatures | Always |
| 0x9d | Key Management | Encryption/decryption | Yes |
| 0x9e | Card Authentication | Card authentication | No |
| 0x82-0x95 | Retired Key Management | 20 additional key slots | Yes |

## Usage Examples

### Key Generation

```go
// Generate RSA 2048 key in Authentication slot
attrs := &types.KeyAttributes{
    CN:           "canokey-rsa-key",
    KeyAlgorithm: x509.RSA,
    RSAAttributes: &types.RSAAttributes{
        KeySize: 2048,
    },
}

key, err := backend.GenerateKey(attrs)
if err != nil {
    log.Fatal(err)
}

// Use key for signing
signer, err := backend.Signer(attrs)
if err != nil {
    log.Fatal(err)
}
signature, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
```

### ECDSA Key Generation

```go
attrs := &types.KeyAttributes{
    CN:           "canokey-ecdsa-key",
    KeyAlgorithm: x509.ECDSA,
    ECCAttributes: &types.ECCAttributes{
        Curve: elliptic.P256(),
    },
}

key, err := backend.GenerateKey(attrs)
```

### Hardware Random Number Generation

```go
// Generate 256 bytes of hardware entropy
randomBytes, err := backend.GenerateRandom(256)
if err != nil {
    log.Fatal(err)
}
```

### Symmetric Encryption (Envelope Encryption)

CanoKey supports symmetric encryption via envelope encryption - symmetric keys are wrapped/unwrapped using the PIV RSA or ECDSA keys:

```go
// Generate a symmetric key
symAttrs := &types.KeyAttributes{
    CN:                 "canokey-aes-key",
    SymmetricAlgorithm: types.SymmetricAES256GCM,
}

symKey, err := backend.GenerateSymmetricKey(symAttrs)
if err != nil {
    log.Fatal(err)
}

// Get encrypter for symmetric operations
encrypter, err := backend.SymmetricEncrypter(symAttrs)
if err != nil {
    log.Fatal(err)
}

// Encrypt data
ciphertext, err := encrypter.Encrypt([]byte("sensitive data"), nil)

// Decrypt data
plaintext, err := encrypter.Decrypt(ciphertext, nil)
```

### Sealing Operations

```go
// Seal data (hardware-backed encryption)
ctx := context.Background()
sealOpts := &types.SealOptions{
    KeyAttributes: attrs,
}

sealed, err := backend.Seal(ctx, []byte("secret data"), sealOpts)
if err != nil {
    log.Fatal(err)
}

// Unseal data
unsealOpts := &types.UnsealOptions{
    KeyAttributes: attrs,
}

plaintext, err := backend.Unseal(ctx, sealed, unsealOpts)
```

## Virtual Mode (CanoKey QEMU)

For CI/CD testing without physical hardware, use CanoKey QEMU:

```go
config := &canokey.Config{
    PIN:       "123456",
    IsVirtual: true,  // Marks as software emulation
}

backend, err := canokey.NewBackend(config)
```

**Note**: Virtual mode sets `HardwareBacked = false` in capabilities to indicate keys are not protected by physical hardware.

### Setting Up CanoKey QEMU

```bash
# Clone CanoKey QEMU
git clone https://github.com/canokeys/canokey-qemu.git
cd canokey-qemu

# Build and run
make
./qemu-system-x86_64 -usb -device canokey
```

## Firmware Version Matrix

| Firmware | RSA Sizes | ECDSA Curves | Ed25519/X25519 |
|----------|-----------|--------------|----------------|
| 1.x | Limited | Limited | No |
| 2.0+ | 2048, 4096 | P-256, P-384 | No |
| 3.0+ | 2048, 4096 | P-256, P-384 | Yes |

## Hardware Requirements

### Supported CanoKeys

- CanoKey Pigeon
- CanoKey STM32
- CanoKey QEMU (virtual, for testing)

### System Requirements

**Linux:**
```bash
# Install OpenSC PKCS#11 library
apt-get install opensc   # Debian/Ubuntu
dnf install opensc       # Fedora/RHEL
```

**macOS:**
```bash
brew install opensc
```

### Library Paths

- **Linux**: `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so`
- **macOS**: `/usr/local/lib/opensc-pkcs11.so`

Override with environment variable:
```bash
export CANOKEY_PKCS11_LIBRARY=/path/to/opensc-pkcs11.so
```

## Security Considerations

### PIN Management

- **Default PIN**: 123456 (change immediately!)
- **Length**: 6-8 characters
- **Attempts**: 3 failed attempts locks the PIN
- **PUK**: Used to reset PIN after lockout

### Hardware vs Virtual Mode

| Mode | HardwareBacked | Use Case |
|------|----------------|----------|
| Hardware | true | Production deployments |
| Virtual (QEMU) | false | CI/CD testing, development |

**Important**: Virtual mode provides the same API but keys are NOT protected by hardware. Never use virtual mode for production secrets.

### Slot Management

- **One key per slot**: Each PIV slot holds one key
- **No overwrite**: Must delete existing key before generating new one

## Integration Testing

Run CanoKey integration tests:

```bash
# With physical CanoKey
go test -v -tags="pkcs11" ./test/integration/canokey/...

# With CanoKey QEMU (virtual)
CANOKEY_VIRTUAL=true go test -v -tags="pkcs11" ./test/integration/canokey/...
```

## Troubleshooting

### CanoKey Not Detected

**Error**: `canokey: no CanoKey device found`

**Solutions**:
1. Check CanoKey is plugged in: `lsusb | grep -i cano`
2. Verify OpenSC is installed: `pkcs11-tool --list-slots`
3. Check PKCS#11 library path
4. Restart pcscd service: `systemctl restart pcscd`

### PIN Authentication Failed

**Error**: `canokey: failed to login with PIN`

**Solutions**:
1. Verify PIN is correct
2. Check if PIN is locked (too many failed attempts)
3. Reset PIN using PUK if locked

### Firmware Version Mismatch

**Error**: `canokey: Ed25519 requires firmware 3.0+`

**Solution**: Either use supported algorithms (RSA, ECDSA P-256/P-384) or upgrade CanoKey firmware.

## Comparison with YubiKey

| Feature | CanoKey | YubiKey |
|---------|---------|---------|
| Open Source | Yes | No |
| PIV Slots | 24 | 24 |
| RSA Support | 2048, 4096 | 1024-4096 |
| ECDSA Support | P-256, P-384 | P-256, P-384 |
| Ed25519 | Firmware 3.0+ | Firmware 5.7+ |
| Virtual Mode | QEMU | No |
| Price | Lower | Higher |

## Best Practices

1. **Change Default Credentials**
   - Change PIN from 123456
   - Change PUK from default

2. **Use Virtual Mode for Testing**
   - CI/CD pipelines should use IsVirtual: true
   - Never use virtual mode for production

3. **Slot Usage**
   - Use slot 9a for authentication
   - Use slot 9c for code signing
   - Use slot 9d for encryption
   - Use retired slots (82-95) for key rotation

4. **Security**
   - Physical CanoKey for production
   - Virtual CanoKey only for testing
   - Regular firmware updates

## Additional Resources

- [CanoKey Documentation](https://docs.canokeys.org/)
- [CanoKey GitHub](https://github.com/canokeys/canokey-core)
- [CanoKey QEMU](https://github.com/canokeys/canokey-qemu)
- [OpenSC PKCS#11](https://github.com/OpenSC/OpenSC)

## See Also

- [YubiKey Backend](yubikey.md) - YubiKey PIV support
- [PKCS#11 Backend](pkcs11.md) - Generic HSM support
- [Getting Started](../usage/getting-started.md) - General usage guide
