# YubiKey Backend

The YubiKey backend provides hardware-backed cryptographic key management using YubiKey PIV (Personal Identity Verification) functionality.

## Overview

YubiKey is a hardware security key that provides strong two-factor authentication and hardware-backed cryptographic operations through its PIV application. The YubiKey backend wraps PKCS#11 operations with YubiKey-specific features including firmware version detection, management key authentication, and hardware random number generation.

## Features

- **Hardware-Backed Keys**: All keys stored and operated on YubiKey hardware
- **PIV Compliance**: Full PIV smart card standard support
- **Firmware Detection**: Automatic firmware version detection with feature capability checks
- **Management Key Auth**: Secure key generation using management key authentication
- **Hardware RNG**: NIST-certified hardware random number generator
- **Multiple Algorithms**: RSA, ECDSA with firmware-dependent feature support
- **24 PIV Slots**: Support for all standard PIV slots (9a, 9c, 9d, 9e, 82-95)

## Supported Algorithms

### Current Firmware (5.4+)
- **RSA**: 1024, 2048 bits
- **ECDSA**: P-256, P-384 curves
- **AES**: 128, 192, 256-bit (symmetric encryption)
- **Hardware RNG**: Up to 1024 bytes per call

### Advanced Firmware (5.7+)
- **RSA**: 3072, 4096 bits
- **Ed25519**: EdDSA signatures
- **X25519**: ECDH key agreement

## Configuration

```go
import "github.com/jeremyhahn/go-keychain/pkg/backend/yubikey"

slot := uint(0x9a) // PIV Authentication slot

config := &yubikey.Config{
    Library:       "/usr/lib/x86_64-linux-gnu/libykcs11.so",
    TokenLabel:    "YubiKey PIV #12345678", // Auto-detected if empty
    PIN:           "123456",                // Default PIN
    Slot:          &slot,
    ManagementKey: yubikey.DefaultMgmtKey,  // For key generation
    KeyStorage:    keyStorage,
    CertStorage:   certStorage,
}

backend, err := yubikey.NewBackend(config)
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
| `Library` | string | No | Auto-detect | Path to libykcs11.so |
| `TokenLabel` | string | No | Auto-detect | YubiKey PIV token label |
| `PIN` | string | Yes | "123456" | PIV PIN (6-8 digits) |
| `Slot` | *uint | Yes | nil | PIV slot (0x9a, 0x9c, 0x9d, 0x9e, 0x82-0x95) |
| `ManagementKey` | []byte | No | DefaultMgmtKey | 24-byte management key |
| `KeyStorage` | storage.KeyStorage | Yes | - | Key metadata storage |
| `CertStorage` | storage.CertificateStorage | Yes | - | Certificate storage |

### PIV Slots

YubiKey PIV supports the following standard PIV slots:

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
// Generate RSA 2048 key
attrs := &types.KeyAttributes{
    CN:           "yubikey-rsa-key",
    KeyAlgorithm: x509.RSA,
    RSAAttributes: &types.RSAAttributes{
        KeySize: 2048,
    },
}

key, err := backend.GenerateRSA(attrs)
if err != nil {
    log.Fatal(err)
}

// Use key for signing
signer := key.(crypto.Signer)
signature, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
```

### ECDSA Key Generation

```go
attrs := &types.KeyAttributes{
    CN:           "yubikey-ecdsa-key",
    KeyAlgorithm: x509.ECDSA,
    ECCAttributes: &types.ECCAttributes{
        Curve: elliptic.P256(),
    },
}

key, err := backend.GenerateECDSA(attrs)
```

### Hardware Random Number Generation

```go
// Generate 256 bytes of hardware entropy
randomBytes, err := backend.GenerateRandom(256)
if err != nil {
    log.Fatal(err)
}

// Use for cryptographic key material
keyMaterial := randomBytes[:32]
```

### Firmware Version Detection

```go
fwVer := backend.GetFirmwareVersion()
fmt.Printf("Firmware: %d.%d.%d\n", fwVer.Major, fwVer.Minor, fwVer.Patch)

// Check feature support
if backend.SupportsRSA3072() {
    // Use RSA 3072-bit keys
}

if backend.SupportsEd25519() {
    // Use Ed25519 signatures
}

if backend.SupportsAES() {
    // Use AES symmetric encryption
}
```

## Firmware Version Matrix

| Firmware | RSA Sizes | ECDSA Curves | Ed25519/X25519 | AES |
|----------|-----------|--------------|----------------|-----|
| 5.0-5.3 | 1024, 2048 | P-256, P-384 | No | No |
| 5.4-5.6 | 1024, 2048 | P-256, P-384 | No | Yes |
| 5.7+ | 1024-4096 | P-256, P-384 | Yes | Yes |

## Security Considerations

### Management Key

The management key is required for key generation operations. It should be:

- **Changed from default**: The default key is well-known and insecure
- **Stored securely**: Keep separate from PIN, use secure storage
- **24 bytes**: Must be exactly 24 bytes (192 bits)
- **Hex format**: Pass as hex-encoded string to PKCS#11

Change the management key using yubico-piv-tool:
```bash
yubico-piv-tool -a set-mgm-key -n <new-key-hex>
```

### PIN Management

- **Default PIN**: 123456 (change immediately!)
- **Length**: 6-8 characters
- **Attempts**: 3 failed attempts locks the PIN
- **PUK**: 12345678 (default, used to reset PIN)

Change PIN:
```bash
yubico-piv-tool -a change-pin
```

### Slot Management

- **One key per slot**: Each PIV slot holds one key
- **No overwrite**: Must delete existing key before generating new one
- **Slot cleanup**: Use `DeleteKey()` or `yubico-piv-tool -a delete-certificate`

## Hardware Requirements

### Supported YubiKeys

- YubiKey 5 Series (5, 5C, 5 NFC, 5C NFC, 5Ci, 5C Nano, 5 Nano)
- YubiKey 4 Series (limited algorithm support)
- YubiKey NEO (limited algorithm support)

### System Requirements

**Linux:**
```bash
# Install YubiKey PKCS#11 library
apt-get install libykcs11    # Debian/Ubuntu
dnf install ykpers-devel      # Fedora/RHEL
```

**macOS:**
```bash
brew install yubico-piv-tool
```

**Windows:**
Download and install from [Yubico Downloads](https://www.yubico.com/support/download/)

### Library Paths

- **Linux**: `/usr/lib/x86_64-linux-gnu/libykcs11.so`
- **macOS**: `/usr/local/lib/libykcs11.dylib`
- **Windows**: `C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll`

Override with environment variable:
```bash
export YUBIKEY_PKCS11_LIBRARY=/path/to/libykcs11.so
```

## Integration Testing

Run YubiKey integration tests (requires physical YubiKey):

```bash
# All YubiKey PIV tests
go test -v -tags="yubikey && pkcs11" ./test/integration/pkcs11 -run TestYubiKeyPIV

# Hardware RNG tests
go test -v -tags="yubikey && pkcs11" ./test/integration/crypto -run TestRandYubiKey

# Individual test suites
go test -v -tags="yubikey && pkcs11" ./test/integration/pkcs11 -run TestYubiKeyPIV_RSA
go test -v -tags="yubikey && pkcs11" ./test/integration/pkcs11 -run TestYubiKeyPIV_ECDSA
go test -v -tags="yubikey && pkcs11" ./test/integration/pkcs11 -run TestYubiKeyPIV_RandomGeneration
```

## Troubleshooting

### Slot Already in Use

**Error**: `pkcs11: 0x12: CKR_ATTRIBUTE_TYPE_INVALID`

**Solution**: Delete existing key from slot:
```bash
yubico-piv-tool -a delete-certificate -s 9a
```

Or in code:
```go
backend.DeleteKey(attrs)
```

### Management Key Auth Failed

**Error**: `yubikey: management key authentication failed`

**Causes**:
- Using default management key when it was changed
- Incorrect key format (must be 24 bytes hex)
- YubiKey firmware doesn't support operation

**Solution**: Verify management key:
```bash
yubico-piv-tool -a status
```

### YubiKey Not Detected

**Error**: `yubikey: no YubiKey device found`

**Solutions**:
1. Check YubiKey is plugged in: `lsusb | grep Yubico`
2. Verify permissions: Add user to `pcscd` group
3. Check PKCS#11 library path
4. Restart pcscd service: `systemctl restart pcscd`

### Firmware Version Mismatch

**Error**: `yubikey: RSA 3072 requires firmware 5.7+`

**Solution**: This is expected - the feature requires newer firmware. Either:
- Use supported key sizes (RSA 2048, ECDSA P-256/P-384)
- Upgrade to a newer YubiKey with firmware 5.7+

## Command Line Tools

### Check YubiKey Status

```bash
# View YubiKey information
ykman info

# PIV application status
ykman piv info

# List certificates in PIV slots
yubico-piv-tool -a status
```

### Manage PIV Application

```bash
# Reset PIV application (WARNING: erases all keys!)
yubico-piv-tool -a reset

# Generate key in specific slot
yubico-piv-tool -a generate -s 9a -A RSA2048

# Import certificate
yubico-piv-tool -a import-certificate -s 9a -i cert.pem

# Delete certificate from slot
yubico-piv-tool -a delete-certificate -s 9a
```

## Performance

Hardware operations are slower than software due to hardware security features:

| Operation | Typical Time | Notes |
|-----------|--------------|-------|
| RSA 2048 Key Gen | 2-8 seconds | Depends on YubiKey model |
| ECDSA P-256 Key Gen | 0.5-1 second | Faster than RSA |
| RSA 2048 Sign | 50-100 ms | Hardware-bound |
| ECDSA P-256 Sign | 20-50 ms | Faster than RSA |
| Hardware RNG (32 bytes) | <10 ms | Very fast |

## Best Practices

1. **Change Default Credentials**
   - Change PIN from 123456
   - Change PUK from 12345678
   - Change management key from default

2. **Backup Strategy**
   - YubiKey keys cannot be extracted
   - Generate backup keys in different slot
   - Store recovery certificates separately

3. **Slot Usage**
   - Use slot 9a for SSH authentication
   - Use slot 9c for code signing
   - Use slot 9d for encryption
   - Use retired slots (82-95) for key rotation

4. **Security**
   - Never share your YubiKey
   - Use touch policy for sensitive keys
   - Enable PIN caching carefully
   - Store management key securely

5. **Testing**
   - Test on development YubiKey first
   - Verify firmware version before deployment
   - Run integration tests regularly

## Additional Resources

- [YubiKey PIV Documentation](https://developers.yubico.com/PIV/)
- [YKCS11 PKCS#11 Module](https://developers.yubico.com/yubico-piv-tool/YKCS11/)
- [YubiKey Manager CLI](https://developers.yubico.com/yubikey-manager/)
- [PIV Tool](https://developers.yubico.com/yubico-piv-tool/)

## See Also

- [PKCS#11 Backend](pkcs11.md) - Generic HSM support
- [TPM2 Backend](tpm2.md) - Trusted Platform Module support
- [Getting Started](../usage/getting-started.md) - General usage guide
