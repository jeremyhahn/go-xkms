# Nitrokey HSM Backend

The Nitrokey HSM backend provides hardware-backed cryptographic key management using the Nitrokey HSM (Hardware Security Module) device via OpenSC PKCS#11 interface.

## Overview

Nitrokey HSM is a USB hardware security module that provides secure key storage and cryptographic operations. The device uses the SmartCard-HSM applet and is fully supported through standard PKCS#11 interfaces via OpenSC.

## Features

- **Hardware-Backed Keys**: All keys stored and operated on Nitrokey HSM hardware
- **PKCS#11 Compliance**: Full PKCS#11 support through OpenSC
- **SmartCard-HSM**: Based on the SmartCard-HSM specification
- **Hardware RNG**: NIST-certified hardware random number generator
- **Multiple Algorithms**: RSA (1024-4096), ECDSA (P-256, P-384, P-521)
- **Secure Storage**: Keys never leave the hardware
- **PIN Protection**: User and SO PIN protection

## Supported Algorithms

The Nitrokey HSM supports the following cryptographic algorithms:

### Asymmetric Algorithms
- **RSA**: 1024, 2048, 3072, 4096 bits
- **ECDSA**: P-192, P-224, P-256, P-384, P-521 curves
- **ECDH**: Key agreement using EC curves

### Symmetric Algorithms
- **AES**: 128, 192, 256-bit (via PKCS#11 wrap/unwrap)

### Hash Algorithms
- **MD5**: For compatibility (not recommended)
- **SHA-1**: For legacy systems
- **SHA-224, SHA-256, SHA-384, SHA-512**: Modern hashing
- **RIPEMD-160**: Alternative hash function

## Configuration

```go
import (
	"github.com/jeremyhahn/go-keychain/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-keychain/pkg/storage/memory"
)

// Create storage backends
keyStorage := memory.New()
certStorage := memory.New()

// Create PKCS#11 backend configuration for Nitrokey HSM
config := &pkcs11.Config{
	Library:     "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
	TokenLabel:  "SmartCard-HSM (UserPIN)",  // Or your custom label
	PIN:         "648219",                     // Default PIN
	KeyStorage:  keyStorage,
	CertStorage: certStorage,
}

// Create backend
backend, err := pkcs11.NewBackend(config)
if err != nil {
	log.Fatal(err)
}
defer backend.Close()

// Initialize backend
err = backend.Initialize("3537363231383830", "648219")  // SO PIN, User PIN
if err != nil && err != pkcs11.ErrAlreadyInitialized {
	log.Fatal(err)
}
```

### Configuration Options

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `Library` | string | Yes | - | Path to opensc-pkcs11.so |
| `TokenLabel` | string | Yes | - | Token label (see initialization) |
| `PIN` | string | Yes | - | User PIN (6-15 characters) |
| `KeyStorage` | storage.KeyStorage | Yes | - | Key metadata storage |
| `CertStorage` | storage.CertificateStorage | Yes | - | Certificate storage |

### Default Credentials

**Important**: Change these immediately after initialization!

- **Default SO PIN**: `3537363231383830` (hex-encoded)
- **Default User PIN**: `648219`
- **PIN Length**: 6-15 characters

## Initialization

The Nitrokey HSM must be initialized before first use. This sets up the device with a label and PIN:

```bash
# Initialize Nitrokey HSM with custom label and PIN
sc-hsm-tool --initialize \
  --so-pin 3537363231383830 \
  --pin 648219 \
  --label "go-keychain-hsm"
```

After initialization, the token label will be `"go-keychain-hsm (UserPIN)"`.

## Usage Examples

### Key Generation

#### RSA Key Generation

```go
attrs := &types.KeyAttributes{
	CN:           "nitrokey-rsa-2048",
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

#### ECDSA Key Generation

```go
attrs := &types.KeyAttributes{
	CN:           "nitrokey-ecdsa-p256",
	KeyAlgorithm: x509.ECDSA,
	ECCAttributes: &types.ECCAttributes{
		Curve: elliptic.P256(),
	},
}

key, err := backend.GenerateECDSA(attrs)
if err != nil {
	log.Fatal(err)
}
```

### Signing and Verification

```go
// Sign data
message := []byte("important message")
digest := sha256.Sum256(message)

signer := key.(crypto.Signer)
signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
if err != nil {
	log.Fatal(err)
}

// Verify signature (RSA)
rsaPubKey := signer.Public().(*rsa.PublicKey)
err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, digest[:], signature)
if err != nil {
	log.Fatal(err)
}

// Verify signature (ECDSA)
ecdsaPubKey := signer.Public().(*ecdsa.PublicKey)
verified := ecdsa.VerifyASN1(ecdsaPubKey, digest[:], signature)
```

### Hardware Random Number Generation

```go
// Generate 256 bytes of hardware entropy
randomBytes, err := backend.GenerateRandom(256)
if err != nil {
	log.Fatal(err)
}

// Use for cryptographic operations
keyMaterial := randomBytes[:32]
```

### Key Deletion

```go
attrs := &types.KeyAttributes{
	CN:           "key-to-delete",
	KeyAlgorithm: x509.RSA,
}

err := backend.DeleteKey(attrs)
if err != nil {
	log.Fatal(err)
}
```

## Hardware Requirements

### Supported Devices

- Nitrokey HSM
- Nitrokey HSM 2
- Compatible SmartCard-HSM devices

### System Requirements

**Linux:**
```bash
# Install OpenSC
apt-get install opensc          # Debian/Ubuntu
dnf install opensc              # Fedora/RHEL
```

**macOS:**
```bash
brew install opensc
```

**Windows:**
Download and install from [OpenSC Downloads](https://github.com/OpenSC/OpenSC/releases)

### Library Paths

- **Linux**: `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so`
- **macOS**: `/usr/local/lib/opensc-pkcs11.so`
- **Windows**: `C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll`

## Device Information

### Check Device Status

```bash
# View Nitrokey HSM information
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so --list-token-slots

# List supported mechanisms
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so --list-mechanisms

# List keys on device
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
  --login --pin 648219 --list-objects
```

### Device Capabilities

```bash
# Check SmartCard-HSM status
sc-hsm-tool --status

# Get device information
sc-hsm-tool --info
```

## Integration Testing

Run Nitrokey HSM integration tests (requires physical device):

```bash
# All Nitrokey HSM tests
go test -v -tags="integration && nitrokey && pkcs11" \
  ./test/integration/pkcs11 -run TestNitrokeyHSM

# Specific test suites
go test -v -tags="integration && nitrokey && pkcs11" \
  ./test/integration/pkcs11 -run TestNitrokeyHSM/GenerateAndSign_RSA2048

go test -v -tags="integration && nitrokey && pkcs11" \
  ./test/integration/pkcs11 -run TestNitrokeyHSM/GenerateRandom
```

## Security Considerations

### PIN Management

**Critical**: Change default PINs immediately after initialization!

```bash
# Change User PIN
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
  --login --pin 648219 --change-pin --new-pin YOUR_NEW_PIN

# Change SO PIN (requires SO login)
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
  --login --login-type so --so-pin 3537363231383830 \
  --change-pin --new-pin YOUR_NEW_SO_PIN
```

### PIN Requirements

- **User PIN**: 6-15 characters
- **SO PIN**: 16 hex characters (8 bytes hex-encoded)
- **Failed Attempts**: 3 attempts before lockout
- **Unlock**: Use SO PIN to reset User PIN

### Key Security

- **Non-Extractable**: Private keys cannot be exported from the device
- **Hardware Protection**: All operations performed on-device
- **Tamper Resistant**: Physical security features
- **PIN Required**: Operations require PIN authentication

### Best Practices

1. **Change Default Credentials**
   - Change User PIN from 648219
   - Change SO PIN from default
   - Store SO PIN securely offline

2. **Backup Strategy**
   - Nitrokey HSM keys cannot be extracted
   - Use key wrapping for backups
   - Maintain separate backup device
   - Store recovery PINs securely

3. **Access Control**
   - Limit physical access to device
   - Use strong PINs (alphanumeric)
   - Monitor failed login attempts
   - Keep firmware updated

4. **Operational Security**
   - Unplug device when not in use
   - Use separate devices for different purposes
   - Regular security audits
   - Test backup/recovery procedures

## Performance

Hardware operations have different performance characteristics:

| Operation | Typical Time | Notes |
|-----------|--------------|-------|
| RSA 2048 Key Gen | 15-20 seconds | Slower than YubiKey |
| RSA 3072 Key Gen | 12-15 seconds | Hardware-accelerated |
| RSA 4096 Key Gen | 55-60 seconds | Very slow |
| ECDSA P-256 Key Gen | 3-5 seconds | Fast |
| ECDSA P-384 Key Gen | 4-6 seconds | Fast |
| ECDSA P-521 Key Gen | 5-7 seconds | Moderate |
| RSA 2048 Sign | 50-100 ms | Hardware-bound |
| ECDSA P-256 Sign | 20-40 ms | Faster than RSA |
| Hardware RNG (32 bytes) | <10 ms | Very fast |

## Troubleshooting

### Device Not Detected

**Error**: `no slots available` or `no token found`

**Solutions**:
1. Check device connection: `lsusb | grep Nitrokey`
2. Verify permissions: Add user to `scard` group
3. Check pcscd service: `systemctl status pcscd`
4. Restart pcscd: `systemctl restart pcscd`

### PIN Locked

**Error**: `CKR_PIN_LOCKED`

**Solution**: Reset PIN using SO PIN:
```bash
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
  --login-type so --so-pin YOUR_SO_PIN \
  --init-pin --new-pin YOUR_NEW_USER_PIN
```

### Device Initialization Failed

**Error**: `initialization failed`

**Solutions**:
1. Device may already be initialized - check status
2. Verify SO PIN is correct
3. Try resetting device (WARNING: erases all data)

### Device Full

**Error**: `no space left` or `CKR_DEVICE_MEMORY`

**Cause**: Nitrokey HSM has limited storage (typically ~30 RSA 2048 keys)

**Solution**: Delete unused keys:
```bash
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
  --login --pin YOUR_PIN \
  --delete-object --type privkey --label "key-name"
```

## Limitations

### Storage Capacity

- **RSA 2048**: ~30 keys
- **RSA 4096**: ~10 keys
- **ECDSA P-256**: ~100 keys
- **Certificates**: Limited by available memory

### Algorithm Support

- **No Ed25519**: Not supported (unlike YubiKey 5.7+)
- **No X25519**: Not supported
- **Limited AES**: Only via key wrapping

### Performance

- **Slower Key Generation**: Significantly slower than YubiKey
- **RSA 4096**: Very slow (60+ seconds)
- **No USB-C**: Original Nitrokey HSM is USB-A only

## Migration from YubiKey

If migrating from YubiKey PIV to Nitrokey HSM:

1. **Different Interface**: YubiKey uses PIV, Nitrokey uses SmartCard-HSM
2. **No Slot Concept**: Nitrokey doesn't use PIV slots
3. **Different PINs**: Default PINs are different
4. **Slower Performance**: Key generation is slower
5. **More Storage**: Nitrokey HSM has more key storage
6. **Different Tools**: Use `sc-hsm-tool` instead of `yubico-piv-tool`

## Additional Resources

- [Nitrokey HSM Documentation](https://docs.nitrokey.com/hsm/)
- [SmartCard-HSM Project](https://github.com/CardContact/SmartCard-HSM)
- [OpenSC Documentation](https://github.com/OpenSC/OpenSC/wiki)
- [PKCS#11 Specification](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html)

## See Also

- [PKCS#11 Backend](pkcs11.md) - Generic HSM support
- [YubiKey Backend](yubikey.md) - YubiKey PIV support
- [TPM2 Backend](tpm2.md) - Trusted Platform Module support
- [Getting Started](../usage/getting-started.md) - General usage guide
