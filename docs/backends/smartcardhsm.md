# SmartCard-HSM Backend

The SmartCard-HSM backend provides hardware-backed cryptographic key management using SmartCard-HSM devices (including Nitrokey HSM and CardContact SmartCard-HSM) with support for DKEK (Device Key Encryption Key) protocol for secure key backup and restore operations.

## Overview

SmartCard-HSM is a lightweight, affordable hardware security module that provides secure key storage and cryptographic operations through the standard PKCS#11 interface, with the added capability of DKEK for distributed key management using Shamir's Secret Sharing scheme.

## Key Features

- **Hardware-Backed Keys**: All private keys stored and operated on hardware
- **PKCS#11 Compliance**: Standard PKCS#11 interface via OpenSC
- **DKEK Protocol**: Secure key backup/restore using Shamir's Secret Sharing
- **Distributed Key Management**: Split master key into N shares, require M shares to reconstruct
- **Multiple Algorithms**: RSA (1024-4096), ECDSA (P-256, P-384, P-521), Ed25519
- **Symmetric Encryption**: AES-GCM support
- **Hardware RNG**: NIST-certified hardware random number generator
- **PIN Protection**: User and SO PIN protection

## DKEK Protocol

### What is DKEK?

DKEK (Device Key Encryption Key) is a protocol for secure key backup and restore operations. It uses Shamir's Secret Sharing to split a master encryption key into multiple shares:

- **N shares** are created from the master key
- Any **M shares** (threshold) can reconstruct the master key
- Fewer than M shares reveal nothing about the master key

### Use Cases

1. **Distributed Key Management**: Multiple administrators each hold a share
2. **Secure Backup**: Keys can be backed up and restored across devices
3. **Key Migration**: Move keys between SmartCard-HSM devices
4. **Raft Clusters**: Distributed key management for consensus systems (e.g., go-dragondb)
5. **Disaster Recovery**: Reconstruct keys when devices fail

### Security Properties

- Shares can be distributed to different administrators
- Threshold balances security and availability
- Shares can be stored offline (paper, vault)
- Reconstructed DKEK should never be persisted
- Each share alone reveals no information about the key

## Supported Algorithms

### Asymmetric Algorithms
- **RSA**: 1024, 2048, 3072, 4096 bits
- **ECDSA**: P-192, P-224, P-256, P-384, P-521 curves
- **Ed25519**: Modern elliptic curve (device-dependent)
- **ECDH**: Key agreement using EC curves

### Symmetric Algorithms
- **AES-GCM**: 128, 192, 256-bit authenticated encryption

### Hash Algorithms
- **SHA-256, SHA-384, SHA-512**: Modern hashing
- **SHA-1**: Legacy support
- **MD5**: Compatibility only (not recommended)

## Configuration

### Basic Configuration

```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/backend/smartcardhsm"
    "github.com/jeremyhahn/go-keychain/pkg/backend/pkcs11"
    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
)

// Create storage backends
keyStorage, err := file.New("./keys")
if err != nil {
    log.Fatal(err)
}
certStorage, err := file.New("./certs")
if err != nil {
    log.Fatal(err)
}

// Create PKCS#11 config for SmartCard-HSM
pkcs11Config := &pkcs11.Config{
    Library:     "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    TokenLabel:  "SmartCard-HSM (UserPIN)",
    PIN:         "648219", // Change this!
    KeyStorage:  keyStorage,
    CertStorage: certStorage,
}

// Create SmartCard-HSM backend with DKEK
config := &smartcardhsm.Config{
    PKCS11Config:  pkcs11Config,
    DKEKShares:    5,  // Create 5 shares
    DKEKThreshold: 3,  // Need any 3 to reconstruct
}

backend, err := smartcardhsm.NewBackend(config)
if err != nil {
    log.Fatal(err)
}
defer backend.Close()
```

### Configuration Options

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `PKCS11Config` | *pkcs11.Config | Yes | - | Underlying PKCS#11 configuration |
| `DKEKShares` | int | No | 5 | Number of DKEK shares to create |
| `DKEKThreshold` | int | No | 3 | Minimum shares needed to reconstruct |
| `DKEKStorage` | storage.Storage | No | nil | Optional storage for DKEK shares |

### Default Credentials

**Important**: Change these immediately after initialization!

- **Default SO PIN**: `3537363231383830` (hex-encoded)
- **Default User PIN**: `648219`
- **PIN Length**: 6-15 characters

## Usage Examples

### Key Generation

#### RSA Key Generation

```go
attrs := &backend.KeyAttributes{
    CN:           "smartcard-rsa-2048",
    KeyType:      backend.KEY_TYPE_TLS,
    StoreType:    backend.STORE_HSM,
    KeyAlgorithm: backend.ALG_RSA,
    RSAAttributes: &backend.RSAAttributes{
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
attrs := &backend.KeyAttributes{
    CN:           "smartcard-ecdsa-p256",
    KeyType:      backend.KEY_TYPE_TLS,
    StoreType:    backend.STORE_HSM,
    KeyAlgorithm: backend.ALG_ECDSA,
    ECCAttributes: &backend.ECCAttributes{
        Curve: elliptic.P256(),
    },
}

key, err := backend.GenerateECDSA(attrs)
if err != nil {
    log.Fatal(err)
}
```

### DKEK Operations

#### Generate DKEK Shares

```go
// Generate DKEK shares
shares, err := backend.DKEK().Generate()
if err != nil {
    log.Fatal(err)
}

// Distribute shares to N administrators
for i, share := range shares {
    // Store each share securely
    // Could be: paper backup, secure vault, encrypted storage
    fmt.Printf("Share %d: %x\n", i+1, share)

    // Example: Save to file for admin i
    err = ioutil.WriteFile(
        fmt.Sprintf("admin-%d-share.key", i+1),
        share,
        0600,
    )
    if err != nil {
        log.Fatal(err)
    }
}
```

#### Reconstruct DKEK from Shares

```go
// Collect M shares from administrators (where M >= threshold)
var collectedShares [][]byte

// Admin 1 provides their share
share1, err := ioutil.ReadFile("admin-1-share.key")
if err != nil {
    log.Fatal(err)
}
collectedShares = append(collectedShares, share1)

// Admin 3 provides their share
share3, err := ioutil.ReadFile("admin-3-share.key")
if err != nil {
    log.Fatal(err)
}
collectedShares = append(collectedShares, share3)

// Admin 5 provides their share
share5, err := ioutil.ReadFile("admin-5-share.key")
if err != nil {
    log.Fatal(err)
}
collectedShares = append(collectedShares, share5)

// Reconstruct the DKEK (need 3 out of 5 shares)
dkek, err := backend.DKEK().Reconstruct(collectedShares)
if err != nil {
    log.Fatal(err)
}

// Use DKEK for key backup/restore operations
// Note: Never persist the reconstructed DKEK
```

#### Backup Key with DKEK

```go
// First, reconstruct DKEK from M shares
dkek, err := backend.DKEK().Reconstruct(shares)
if err != nil {
    log.Fatal(err)
}

// Backup a key
attrs := &backend.KeyAttributes{
    CN: "my-important-key",
}

encryptedKeyBlob, err := backend.DKEK().BackupKey(attrs, dkek)
if err != nil {
    log.Fatal(err)
}

// Store encrypted key blob securely
err = ioutil.WriteFile("key-backup.blob", encryptedKeyBlob, 0600)
if err != nil {
    log.Fatal(err)
}

// Zero out DKEK from memory
for i := range dkek {
    dkek[i] = 0
}
```

#### Restore Key with DKEK

```go
// Read encrypted key blob
encryptedKeyBlob, err := ioutil.ReadFile("key-backup.blob")
if err != nil {
    log.Fatal(err)
}

// Reconstruct DKEK from M shares
dkek, err := backend.DKEK().Reconstruct(shares)
if err != nil {
    log.Fatal(err)
}

// Restore the key to new device
attrs := &backend.KeyAttributes{
    CN: "my-important-key",
}

err = backend.DKEK().RestoreKey(attrs, encryptedKeyBlob, dkek)
if err != nil {
    log.Fatal(err)
}

// Zero out DKEK from memory
for i := range dkek {
    dkek[i] = 0
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
    log.Println("Signature verification failed")
}

// Verify signature (ECDSA)
ecdsaPubKey := signer.Public().(*ecdsa.PublicKey)
verified := ecdsa.VerifyASN1(ecdsaPubKey, digest[:], signature)
if !verified {
    log.Println("Signature verification failed")
}
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
nonce := randomBytes[32:44]
```

## Hardware Requirements

### Supported Devices

- **Nitrokey HSM**: USB hardware security module
- **Nitrokey HSM 2**: Updated version with more storage
- **CardContact SmartCard-HSM**: Original SmartCard-HSM implementation
- **Compatible Devices**: Any PKCS#11 device supporting DKEK protocol

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

## Device Management

### Check Device Status

```bash
# View SmartCard-HSM information
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so --list-token-slots

# List supported mechanisms
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so --list-mechanisms

# List keys on device
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
  --login --pin 648219 --list-objects
```

### Device Initialization

```bash
# Initialize SmartCard-HSM with custom label and PIN
sc-hsm-tool --initialize \
  --so-pin 3537363231383830 \
  --pin 648219 \
  --label "go-keychain-hsm"
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

### DKEK Share Management

1. **Distribution**
   - Distribute shares to different trusted administrators
   - Never store all shares in one location
   - Consider geographic distribution

2. **Storage**
   - Paper backups in secure vaults
   - Encrypted digital storage with different keys
   - Hardware security modules for shares
   - Never store shares on the same device as keys

3. **Threshold Selection**
   - Balance security and availability
   - Too low: Reduced security
   - Too high: Risk of losing access
   - Common: 3-of-5, 5-of-7, 7-of-10

4. **Access Control**
   - Different administrators for each share
   - Dual control for sensitive operations
   - Audit trail for share usage
   - Regular share rotation

### Key Security

- **Non-Extractable**: Private keys cannot be exported without DKEK
- **Hardware Protection**: All operations performed on-device
- **Tamper Resistant**: Physical security features
- **PIN Required**: Operations require PIN authentication
- **DKEK Encryption**: Backed-up keys are encrypted with DKEK

### Best Practices

1. **Change Default Credentials**
   - Change User PIN from 648219
   - Change SO PIN from default
   - Store SO PIN securely offline
   - Use strong, random PINs

2. **DKEK Management**
   - Generate DKEK shares during initial setup
   - Test reconstruction before deploying
   - Store shares in geographically distributed locations
   - Never reconstruct DKEK unless absolutely necessary
   - Zero DKEK from memory immediately after use

3. **Backup Strategy**
   - Regular key backups using DKEK
   - Test restore procedures
   - Maintain separate backup device
   - Document backup/restore procedures

4. **Access Control**
   - Limit physical access to device
   - Use strong PINs (alphanumeric)
   - Monitor failed login attempts
   - Keep firmware updated
   - Implement audit logging

5. **Operational Security**
   - Unplug device when not in use
   - Use separate devices for different purposes
   - Regular security audits
   - Test disaster recovery procedures
   - Rotate DKEK shares periodically

## Performance

Hardware operations have different performance characteristics:

| Operation | Typical Time | Notes |
|-----------|--------------|-------|
| RSA 2048 Key Gen | 15-20 seconds | Hardware-bound |
| RSA 3072 Key Gen | 12-15 seconds | Hardware-accelerated |
| RSA 4096 Key Gen | 55-60 seconds | Very slow |
| ECDSA P-256 Key Gen | 3-5 seconds | Fast |
| ECDSA P-384 Key Gen | 4-6 seconds | Fast |
| ECDSA P-521 Key Gen | 5-7 seconds | Moderate |
| RSA 2048 Sign | 50-100 ms | Hardware-bound |
| ECDSA P-256 Sign | 20-40 ms | Faster than RSA |
| Hardware RNG (32 bytes) | <10 ms | Very fast |
| DKEK Share Generation | 1-2 seconds | One-time operation |
| DKEK Reconstruction | <100 ms | Fast |

## Build Tags

This backend requires the `pkcs11` build tag:

```bash
# Build with SmartCard-HSM support
go build -tags=pkcs11

# Run tests
go test -tags=pkcs11 ./pkg/backend/smartcardhsm/...

# Integration tests (requires device)
go test -tags="integration pkcs11" ./test/integration/smartcardhsm/...
```

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

### DKEK Reconstruction Failed

**Error**: `failed to reconstruct DKEK`

**Possible Causes**:
1. Insufficient shares (need M out of N)
2. Corrupted share data
3. Shares from different DKEK sets
4. Share data modified

**Solutions**:
- Verify share integrity
- Ensure shares are from the same DKEK generation
- Check threshold requirements

### Device Full

**Error**: `no space left` or `CKR_DEVICE_MEMORY`

**Cause**: Limited storage (typically ~30 RSA 2048 keys)

**Solution**: Delete unused keys:
```bash
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
  --login --pin YOUR_PIN \
  --delete-object --type privkey --label "key-name"
```

## Comparison with Other Backends

### SmartCard-HSM vs PKCS#11

- **SmartCard-HSM**: PKCS#11 + DKEK protocol
- **PKCS#11**: Standard HSM interface only
- **Use SmartCard-HSM when**: Need distributed key management
- **Use PKCS#11 when**: Basic HSM functionality sufficient

### SmartCard-HSM vs YubiKey

- **SmartCard-HSM**: DKEK support, more storage
- **YubiKey**: Faster key generation, USB-C available
- **SmartCard-HSM**: Better for key backup/restore
- **YubiKey**: Better for daily use/portability

### SmartCard-HSM vs TPM2

- **SmartCard-HSM**: Portable, DKEK support
- **TPM2**: Built into motherboard, attestation
- **SmartCard-HSM**: For distributed systems
- **TPM2**: For device-specific security

## Integration Examples

### Distributed Key Management in Raft Cluster

```go
// Setup DKEK for distributed raft cluster
config := &smartcardhsm.Config{
    PKCS11Config:  pkcs11Config,
    DKEKShares:    len(raftNodes),  // One share per node
    DKEKThreshold: (len(raftNodes) / 2) + 1,  // Majority
}

backend, err := smartcardhsm.NewBackend(config)
if err != nil {
    log.Fatal(err)
}

// Generate and distribute shares to raft nodes
shares, err := backend.DKEK().Generate()
if err != nil {
    log.Fatal(err)
}

for i, node := range raftNodes {
    // Send share to each raft node securely
    err = node.ReceiveShare(shares[i])
    if err != nil {
        log.Fatal(err)
    }
}
```

## Additional Resources

- [SmartCard-HSM Project](https://github.com/CardContact/SmartCard-HSM)
- [Nitrokey HSM Documentation](https://docs.nitrokey.com/hsm/)
- [OpenSC Documentation](https://github.com/OpenSC/OpenSC/wiki)
- [PKCS#11 Specification](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/)
- [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)

## See Also

- [PKCS#11 Backend](pkcs11.md) - Generic HSM support
- [Nitrokey HSM Backend](nitrokey-hsm.md) - Specific Nitrokey HSM device
- [YubiKey Backend](yubikey.md) - YubiKey PIV support
- [TPM2 Backend](tpm2.md) - Trusted Platform Module support
- [Getting Started](../usage/getting-started.md) - General usage guide
