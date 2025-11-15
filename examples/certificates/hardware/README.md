# Hardware Certificate Storage Examples

This directory contains comprehensive examples demonstrating hardware-backed certificate storage for PKCS#11 HSMs and TPM2 devices.

## Overview

go-keychain supports three certificate storage modes:

1. **External Storage** - Certificates in files/memory (traditional, default)
2. **Hardware Storage** - Certificates in HSM or TPM2 NV RAM
3. **Hybrid Storage** - Automatic failover between hardware and external

## Examples

### 1. PKCS#11 Hardware Storage

**File:** `pkcs11_hardware_storage.go`

Demonstrates storing certificates directly in a PKCS#11 HSM alongside keys.

**Features:**
- Creating PKCS#11 hardware certificate storage
- Storing certificates as CKO_CERTIFICATE objects
- Certificate chain storage with ID relationships
- Capacity monitoring and management
- Certificate retrieval and verification
- Proper cleanup

**Prerequisites:**
```bash
# Install SoftHSM
sudo apt-get install softhsm2

# Initialize token
softhsm2-util --init-token --slot 0 --label "test-token" --pin 1234 --so-pin 1234

# Verify token
softhsm2-util --show-slots
```

**Run:**
```bash
go run -tags=pkcs11 pkcs11_hardware_storage.go
```

**Key Takeaways:**
- HSM provides tamper-resistant certificate storage
- Capacity: 100-10,000 objects depending on HSM model
- Performance: ~50ms writes, ~20ms reads
- Suitable for CA certificates and high-value certs

### 2. TPM2 NV RAM Storage

**File:** `tpm2_nvram_storage.go`

Demonstrates storing certificates in TPM2 Non-Volatile RAM.

**Features:**
- TPM2 NV RAM certificate storage
- NV index allocation and management
- Capacity constraint handling
- Certificate chain storage as PEM bundles
- Certificate retrieval from NV RAM
- Proper NV index cleanup

**Prerequisites:**
```bash
# For hardware TPM
ls -l /dev/tpmrm0

# For simulator (swtpm)
swtpm socket \
  --tpmstate dir=/tmp/tpm \
  --ctrl type=tcp,port=2322 \
  --server type=tcp,port=2321 \
  --flags not-need-init
```

**Run:**
```bash
# With hardware TPM
go run -tags=tpm2 tpm2_nvram_storage.go

# With simulator
go run -tags=tpm2 tpm2_nvram_storage.go
```

**Key Takeaways:**
- TPM NV RAM is very limited (2-8KB total)
- Practical limit: 2-4 certificates per TPM
- Performance: ~100-200ms writes, ~50-100ms reads
- Use for critical certificates only (CA roots, device identity)

### 3. Hybrid Storage

**File:** `hybrid_storage.go`

Demonstrates hybrid storage with automatic failover between hardware and external storage.

**Features:**
- Hybrid storage configuration
- Automatic failover when hardware is full
- Certificate migration from external to hardware
- Capacity management strategies
- Read/write/delete from both storages
- Production best practices

**Prerequisites:**
```bash
# Install SoftHSM
sudo apt-get install softhsm2

# Initialize token
softhsm2-util --init-token --slot 0 --label "hybrid-demo" --pin 1234 --so-pin 1234
```

**Run:**
```bash
go run -tags=pkcs11 hybrid_storage.go
```

**Key Takeaways:**
- Best of both worlds: hardware security + unlimited capacity
- Automatic overflow handling
- Perfect for migration scenarios
- Recommended for production deployments

## Common Patterns

### Basic Certificate Storage

```go
// Create hardware certificate storage
certConfig := &pkcs11.CertStorageConfig{
    Mode:                  hardware.CertStorageModeHardware,
    EnableHardwareStorage: true,
    MaxCertificates:       100,
}

certStorage, err := backend.CreateCertificateStorage(certConfig)
if err != nil {
    log.Fatal(err)
}
defer certStorage.Close()

// Store certificate
err = certStorage.SaveCert("my-cert", cert)
if err != nil {
    log.Fatal(err)
}

// Retrieve certificate
cert, err := certStorage.GetCert("my-cert")
if err != nil {
    log.Fatal(err)
}
```

### Hybrid Storage with Failover

```go
// Create external storage
externalStorage, _ := file.NewCertStorage("./certs")

// Create hybrid storage
certConfig := &pkcs11.CertStorageConfig{
    Mode:                  hardware.CertStorageModeHybrid,
    ExternalStorage:       externalStorage,
    EnableHardwareStorage: true,
    MaxCertificates:       50,
}

certStorage, _ := backend.CreateCertificateStorage(certConfig)

// Automatic failover on capacity errors
err := certStorage.SaveCert("cert", largeCert)
// Tries hardware first, falls back to external if full
```

### Capacity Monitoring

```go
if hwStorage, ok := certStorage.(hardware.HardwareCertStorage); ok {
    total, available, err := hwStorage.GetCapacity()
    if err == nil {
        usagePercent := float64(total-available) / float64(total) * 100
        log.Printf("Storage: %.1f%% used", usagePercent)

        if usagePercent > 80 {
            log.Println("WARNING: Approaching capacity limit")
        }
    }
}
```

### Error Handling

```go
import "github.com/jeremyhahn/go-keychain/pkg/storage/hardware"

err := certStorage.SaveCert("cert", cert)
if err != nil {
    // Check for capacity errors
    if hardware.IsCapacityError(err) {
        log.Println("Hardware full, consider hybrid mode")
        // Fall back to external storage
    }

    // Check for hardware errors
    if hardware.IsHardwareError(err) {
        log.Println("Hardware unavailable")
        // Use external storage
    }
}
```

## Comparison Table

| Feature | PKCS#11 HSM | TPM2 NV RAM | External |
|---------|-------------|-------------|----------|
| **Capacity** | 100-10,000 certs | 2-4 certs | Unlimited |
| **Performance (write)** | ~50ms | ~100-200ms | ~5ms |
| **Performance (read)** | ~20ms | ~50-100ms | ~2ms |
| **Security** | Tamper-resistant | Tamper-resistant | File permissions |
| **Portability** | Hardware-specific | Device-specific | Fully portable |
| **Use Case** | Production CA, critical | Device identity | Development, bulk |

## Production Recommendations

### For PKCS#11 HSMs:

1. **Use Hardware Mode** for CA certificates and critical keys
2. **Monitor Capacity** regularly (80% threshold)
3. **Set MaxCertificates** conservatively
4. **Use Hybrid Mode** for production systems
5. **Implement Backup** for external storage

### For TPM2 Devices:

1. **Use Hybrid Mode** due to limited NV RAM
2. **Store Only Critical Certs** in NV RAM (2-4 max)
3. **Use External Storage** for bulk certificates
4. **Monitor NV RAM** carefully
5. **Minimize Writes** (no wear leveling)

### For Hybrid Deployments:

1. **Primary:** Hardware for CA roots and high-value certs
2. **Secondary:** External for frequently-accessed certs
3. **Monitor Both** storage backends
4. **Implement Alerts** at 80% hardware capacity
5. **Test Failover** scenarios regularly

## Troubleshooting

### PKCS#11 Issues

**Problem:** Token not found
```bash
# List available tokens
pkcs11-tool --list-slots

# Check library path
ls -l /usr/lib/softhsm/libsofthsm2.so
```

**Problem:** Token full
```bash
# List objects
pkcs11-tool --list-objects --login --pin 1234

# Delete unused certificates via application
```

### TPM2 Issues

**Problem:** Device not found
```bash
# Check TPM device
ls -l /dev/tpm*

# Check permissions
sudo chmod 666 /dev/tpmrm0
```

**Problem:** NV RAM full
```bash
# List NV indices
tpm2_nvreadpublic

# Delete specific index
tpm2_nvundefine 0x01800000
```

## See Also

- [Certificate Management Guide](../../../docs/certificate-management.md)
- [PKCS#11 Backend Documentation](../../../docs/backends/pkcs11.md)
- [TPM2 Backend Documentation](../../../docs/backends/tpm2.md)
- [Storage Abstraction](../../../docs/storage-abstraction.md)

## License

Copyright 2025 Jeremy Hahn

AGPL-3.0 License - See LICENSE file for details
