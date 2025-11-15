# Certificate Management

This guide covers certificate storage and management in go-keychain, including hardware-backed certificate storage options for PKCS#11 HSMs and TPM2 devices.

## Overview

go-keychain provides flexible certificate storage options:

1. **External Storage** - Certificates stored in files, memory, or distributed storage (default)
2. **Hardware Storage** - Certificates stored directly in HSM or TPM2 device
3. **Hybrid Storage** - Automatic failover between hardware and external storage

### When to Use Each Storage Mode

| Mode | Use Case | Pros | Cons |
|------|----------|------|------|
| **External** | Development, high-volume, distributed systems | Fast, unlimited capacity, flexible | Certificates not tamper-protected |
| **Hardware** | High security, compliance, tamper resistance | Hardware-protected, attestation | Limited capacity, slower |
| **Hybrid** | Migration, overflow handling, HA | Best of both, automatic failover | More complex setup |

## Certificate Storage Architecture

### Storage Separation

go-keychain follows a clean separation between keys and certificates:

```
Backend (keys) -> CertificateStorage (certificates)
```

- **Backends** handle cryptographic key operations (PKCS#11, TPM2, PKCS#8, etc.)
- **CertificateStorage** handles certificate storage (file, memory, hardware, etc.)
- This allows maximum flexibility: any backend with any certificate storage

### Hardware Certificate Storage

Hardware backends (PKCS#11 and TPM2) support native certificate storage:

- **PKCS#11**: Certificates stored as `CKO_CERTIFICATE` objects in HSM
- **TPM2**: Certificates stored in NV (Non-Volatile) RAM

## Configuration Examples

### External Storage (Default)

This is the traditional mode where certificates are stored separately from keys:

```go
package main

import (
    "github.com/jeremyhahn/go-keychain/pkg/backend/pkcs11"
    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
)

func main() {
    // Create external certificate storage
    certStorage, err := file.New("./certs")
    if err != nil {
        panic(err)
    }

    // PKCS#11 backend stores keys in HSM
    backend, err := pkcs11.NewBackend(&pkcs11.Config{
        Library:    "/usr/lib/softhsm/libsofthsm2.so",
        TokenLabel: "my-token",
        PIN:        "1234",
    })
    if err != nil {
        panic(err)
    }

    // Certificates stored externally (current default behavior)
    // Keys in HSM, certificates in files
}
```

### PKCS#11 Hardware Storage

Store certificates directly in the HSM alongside keys:

```go
package main

import (
    "github.com/jeremyhahn/go-keychain/pkg/backend/pkcs11"
    "github.com/jeremyhahn/go-keychain/pkg/storage/hardware"
)

func main() {
    // Create and initialize PKCS#11 backend
    backend, err := pkcs11.NewBackend(&pkcs11.Config{
        Library:    "/usr/lib/softhsm/libsofthsm2.so",
        TokenLabel: "my-token",
        PIN:        "1234",
    })
    if err != nil {
        panic(err)
    }

    // Configure hardware certificate storage
    certConfig := &pkcs11.CertStorageConfig{
        Mode:                  hardware.CertStorageModeHardware,
        EnableHardwareStorage: true,
        MaxCertificates:       100, // Prevent token exhaustion
    }

    // Create hardware certificate storage
    certStorage, err := backend.CreateCertificateStorage(certConfig)
    if err != nil {
        panic(err)
    }

    // Both keys and certificates now in HSM
}
```

### TPM2 NV RAM Storage

Store certificates in TPM2 Non-Volatile RAM:

```go
package main

import (
    "github.com/jeremyhahn/go-keychain/pkg/tpm2"
    "github.com/jeremyhahn/go-keychain/pkg/storage/hardware"
)

func main() {
    // Create TPM2 backend
    tpmBackend, err := tpm2.NewTPM2KeyStore(&tpm2.Config{
        Device: "/dev/tpmrm0",
        // ... other config
    })
    if err != nil {
        panic(err)
    }

    // Configure NV RAM certificate storage
    certConfig := &tpm2.CertStorageConfig{
        Mode:            hardware.CertStorageModeHardware,
        EnableNVStorage: true,
        NVBaseIndex:     0x01800000, // TPM NV index base
        MaxCertSize:     2048,       // Bytes per certificate
        MaxCertificates: 4,          // Conservative for NV RAM
        OwnerAuth:       []byte{},   // Owner password
    }

    // Create hardware certificate storage
    certStorage, err := tpmBackend.CreateCertificateStorage(certConfig)
    if err != nil {
        panic(err)
    }

    // Keys and certificates in TPM
}
```

### Hybrid Storage

Combines hardware and external storage with automatic failover:

```go
package main

import (
    "github.com/jeremyhahn/go-keychain/pkg/backend/pkcs11"
    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
    "github.com/jeremyhahn/go-keychain/pkg/storage/hardware"
)

func main() {
    // Create external storage for fallback
    externalStorage, err := file.New("./certs")
    if err != nil {
        panic(err)
    }

    // Create PKCS#11 backend
    backend, err := pkcs11.NewBackend(&pkcs11.Config{
        Library:    "/usr/lib/softhsm/libsofthsm2.so",
        TokenLabel: "my-token",
        PIN:        "1234",
    })
    if err != nil {
        panic(err)
    }

    // Configure hybrid storage
    certConfig := &pkcs11.CertStorageConfig{
        Mode:                  hardware.CertStorageModeHybrid,
        ExternalStorage:       externalStorage,
        EnableHardwareStorage: true,
        MaxCertificates:       50,
    }

    // Create hybrid certificate storage
    certStorage, err := backend.CreateCertificateStorage(certConfig)
    if err != nil {
        panic(err)
    }

    // Writes go to hardware first, fall back to external on capacity errors
    // Reads check hardware first, then external
}
```

## Best Practices for Production

### Capacity Planning

**PKCS#11 HSMs:**
- Typical capacity: 100-10,000 objects depending on HSM model
- Each certificate consumes one object slot
- Monitor capacity with `GetCapacity()`
- Set `MaxCertificates` conservatively

**TPM2 Devices:**
- Limited NV RAM: typically 2KB-8KB total
- Each certificate: ~2KB including overhead
- Practical limit: 2-4 certificates per TPM
- Use external storage for bulk certificates
- Store only critical certificates in TPM

### Storage Mode Selection

```go
// Development/Testing: External
certConfig := &pkcs11.CertStorageConfig{
    Mode:            hardware.CertStorageModeExternal,
    ExternalStorage: fileStorage,
}

// Production High-Security: Hardware
certConfig := &pkcs11.CertStorageConfig{
    Mode:                  hardware.CertStorageModeHardware,
    EnableHardwareStorage: true,
    MaxCertificates:       100,
}

// Production HA/Migration: Hybrid
certConfig := &pkcs11.CertStorageConfig{
    Mode:                  hardware.CertStorageModeHybrid,
    ExternalStorage:       externalStorage,
    EnableHardwareStorage: true,
    MaxCertificates:       50,
}
```

### Error Handling

```go
import "github.com/jeremyhahn/go-keychain/pkg/storage/hardware"

err := certStorage.SaveCert("example", cert)
if err != nil {
    // Check for capacity errors
    if hardware.IsCapacityError(err) {
        log.Println("Hardware storage full, consider hybrid mode")
    }

    // Check for hardware errors
    if hardware.IsHardwareError(err) {
        log.Println("Hardware unavailable, falling back to external")
    }

    return err
}
```

### Monitoring

```go
// Check hardware capacity periodically
if hwStorage, ok := certStorage.(hardware.HardwareCertStorage); ok {
    total, available, err := hwStorage.GetCapacity()
    if err == nil {
        usagePercent := float64(total-available) / float64(total) * 100
        log.Printf("Certificate storage: %.1f%% used (%d/%d)",
            usagePercent, total-available, total)

        // Alert if near capacity
        if usagePercent > 80 {
            log.Printf("WARNING: Certificate storage >80%% full")
        }
    }
}
```

## Troubleshooting Common Issues

### PKCS#11 Token Full

**Problem:** `ErrTokenFull` when saving certificates

**Solutions:**
1. Delete unused certificates
2. Increase `MaxCertificates` if HSM has capacity
3. Switch to hybrid mode
4. Use external storage for less critical certificates

```go
// Check capacity before saving
total, available, err := certStorage.GetCapacity()
if available < 10 {
    log.Printf("WARNING: Only %d certificate slots available", available)
}
```

### TPM NV RAM Exhausted

**Problem:** `ErrCapacityExceeded` when saving to TPM

**Solutions:**
1. TPM has very limited NV RAM (2-8KB)
2. Store only critical certificates in TPM
3. Use hybrid mode with external storage for bulk certificates
4. Delete old certificates to free space

```go
// Conservative TPM certificate config
certConfig := &tpm2.CertStorageConfig{
    Mode:            hardware.CertStorageModeHybrid,
    ExternalStorage: fileStorage,
    MaxCertificates: 4,  // Very conservative for TPM
    MaxCertSize:     2048,
}
```

### Certificate Too Large

**Problem:** `ErrCertificateTooLarge` for large certificates or chains

**Solutions:**
1. Increase `MaxCertSize` if hardware supports it
2. Use external storage for large certificates
3. Split large chains across multiple IDs

```go
// Check certificate size before storage
pemData := pem.EncodeToMemory(&pem.Block{
    Type:  "CERTIFICATE",
    Bytes: cert.Raw,
})

if len(pemData) > 2048 {
    log.Printf("Certificate too large for TPM, using external storage")
    // Use external storage instead
}
```

### Hardware Unavailable

**Problem:** `ErrHardwareUnavailable` or connection errors

**Solutions:**
1. Verify HSM/TPM is connected and initialized
2. Check permissions on device files
3. Use hybrid mode for automatic fallback
4. Implement retry logic for transient errors

```go
// Retry logic for hardware errors
var cert *x509.Certificate
var err error
for i := 0; i < 3; i++ {
    cert, err = certStorage.GetCert("my-cert")
    if err == nil || !hardware.IsHardwareError(err) {
        break
    }
    time.Sleep(time.Second * time.Duration(i+1))
}
```

### Session Authentication Errors

**Problem:** PKCS#11 authentication failures

**Solutions:**
1. Ensure backend is initialized before creating certificate storage
2. Verify PIN/password is correct
3. Check if session has timed out

```go
// Ensure proper initialization order
backend.Initialize(soPin, userPin)
backend.Login()

// Then create certificate storage
certStorage, err := backend.CreateCertificateStorage(certConfig)
```

## Migration Scenarios

### Migrating from External to Hardware Storage

```go
// Step 1: Start with external storage
externalStorage, _ := file.New("./certs")

// Step 2: Create hybrid storage
certConfig := &pkcs11.CertStorageConfig{
    Mode:                  hardware.CertStorageModeHybrid,
    ExternalStorage:       externalStorage,
    EnableHardwareStorage: true,
}
hybridStorage, _ := backend.CreateCertificateStorage(certConfig)

// Step 3: List existing certificates
certIDs, _ := externalStorage.ListCerts()

// Step 4: Copy to hardware (hybrid will write to hardware first)
for _, id := range certIDs {
    cert, _ := externalStorage.GetCert(id)
    err := hybridStorage.SaveCert(id, cert)
    if hardware.IsCapacityError(err) {
        log.Printf("Hardware full, remaining certs stay in external: %s", id)
        break
    }
}

// Step 5: Continue using hybrid mode for automatic failover
```

### Testing Hardware Storage

```go
// Use a test HSM/TPM for development
certConfig := &pkcs11.CertStorageConfig{
    Mode:                  hardware.CertStorageModeHardware,
    EnableHardwareStorage: true,
    MaxCertificates:       10, // Low limit for testing
}

certStorage, err := backend.CreateCertificateStorage(certConfig)

// Test basic operations
testCert := generateTestCertificate()
err = certStorage.SaveCert("test", testCert)
retrieved, err := certStorage.GetCert("test")
err = certStorage.DeleteCert("test")
```

## Performance Considerations

### Latency Comparison

| Operation | External (File) | PKCS#11 HSM | TPM2 NV RAM |
|-----------|----------------|-------------|-------------|
| SaveCert  | ~5ms | ~50ms | ~100-200ms |
| GetCert   | ~2ms | ~20ms | ~50-100ms |
| ListCerts | ~10ms | ~100ms | ~200-500ms |
| DeleteCert | ~5ms | ~50ms | ~100ms |

### Recommendations

- Use hardware storage for security-critical certificates
- Use external storage for frequently accessed certificates
- Cache certificate reads in application layer
- Use hybrid mode to balance security and performance

## Security Considerations

### Access Control

**PKCS#11:**
- Certificates protected by HSM PIN
- Hardware-level access control
- Tamper-resistant storage

**TPM2:**
- Owner hierarchy authorization required
- NV indices protected by TPM policies
- Platform attestation available

### Best Practices

1. Use hardware storage for CA certificates and high-value certificates
2. Enable hardware storage only when security requirements justify the cost
3. Monitor hardware capacity and set appropriate limits
4. Use strong PINs/passwords for HSM/TPM access
5. Implement proper backup and disaster recovery for external storage
6. Use hybrid mode for critical production systems

## See Also

- [PKCS#11 Backend Documentation](backends/pkcs11.md)
- [TPM2 Backend Documentation](backends/tpm2.md)
- [Storage Abstraction](storage-abstraction.md)
- [Certificate Examples](../examples/certificates/README.md)
