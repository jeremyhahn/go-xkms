# Hardware Certificate Storage

This document describes the hardware certificate storage architecture for PKCS#11 and TPM2 backends, enabling certificates to be stored directly in hardware modules while maintaining full backward compatibility with external storage.

## Background

### Current Architecture

The go-keychain repository follows a clean separation of concerns:

```
Backend (keys) -> CertificateStorage (certificates)
```

- **Backends** handle cryptographic operations (PKCS#11, TPM2, PKCS#8, etc.)
- **CertificateStorage** handles certificate storage (file, memory, Raft, S3, etc.)
- This separation allows maximum flexibility: PKCS#11 keys + Raft certificates, TPM2 keys + S3 certificates, etc.

### Implementation Overview

Hardware security modules (HSMs) and TPMs provide native certificate storage capabilities:

- **PKCS#11**: Certificates stored as `CKO_CERTIFICATE` objects in HSM
- **TPM2**: Certificates stored in NV (Non-Volatile) RAM

### Key Features

1. **Native Hardware Storage**: Certificates stored directly in PKCS#11/TPM2
2. **Backward Compatibility**: Full support for external certificate storage
3. **Hybrid Mode**: Automatic failover between hardware and external storage
4. **Configuration Flexibility**: Easy switching between storage modes via config
5. **Thread Safety**: All implementations are fully concurrent-safe
6. **Interface Consistency**: Maintains existing CertificateStorage interface

## Design Overview

### Architecture Principles

1. **Composition over Inheritance**: Use interface composition to extend functionality
2. **Fail-Safe Defaults**: Default to external storage, opt-in to hardware storage
3. **Explicit Configuration**: Clear, unambiguous configuration options
4. **Graceful Degradation**: Fall back to external storage if hardware unavailable
5. **Zero Breaking Changes**: Existing code continues to work unchanged

### Storage Mode Strategy

Three storage modes provide deployment flexibility:

```go
type CertStorageMode string

const (
    // CertStorageModeExternal - All certificates in external storage (default)
    CertStorageModeExternal CertStorageMode = "external"

    // CertStorageModeHardware - All certificates in hardware storage
    CertStorageModeHardware CertStorageMode = "hardware"

    // CertStorageModeHybrid - New certificates in hardware, fallback to external
    CertStorageModeHybrid CertStorageMode = "hybrid"
)
```

## File Structure

### New Files

```
pkg/storage/hardware/
├── interface.go              # HardwareCertStorage interface
├── pkcs11_cert_storage.go    # PKCS#11 implementation
├── tpm2_cert_storage.go      # TPM2 implementation
├── hybrid_cert_storage.go    # Hybrid mode wrapper
└── errors.go                 # Hardware-specific errors

pkg/backend/pkcs11/cert_config.go
pkg/tpm2/cert_config.go
```

### Modified Files

```
pkg/backend/pkcs11/pkcs11.go  # Add certificate storage factory
pkg/tpm2/tpm2.go              # Add certificate storage factory
```

## Interface Definitions

### Core Hardware Certificate Storage Interface

```go
package hardware

// HardwareCertStorage extends CertificateStorage with hardware-specific capabilities.
// Implementations MUST be thread-safe.
type HardwareCertStorage interface {
    storage.CertificateStorage

    // GetCapacity returns (total slots, available slots, error)
    GetCapacity() (total int, available int, err error)

    // SupportsChains returns true if hardware supports certificate chains
    SupportsChains() bool

    // IsHardwareBacked returns true to distinguish from external storage
    IsHardwareBacked() bool

    // Compact performs storage optimization if supported
    Compact() error
}

// CertificateAttributes provides metadata for hardware certificate storage
type CertificateAttributes struct {
    ID              string          // Unique identifier (CKA_ID for PKCS#11)
    Label           string          // Human-readable name (CKA_LABEL)
    Trusted         bool            // Trust anchor flag (CKA_TRUSTED)
    CertificateType CertificateType // Certificate type
    Subject         []byte          // DER-encoded X.509 subject
    Issuer          []byte          // DER-encoded X.509 issuer
    SerialNumber    []byte          // Certificate serial number
}

// StorageInfo provides information about hardware storage state
type StorageInfo struct {
    Mode               CertStorageMode
    HardwareType       string  // pkcs11, tpm2
    TotalSlots         int
    UsedSlots          int
    SupportsChains     bool
    SupportsCompaction bool
}
```

### PKCS#11 Certificate Storage

```go
// PKCS11CertStorage implements HardwareCertStorage for PKCS#11 HSMs.
// Certificates are stored as CKO_CERTIFICATE objects on the token.
//
// Thread Safety: All operations protected by RWMutex
//
// Certificate Storage:
// - Each certificate is a CKO_CERTIFICATE object
// - CKA_ID links certificates to private keys
// - CKA_LABEL provides human-readable identification
//
// Limitations:
// - Chain storage maps to individual certificates with ID relationships
// - Not all HSMs support certificate deletion
// - Capacity depends on token memory/object limits
type PKCS11CertStorage struct {
    ctx        *pkcs11.Ctx
    session    pkcs11.SessionHandle
    tokenLabel string
    slotID     uint
    mu         sync.RWMutex
    closed     bool
}

// Core methods implement storage.CertificateStorage interface
func (p *PKCS11CertStorage) SaveCert(id string, cert *x509.Certificate) error
func (p *PKCS11CertStorage) GetCert(id string) (*x509.Certificate, error)
func (p *PKCS11CertStorage) DeleteCert(id string) error
func (p *PKCS11CertStorage) SaveCertChain(id string, chain []*x509.Certificate) error
func (p *PKCS11CertStorage) GetCertChain(id string) ([]*x509.Certificate, error)
func (p *PKCS11CertStorage) ListCerts() ([]string, error)
func (p *PKCS11CertStorage) CertExists(id string) (bool, error)
func (p *PKCS11CertStorage) Close() error

// Hardware-specific methods
func (p *PKCS11CertStorage) GetCapacity() (total int, available int, err error)
func (p *PKCS11CertStorage) SupportsChains() bool { return true }
func (p *PKCS11CertStorage) IsHardwareBacked() bool { return true }
func (p *PKCS11CertStorage) Compact() error { return ErrNotSupported }
```

### TPM2 Certificate Storage

```go
// TPM2CertStorage implements HardwareCertStorage for TPM 2.0 devices.
// Certificates are stored in TPM NV (Non-Volatile) RAM.
//
// Thread Safety: All operations protected by RWMutex
//
// Certificate Storage:
// - Each certificate stored in dedicated NV index
// - NV indices derived from base index + hash(ID)
// - Certificates stored as PEM-encoded data
//
// NV Index Layout:
//   Base Index: 0x01800000 (TPM_NV_INDEX_FIRST)
//   Cert Index: Base + (FNV-1a hash of ID % 0x00FFFFFF)
//
// Limitations:
// - Limited NV RAM capacity (typically 2KB-8KB total)
// - Each certificate consumes ~2KB (including overhead)
// - Practical limit: 2-4 certificates per TPM
type TPM2CertStorage struct {
    tpm       transport.TPMCloser
    baseIndex uint32
    maxSize   int
    mu        sync.RWMutex
    closed    bool
}

type TPM2CertStorageConfig struct {
    BaseIndex   uint32  // Default: 0x01800000
    MaxCertSize int     // Default: 2048 bytes
    OwnerAuth   []byte  // Owner hierarchy password
}

// Core methods implement storage.CertificateStorage interface
func (t *TPM2CertStorage) SaveCert(id string, cert *x509.Certificate) error
func (t *TPM2CertStorage) GetCert(id string) (*x509.Certificate, error)
func (t *TPM2CertStorage) DeleteCert(id string) error
func (t *TPM2CertStorage) SaveCertChain(id string, chain []*x509.Certificate) error
func (t *TPM2CertStorage) GetCertChain(id string) ([]*x509.Certificate, error)
func (t *TPM2CertStorage) ListCerts() ([]string, error)
func (t *TPM2CertStorage) CertExists(id string) (bool, error)
func (t *TPM2CertStorage) Close() error

// Hardware-specific methods
func (t *TPM2CertStorage) GetCapacity() (total int, available int, err error)
func (t *TPM2CertStorage) SupportsChains() bool { return true }
func (t *TPM2CertStorage) IsHardwareBacked() bool { return true }
func (t *TPM2CertStorage) Compact() error // TPM 2.0 spec optional
```

### Hybrid Certificate Storage

```go
// HybridCertStorage combines hardware and external storage.
//
// Storage Strategy:
//   - SaveCert: Writes to hardware, falls back to external on error
//   - GetCert: Tries hardware first, falls back to external
//   - DeleteCert: Deletes from both hardware and external
//   - ListCerts: Merges IDs from both storages (deduplicated)
//
// Use Cases:
//   - Migration from external to hardware storage
//   - Overflow handling when hardware capacity exhausted
//   - High-availability with redundant storage
type HybridCertStorage struct {
    hardware HardwareCertStorage
    external storage.CertificateStorage
    mu       sync.RWMutex
    closed   bool
}

func NewHybridCertStorage(
    hardware HardwareCertStorage,
    external storage.CertificateStorage,
) (storage.CertificateStorage, error)

func (h *HybridCertStorage) GetInfo() (*HybridStorageInfo, error)

type HybridStorageInfo struct {
    HardwareInfo  StorageInfo
    ExternalInfo  StorageInfo
    HardwareCount int // Certificates in hardware
    ExternalCount int // Certificates in external
    SharedCount   int // Certificates in both
}
```

## Configuration Design

### PKCS#11 Configuration

```go
type CertStorageConfig struct {
    Mode                  hardware.CertStorageMode
    ExternalStorage       storage.CertificateStorage
    EnableHardwareStorage bool
    MaxCertificates       int // Default: 100
}

func DefaultCertStorageConfig() *CertStorageConfig {
    return &CertStorageConfig{
        Mode:                  hardware.CertStorageModeExternal,
        EnableHardwareStorage: false,
        MaxCertificates:       100,
    }
}
```

### TPM2 Configuration

```go
type CertStorageConfig struct {
    Mode            hardware.CertStorageMode
    ExternalStorage storage.CertificateStorage
    EnableNVStorage bool
    NVBaseIndex     uint32 // Default: 0x01800000
    MaxCertSize     int    // Default: 2048
    MaxCertificates int    // Default: 4 (conservative for NV RAM)
}

func DefaultCertStorageConfig() *CertStorageConfig {
    return &CertStorageConfig{
        Mode:            hardware.CertStorageModeExternal,
        EnableNVStorage: false,
        NVBaseIndex:     0x01800000,
        MaxCertSize:     2048,
        MaxCertificates: 4,
    }
}
```

## Integration with Backends

### PKCS#11 Backend

```go
func (b *Backend) CreateCertificateStorage(config *CertStorageConfig) (storage.CertificateStorage, error) {
    if config == nil {
        config = DefaultCertStorageConfig()
    }

    switch config.Mode {
    case hardware.CertStorageModeExternal:
        return config.ExternalStorage, nil

    case hardware.CertStorageModeHardware:
        return hardware.NewPKCS11CertStorage(
            b.p11ctx, b.session, b.config.TokenLabel, b.config.Slot)

    case hardware.CertStorageModeHybrid:
        hwStorage, _ := hardware.NewPKCS11CertStorage(
            b.p11ctx, b.session, b.config.TokenLabel, b.config.Slot)
        return hardware.NewHybridCertStorage(hwStorage, config.ExternalStorage)
    }
}
```

### TPM2 Backend

```go
func (ks *TPM2KeyStore) CreateCertificateStorage(config *CertStorageConfig) (storage.CertificateStorage, error) {
    if config == nil {
        config = DefaultCertStorageConfig()
    }

    switch config.Mode {
    case hardware.CertStorageModeExternal:
        return config.ExternalStorage, nil

    case hardware.CertStorageModeHardware:
        tpmConfig := &hardware.TPM2CertStorageConfig{
            BaseIndex:   config.NVBaseIndex,
            MaxCertSize: config.MaxCertSize,
            OwnerAuth:   []byte{},
        }
        return hardware.NewTPM2CertStorage(ks.tpm, tpmConfig)

    case hardware.CertStorageModeHybrid:
        tpmConfig := &hardware.TPM2CertStorageConfig{
            BaseIndex:   config.NVBaseIndex,
            MaxCertSize: config.MaxCertSize,
        }
        hwStorage, _ := hardware.NewTPM2CertStorage(ks.tpm, tpmConfig)
        return hardware.NewHybridCertStorage(hwStorage, config.ExternalStorage)
    }
}
```

## Usage Examples

### Example 1: PKCS#11 with External Storage (Default)

```go
backend, _ := pkcs11.NewBackend(pkcs11Config)
backend.Initialize(soPIN, userPIN)
backend.Login()

certStorage, _ := file.New("/var/lib/certs")
keychain := keychain.New(backend, certStorage)
```

### Example 2: PKCS#11 with Hardware Storage

```go
backend, _ := pkcs11.NewBackend(pkcs11Config)
backend.Initialize(soPIN, userPIN)
backend.Login()

certConfig := &pkcs11.CertStorageConfig{
    Mode:                  hardware.CertStorageModeHardware,
    EnableHardwareStorage: true,
    MaxCertificates:       50,
}

certStorage, _ := backend.CreateCertificateStorage(certConfig)
keychain := keychain.New(backend, certStorage)
```

### Example 3: TPM2 with Hybrid Storage

```go
ks, _ := tpm2.NewTPM2KeyStore(tpm2Config, backend, keyStorage, nil)
ks.Initialize(soPIN, userPIN)

externalStorage, _ := file.New("/var/lib/certs")

certConfig := &tpm2.CertStorageConfig{
    Mode:             hardware.CertStorageModeHybrid,
    ExternalStorage:  externalStorage,
    EnableNVStorage:  true,
    MaxCertificates:  4,
}

certStorage, _ := ks.CreateCertificateStorage(certConfig)
keychain := keychain.New(ks, certStorage)
```

### Example 4: Migration from External to Hardware

```go
externalStorage, _ := file.New("./certs")

// Step 1: Start with hybrid mode
certConfig := &pkcs11.CertStorageConfig{
    Mode:                  hardware.CertStorageModeHybrid,
    ExternalStorage:       externalStorage,
    EnableHardwareStorage: true,
}
certStorage, _ := backend.CreateCertificateStorage(certConfig)

// Step 2: Migrate existing certificates
oldCerts, _ := externalStorage.ListCerts()
for _, id := range oldCerts {
    cert, _ := externalStorage.GetCert(id)
    certStorage.SaveCert(id, cert) // Writes to hardware
}

// Step 3: Switch to hardware-only mode
certConfig.Mode = hardware.CertStorageModeHardware
certStorage, _ = backend.CreateCertificateStorage(certConfig)
```

## Error Handling

### Hardware-Specific Errors

```go
var (
    ErrCapacityExceeded    = errors.New("hardware certificate storage capacity exceeded")
    ErrCertificateTooLarge = errors.New("certificate exceeds maximum size")
    ErrNotSupported        = errors.New("operation not supported by hardware")
    ErrHardwareUnavailable = errors.New("hardware certificate storage unavailable")
    ErrNVIndexUnavailable  = errors.New("TPM NV index already in use")
    ErrTokenFull           = errors.New("PKCS#11 token is full")
)
```

### Error Recovery Strategies

1. **Capacity Exceeded**: Hybrid mode automatically falls back to external; hardware mode returns error
2. **Hardware Unavailable**: Hybrid mode uses external exclusively; hardware mode returns error
3. **Certificate Too Large**: Reject with error (no silent truncation)
4. **NV Index Conflicts** (TPM2): Try alternative indices (max 3 attempts)

## Performance Considerations

### PKCS#11 Performance

| Operation | Hardware | External | Notes |
|-----------|----------|----------|-------|
| SaveCert | ~50ms | ~5ms | HSM write latency |
| GetCert | ~20ms | ~2ms | HSM read latency |
| ListCerts | ~100ms | ~10ms | Object enumeration |

**Optimization**: Cache certificate lists, use hybrid mode for read-heavy workloads

### TPM2 Performance

| Operation | Hardware (NV) | External | Notes |
|-----------|---------------|----------|-------|
| SaveCert | ~100-200ms | ~5ms | NV write + startup |
| GetCert | ~50-100ms | ~2ms | NV read latency |
| ListCerts | ~200-500ms | ~10ms | NV enumeration |

**Optimization**: Minimize NV writes (wear leveling), use external for frequently accessed certificates

### Storage Mode Recommendations

| Use Case | Recommended Mode | Rationale |
|----------|------------------|-----------|
| High security, low volume | Hardware | Maximum tamper resistance |
| High performance | External | Lowest latency |
| Gradual migration | Hybrid | Transparent transition |
| Capacity constraints | Hybrid | Automatic overflow |
| Development/testing | External | Fast iteration |

## Security Considerations

### Access Control

**PKCS#11**:
- CKA_PRIVATE restricts certificate access
- Session authentication required
- Hardware-level access control and logging

**TPM2**:
- NV index attributes control read/write access
- Owner hierarchy authorization required
- Platform policy can restrict operations

### Threat Model

| Threat | External Storage | Hardware Storage |
|--------|------------------|------------------|
| File system tampering | Vulnerable | Protected |
| Memory extraction | Vulnerable | Protected |
| Physical theft | Vulnerable | Protected |
| Remote access | Depends on permissions | Requires HSM/TPM access |

## Backward Compatibility

All changes are opt-in via configuration. Existing code continues to work unchanged.

**No breaking changes.** External storage remains fully supported.

## References

### Specifications

- [PKCS#11 v3.0 Specification](http://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html)
- [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [X.509 Certificate Standard (RFC 5280)](https://datatracker.ietf.org/doc/html/rfc5280)

### Related Documentation

- `/docs/storage-abstraction.md` - Storage interface design
- `/docs/backends/pkcs11.md` - PKCS#11 backend documentation
- `/docs/backends/tpm2.md` - TPM2 backend documentation

## Appendix: Key Attributes

### PKCS#11 Certificate Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| CKA_CLASS | CK_OBJECT_CLASS | Must be CKO_CERTIFICATE |
| CKA_TOKEN | CK_BBOOL | TRUE for persistent storage |
| CKA_ID | CK_BYTE | Links to corresponding key |
| CKA_LABEL | CK_UTF8CHAR | Human-readable label |
| CKA_SUBJECT | CK_BYTE | DER-encoded subject |
| CKA_ISSUER | CK_BYTE | DER-encoded issuer |
| CKA_VALUE | CK_BYTE | DER-encoded certificate |

### TPM2 NV Index Attributes

| Attribute | Value | Description |
|-----------|-------|-------------|
| TPMA_NV_AUTHREAD | 1 | Requires auth to read |
| TPMA_NV_AUTHWRITE | 1 | Requires auth to write |
| TPMA_NV_NO_DA | 1 | Not DA-protected |
| TPMA_NV_OWNERWRITE | 1 | Owner can write |
| TPMA_NV_OWNERREAD | 1 | Owner can read |
