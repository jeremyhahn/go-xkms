# Hardware Certificate Storage

This document describes the hardware certificate storage implementation for PKCS#11 and TPM2 backends, enabling certificates to be stored directly in hardware modules while maintaining full backward compatibility with external storage.

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

Hardware security modules (HSMs) and TPMs provide native certificate storage capabilities that are now fully supported:

- **PKCS#11**: Certificates stored as `CKO_CERTIFICATE` objects in HSM
- **TPM2**: Certificates stored in NV (Non-Volatile) RAM

This implementation provides:

1. **Hardware consistency**: Both keys and certificates can reside in hardware
2. **Enhanced security**: Certificates protected by hardware tamper resistance
3. **Hardware attestation**: Leverages native certificate validation features
4. **Flexible deployment**: Choose external, hardware, or hybrid storage modes

### Key Features

1. **Native Hardware Storage**: Certificates stored directly in PKCS#11/TPM2
2. **Backward Compatibility**: Full support for external certificate storage
3. **Hybrid Mode**: Automatic failover between hardware and external storage
4. **Configuration Flexibility**: Easy switching between storage modes via config
5. **Migration Support**: Patterns for migrating between storage backends
6. **Thread Safety**: All implementations are fully concurrent-safe
7. **Interface Consistency**: Maintains existing CertificateStorage interface

## Design Overview

### Architecture Principles

1. **Composition over Inheritance**: Use interface composition to extend functionality
2. **Fail-Safe Defaults**: Default to external storage, opt-in to hardware storage
3. **Explicit Configuration**: Clear, unambiguous configuration options
4. **Graceful Degradation**: Fall back to external storage if hardware unavailable
5. **Zero Breaking Changes**: Existing code continues to work unchanged

### Storage Mode Strategy

We introduce three storage modes:

```go
type CertStorageMode string

const (
    // CertStorageModeExternal - All certificates in external storage (default, current behavior)
    CertStorageModeExternal CertStorageMode = "external"

    // CertStorageModeHardware - All certificates in hardware storage
    CertStorageModeHardware CertStorageMode = "hardware"

    // CertStorageModeHybrid - New certificates in hardware, fallback to external for reads
    CertStorageModeHybrid CertStorageMode = "hybrid"
)
```

## File Structure

### New Files to Create

```
pkg/storage/
├── hardware/
│   ├── interface.go              # HardwareCertStorage interface
│   ├── pkcs11_cert_storage.go    # PKCS#11 implementation
│   ├── pkcs11_cert_storage_test.go
│   ├── tpm2_cert_storage.go      # TPM2 implementation
│   ├── tpm2_cert_storage_test.go
│   ├── hybrid_cert_storage.go    # Hybrid mode wrapper
│   ├── hybrid_cert_storage_test.go
│   └── errors.go                 # Hardware-specific errors
│
pkg/backend/pkcs11/
├── cert_config.go                # Certificate storage configuration
│
pkg/tpm2/
├── cert_config.go                # Certificate storage configuration
│
docs/design/
├── hardware-certificate-storage.md  # This document
```

### Modified Files

```
pkg/backend/pkcs11/pkcs11.go      # Add certificate storage factory
pkg/tpm2/tpm2.go                  # Add certificate storage factory
pkg/backend/pkcs11/config.go      # Add CertStorageMode field
pkg/tpm2/config.go                # Add CertStorageMode field
```

## Interface Definitions

### Core Hardware Certificate Storage Interface

```go
// Package hardware provides hardware-backed certificate storage implementations
// for PKCS#11 HSMs and TPM2 devices.
package hardware

import (
    "crypto/x509"
    "github.com/jeremyhahn/go-keychain/pkg/storage"
)

// HardwareCertStorage extends CertificateStorage with hardware-specific capabilities.
// This interface is implemented by PKCS#11 and TPM2 certificate storage backends.
//
// Implementations MUST be thread-safe.
type HardwareCertStorage interface {
    storage.CertificateStorage

    // GetCapacity returns the total and available certificate storage capacity.
    // For PKCS#11, this queries token info. For TPM2, this queries NV RAM.
    // Returns (total slots, available slots, error).
    // Returns ErrNotSupported if the hardware doesn't report capacity.
    GetCapacity() (total int, available int, err error)

    // SupportsChains returns true if the hardware supports storing certificate chains.
    // PKCS#11 typically stores individual certificates with relationships.
    // TPM2 stores chains as serialized blobs in NV RAM.
    SupportsChains() bool

    // IsHardwareBacked returns true to distinguish from external storage.
    // This allows runtime type checking without reflection.
    IsHardwareBacked() bool

    // Compact performs storage optimization if supported by hardware.
    // For PKCS#11, this is a no-op. For TPM2, this may defragment NV RAM.
    // Returns ErrNotSupported if compaction is not available.
    Compact() error
}

// CertificateAttributes provides metadata for hardware certificate storage.
// This maps to PKCS#11 CKA_* attributes and TPM2 NV index properties.
type CertificateAttributes struct {
    // ID uniquely identifies the certificate (maps to CKA_ID for PKCS#11)
    ID string

    // Label is a human-readable name (maps to CKA_LABEL for PKCS#11)
    Label string

    // Trusted indicates if this is a trusted CA certificate
    // (maps to CKA_TRUSTED for PKCS#11, policy for TPM2)
    Trusted bool

    // CertificateType specifies the certificate type
    // (maps to CKA_CERTIFICATE_TYPE for PKCS#11)
    CertificateType CertificateType

    // Subject is the DER-encoded X.509 subject
    Subject []byte

    // Issuer is the DER-encoded X.509 issuer
    Issuer []byte

    // SerialNumber is the certificate serial number
    SerialNumber []byte
}

// CertificateType identifies the certificate format/type
type CertificateType int

const (
    CertTypeX509 CertificateType = 0 // Standard X.509 certificate
)

// StorageInfo provides information about hardware certificate storage state
type StorageInfo struct {
    // Mode indicates the current storage mode
    Mode CertStorageMode

    // HardwareType identifies the hardware backend (pkcs11, tpm2)
    HardwareType string

    // TotalSlots is the total certificate capacity
    TotalSlots int

    // UsedSlots is the number of certificates currently stored
    UsedSlots int

    // SupportsChains indicates if certificate chains are supported
    SupportsChains bool

    // SupportsCompaction indicates if storage can be compacted
    SupportsCompaction bool
}

// CertStorageMode defines where certificates are stored
type CertStorageMode string

const (
    // CertStorageModeExternal stores all certificates in external storage (default)
    CertStorageModeExternal CertStorageMode = "external"

    // CertStorageModeHardware stores all certificates in hardware
    CertStorageModeHardware CertStorageMode = "hardware"

    // CertStorageModeHybrid stores new certificates in hardware, reads from both
    CertStorageModeHybrid CertStorageMode = "hybrid"
)
```

### PKCS#11 Certificate Storage Implementation

```go
// Package hardware provides hardware-backed certificate storage
package hardware

import (
    "crypto/x509"
    "fmt"
    "sync"

    "github.com/miekg/pkcs11"
    "github.com/jeremyhahn/go-keychain/pkg/storage"
)

// PKCS11CertStorage implements HardwareCertStorage for PKCS#11 HSMs.
// Certificates are stored as CKO_CERTIFICATE objects on the token.
//
// Thread Safety:
// All operations are protected by a read-write mutex for concurrent access.
//
// Certificate Storage:
// - Each certificate is stored as a CKO_CERTIFICATE object
// - CKA_ID links certificates to their corresponding private keys
// - CKA_LABEL provides human-readable identification
// - CKA_SUBJECT and CKA_ISSUER enable searching/filtering
//
// Limitations:
// - Chain storage maps to individual certificates with ID relationships
// - Not all HSMs support certificate deletion
// - Capacity depends on token memory/object limits
type PKCS11CertStorage struct {
    ctx        *pkcs11.Ctx         // PKCS#11 context
    session    pkcs11.SessionHandle // Open session handle
    tokenLabel string               // Token identifier
    slotID     uint                 // Slot ID for operations
    mu         sync.RWMutex         // Protects concurrent access
    closed     bool                 // Tracks if storage is closed
}

// NewPKCS11CertStorage creates a new PKCS#11 certificate storage instance.
// The session must be authenticated (logged in) before calling this.
//
// Parameters:
//   - ctx: Initialized PKCS#11 context
//   - session: Authenticated session handle
//   - tokenLabel: Token label for identification
//   - slotID: Slot ID for the token
//
// Returns an error if the session is invalid or token is inaccessible.
func NewPKCS11CertStorage(
    ctx *pkcs11.Ctx,
    session pkcs11.SessionHandle,
    tokenLabel string,
    slotID uint,
) (HardwareCertStorage, error)

// SaveCert stores a certificate as a CKO_CERTIFICATE object.
// If a certificate with the same ID exists, it will be overwritten.
//
// PKCS#11 Attributes Set:
//   - CKA_CLASS = CKO_CERTIFICATE
//   - CKA_CERTIFICATE_TYPE = CKC_X_509
//   - CKA_TOKEN = true (persistent storage)
//   - CKA_ID = certificate ID
//   - CKA_LABEL = certificate ID (for human readability)
//   - CKA_SUBJECT = DER-encoded subject
//   - CKA_ISSUER = DER-encoded issuer
//   - CKA_SERIAL_NUMBER = serial number
//   - CKA_VALUE = DER-encoded certificate
func (p *PKCS11CertStorage) SaveCert(id string, cert *x509.Certificate) error

// GetCert retrieves a certificate by ID using CKA_ID attribute search.
func (p *PKCS11CertStorage) GetCert(id string) (*x509.Certificate, error)

// DeleteCert removes a certificate object from the token.
// Note: Some HSMs may not support certificate deletion.
func (p *PKCS11CertStorage) DeleteCert(id string) error

// SaveCertChain stores a certificate chain as individual certificates
// with ID relationships. The leaf certificate uses the provided ID,
// intermediates use ID-chain-0, ID-chain-1, etc.
func (p *PKCS11CertStorage) SaveCertChain(id string, chain []*x509.Certificate) error

// GetCertChain retrieves a certificate chain by loading related certificates.
func (p *PKCS11CertStorage) GetCertChain(id string) ([]*x509.Certificate, error)

// ListCerts returns all certificate IDs by enumerating CKO_CERTIFICATE objects.
func (p *PKCS11CertStorage) ListCerts() ([]string, error)

// CertExists checks if a certificate object exists with the given ID.
func (p *PKCS11CertStorage) CertExists(id string) (bool, error)

// Close releases the PKCS#11 session.
func (p *PKCS11CertStorage) Close() error

// GetCapacity queries token info for certificate storage capacity.
func (p *PKCS11CertStorage) GetCapacity() (total int, available int, err error)

// SupportsChains returns true (PKCS#11 supports chains via relationships).
func (p *PKCS11CertStorage) SupportsChains() bool

// IsHardwareBacked returns true.
func (p *PKCS11CertStorage) IsHardwareBacked() bool

// Compact is a no-op for PKCS#11 (returns ErrNotSupported).
func (p *PKCS11CertStorage) Compact() error
```

### TPM2 Certificate Storage Implementation

```go
// Package hardware provides hardware-backed certificate storage
package hardware

import (
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "sync"

    "github.com/google/go-tpm/tpm2"
    "github.com/google/go-tpm/tpm2/transport"
    "github.com/jeremyhahn/go-keychain/pkg/storage"
)

// TPM2CertStorage implements HardwareCertStorage for TPM 2.0 devices.
// Certificates are stored in TPM NV (Non-Volatile) RAM.
//
// Thread Safety:
// All operations are protected by a read-write mutex for concurrent access.
//
// Certificate Storage:
// - Each certificate is stored in a dedicated NV index
// - NV indices are derived from a base index + hash(ID)
// - Certificates are stored as PEM-encoded data
// - NV index attributes provide access control
//
// NV Index Layout:
//   Base Index: 0x01800000 (TPM_NV_INDEX_FIRST)
//   Cert Index: Base + (FNV-1a hash of ID % 0x00FFFFFF)
//
// Limitations:
// - Limited NV RAM capacity (typically 2KB-8KB total)
// - Each certificate consumes ~2KB (including overhead)
// - Practical limit: 2-4 certificates per TPM
// - No built-in chain support (stored as single blob)
type TPM2CertStorage struct {
    tpm        transport.TPMCloser  // TPM device connection
    baseIndex  uint32               // Base NV index for certificates
    maxSize    int                  // Maximum certificate size (bytes)
    mu         sync.RWMutex         // Protects concurrent access
    closed     bool                 // Tracks if storage is closed
}

// TPM2CertStorageConfig configures TPM2 certificate storage
type TPM2CertStorageConfig struct {
    // BaseIndex is the starting NV index for certificate storage
    // Default: 0x01800000 (TPM_NV_INDEX_FIRST)
    BaseIndex uint32

    // MaxCertSize is the maximum certificate size in bytes
    // Default: 2048 bytes
    MaxCertSize int

    // OwnerAuth is the owner hierarchy password
    // Required for creating/deleting NV indices
    OwnerAuth []byte
}

// NewTPM2CertStorage creates a new TPM2 certificate storage instance.
//
// Parameters:
//   - tpm: Open TPM device connection
//   - config: Storage configuration
//
// Returns an error if NV RAM is inaccessible.
func NewTPM2CertStorage(
    tpm transport.TPMCloser,
    config *TPM2CertStorageConfig,
) (HardwareCertStorage, error)

// SaveCert stores a certificate in TPM NV RAM.
// The certificate is PEM-encoded and written to a dedicated NV index.
//
// NV Index Attributes:
//   - TPMA_NV_AUTHWRITE: Requires authorization to write
//   - TPMA_NV_AUTHREAD: Requires authorization to read
//   - TPMA_NV_NO_DA: Not subject to dictionary attack protection
//   - TPMA_NV_OWNERWRITE: Owner hierarchy can write
//   - TPMA_NV_OWNERREAD: Owner hierarchy can read
func (t *TPM2CertStorage) SaveCert(id string, cert *x509.Certificate) error

// GetCert retrieves a certificate from TPM NV RAM.
func (t *TPM2CertStorage) GetCert(id string) (*x509.Certificate, error)

// DeleteCert removes a certificate by undefining its NV index.
func (t *TPM2CertStorage) DeleteCert(id string) error

// SaveCertChain stores a certificate chain as a PEM-encoded bundle.
// All certificates are concatenated and stored in a single NV index.
func (t *TPM2CertStorage) SaveCertChain(id string, chain []*x509.Certificate) error

// GetCertChain retrieves and parses a certificate chain bundle.
func (t *TPM2CertStorage) GetCertChain(id string) ([]*x509.Certificate, error)

// ListCerts returns certificate IDs by scanning defined NV indices.
func (t *TPM2CertStorage) ListCerts() ([]string, error)

// CertExists checks if an NV index exists for the certificate.
func (t *TPM2CertStorage) CertExists(id string) (bool, error)

// Close releases TPM resources (NV handles are persistent, no cleanup needed).
func (t *TPM2CertStorage) Close() error

// GetCapacity queries TPM NV RAM capacity and usage.
func (t *TPM2CertStorage) GetCapacity() (total int, available int, err error)

// SupportsChains returns true (chains stored as concatenated PEM).
func (t *TPM2CertStorage) SupportsChains() bool

// IsHardwareBacked returns true.
func (t *TPM2CertStorage) IsHardwareBacked() bool

// Compact defragments TPM NV RAM if supported (TPM 2.0 spec optional).
func (t *TPM2CertStorage) Compact() error

// Helper Functions

// certIndexFromID computes the NV index for a certificate ID
// using FNV-1a hash to distribute IDs across index space.
func (t *TPM2CertStorage) certIndexFromID(id string) uint32

// readNVIndex reads data from an NV index with authorization.
func (t *TPM2CertStorage) readNVIndex(index uint32) ([]byte, error)

// writeNVIndex writes data to an NV index, creating if necessary.
func (t *TPM2CertStorage) writeNVIndex(index uint32, data []byte) error

// deleteNVIndex undefines an NV index to free NV RAM.
func (t *TPM2CertStorage) deleteNVIndex(index uint32) error
```

### Hybrid Certificate Storage

```go
// Package hardware provides hardware-backed certificate storage
package hardware

import (
    "crypto/x509"
    "errors"
    "sync"

    "github.com/jeremyhahn/go-keychain/pkg/storage"
)

// HybridCertStorage provides a hybrid storage strategy combining
// hardware and external storage.
//
// Storage Strategy:
//   - SaveCert: Always writes to hardware, falls back to external on error
//   - GetCert: Tries hardware first, falls back to external
//   - DeleteCert: Deletes from both hardware and external
//   - ListCerts: Merges IDs from both storages (deduplicates)
//
// Use Cases:
//   - Migration from external to hardware storage
//   - Overflow handling when hardware capacity is exhausted
//   - High-availability with redundant storage
//   - Gradual rollout of hardware certificate storage
//
// Thread Safety:
// Uses separate mutexes for each storage backend to allow concurrent access.
type HybridCertStorage struct {
    hardware HardwareCertStorage     // Hardware-backed storage
    external storage.CertificateStorage // External storage (file, memory, etc.)
    mu       sync.RWMutex            // Protects storage state
    closed   bool                    // Tracks if storage is closed
}

// NewHybridCertStorage creates a hybrid certificate storage.
//
// Parameters:
//   - hardware: Hardware certificate storage implementation
//   - external: External certificate storage implementation
//
// Returns an error if either storage is nil.
func NewHybridCertStorage(
    hardware HardwareCertStorage,
    external storage.CertificateStorage,
) (storage.CertificateStorage, error)

// SaveCert attempts to save to hardware first, falls back to external.
// Returns success if either storage succeeds.
func (h *HybridCertStorage) SaveCert(id string, cert *x509.Certificate) error

// GetCert tries hardware first, then external.
func (h *HybridCertStorage) GetCert(id string) (*x509.Certificate, error)

// DeleteCert removes from both hardware and external storage.
// Returns success if either deletion succeeds (idempotent).
func (h *HybridCertStorage) DeleteCert(id string) error

// SaveCertChain saves to hardware first, falls back to external.
func (h *HybridCertStorage) SaveCertChain(id string, chain []*x509.Certificate) error

// GetCertChain tries hardware first, then external.
func (h *HybridCertStorage) GetCertChain(id string) ([]*x509.Certificate, error)

// ListCerts merges certificate IDs from both storages (deduplicated).
func (h *HybridCertStorage) ListCerts() ([]string, error)

// CertExists returns true if certificate exists in either storage.
func (h *HybridCertStorage) CertExists(id string) (bool, error)

// Close closes both hardware and external storage.
func (h *HybridCertStorage) Close() error

// GetInfo returns information about storage state
func (h *HybridCertStorage) GetInfo() (*HybridStorageInfo, error)

// HybridStorageInfo provides information about hybrid storage state
type HybridStorageInfo struct {
    HardwareInfo  StorageInfo
    ExternalInfo  StorageInfo
    HardwareCount int // Certificates in hardware
    ExternalCount int // Certificates in external
    SharedCount   int // Certificates in both
}
```

## Configuration Design

### PKCS#11 Backend Configuration

```go
// pkg/backend/pkcs11/cert_config.go

package pkcs11

// CertStorageConfig configures certificate storage for PKCS#11 backend
type CertStorageConfig struct {
    // Mode determines where certificates are stored
    // Default: CertStorageModeExternal
    Mode hardware.CertStorageMode

    // ExternalStorage provides external certificate storage
    // Required for External and Hybrid modes
    ExternalStorage storage.CertificateStorage

    // EnableHardwareStorage allows certificates to be stored in the HSM
    // Default: false (use external storage only)
    EnableHardwareStorage bool

    // MaxCertificates limits the number of certificates in hardware
    // Default: 100 (prevents token exhaustion)
    MaxCertificates int
}

// DefaultCertStorageConfig returns safe defaults
func DefaultCertStorageConfig() *CertStorageConfig {
    return &CertStorageConfig{
        Mode:                  hardware.CertStorageModeExternal,
        EnableHardwareStorage: false,
        MaxCertificates:       100,
    }
}

// Validate checks configuration consistency
func (c *CertStorageConfig) Validate() error {
    if c.Mode == hardware.CertStorageModeExternal && c.ExternalStorage == nil {
        return errors.New("external storage required for external mode")
    }
    if c.Mode == hardware.CertStorageModeHybrid && c.ExternalStorage == nil {
        return errors.New("external storage required for hybrid mode")
    }
    if c.MaxCertificates < 1 {
        return errors.New("max certificates must be at least 1")
    }
    return nil
}
```

### TPM2 Backend Configuration

```go
// pkg/tpm2/cert_config.go

package tpm2

// CertStorageConfig configures certificate storage for TPM2 backend
type CertStorageConfig struct {
    // Mode determines where certificates are stored
    // Default: CertStorageModeExternal
    Mode hardware.CertStorageMode

    // ExternalStorage provides external certificate storage
    // Required for External and Hybrid modes
    ExternalStorage storage.CertificateStorage

    // EnableNVStorage allows certificates to be stored in TPM NV RAM
    // Default: false (use external storage only)
    EnableNVStorage bool

    // NVBaseIndex is the starting NV index for certificate storage
    // Default: 0x01800000 (TPM_NV_INDEX_FIRST)
    NVBaseIndex uint32

    // MaxCertSize is the maximum certificate size in bytes
    // Default: 2048 bytes
    MaxCertSize int

    // MaxCertificates limits the number of certificates in NV RAM
    // Default: 4 (TPM NV RAM is limited, typically 2-8KB total)
    MaxCertificates int
}

// DefaultCertStorageConfig returns safe defaults for TPM2
func DefaultCertStorageConfig() *CertStorageConfig {
    return &CertStorageConfig{
        Mode:            hardware.CertStorageModeExternal,
        EnableNVStorage: false,
        NVBaseIndex:     0x01800000, // TPM_NV_INDEX_FIRST
        MaxCertSize:     2048,
        MaxCertificates: 4, // Conservative limit for NV RAM
    }
}

// Validate checks configuration consistency
func (c *CertStorageConfig) Validate() error {
    if c.Mode == hardware.CertStorageModeExternal && c.ExternalStorage == nil {
        return errors.New("external storage required for external mode")
    }
    if c.Mode == hardware.CertStorageModeHybrid && c.ExternalStorage == nil {
        return errors.New("external storage required for hybrid mode")
    }
    if c.MaxCertificates < 1 || c.MaxCertificates > 10 {
        return errors.New("max certificates must be between 1 and 10 for TPM2")
    }
    if c.MaxCertSize < 512 || c.MaxCertSize > 4096 {
        return errors.New("max cert size must be between 512 and 4096 bytes")
    }
    return nil
}
```

## Integration with Existing Backends

### PKCS#11 Backend Integration

```go
// pkg/backend/pkcs11/pkcs11.go

// CreateCertificateStorage creates appropriate certificate storage based on configuration
func (b *Backend) CreateCertificateStorage(config *CertStorageConfig) (storage.CertificateStorage, error) {
    if config == nil {
        config = DefaultCertStorageConfig()
    }

    if err := config.Validate(); err != nil {
        return nil, fmt.Errorf("invalid certificate storage config: %w", err)
    }

    switch config.Mode {
    case hardware.CertStorageModeExternal:
        return config.ExternalStorage, nil

    case hardware.CertStorageModeHardware:
        return hardware.NewPKCS11CertStorage(
            b.p11ctx,
            b.session,
            b.config.TokenLabel,
            b.config.Slot,
        )

    case hardware.CertStorageModeHybrid:
        hwStorage, err := hardware.NewPKCS11CertStorage(
            b.p11ctx,
            b.session,
            b.config.TokenLabel,
            b.config.Slot,
        )
        if err != nil {
            return nil, fmt.Errorf("failed to create hardware storage: %w", err)
        }

        return hardware.NewHybridCertStorage(hwStorage, config.ExternalStorage)

    default:
        return nil, fmt.Errorf("unknown certificate storage mode: %s", config.Mode)
    }
}
```

### TPM2 Backend Integration

```go
// pkg/tpm2/tpm2.go

// CreateCertificateStorage creates appropriate certificate storage based on configuration
func (ks *TPM2KeyStore) CreateCertificateStorage(config *CertStorageConfig) (storage.CertificateStorage, error) {
    if config == nil {
        config = DefaultCertStorageConfig()
    }

    if err := config.Validate(); err != nil {
        return nil, fmt.Errorf("invalid certificate storage config: %w", err)
    }

    switch config.Mode {
    case hardware.CertStorageModeExternal:
        return config.ExternalStorage, nil

    case hardware.CertStorageModeHardware:
        tpmConfig := &hardware.TPM2CertStorageConfig{
            BaseIndex:   config.NVBaseIndex,
            MaxCertSize: config.MaxCertSize,
            OwnerAuth:   []byte{}, // Use from TPM2 config
        }
        return hardware.NewTPM2CertStorage(ks.tpm, tpmConfig)

    case hardware.CertStorageModeHybrid:
        tpmConfig := &hardware.TPM2CertStorageConfig{
            BaseIndex:   config.NVBaseIndex,
            MaxCertSize: config.MaxCertSize,
            OwnerAuth:   []byte{},
        }
        hwStorage, err := hardware.NewTPM2CertStorage(ks.tpm, tpmConfig)
        if err != nil {
            return nil, fmt.Errorf("failed to create hardware storage: %w", err)
        }

        return hardware.NewHybridCertStorage(hwStorage, config.ExternalStorage)

    default:
        return nil, fmt.Errorf("unknown certificate storage mode: %s", config.Mode)
    }
}
```

## Usage Examples

### Example 1: PKCS#11 with External Storage (Default)

```go
// Current behavior - continues to work unchanged
backend, _ := pkcs11.NewBackend(pkcs11Config)
backend.Initialize(soPIN, userPIN)
backend.Login()

// Certificates stored externally (current behavior)
certStorage, _ := file.New("/var/lib/certs")

// Use with keychain
keychain := keychain.New(backend, certStorage)
```

### Example 2: PKCS#11 with Hardware Storage

```go
backend, _ := pkcs11.NewBackend(pkcs11Config)
backend.Initialize(soPIN, userPIN)
backend.Login()

// Create hardware certificate storage
certConfig := &pkcs11.CertStorageConfig{
    Mode:                  hardware.CertStorageModeHardware,
    EnableHardwareStorage: true,
    MaxCertificates:       50,
}

certStorage, _ := backend.CreateCertificateStorage(certConfig)

// Certificates now stored in HSM
keychain := keychain.New(backend, certStorage)
```

### Example 3: TPM2 with Hybrid Storage

```go
ks, _ := tpm2.NewTPM2KeyStore(tpm2Config, backend, keyStorage, nil)
ks.Initialize(soPIN, userPIN)

// External storage for fallback
externalStorage, _ := file.New("/var/lib/certs")

// Create hybrid storage (new certs in TPM, fallback to external)
certConfig := &tpm2.CertStorageConfig{
    Mode:             hardware.CertStorageModeHybrid,
    ExternalStorage:  externalStorage,
    EnableNVStorage:  true,
    MaxCertificates:  4,
}

certStorage, _ := ks.CreateCertificateStorage(certConfig)

// Certificates prioritize TPM NV RAM, overflow to filesystem
keychain := keychain.New(ks, certStorage)
```

### Example 4: Migration from External to Hardware

```go
// Create external storage
externalStorage, _ := file.New("./certs")

// Step 1: Start with hybrid mode
certConfig := &pkcs11.CertStorageConfig{
    Mode:                  hardware.CertStorageModeHybrid,
    ExternalStorage:       externalStorage,
    EnableHardwareStorage: true,
}
certStorage, _ := backend.CreateCertificateStorage(certConfig)

// Step 2: Read from external, write to hardware
oldCerts, _ := externalStorage.ListCerts()
for _, id := range oldCerts {
    cert, _ := externalStorage.GetCert(id)
    certStorage.SaveCert(id, cert) // Writes to hardware
}

// Step 3: Switch to hardware-only mode
certConfig.Mode = hardware.CertStorageModeHardware
certStorage, _ = backend.CreateCertificateStorage(certConfig)
```

## Adoption Guide

This section provides guidance for adopting hardware certificate storage in your deployment.

### Preparation

1. Review existing certificate usage patterns
2. Identify certificate count and size requirements
3. Determine hardware capacity limits
4. Choose appropriate storage mode (external/hardware/hybrid)

### Testing

Before production deployment:

1. Test with SoftHSM or TPM simulator
2. Verify capacity limits with your hardware
3. Benchmark performance for your use case
4. Test failover scenarios (if using hybrid mode)
5. Validate backup and recovery procedures

### Gradual Rollout

Recommended approach for production:

1. **Start with hybrid mode** - Provides automatic failover
2. **Monitor hardware capacity** - Track usage and performance
3. **Migrate critical certificates first** - Prioritize high-value assets
4. **Gradual transition** - Move to hardware-only if desired
5. **Maintain external backup** - Keep external storage as safety net

### Migration Example

See the usage examples in this document for specific code examples of migrating from external to hardware storage.

## Error Handling

### Hardware-Specific Errors

```go
// pkg/storage/hardware/errors.go

package hardware

import "errors"

var (
    // ErrCapacityExceeded indicates hardware storage is full
    ErrCapacityExceeded = errors.New("hardware certificate storage capacity exceeded")

    // ErrCertificateTooLarge indicates certificate exceeds maximum size
    ErrCertificateTooLarge = errors.New("certificate exceeds maximum size for hardware storage")

    // ErrNotSupported indicates hardware doesn't support the operation
    ErrNotSupported = errors.New("operation not supported by hardware")

    // ErrHardwareUnavailable indicates hardware storage is inaccessible
    ErrHardwareUnavailable = errors.New("hardware certificate storage unavailable")

    // ErrNVIndexUnavailable indicates TPM NV index conflicts with existing data
    ErrNVIndexUnavailable = errors.New("TPM NV index already in use")

    // ErrTokenFull indicates PKCS#11 token has no free object slots
    ErrTokenFull = errors.New("PKCS#11 token is full")
)
```

### Error Recovery Strategies

1. **Capacity Exceeded**:
   - Hybrid mode: Automatically fall back to external storage
   - Hardware mode: Return error, require manual intervention

2. **Hardware Unavailable**:
   - Hybrid mode: Use external storage exclusively
   - Hardware mode: Return error, prevent operations

3. **Certificate Too Large**:
   - Reject and return error (don't silently truncate)
   - Suggest using external storage for large certificates

4. **NV Index Conflicts** (TPM2):
   - Try alternative index (base + hash + collision offset)
   - Maximum 3 collision attempts before returning error

## Thread Safety Considerations

### Mutex Strategy

All implementations use read-write mutexes:

```go
// Read operations acquire RLock
func (s *Storage) GetCert(id string) (*x509.Certificate, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    // ... read operation
}

// Write operations acquire Lock
func (s *Storage) SaveCert(id string, cert *x509.Certificate) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    // ... write operation
}
```

### Concurrent Access Patterns

1. **PKCS#11**: Session-based locking
   - Each storage instance maintains dedicated session
   - PKCS#11 library handles token-level locking
   - Application-level mutex prevents session conflicts

2. **TPM2**: Command serialization
   - TPM operations are inherently serialized
   - Mutex prevents concurrent command submission
   - NV index operations are atomic at TPM level

3. **Hybrid**: Dual mutex strategy
   - Separate mutexes for hardware and external storage
   - Allows concurrent access to different backends
   - Operation-level mutex for consistency

## Performance Considerations

### PKCS#11 Performance

| Operation | Hardware | External (File) | Notes |
|-----------|----------|-----------------|-------|
| SaveCert | ~50ms | ~5ms | HSM write latency |
| GetCert | ~20ms | ~2ms | HSM read latency |
| ListCerts | ~100ms | ~10ms | Object enumeration |
| DeleteCert | ~50ms | ~5ms | HSM delete latency |

**Optimization Strategies**:
- Cache certificate list to reduce enumeration overhead
- Batch operations when possible
- Use hybrid mode to reduce hardware access for read-heavy workloads

### TPM2 Performance

| Operation | Hardware (NV) | External (File) | Notes |
|-----------|---------------|-----------------|-------|
| SaveCert | ~100-200ms | ~5ms | NV write + TPM startup |
| GetCert | ~50-100ms | ~2ms | NV read latency |
| ListCerts | ~200-500ms | ~10ms | NV index enumeration |
| DeleteCert | ~100ms | ~5ms | NV undefine latency |

**Optimization Strategies**:
- Minimize NV writes (wear leveling)
- Use external storage for frequently accessed certificates
- Limit hardware storage to critical certificates only
- Consider NV index caching for read operations

### Storage Mode Recommendations

| Use Case | Recommended Mode | Rationale |
|----------|------------------|-----------|
| High security, low volume | Hardware | Maximum tamper resistance |
| High performance | External | Lowest latency |
| Gradual migration | Hybrid | Transparent transition |
| Capacity constraints | Hybrid | Automatic overflow handling |
| Development/testing | External | Fast iteration, no hardware wear |

## Security Considerations

### Access Control

**PKCS#11**:
- CKA_PRIVATE attribute restricts certificate access
- CKA_TOKEN ensures persistent storage
- Session authentication required for operations

**TPM2**:
- NV index attributes control read/write access
- Owner hierarchy authorization required
- Platform policy can restrict operations

### Tamper Resistance

**PKCS#11**:
- Certificates stored in HSM tamper-resistant memory
- Hardware-level access control and logging
- Physical security of HSM device

**TPM2**:
- Certificates in NV RAM protected by TPM hardware
- Attestation can prove certificate integrity
- Platform configuration registers (PCRs) can gate access

### Threat Model

| Threat | External Storage | Hardware Storage |
|--------|------------------|------------------|
| File system tampering | Vulnerable | Protected |
| Memory extraction | Vulnerable | Protected |
| Physical theft | Vulnerable | Protected |
| Remote access | Depends on permissions | Requires HSM/TPM access |
| Insider threat | Vulnerable | Audit trail |

## Testing Strategy

### Unit Tests

```go
// Test each storage implementation independently
func TestPKCS11CertStorage_SaveCert(t *testing.T)
func TestPKCS11CertStorage_GetCert(t *testing.T)
func TestPKCS11CertStorage_DeleteCert(t *testing.T)
func TestPKCS11CertStorage_Capacity(t *testing.T)
func TestPKCS11CertStorage_Concurrent(t *testing.T)

func TestTPM2CertStorage_SaveCert(t *testing.T)
func TestTPM2CertStorage_GetCert(t *testing.T)
func TestTPM2CertStorage_DeleteCert(t *testing.T)
func TestTPM2CertStorage_NVIndexAllocation(t *testing.T)

func TestHybridCertStorage_Fallback(t *testing.T)
func TestHybridCertStorage_Migration(t *testing.T)
```

### Integration Tests

```go
// Test with real HSMs/TPMs
func TestPKCS11CertStorage_Integration_SoftHSM(t *testing.T)
func TestPKCS11CertStorage_Integration_YubiHSM(t *testing.T)

func TestTPM2CertStorage_Integration_Simulator(t *testing.T)
func TestTPM2CertStorage_Integration_RealTPM(t *testing.T)
```

### Benchmark Tests

```go
func BenchmarkPKCS11CertStorage_SaveCert(b *testing.B)
func BenchmarkPKCS11CertStorage_GetCert(b *testing.B)

func BenchmarkTPM2CertStorage_SaveCert(b *testing.B)
func BenchmarkTPM2CertStorage_GetCert(b *testing.B)

func BenchmarkHybridCertStorage_Mixed(b *testing.B)
```

## Backward Compatibility

### Compatibility Matrix

| Existing Code | Hardware Storage Disabled | Hardware Storage Enabled |
|---------------|---------------------------|--------------------------|
| File-based cert storage | Works unchanged | Works unchanged |
| Memory-based cert storage | Works unchanged | Works unchanged |
| Custom cert storage | Works unchanged | Works unchanged |
| Direct backend usage | Works unchanged | ⚠️ Requires config update |

### Breaking Changes

**None**. All changes are opt-in via configuration.

### Deprecation Policy

No deprecations planned. External storage remains fully supported indefinitely.


## References

### Specifications

- [PKCS#11 v3.0 Specification](http://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html)
- [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [X.509 Certificate Standard (RFC 5280)](https://datatracker.ietf.org/doc/html/rfc5280)

### Related Documentation

- `/docs/storage-abstraction.md` - Storage interface design
- `/docs/backends/pkcs11.md` - PKCS#11 backend documentation
- `/docs/backends/tpm2.md` - TPM2 backend documentation
- `/docs/architecture/` - Overall architecture documentation

## Appendix A: PKCS#11 Certificate Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| CKA_CLASS | CK_OBJECT_CLASS | Must be CKO_CERTIFICATE |
| CKA_TOKEN | CK_BBOOL | TRUE for persistent storage |
| CKA_PRIVATE | CK_BBOOL | TRUE for access control |
| CKA_MODIFIABLE | CK_BBOOL | TRUE to allow updates |
| CKA_LABEL | CK_UTF8CHAR | Human-readable label |
| CKA_ID | CK_BYTE | Links to corresponding key |
| CKA_CERTIFICATE_TYPE | CK_CERTIFICATE_TYPE | CKC_X_509 |
| CKA_TRUSTED | CK_BBOOL | TRUE for trust anchors |
| CKA_SUBJECT | CK_BYTE | DER-encoded subject |
| CKA_ISSUER | CK_BYTE | DER-encoded issuer |
| CKA_SERIAL_NUMBER | CK_BYTE | Certificate serial number |
| CKA_VALUE | CK_BYTE | DER-encoded certificate |

## Appendix B: TPM2 NV Index Attributes

| Attribute | Value | Description |
|-----------|-------|-------------|
| TPMA_NV_PLATFORMCREATE | 0 | Not platform-created |
| TPMA_NV_AUTHREAD | 1 | Requires auth to read |
| TPMA_NV_AUTHWRITE | 1 | Requires auth to write |
| TPMA_NV_POLICYWRITE | 0 | No policy required |
| TPMA_NV_POLICYREAD | 0 | No policy required |
| TPMA_NV_NO_DA | 1 | Not DA-protected |
| TPMA_NV_ORDERLY | 0 | Not orderly |
| TPMA_NV_OWNERWRITE | 1 | Owner can write |
| TPMA_NV_OWNERREAD | 1 | Owner can read |

