# PIV Certificate Storage Architecture

## 1. Executive Summary

This document defines a comprehensive PIV (Personal Identity Verification) certificate storage abstraction for the xkey project. The architecture provides a pluggable certificate storage layer that operates independently from the existing key backend infrastructure while maintaining seamless integration.

**Key Design Principles:**
- Clean separation between key operations (handled by existing backends) and certificate storage (new abstraction)
- Default behavior follows the configured key backend storage mechanism
- Override capability via `--piv-storage` flag for mixed deployment scenarios
- Support for file system, TPM2 NV, and PKCS#11 token storage
- Thread-safe, production-ready implementations with comprehensive error handling
- Consistent with existing go-xkms architecture patterns

**Current State Acknowledgment:**
This design builds upon the existing backend infrastructure in go-xkms, which already provides:
- Key backend abstraction (`FIDO2KeyBackend` interface)
- Multiple storage implementations (software, TPM2)
- Storage interfaces (`storage.Backend`)
- Configuration management via Viper

## 2. Architecture Overview

The PIV certificate storage system consists of four primary layers:

```
┌─────────────────────────────────────────────────────────────┐
│                    xKey CLI Layer                            │
│  (piv commands with --backend and --piv-storage flags)     │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│              PIVCertificateStorageFactory                   │
│  (Creates appropriate storage based on configuration)       │
└─────────────────────────┬───────────────────────────────────┘
                          │
            ┌─────────────┴─────────────┐
            │                           │
┌───────────▼───────────┐   ┌──────────▼──────────┐
│ PIVCertificateStorage │   │   PIVSlotRegistry   │
│     Interface         │   │   (Slot validation) │
└───────────┬───────────┘   └─────────────────────┘
            │
    ┌───────┴────────┬──────────────┐
    │                │              │
┌───▼────┐     ┌─────▼─────┐  ┌────▼──────┐
│  File  │     │   TPM2    │  │  PKCS11   │
│Backend │     │  Backend  │  │  Backend  │
└────────┘     └───────────┘  └───────────┘
```

**Data Flow:**
1. User executes PIV command with optional `--piv-storage` override
2. Factory inspects configuration and creates appropriate storage backend
3. PIV operations route certificate requests to the storage implementation
4. Storage backend persists/retrieves certificates using its native mechanism
5. Key operations continue to use existing `FIDO2KeyBackend` implementations

**Storage Decision Logic:**
```
IF --piv-storage is set:
    USE specified storage type
ELSE:
    USE storage matching --backend value
```

## 3. Service Definitions

### Core Services

#### PIVCertificateStorageFactory
**Responsibility:** Create and configure certificate storage backends based on configuration.

**Operations:**
- Parse configuration to determine storage type
- Instantiate the appropriate backend implementation
- Validate configuration compatibility
- Manage backend lifecycle

#### PIVSlotRegistry
**Responsibility:** Validate PIV slot identifiers and provide metadata.

**Operations:**
- Validate slot identifiers (9a, 9c, 9d, 9e, etc.)
- Provide slot metadata (purpose, key type restrictions)
- Map slot IDs to storage keys
- Enumerate available slots

#### FileBackend
**Responsibility:** Store certificates in the file system.

**Operations:**
- Store certificates as PEM or DER files
- Organize by slot ID in configured directory
- Implement atomic write operations
- Handle file permissions (0600 for private data)

#### TPM2Backend
**Responsibility:** Store certificates in TPM NV (Non-Volatile) storage.

**Operations:**
- Allocate NV indices for each slot
- Write certificates to NV storage
- Read certificates from NV storage
- Manage NV index lifecycle

#### PKCS11Backend
**Responsibility:** Store certificates in PKCS#11 token storage.

**Operations:**
- Store certificates as PKCS#11 certificate objects
- Associate with corresponding keys
- Query token capacity
- Handle token session management

## 4. API Contracts

### PIVCertificateStorage Interface

```go
type PIVCertificateStorage interface {
    // Store stores a certificate for the given slot.
    //
    // Parameters:
    //   - slot: PIV slot identifier (e.g., "9a", "9c")
    //   - cert: X.509 certificate to store
    //
    // Returns:
    //   - error: ErrInvalidSlot, ErrStorageFull, ErrPermissionDenied
    Store(slot PIVSlot, cert *x509.Certificate) error

    // Retrieve retrieves the certificate for the given slot.
    //
    // Parameters:
    //   - slot: PIV slot identifier
    //
    // Returns:
    //   - *x509.Certificate: The stored certificate
    //   - error: ErrCertificateNotFound, ErrInvalidSlot
    Retrieve(slot PIVSlot) (*x509.Certificate, error)

    // Delete removes the certificate from the given slot.
    //
    // Parameters:
    //   - slot: PIV slot identifier
    //
    // Returns:
    //   - error: ErrCertificateNotFound, ErrInvalidSlot
    Delete(slot PIVSlot) error

    // List returns all slots that contain certificates.
    //
    // Returns:
    //   - []PIVSlotInfo: Slice of slot information
    //   - error: Any storage access error
    List() ([]PIVSlotInfo, error)

    // Import imports a certificate from external encoding.
    //
    // Parameters:
    //   - slot: PIV slot identifier
    //   - data: Certificate data (PEM or DER encoded)
    //   - format: Import format (FormatPEM or FormatDER)
    //
    // Returns:
    //   - error: ErrInvalidFormat, ErrInvalidSlot
    Import(slot PIVSlot, data []byte, format CertFormat) error

    // Export exports a certificate in the specified format.
    //
    // Parameters:
    //   - slot: PIV slot identifier
    //   - format: Export format (FormatPEM or FormatDER)
    //
    // Returns:
    //   - []byte: Encoded certificate data
    //   - error: ErrCertificateNotFound, ErrInvalidFormat
    Export(slot PIVSlot, format CertFormat) ([]byte, error)

    // Close releases any resources held by the storage.
    Close() error

    // Type returns the storage type identifier.
    Type() PIVStorageType
}
```

**Sample Request/Response Examples:**

**1. Store Certificate**
```go
// Request
slot := PIVSlotAuthentication // "9a"
cert := &x509.Certificate{ /* ... */ }
err := storage.Store(slot, cert)

// Success Response
// err == nil

// Error Response
// err = &PIVStorageError{
//     Op: "Store",
//     Slot: "9a",
//     Err: ErrStorageFull,
// }
```

**2. Retrieve Certificate**
```go
// Request
slot := PIVSlotAuthentication
cert, err := storage.Retrieve(slot)

// Success Response
// cert = &x509.Certificate{
//     Subject: pkix.Name{CommonName: "user@example.com"},
//     NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
//     ...
// }
// err == nil

// Error Response
// cert = nil
// err = ErrCertificateNotFound
```

**3. List Certificates**
```go
// Request
slots, err := storage.List()

// Success Response
// slots = []PIVSlotInfo{
//     {Slot: "9a", Subject: "CN=user@example.com", NotAfter: "2027-01-01"},
//     {Slot: "9c", Subject: "CN=admin@example.com", NotAfter: "2026-12-31"},
// }
// err == nil
```

**4. Export Certificate (PEM)**
```go
// Request
slot := PIVSlotAuthentication
data, err := storage.Export(slot, FormatPEM)

// Success Response
// data = []byte(`-----BEGIN CERTIFICATE-----
// MIICxzCCAa+gAwIBAgIUXxW...
// -----END CERTIFICATE-----`)
// err == nil
```

**5. Delete Certificate**
```go
// Request
slot := PIVSlotAuthentication
err := storage.Delete(slot)

// Success Response
// err == nil

// Error Response
// err = ErrCertificateNotFound
```

### Factory API

```go
// NewPIVCertificateStorage creates a certificate storage backend.
//
// Parameters:
//   - config: PIV configuration including storage type
//
// Returns:
//   - PIVCertificateStorage: Initialized storage backend
//   - error: Configuration or initialization errors
func NewPIVCertificateStorage(config *PIVConfig) (PIVCertificateStorage, error)
```

## 5. Data Schema

### File System Storage Schema

**Directory Structure:**
```
<storage_path>/piv/
├── certificates/
│   ├── 9a.der          # Authentication certificate (DER)
│   ├── 9a.pem          # Authentication certificate (PEM backup)
│   ├── 9c.der          # Digital signature certificate
│   ├── 9c.pem
│   ├── 9d.der          # Key management certificate
│   ├── 9d.pem
│   └── 9e.der          # Card authentication certificate
│       └── 9e.pem
├── metadata/
│   └── slots.json      # Slot metadata index
└── .lock               # File lock for atomic operations
```

**Metadata Schema (slots.json):**
```json
{
  "version": "1.0",
  "slots": {
    "9a": {
      "subject": "CN=user@example.com",
      "issuer": "CN=Corporate CA",
      "serial": "3a:4f:e2:1d:c9",
      "not_before": "2025-01-01T00:00:00Z",
      "not_after": "2027-01-01T00:00:00Z",
      "key_algorithm": "RSA",
      "stored_at": "2025-01-31T10:30:00Z"
    },
    "9c": {
      "subject": "CN=admin@example.com",
      "issuer": "CN=Corporate CA",
      "serial": "7b:2c:91:8a:f3",
      "not_before": "2025-01-15T00:00:00Z",
      "not_after": "2026-12-31T23:59:59Z",
      "key_algorithm": "ECDSA",
      "stored_at": "2025-01-31T11:15:00Z"
    }
  }
}
```

### TPM2 NV Storage Schema

**NV Index Allocation:**
```
Base Index: 0x01C00000 (NV_INDEX_FIRST)

Slot Mapping:
- 9a (Authentication):      0x01C00100
- 9c (Digital Signature):   0x01C00101
- 9d (Key Management):       0x01C00102
- 9e (Card Authentication): 0x01C00103
- 82-95 (Retired Keys):      0x01C00110 - 0x01C0011D

NV Attributes:
- TPMA_NV_AUTHWRITE   (requires authorization to write)
- TPMA_NV_AUTHREAD    (requires authorization to read)
- TPMA_NV_NO_DA       (not subject to dictionary attack)
- TPMA_NV_PLATFORMCREATE (platform-created NV)
```

**NV Index Structure:**
```
Each NV Index contains:
┌─────────────────────────────┐
│ Header (16 bytes)           │
│  - Magic: 0x50495643 (PIVC)│
│  - Version: uint16          │
│  - Length: uint16           │
│  - Reserved: 8 bytes        │
├─────────────────────────────┤
│ Certificate Data (DER)      │
│  - Variable length          │
│  - Max: 4096 bytes          │
└─────────────────────────────┘
```

### PKCS#11 Storage Schema

**Object Attributes:**
```
Certificate Object Template:
- CKA_CLASS:              CKO_CERTIFICATE
- CKA_CERTIFICATE_TYPE:   CKC_X_509
- CKA_TOKEN:              CK_TRUE (persistent)
- CKA_PRIVATE:            CK_FALSE (public object)
- CKA_LABEL:              "PIV Slot <slot_id>"
- CKA_ID:                 Slot-specific identifier
- CKA_VALUE:              DER-encoded certificate

Slot ID Mapping (CKA_ID):
- 9a: 0x9a
- 9c: 0x9c
- 9d: 0x9d
- 9e: 0x9e
```

## 6. Technology Stack Rationale

### Core Language: Go 1.21+

**Justification:**
- Consistent with existing go-xkms codebase
- Excellent concurrency primitives for thread-safe operations
- Strong standard library support for X.509 and cryptography
- Cross-platform compatibility

**Trade-offs:**
- **Alternative: Rust** - Would provide memory safety guarantees but introduce language fragmentation
- **Chosen Approach: Go** - Maintains codebase consistency and team expertise

### Storage Backend: Pluggable Architecture

**Justification:**
- Allows deployment flexibility (development vs. production)
- Supports mixed scenarios (keys in hardware, certs on filesystem)
- Future-proof for additional storage types

**Trade-offs:**
- **Alternative: Single Storage Type** - Simpler but less flexible
- **Chosen Approach: Pluggable** - Higher initial complexity, significantly better long-term flexibility

### File System Backend: Direct File I/O

**Justification:**
- Simple, reliable, and debuggable
- No external dependencies
- Portable across platforms
- Atomic operations via rename

**Trade-offs:**
- **Alternative: Database (SQLite)** - Better query capabilities but adds dependency
- **Chosen Approach: File I/O** - Minimal dependencies, sufficient for certificate storage

### TPM2 Backend: go-tpm Library

**Justification:**
- Official Google-maintained TPM2 library for Go
- Direct TPM2 API access
- Well-tested and production-ready

**Trade-offs:**
- **Alternative: tpm2-tools via exec** - More brittle, slower, harder to test
- **Chosen Approach: go-tpm** - Native Go, better error handling, testable

### PKCS#11 Backend: miekg/pkcs11 Wrapper

**Justification:**
- Mature, widely-used PKCS#11 binding for Go
- CGo-based interface to native PKCS#11 libraries
- Supports all major HSM vendors

**Trade-offs:**
- **Alternative: Custom PKCS#11 binding** - Full control but significant maintenance burden
- **Chosen Approach: miekg/pkcs11** - Battle-tested, community-supported

### Configuration: Viper

**Justification:**
- Already used in xkey for configuration management
- Supports file, environment, and flag-based configuration
- Consistent user experience

**Trade-offs:**
- **No reasonable alternative** given existing adoption

### Error Handling: Typed Errors

**Justification:**
- Follows Go best practices and project conventions
- Allows programmatic error handling
- Better debugging and logging

**Trade-offs:**
- **Alternative: String errors** - Simpler but harder to handle programmatically
- **Chosen Approach: Typed errors** - More verbose but significantly more maintainable

## 7. Key Considerations

### Scalability

**10x Load Handling:**

1. **Certificate Retrieval Operations:**
   - Current: Single certificate read from storage
   - 10x Load: Implement read-through cache with LRU eviction
   - Strategy: Cache parsed certificates in memory with TTL
   - Metric: Sub-millisecond cache hits, <10ms cache misses

2. **Concurrent Access:**
   - Current: File-based locking for filesystem backend
   - 10x Load: Lock-free reads with copy-on-write for updates
   - Strategy: Read-write mutex per slot for fine-grained locking
   - Metric: 1000+ concurrent reads/second per slot

3. **TPM2 NV Storage:**
   - Limitation: TPM NV storage is finite (~8KB typical)
   - Strategy: Store only active certificates, archive retired to filesystem
   - Fallback: Automatic spillover to file storage when NV full

4. **Storage Capacity:**
   - File: Unlimited (constrained by filesystem)
   - TPM2: 24 slots max (based on NV availability)
   - PKCS#11: Token-dependent (typically 32-128 objects)

### Security

**Threat Vectors and Mitigations:**

1. **Unauthorized Certificate Access:**
   - **Threat:** Attacker reads certificates from storage
   - **Mitigation:**
     - File backend: 0600 permissions (owner-only)
     - TPM2: AUTHREAD attribute requires TPM authorization
     - PKCS#11: PIN-protected token access
   - **Defense-in-Depth:** Encrypt file storage using platform key

2. **Certificate Substitution:**
   - **Threat:** Attacker replaces legitimate certificate with malicious one
   - **Mitigation:**
     - File backend: HMAC metadata with platform key
     - TPM2: AUTHWRITE attribute prevents unauthorized writes
     - PKCS#11: Token write protection
   - **Detection:** Certificate fingerprint validation on load

3. **Denial of Service:**
   - **Threat:** Storage exhaustion or lock contention
   - **Mitigation:**
     - Quota limits per slot (max certificate size: 4KB)
     - Timeout-based lock acquisition (5s max)
     - Rate limiting on storage operations

4. **Information Disclosure via Metadata:**
   - **Threat:** Metadata reveals sensitive information
   - **Mitigation:**
     - Minimal metadata storage (only required for indexing)
     - File permissions on metadata directory
   - **Alternative:** Store metadata in same protection domain as certificates

5. **Privilege Escalation:**
   - **Threat:** Non-privileged user accesses TPM/PKCS11 storage
   - **Mitigation:**
     - TPM: Platform hierarchy for NV index creation
     - PKCS#11: User PIN required for token access
     - File: Unix permissions and SELinux labels

### Observability

**Monitoring Strategy:**

1. **Structured Logging:**
   - Log Level: INFO for operations, DEBUG for details
   - Fields: operation, slot, storage_type, duration_ms, error
   - Format: JSON for machine parsing
   - Example:
     ```json
     {
       "timestamp": "2025-01-31T12:00:00Z",
       "level": "INFO",
       "operation": "certificate_store",
       "slot": "9a",
       "storage_type": "tpm2",
       "duration_ms": 45,
       "success": true
     }
     ```

2. **Metrics:**
   - Operation counters: `piv_cert_store_total{slot,storage_type,status}`
   - Operation latency: `piv_cert_operation_duration_ms{operation,storage_type}`
   - Storage utilization: `piv_cert_storage_used_slots{storage_type}`
   - Error rates: `piv_cert_errors_total{operation,error_type}`

3. **Health Checks:**
   - Storage connectivity: `piv_cert_storage_healthy{storage_type}`
   - Slot availability: `piv_cert_slots_available{storage_type}`
   - Last successful operation: `piv_cert_last_success_timestamp`

4. **Debugging Capabilities:**
   - Trace IDs for request correlation
   - Debug mode: Log certificate fingerprints (not full certs)
   - Storage dump command for diagnostics
   - Dry-run mode for testing configuration

5. **Audit Trail:**
   - Record all certificate modifications
   - Include: timestamp, operation, slot, user, source IP (if applicable)
   - Tamper-evident: Append-only log with checksums
   - Retention: 90 days minimum

### Deployment & CI/CD

**Deployment Strategy:**

1. **Build Process:**
   - Static binary compilation (CGo for PKCS#11 backend)
   - Cross-compilation targets: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64
   - Build-time flag: `-tags nopkcs11` to exclude PKCS#11 support
   - Artifact: Single `xkey` binary with all backends

2. **Configuration Management:**
   - Default: Config file at `~/.config/xkey/config.yaml`
   - Override: `--config` flag or `XKEY_CONFIG_FILE` env var
   - Validation: Startup config check with detailed error messages
   - Migration: Automatic config version upgrade

3. **Initialization:**
   - Storage initialization: `xkey piv init --storage <type>`
   - Pre-flight checks: Verify storage accessibility
   - Setup wizard: Interactive mode for first-time setup
   - Example:
     ```bash
     # Initialize file storage
     xkey piv init --storage file --path /var/lib/xkey/piv

     # Initialize TPM2 storage
     xkey piv init --storage tpm2 --tpm-device /dev/tpmrm0
     ```

4. **Testing Pipeline:**
   - Unit Tests: All backends with mocked dependencies
   - Integration Tests: File backend with temp directories
   - E2E Tests: Docker container with swtpm for TPM2 testing
   - Coverage Target: 90%+ per project conventions

5. **Continuous Integration:**
   ```yaml
   # .github/workflows/piv-cert-storage.yml
   name: PIV Certificate Storage
   on: [push, pull_request]
   jobs:
     test:
       runs-on: ubuntu-latest
       steps:
         - name: Unit Tests
           run: make test-piv-cert-storage
         - name: Integration Tests (File)
           run: make integration-test-piv-cert-storage-file
         - name: Integration Tests (TPM2)
           run: |
             # Start swtpm
             docker run -d --name swtpm ...
             make integration-test-piv-cert-storage-tpm2
         - name: Coverage Report
           run: make coverage-piv-cert-storage
   ```

6. **Deployment Patterns:**
   - **Development:** File storage with local paths
   - **CI/CD:** Memory-backed or tmpfs for ephemeral testing
   - **Production:** TPM2 or PKCS#11 for hardware-backed security
   - **Mixed:** Keys in TPM2, certificates on encrypted filesystem

7. **Rollback Strategy:**
   - Version in metadata schema for forward/backward compatibility
   - Backup before upgrade: `xkey piv backup --output piv-certs.tar`
   - Restore capability: `xkey piv restore --input piv-certs.tar`

---

## Interface Definitions (Go)

```go
// Package pivcert provides PIV certificate storage abstraction.
package pivcert

import (
    "crypto/x509"
    "io"
)

// PIVStorageType identifies the certificate storage backend type.
type PIVStorageType string

const (
    StorageTypeFile   PIVStorageType = "file"
    StorageTypeTPM2   PIVStorageType = "tpm2"
    StorageTypePKCS11 PIVStorageType = "pkcs11"
)

// PIVSlot represents a PIV certificate slot identifier.
type PIVSlot string

const (
    PIVSlotAuthentication     PIVSlot = "9a" // PIV Authentication
    PIVSlotDigitalSignature   PIVSlot = "9c" // Digital Signature
    PIVSlotKeyManagement      PIVSlot = "9d" // Key Management
    PIVSlotCardAuthentication PIVSlot = "9e" // Card Authentication
    // Retired key slots 82-95 omitted for brevity
)

// PIVSlotInfo contains metadata about a certificate slot.
type PIVSlotInfo struct {
    Slot      PIVSlot
    Subject   string
    Issuer    string
    NotBefore string
    NotAfter  string
    Algorithm string
}

// CertFormat specifies certificate encoding format.
type CertFormat int

const (
    FormatDER CertFormat = iota
    FormatPEM
)

// PIVCertificateStorage defines the interface for PIV certificate storage backends.
// All implementations must be safe for concurrent use.
type PIVCertificateStorage interface {
    // Store stores a certificate for the given slot.
    Store(slot PIVSlot, cert *x509.Certificate) error

    // Retrieve retrieves the certificate for the given slot.
    Retrieve(slot PIVSlot) (*x509.Certificate, error)

    // Delete removes the certificate from the given slot.
    Delete(slot PIVSlot) error

    // List returns all slots that contain certificates.
    List() ([]PIVSlotInfo, error)

    // Import imports a certificate from external encoding.
    Import(slot PIVSlot, data []byte, format CertFormat) error

    // Export exports a certificate in the specified format.
    Export(slot PIVSlot, format CertFormat) ([]byte, error)

    // Close releases any resources held by the storage.
    Close() error

    // Type returns the storage type identifier.
    Type() PIVStorageType
}

// PIVConfig contains configuration for PIV certificate storage.
type PIVConfig struct {
    // StorageType specifies the backend storage type.
    // If empty, defaults to the key backend type.
    StorageType PIVStorageType

    // FileConfig is used when StorageType is StorageTypeFile.
    FileConfig *FileStorageConfig

    // TPM2Config is used when StorageType is StorageTypeTPM2.
    TPM2Config *TPM2StorageConfig

    // PKCS11Config is used when StorageType is StorageTypePKCS11.
    PKCS11Config *PKCS11StorageConfig
}

// FileStorageConfig contains file backend configuration.
type FileStorageConfig struct {
    // BasePath is the root directory for certificate storage.
    BasePath string

    // DEREnabled controls whether DER files are written.
    DEREnabled bool

    // PEMEnabled controls whether PEM files are written.
    PEMEnabled bool
}

// TPM2StorageConfig contains TPM2 NV storage configuration.
type TPM2StorageConfig struct {
    // DevicePath is the path to the TPM device.
    DevicePath string

    // BaseIndex is the starting NV index for certificates.
    // Default: 0x01C00100
    BaseIndex uint32

    // OwnerAuth is the TPM owner authorization.
    OwnerAuth string
}

// PKCS11StorageConfig contains PKCS#11 storage configuration.
type PKCS11StorageConfig struct {
    // LibraryPath is the path to the PKCS#11 library.
    LibraryPath string

    // TokenLabel is the token label to use.
    TokenLabel string

    // PIN is the user PIN for the token.
    PIN string
}

// NewPIVCertificateStorage creates a certificate storage backend.
func NewPIVCertificateStorage(config *PIVConfig) (PIVCertificateStorage, error)

// PIVSlotRegistry provides slot metadata and validation.
type PIVSlotRegistry interface {
    // ValidateSlot checks if a slot identifier is valid.
    ValidateSlot(slot PIVSlot) error

    // GetSlotInfo returns metadata about a slot.
    GetSlotInfo(slot PIVSlot) (*SlotMetadata, error)

    // ListSlots returns all valid slot identifiers.
    ListSlots() []PIVSlot
}

// SlotMetadata contains information about a PIV slot.
type SlotMetadata struct {
    Slot        PIVSlot
    Name        string
    Description string
    KeyUsage    x509.KeyUsage
    MaxCertSize int
}

// FileBackend implements PIVCertificateStorage using the file system.
type FileBackend struct {
    basePath   string
    derEnabled bool
    pemEnabled bool
    mu         sync.RWMutex
}

// TPM2Backend implements PIVCertificateStorage using TPM2 NV storage.
type TPM2Backend struct {
    device    io.ReadWriteCloser
    baseIndex uint32
    ownerAuth string
    mu        sync.RWMutex
}

// PKCS11Backend implements PIVCertificateStorage using PKCS#11 tokens.
type PKCS11Backend struct {
    ctx        *pkcs11.Ctx
    session    pkcs11.SessionHandle
    tokenLabel string
    mu         sync.RWMutex
}
```

## Error Types

```go
// Errors
var (
    // ErrInvalidSlot indicates an invalid slot identifier.
    ErrInvalidSlot = errors.New("pivcert: invalid slot identifier")

    // ErrCertificateNotFound indicates no certificate exists in the slot.
    ErrCertificateNotFound = errors.New("pivcert: certificate not found")

    // ErrStorageFull indicates the storage backend is full.
    ErrStorageFull = errors.New("pivcert: storage full")

    // ErrPermissionDenied indicates insufficient permissions for operation.
    ErrPermissionDenied = errors.New("pivcert: permission denied")

    // ErrInvalidFormat indicates an invalid certificate format.
    ErrInvalidFormat = errors.New("pivcert: invalid certificate format")

    // ErrStorageClosed indicates the storage has been closed.
    ErrStorageClosed = errors.New("pivcert: storage closed")
)

// PIVStorageError wraps errors with operation context.
type PIVStorageError struct {
    Op   string   // Operation being performed
    Slot PIVSlot  // Slot involved
    Err  error    // Underlying error
}

func (e *PIVStorageError) Error() string {
    return fmt.Sprintf("pivcert: %s slot %s: %v", e.Op, e.Slot, e.Err)
}

func (e *PIVStorageError) Unwrap() error {
    return e.Err
}
```

## CLI Integration

```go
// Viper configuration keys
const (
    ConfigKeyPIVStorage     = "piv.storage"
    ConfigKeyPIVStoragePath = "piv.storage_path"
    ConfigKeyPIVTPMDevice   = "piv.tpm_device"
    ConfigKeyPIVPKCS11Lib   = "piv.pkcs11_library"
    ConfigKeyPIVPKCS11Token = "piv.pkcs11_token"
    ConfigKeyPIVPKCS11PIN   = "piv.pkcs11_pin"
)

// Example cobra command structure
var pivCertStoreCmd = &cobra.Command{
    Use:   "store <slot> <cert-file>",
    Short: "Store a certificate in a PIV slot",
    Args:  cobra.ExactArgs(2),
    RunE:  runPIVCertStore,
}

func runPIVCertStore(cmd *cobra.Command, args []string) error {
    slot := PIVSlot(args[0])
    certFile := args[1]

    // Load configuration
    config, err := loadPIVConfig()
    if err != nil {
        return err
    }

    // Create storage backend
    storage, err := NewPIVCertificateStorage(config)
    if err != nil {
        return err
    }
    defer storage.Close()

    // Read and parse certificate
    certData, err := os.ReadFile(certFile)
    if err != nil {
        return err
    }

    cert, err := parseCertificate(certData)
    if err != nil {
        return err
    }

    // Store certificate
    if err := storage.Store(slot, cert); err != nil {
        return err
    }

    fmt.Printf("Certificate stored in slot %s\n", slot)
    return nil
}

func loadPIVConfig() (*PIVConfig, error) {
    storageType := PIVStorageType(viper.GetString(ConfigKeyPIVStorage))

    // If no override, use key backend type
    if storageType == "" {
        keyBackend := viper.GetString("backend")
        storageType = PIVStorageType(keyBackend)
    }

    config := &PIVConfig{
        StorageType: storageType,
    }

    switch storageType {
    case StorageTypeFile:
        config.FileConfig = &FileStorageConfig{
            BasePath:   viper.GetString(ConfigKeyPIVStoragePath),
            DEREnabled: true,
            PEMEnabled: true,
        }
    case StorageTypeTPM2:
        config.TPM2Config = &TPM2StorageConfig{
            DevicePath: viper.GetString(ConfigKeyPIVTPMDevice),
            BaseIndex:  0x01C00100,
        }
    case StorageTypePKCS11:
        config.PKCS11Config = &PKCS11StorageConfig{
            LibraryPath: viper.GetString(ConfigKeyPIVPKCS11Lib),
            TokenLabel:  viper.GetString(ConfigKeyPIVPKCS11Token),
            PIN:         viper.GetString(ConfigKeyPIVPKCS11PIN),
        }
    default:
        return nil, fmt.Errorf("unsupported storage type: %s", storageType)
    }

    return config, nil
}
```

## Testing Strategy

```go
// Test suite structure

// Unit tests for each backend
func TestFileBackend_Store(t *testing.T) { /* ... */ }
func TestFileBackend_Retrieve(t *testing.T) { /* ... */ }
func TestFileBackend_Delete(t *testing.T) { /* ... */ }
func TestFileBackend_Concurrent(t *testing.T) { /* ... */ }

func TestTPM2Backend_Store(t *testing.T) { /* ... */ }
// TPM2 tests use swtpm or simulator

func TestPKCS11Backend_Store(t *testing.T) { /* ... */ }
// PKCS11 tests use SoftHSMv2

// Interface compliance tests
func TestBackendCompliance(t *testing.T) {
    backends := []PIVCertificateStorage{
        &FileBackend{ /* ... */ },
        &TPM2Backend{ /* ... */ },
        &PKCS11Backend{ /* ... */ },
    }

    for _, backend := range backends {
        t.Run(string(backend.Type()), func(t *testing.T) {
            testBackendOperations(t, backend)
        })
    }
}

// Integration tests
func TestCLI_PIVCertStore(t *testing.T) { /* ... */ }
func TestCLI_PIVCertRetrieve(t *testing.T) { /* ... */ }

// Benchmark tests
func BenchmarkFileBackend_Store(b *testing.B) { /* ... */ }
func BenchmarkTPM2Backend_Retrieve(b *testing.B) { /* ... */ }
```

---

**File Paths Referenced:**
- Interface definitions: `/home/jhahn/sources/go-xkms/pkg/pivcert/interface.go`
- File backend: `/home/jhahn/sources/go-xkms/pkg/pivcert/file/backend.go`
- TPM2 backend: `/home/jhahn/sources/go-xkms/pkg/pivcert/tpm2/backend.go`
- PKCS11 backend: `/home/jhahn/sources/go-xkms/pkg/pivcert/pkcs11/backend.go`
- Factory: `/home/jhahn/sources/go-xkms/pkg/pivcert/factory.go`
- CLI integration: `/home/jhahn/sources/go-xkms/cmd/xkey/cmd/piv_cert.go`
- Configuration: `/home/jhahn/sources/go-xkms/cmd/xkey/cmd/config.go` (updated)
- Tests: `/home/jhahn/sources/go-xkms/pkg/pivcert/*_test.go`

**Next Steps:**
1. Review and approve this architecture design
2. Create implementation plan with phased rollout
3. Begin with interface definitions and file backend
4. Add TPM2 backend with integration tests
5. Add PKCS11 backend
6. Update CLI commands and documentation
