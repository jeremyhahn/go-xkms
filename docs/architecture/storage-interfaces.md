# Storage Interface Guide for go-keychain

## Overview

This document describes the storage interfaces in go-keychain and their relationships with go-objstore.

## Interface Hierarchy

```
┌─────────────────────────────────────────────────────┐
│          go-objstore (Cloud Storage)                │
│          common.Storage Interface                    │
│  - GetWithContext / PutWithContext                  │
│  - io.Reader / io.ReadCloser based                  │
│  - S3, Azure, GCS, Local backends                   │
└──────────────────┬──────────────────────────────────┘
                   │
                   │ ObjStoreBlobAdapter
                   │ (Converts io.Reader ↔ []byte)
                   │
┌──────────────────▼──────────────────────────────────┐
│          TPM Blob Storage                           │
│          BlobStorer Interface                       │
│  - Read / Write / Delete                            │
│  - []byte based (simple)                            │
│  - TPM private/public blobs                         │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│          Certificate Storage                        │
│          CertStore Interface                        │
│  - StoreCertificate / GetCertificate               │
│  - Certificate chain management                     │
│  - CRL operations                                   │
│  - Certificate verification                         │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│          TPM Certificate Storage                    │
│          CertificateStorer Interface (TPM2)        │
│  - Get / Save / Delete                              │
│  - ImportCertificate                                │
│  - Works with KeyAttributes                         │
└─────────────────────────────────────────────────────┘
```

## Interface Details

### 1. BlobStorer (TPM2 Package)

**Purpose**: Store TPM binary blobs (private/public keys, contexts)

**Location**: `/home/jhahn/sources/go-keychain/pkg/tpm2/store/interfaces.go`

**Interface**:
```go
type BlobStorer interface {
    Read(name string) ([]byte, error)
    Write(name string, data []byte) error
    Delete(name string) error
}
```

**Usage**:
- TPM private key blobs (.blob files)
- TPM public key blobs (.pub files)
- TPM context files (.ctx files)

**Implementations**:
- `FSBlobStore`: Uses `storage.Backend`
- `ObjStoreBlobAdapter`: Bridges to `common.Storage` (NEW)

**go-objstore Integration**: ✅ Completed
- Adapter: `ObjStoreBlobAdapter`
- Build Tag: `objstore`
- Status: Tested, documented, production-ready

### 2. CertificateStorer (TPM2 Package)

**Purpose**: Store x509 certificates for TPM keys

**Location**: `/home/jhahn/sources/go-keychain/pkg/tpm2/store/interfaces.go`

**Interface**:
```go
type CertificateStorer interface {
    Get(attrs *types.KeyAttributes) (*x509.Certificate, error)
    Save(attrs *types.KeyAttributes, cert *x509.Certificate) error
    Delete(attrs *types.KeyAttributes) error
    ImportCertificate(attrs *types.KeyAttributes, certPEM []byte) (*x509.Certificate, error)
}
```

**Usage**:
- Endorsement Key (EK) certificates
- Attestation Key (AK) certificates
- IDevID certificates
- Application key certificates

**Key Characteristics**:
- Uses `KeyAttributes` for addressing
- Deals with TPM-specific certificates
- Simple CRUD operations
- No verification logic (handled by caller)

**go-objstore Integration**: ⚠️ Not needed
- Works with higher-level abstractions
- Uses certstore.CertStore underneath
- No direct benefit from object storage integration

### 3. CertStore (Certstore Package)

**Purpose**: Comprehensive certificate management

**Location**: `/home/jhahn/sources/go-keychain/pkg/certstore/certstore.go`

**Interface**:
```go
type CertStore interface {
    // Basic Operations
    StoreCertificate(cert *x509.Certificate) error
    GetCertificate(cn string) (*x509.Certificate, error)
    DeleteCertificate(cn string) error
    ListCertificates() ([]*x509.Certificate, error)

    // Chain Operations
    StoreCertificateChain(chain []*x509.Certificate) error
    GetCertificateChain(cn string) ([]*x509.Certificate, error)

    // CRL Operations
    StoreCRL(crl *x509.RevocationList) error
    GetCRL(issuer string) (*x509.RevocationList, error)

    // Verification
    VerifyCertificate(cert *x509.Certificate, roots *x509.CertPool) error
    IsRevoked(cert *x509.Certificate) (bool, error)

    // Lifecycle
    Close() error
}
```

**Usage**:
- CA certificate storage
- Trust chain management
- Certificate revocation checking
- Full PKI operations

**Implementations**:
- `FSCertStore`: Filesystem-based
- `CompositeCertStore`: Multiple backend composition

**go-objstore Integration**: ℹ️ Future enhancement
- Could benefit from cloud storage
- Would require more complex adapter
- Lower priority (less performance critical)

### 4. storage.Backend (Storage Package)

**Purpose**: General key-value storage abstraction

**Location**: `/home/jhahn/sources/go-keychain/pkg/storage/interface.go`

**Interface**:
```go
type Backend interface {
    Get(key string) ([]byte, error)
    Put(key string, value []byte, opts *Options) error
    Delete(key string) error
    List(prefix string) ([]string, error)
    Exists(key string) (bool, error)
    Close() error
}
```

**Usage**:
- General-purpose storage
- Currently used by `FSBlobStore`
- File-based and in-memory implementations

**Implementations**:
- Filesystem backend
- Memory backend (for testing)
- Namespace wrapper

**go-objstore Integration**: ✅ Via ObjStoreBlobAdapter
- Indirect integration through BlobStorer
- Maintains backward compatibility

### 5. common.Storage (go-objstore)

**Purpose**: Multi-backend object storage

**Location**: `/home/jhahn/sources/go-objstore/pkg/common/storage.go`

**Interface** (simplified):
```go
type Storage interface {
    LifecycleManager

    Configure(settings map[string]string) error

    Put(key string, data io.Reader) error
    PutWithContext(ctx context.Context, key string, data io.Reader) error
    PutWithMetadata(ctx context.Context, key string, data io.Reader, metadata *Metadata) error

    Get(key string) (io.ReadCloser, error)
    GetWithContext(ctx context.Context, key string) (io.ReadCloser, error)
    GetMetadata(ctx context.Context, key string) (*Metadata, error)

    Delete(key string) error
    DeleteWithContext(ctx context.Context, key string) error

    Exists(ctx context.Context, key string) (bool, error)
    List(prefix string) ([]string, error)
    ListWithContext(ctx context.Context, prefix string) ([]string, error)

    Archive(key string, destination Archiver) error
}
```

**Backends**:
- Local filesystem (`pkg/local`)
- Amazon S3 (`pkg/s3`)
- Azure Blob Storage (`pkg/azure`)
- Google Cloud Storage (`pkg/gcs`)
- MinIO (`pkg/minio`)
- AWS Glacier (`pkg/glacier`)

**Key Features**:
- Context support (timeout, cancellation)
- Metadata support
- Lifecycle policies
- Replication capabilities
- Archive support

## Integration Status

| Interface | go-objstore Integration | Status | Priority |
|-----------|------------------------|---------|----------|
| BlobStorer | ObjStoreBlobAdapter | ✅ Complete | High |
| CertificateStorer | Not needed | ⚠️ N/A | Low |
| CertStore | Potential future | ℹ️ Planned | Medium |
| storage.Backend | Via BlobStorer | ✅ Indirect | N/A |

## When to Use Each Interface

### Use BlobStorer When:
- Storing TPM binary blobs
- Need simple read/write/delete operations
- Working with TPM private/public keys
- Want cloud storage option (with ObjStoreBlobAdapter)

### Use CertificateStorer When:
- Storing TPM key certificates
- Working with KeyAttributes
- Need TPM-specific cert operations
- Building TPM2 applications

### Use CertStore When:
- Managing CA certificates
- Need certificate verification
- Handling certificate chains
- Working with CRLs
- Building PKI infrastructure

### Use storage.Backend When:
- Need general key-value storage
- Want simplest possible interface
- Don't need cloud storage
- Building custom storage solutions

### Use common.Storage When:
- Need cloud storage (S3, Azure, GCS)
- Require context support
- Want metadata capabilities
- Need replication/archival
- Building distributed systems

## Migration Patterns

### Pattern 1: Local to Cloud (BlobStorer)

**Before** (Local filesystem):
```go
import "github.com/jeremyhahn/go-keychain/pkg/storage"

backend := storage.NewFilesystemBackend(path)
blobStore := store.NewFSBlobStore(logger, backend)
```

**After** (Cloud storage):
```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
    "github.com/jeremyhahn/go-objstore/pkg/s3"
)

s3Backend := s3.New()
s3Backend.Configure(map[string]string{
    "region": "us-west-2",
    "bucket": "tpm-blobs",
})

blobStore := store.NewObjStoreBlobAdapter(logger, s3Backend)
```

### Pattern 2: Hybrid Storage

Use local for performance, cloud for backup:
```go
// Primary: Local storage
localBackend := local.New()
localBackend.Configure(map[string]string{"path": "/var/lib/tpm"})
primary := store.NewObjStoreBlobAdapter(logger, localBackend)

// Backup: S3 storage
s3Backend := s3.New()
s3Backend.Configure(map[string]string{"bucket": "tpm-backup"})
backup := store.NewObjStoreBlobAdapter(logger, s3Backend)

// Write to both
primary.Write("srk.blob", data)
backup.Write("srk.blob", data)
```

## Performance Comparison

| Interface | Read Latency | Write Latency | Throughput | Memory |
|-----------|--------------|---------------|------------|--------|
| BlobStorer (Local) | ~1ms | ~2ms | High | Low |
| BlobStorer (S3) | ~50-100ms | ~100-200ms | Medium | Low |
| BlobStorer (Azure) | ~50-100ms | ~100-200ms | Medium | Low |
| storage.Backend | ~1ms | ~2ms | High | Low |
| CertStore | ~2-5ms | ~5-10ms | Medium | Medium |

*Note: Network latencies vary by region and conditions*

## Best Practices

### 1. Choose the Right Interface
- TPM blobs → BlobStorer
- Certificates → CertStore or CertificateStorer
- General data → storage.Backend
- Cloud storage → common.Storage (via adapter)

### 2. Use Build Tags Appropriately
```bash
# Local development (no cloud)
go build ./...

# With cloud storage support
go build -tags=objstore ./...
```

### 3. Error Handling
```go
data, err := blobStore.Read("key.blob")
if err != nil {
    if errors.Is(err, storage.ErrNotFound) {
        // Handle missing blob
    }
    return err
}
```

### 4. Context Timeouts (Cloud Storage)
```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

blobStore := store.NewObjStoreBlobAdapterWithContext(logger, backend, ctx)
```

### 5. Batch Operations
```go
// Group related operations
for _, blob := range blobs {
    if err := blobStore.Write(blob.Name, blob.Data); err != nil {
        // Handle error
    }
}
```

## Testing Strategies

### Unit Tests
```go
// Use mock storage for fast tests
mockBackend := &MockStorage{}
blobStore := store.NewObjStoreBlobAdapter(logger, mockBackend)
```

### Integration Tests
```go
// Use real local backend
backend := local.New()
backend.Configure(map[string]string{"path": tempDir})
blobStore := store.NewObjStoreBlobAdapter(logger, backend)
```

### Cloud Integration Tests
```go
// Build with tag, test with real cloud backend
// go test -tags=objstore,integration ./...
s3Backend := s3.New()
// ... configure with test bucket
```

## Troubleshooting

### Import Errors
```bash
# If you see: "undefined: NewObjStoreBlobAdapter"
# Build with objstore tag:
go build -tags=objstore ./...
```

### Module Errors
```bash
# If you see: "no required module provides package"
go get github.com/jeremyhahn/go-objstore@latest
```

### Runtime Errors
```bash
# Enable debug logging
export TPM_LOG_LEVEL=debug

# Check backend configuration
# Verify paths, permissions, credentials
```

## References

- [ObjStore Adapter Documentation](pkg/tpm2/store/OBJSTORE_ADAPTER.md)
- [ObjStore Integration Summary](OBJSTORE_INTEGRATION.md)
- [go-objstore Repository](https://github.com/jeremyhahn/go-objstore)
- [BlobStorer Interface](pkg/tpm2/store/interfaces.go)
- [CertStore Interface](pkg/certstore/certstore.go)
- [storage.Backend Interface](pkg/storage/interface.go)
