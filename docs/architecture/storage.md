# Storage Architecture

This document describes the storage interfaces and abstraction layer in go-xkms.

## Consolidated Storage Layer

Canonical storage engines (file, memory, pebble, namespace) are now maintained in **go-qrdb** (`go-qrdb/pkg/storage/`). go-xkms imports these engines directly. A thin QRDB networked adapter at `pkg/storage/qrdb/` wraps the go-qrdb SDK client for distributed mode.

```yaml
storage:
  backend: memory    # memory | file | pebble
  path: /var/lib/xkms/metadata
```

Available constructors:

| Constructor | Description |
|-------------|-------------|
| `storage.New()` / `storage.NewMemory()` | In-memory storage |
| `file.New(path)` | File-based storage (go-xkms native) |
| `storage.NewFile(path)` | File storage via go-qrdb engine |
| `storage.NewPebble(path)` | PebbleDB storage via go-qrdb engine |
| `qrdb.NewMemory()` | go-qrdb in-memory engine |
| `qrdb.NewFile(path)` | go-qrdb file engine |
| `qrdb.NewPebble(path)` | go-qrdb PebbleDB engine |

## Overview

The storage abstraction layer provides pluggable persistence for xkms backends with the following benefits:

- **Flexibility**: Switch storage backends without changing xkms code
- **Testability**: Use memory storage for tests, file storage for production
- **Extensibility**: Implement custom storage backends (database, cloud, etc.)
- **Separation**: Keystore logic independent of persistence details
- **Compatibility**: Interface design compatible with external storage libraries

## Interface Hierarchy

```
+-----------------------------------------------------------------+
|          Application Layer                                       |
|  (Can create adapters for external storage like go-objstore)    |
+----------------------------+------------------------------------+
                             |
+----------------------------v------------------------------------+
|          General Storage                                         |
|          storage.Backend Interface                               |
|  - Get / Put / Delete / List / Scan / Exists                    |
|  - []byte based key-value storage                                |
|  - Built-in: File, Memory, PebbleDB implementations             |
+------------------------------------------------------------------+

+------------------------------------------------------------------+
|          TPM Blob Storage                                        |
|          BlobStorer Interface                                    |
|  - Read / Write / Delete                                         |
|  - []byte based (simple)                                         |
|  - TPM private/public blobs                                      |
+------------------------------------------------------------------+

+------------------------------------------------------------------+
|          Certificate Storage                                     |
|          CertStore Interface                                     |
|  - StoreCertificate / GetCertificate                             |
|  - Certificate chain management                                  |
|  - CRL operations                                                |
|  - Certificate verification                                      |
+------------------------------------------------------------------+
```

## Core Interfaces

### storage.Backend

General-purpose key-value storage abstraction. All methods accept a `context.Context` for cancellation and deadline propagation.

**Location**: `/home/jhahn/sources/go-xkms/pkg/storage/interface.go`

```go
type Backend interface {
    Get(ctx context.Context, key string) ([]byte, error)
    Put(ctx context.Context, key string, value []byte) error
    Delete(ctx context.Context, key string) error
    List(ctx context.Context, prefix string) ([]string, error)
    Scan(ctx context.Context, prefix string) (map[string][]byte, error)
    Exists(ctx context.Context, key string) (bool, error)
    Close() error
}
```

**Methods:**

| Method | Description |
|--------|-------------|
| `Get` | Retrieve a value by key |
| `Put` | Store a key-value pair |
| `Delete` | Remove a key-value pair |
| `List` | List keys matching a prefix (keys only) |
| `Scan` | Retrieve all key-value pairs matching a prefix |
| `Exists` | Check whether a key exists |
| `Close` | Release resources |

**Usage**:
- General-purpose storage
- File-based, in-memory, and PebbleDB implementations
- Foundation for higher-level storage

### BlobStorer (TPM2)

Store TPM binary blobs (private/public keys, contexts).

**Location**: `/home/jhahn/sources/go-xkms/pkg/tpm2/store/interfaces.go`

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

### CertStore

Comprehensive certificate management.

**Location**: `/home/jhahn/sources/go-xkms/pkg/certstore/certstore.go`

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

## Built-in Storage Backends

### File Storage

Persistent file-based storage using go-xkms's filesystem abstraction.

```go
import (
    "context"
    "github.com/jeremyhahn/go-xkms/pkg/storage/file"
)

ctx := context.Background()

// Create file storage
storage, err := file.New("/var/lib/xkms")
if err != nil {
    log.Fatal(err)
}
defer storage.Close()

// Store data
err = storage.Put(ctx, "my-key", []byte("key-data"))

// Retrieve data
data, err := storage.Get(ctx, "my-key")

// List keys
keys, err := storage.List(ctx, "")

// Scan all key-value pairs under a prefix
entries, err := storage.Scan(ctx, "my-prefix/")

// Check existence
exists, err := storage.Exists(ctx, "my-key")

// Delete key
err = storage.Delete(ctx, "my-key")
```

### Memory Storage

Ephemeral in-memory storage for testing.

```go
import (
    "context"
    "github.com/jeremyhahn/go-xkms/pkg/storage"
)

ctx := context.Background()

// Create memory storage
store := storage.NewMemory()
defer store.Close()

// Same API as file storage
store.Put(ctx, "test-key", []byte("test-data"))
data, _ := store.Get(ctx, "test-key")
```

### PebbleDB Storage

High-performance embedded key-value storage via the go-qrdb PebbleDB engine.

```go
import "github.com/jeremyhahn/go-xkms/pkg/storage"

store, err := storage.NewPebble("/var/lib/xkms/metadata")
```

## Custom Storage Backends

Implement the `Backend` interface for custom storage solutions:

```go
package custom

import (
    "context"
    "github.com/jeremyhahn/go-xkms/pkg/storage"
)

type CustomStorage struct {
    // Your implementation
}

func New() storage.Backend {
    return &CustomStorage{}
}

func (s *CustomStorage) Get(ctx context.Context, key string) ([]byte, error) {
    // Implement
    return nil, nil
}

func (s *CustomStorage) Put(ctx context.Context, key string, value []byte) error {
    // Implement
    return nil
}

func (s *CustomStorage) Delete(ctx context.Context, key string) error {
    // Implement
    return nil
}

func (s *CustomStorage) List(ctx context.Context, prefix string) ([]string, error) {
    // Implement
    return nil, nil
}

func (s *CustomStorage) Scan(ctx context.Context, prefix string) (map[string][]byte, error) {
    // Implement
    return nil, nil
}

func (s *CustomStorage) Exists(ctx context.Context, key string) (bool, error) {
    // Implement
    return false, nil
}

func (s *CustomStorage) Close() error {
    // Cleanup
    return nil
}
```

## Database Storage Example

```go
package database

import (
    "context"
    "database/sql"
    "github.com/jeremyhahn/go-xkms/pkg/storage"
)

type DBStorage struct {
    db *sql.DB
}

func New(connectionString string) (storage.Backend, error) {
    db, err := sql.Open("postgres", connectionString)
    if err != nil {
        return nil, err
    }
    return &DBStorage{db: db}, nil
}

func (s *DBStorage) Put(ctx context.Context, key string, data []byte) error {
    _, err := s.db.ExecContext(ctx,
        "INSERT INTO keys (key, data) VALUES ($1, $2) "+
        "ON CONFLICT (key) DO UPDATE SET data = $2",
        key, data,
    )
    return err
}

func (s *DBStorage) Get(ctx context.Context, key string) ([]byte, error) {
    var data []byte
    err := s.db.QueryRowContext(ctx,
        "SELECT data FROM keys WHERE key = $1",
        key,
    ).Scan(&data)
    return data, err
}

func (s *DBStorage) Delete(ctx context.Context, key string) error {
    _, err := s.db.ExecContext(ctx, "DELETE FROM keys WHERE key = $1", key)
    return err
}

func (s *DBStorage) List(ctx context.Context, prefix string) ([]string, error) {
    rows, err := s.db.QueryContext(ctx,
        "SELECT key FROM keys WHERE key LIKE $1",
        prefix+"%",
    )
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var keys []string
    for rows.Next() {
        var key string
        if err := rows.Scan(&key); err != nil {
            return nil, err
        }
        keys = append(keys, key)
    }
    return keys, rows.Err()
}

func (s *DBStorage) Scan(ctx context.Context, prefix string) (map[string][]byte, error) {
    rows, err := s.db.QueryContext(ctx,
        "SELECT key, data FROM keys WHERE key LIKE $1",
        prefix+"%",
    )
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    result := make(map[string][]byte)
    for rows.Next() {
        var key string
        var data []byte
        if err := rows.Scan(&key, &data); err != nil {
            return nil, err
        }
        result[key] = data
    }
    return result, rows.Err()
}

func (s *DBStorage) Exists(ctx context.Context, key string) (bool, error) {
    var exists bool
    err := s.db.QueryRowContext(ctx,
        "SELECT EXISTS(SELECT 1 FROM keys WHERE key = $1)",
        key,
    ).Scan(&exists)
    return exists, err
}

func (s *DBStorage) Close() error {
    return s.db.Close()
}
```

## External Storage Integration

go-xkms's `storage.Backend` interface is designed to be compatible with external object storage libraries. Higher-level applications can create adapters to use cloud storage backends.

See [Storage Interface Compatibility](./objstore-integration.md) for details on integrating with libraries like go-objstore.

## Thread Safety

Storage implementations must be thread-safe:

```go
type SafeStorage struct {
    mu   sync.RWMutex
    data map[string][]byte
}

func (s *SafeStorage) Put(ctx context.Context, key string, data []byte) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.data[key] = data
    return nil
}

func (s *SafeStorage) Get(ctx context.Context, key string) ([]byte, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    data, exists := s.data[key]
    if !exists {
        return nil, storage.ErrNotFound
    }
    return data, nil
}
```

## Error Handling

Standard errors:

```go
var (
    ErrNotFound       = errors.New("storage: key not found")
    ErrAlreadyExists  = errors.New("storage: key already exists")
    ErrInvalidKey     = errors.New("storage: invalid key")
)
```

Usage:

```go
data, err := storage.Get(ctx, "nonexistent-key")
if errors.Is(err, storage.ErrNotFound) {
    // Handle missing key
}
```

## Performance Characteristics

| Storage Type | Read Latency | Write Latency | Throughput | Use Case |
|-------------|--------------|---------------|------------|----------|
| Memory | ~10us | ~10us | Very High | Testing, cache |
| File (Local) | ~0.5ms | ~1ms | High | Production, local |
| File (SSD) | ~0.1ms | ~0.5ms | Very High | Production, high perf |
| PebbleDB | ~0.05ms | ~0.2ms | Very High | Production, high perf |
| Database | ~2-5ms | ~5-10ms | Medium | Multi-tenant, query |

## Interface Selection Guide

### Use storage.Backend When:
- Need general key-value storage
- Want simplest possible interface
- Building custom storage solutions
- Creating adapters for external storage

### Use BlobStorer When:
- Storing TPM binary blobs
- Need simple read/write/delete operations
- Working with TPM private/public keys

### Use CertStore When:
- Managing CA certificates
- Need certificate verification
- Handling certificate chains
- Working with CRLs
- Building PKI infrastructure

## Best Practices

### 1. Choose the Right Interface
- TPM blobs -> BlobStorer
- Certificates -> CertStore
- General data -> storage.Backend

### 2. Error Handling
```go
ctx := context.Background()
data, err := storage.Get(ctx, "key")
if err != nil {
    if errors.Is(err, storage.ErrNotFound) {
        // Handle missing key
    }
    return err
}
```

### 3. Use Scan for Bulk Reads
```go
// Efficient: single call to retrieve all entries under a prefix
entries, err := storage.Scan(ctx, "keys/")
for key, value := range entries {
    // Process each entry
}
```

### 4. Consider Caching for Read-Heavy Workloads
Implement a caching layer for frequently accessed data to reduce latency.

## See Also

- [Storage Interface Compatibility](./objstore-integration.md)
- [Getting Started Guide](../usage/getting-started.md)
- [Architecture Overview](./overview.md)
