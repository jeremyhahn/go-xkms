# Storage Architecture

This document describes the storage interfaces and abstraction layer in go-keychain.

## Overview

The storage abstraction layer provides pluggable persistence for keychain backends with the following benefits:

- **Flexibility**: Switch storage backends without changing keychain code
- **Testability**: Use memory storage for tests, file storage for production
- **Extensibility**: Implement custom storage backends (database, cloud, etc.)
- **Separation**: Keystore logic independent of persistence details
- **Compatibility**: Interface design compatible with external storage libraries

## Interface Hierarchy

```
┌─────────────────────────────────────────────────────────────┐
│          Application Layer                                   │
│  (Can create adapters for external storage like go-objstore)│
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│          General Storage                                     │
│          storage.Backend Interface                           │
│  - Get / Put / Delete / List / Exists                        │
│  - []byte based key-value storage                            │
│  - Built-in: File and Memory implementations                 │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│          TPM Blob Storage                                    │
│          BlobStorer Interface                                │
│  - Read / Write / Delete                                     │
│  - []byte based (simple)                                     │
│  - TPM private/public blobs                                  │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│          Certificate Storage                                 │
│          CertStore Interface                                 │
│  - StoreCertificate / GetCertificate                         │
│  - Certificate chain management                              │
│  - CRL operations                                            │
│  - Certificate verification                                  │
└─────────────────────────────────────────────────────────────┘
```

## Core Interfaces

### storage.Backend

General-purpose key-value storage abstraction.

**Location**: `/home/jhahn/sources/go-keychain/pkg/storage/interface.go`

```go
type Backend interface {
    Get(key string) ([]byte, error)
    Put(key string, data []byte, opts *Options) error
    Delete(key string) error
    List(prefix string) ([]string, error)
    Exists(key string) (bool, error)
    Close() error
}
```

**Usage**:
- General-purpose storage
- File-based and in-memory implementations
- Foundation for higher-level storage

### BlobStorer (TPM2)

Store TPM binary blobs (private/public keys, contexts).

**Location**: `/home/jhahn/sources/go-keychain/pkg/tpm2/store/interfaces.go`

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

**Location**: `/home/jhahn/sources/go-keychain/pkg/certstore/certstore.go`

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

Persistent file-based storage using go-keychain's filesystem abstraction.

```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
)

// Create file storage
storage, err := file.New("/var/lib/keychain")
if err != nil {
    log.Fatal(err)
}
defer storage.Close()

// Store data
err = storage.Put("my-key", []byte("key-data"), nil)

// Store with custom permissions
err = storage.Put("secure-key", []byte("data"), &storage.Options{
    Permissions: 0600,
})

// Retrieve data
data, err := storage.Get("my-key")

// List keys
keys, err := storage.List("")

// Check existence
exists, err := storage.Exists("my-key")

// Delete key
err = storage.Delete("my-key")
```

### Memory Storage

Ephemeral in-memory storage for testing.

```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/storage"
)

// Create memory storage
storage := storage.NewMemory()
defer storage.Close()

// Same API as file storage
storage.Put("test-key", []byte("test-data"), nil)
data, _ := storage.Get("test-key")
```

## Custom Storage Backends

Implement the `Backend` interface for custom storage solutions:

```go
package custom

import "github.com/jeremyhahn/go-keychain/pkg/storage"

type CustomStorage struct {
    // Your implementation
}

func New() storage.Backend {
    return &CustomStorage{}
}

func (s *CustomStorage) Get(key string) ([]byte, error) {
    // Implement
    return nil, nil
}

func (s *CustomStorage) Put(key string, data []byte, opts *storage.Options) error {
    // Implement
    return nil
}

func (s *CustomStorage) Delete(key string) error {
    // Implement
    return nil
}

func (s *CustomStorage) List(prefix string) ([]string, error) {
    // Implement
    return nil, nil
}

func (s *CustomStorage) Exists(key string) (bool, error) {
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
    "database/sql"
    "github.com/jeremyhahn/go-keychain/pkg/storage"
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

func (s *DBStorage) Put(key string, data []byte, opts *storage.Options) error {
    _, err := s.db.Exec(
        "INSERT INTO keys (key, data) VALUES ($1, $2) "+
        "ON CONFLICT (key) DO UPDATE SET data = $2",
        key, data,
    )
    return err
}

func (s *DBStorage) Get(key string) ([]byte, error) {
    var data []byte
    err := s.db.QueryRow(
        "SELECT data FROM keys WHERE key = $1",
        key,
    ).Scan(&data)
    return data, err
}

func (s *DBStorage) Delete(key string) error {
    _, err := s.db.Exec("DELETE FROM keys WHERE key = $1", key)
    return err
}

func (s *DBStorage) List(prefix string) ([]string, error) {
    rows, err := s.db.Query(
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

func (s *DBStorage) Exists(key string) (bool, error) {
    var exists bool
    err := s.db.QueryRow(
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

go-keychain's `storage.Backend` interface is designed to be compatible with external object storage libraries. Higher-level applications can create adapters to use cloud storage backends.

See [Storage Interface Compatibility](./objstore-integration.md) for details on integrating with libraries like go-objstore.

## Thread Safety

Storage implementations must be thread-safe:

```go
type SafeStorage struct {
    mu   sync.RWMutex
    data map[string][]byte
}

func (s *SafeStorage) Put(key string, data []byte, opts *storage.Options) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.data[key] = data
    return nil
}

func (s *SafeStorage) Get(key string) ([]byte, error) {
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
data, err := storage.Get("nonexistent-key")
if errors.Is(err, storage.ErrNotFound) {
    // Handle missing key
}
```

## Performance Characteristics

| Storage Type | Read Latency | Write Latency | Throughput | Use Case |
|-------------|--------------|---------------|------------|----------|
| Memory | ~10µs | ~10µs | Very High | Testing, cache |
| File (Local) | ~0.5ms | ~1ms | High | Production, local |
| File (SSD) | ~0.1ms | ~0.5ms | Very High | Production, high perf |
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
- TPM blobs → BlobStorer
- Certificates → CertStore
- General data → storage.Backend

### 2. Error Handling
```go
data, err := storage.Get("key")
if err != nil {
    if errors.Is(err, storage.ErrNotFound) {
        // Handle missing key
    }
    return err
}
```

### 3. Use Buffering for Bulk Operations
```go
for _, item := range items {
    if err := storage.Put(item.Key, item.Data, nil); err != nil {
        // Handle error
    }
}
```

### 4. Consider Caching for Read-Heavy Workloads
Implement a caching layer for frequently accessed data to reduce latency.

## See Also

- [Storage Interface Compatibility](./objstore-integration.md)
- [Getting Started Guide](../usage/getting-started.md)
- [Architecture Overview](./overview.md)
