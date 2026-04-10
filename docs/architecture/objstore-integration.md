# Storage Interface Compatibility with go-objstore

## Overview

go-xkms uses its own `storage.Backend` interface for all storage operations. This interface is intentionally designed to be **compatible** with external object storage libraries like [go-objstore](https://github.com/jeremyhahn/go-objstore), enabling higher-level applications to compose both libraries together.

**Key Design Principles:**
- go-xkms has **no direct dependency** on go-objstore
- go-xkms provides built-in file, memory, and PebbleDB storage backends
- The `storage.Backend` interface is simple and adapter-friendly
- Higher-level applications can create adapters to use any storage backend

## go-xkms Storage Interface

```go
// storage.Backend - go-xkms's storage abstraction
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

## go-objstore Storage Interface

```go
// common.Storage - go-objstore's storage abstraction
type Storage interface {
    GetWithContext(ctx context.Context, key string) (io.ReadCloser, error)
    PutWithContext(ctx context.Context, key string, data io.Reader) error
    DeleteWithContext(ctx context.Context, key string) error
    ListWithContext(ctx context.Context, prefix string) ([]string, error)
    ExistsWithContext(ctx context.Context, key string) (bool, error)
    Close() error
}
```

## Interface Compatibility

Both interfaces follow similar patterns:

| Operation | go-xkms | go-objstore |
|-----------|-------------|-------------|
| Read | `Get(ctx, key) ([]byte, error)` | `GetWithContext(ctx, key) (io.ReadCloser, error)` |
| Write | `Put(ctx, key, value) error` | `PutWithContext(ctx, key, reader) error` |
| Delete | `Delete(ctx, key) error` | `DeleteWithContext(ctx, key) error` |
| List | `List(ctx, prefix) ([]string, error)` | `ListWithContext(ctx, prefix) ([]string, error)` |
| Scan | `Scan(ctx, prefix) (map[string][]byte, error)` | N/A |
| Exists | `Exists(ctx, key) (bool, error)` | `ExistsWithContext(ctx, key) (bool, error)` |
| Close | `Close() error` | `Close() error` |

The main differences:
- go-xkms uses `[]byte` for data, go-objstore uses `io.Reader/io.ReadCloser`
- go-xkms includes `Scan` for bulk key-value retrieval
- Both include `context.Context` for cancellation and timeouts

## Creating an Adapter

A higher-level application can create an adapter to use go-objstore backends with go-xkms:

```go
package adapter

import (
    "bytes"
    "context"
    "io"

    "github.com/jeremyhahn/go-xkms/pkg/storage"
    "github.com/jeremyhahn/go-objstore/pkg/common"
)

// ObjStoreAdapter wraps go-objstore's Storage to implement go-xkms's Backend
type ObjStoreAdapter struct {
    store common.Storage
}

// NewObjStoreAdapter creates an adapter from a go-objstore backend
func NewObjStoreAdapter(store common.Storage) storage.Backend {
    return &ObjStoreAdapter{
        store: store,
    }
}

func (a *ObjStoreAdapter) Get(ctx context.Context, key string) ([]byte, error) {
    reader, err := a.store.GetWithContext(ctx, key)
    if err != nil {
        return nil, err
    }
    defer reader.Close()
    return io.ReadAll(reader)
}

func (a *ObjStoreAdapter) Put(ctx context.Context, key string, value []byte) error {
    return a.store.PutWithContext(ctx, key, bytes.NewReader(value))
}

func (a *ObjStoreAdapter) Delete(ctx context.Context, key string) error {
    return a.store.DeleteWithContext(ctx, key)
}

func (a *ObjStoreAdapter) List(ctx context.Context, prefix string) ([]string, error) {
    return a.store.ListWithContext(ctx, prefix)
}

func (a *ObjStoreAdapter) Scan(ctx context.Context, prefix string) (map[string][]byte, error) {
    keys, err := a.store.ListWithContext(ctx, prefix)
    if err != nil {
        return nil, err
    }
    result := make(map[string][]byte, len(keys))
    for _, key := range keys {
        data, err := a.Get(ctx, key)
        if err != nil {
            return nil, err
        }
        result[key] = data
    }
    return result, nil
}

func (a *ObjStoreAdapter) Exists(ctx context.Context, key string) (bool, error) {
    return a.store.ExistsWithContext(ctx, key)
}

func (a *ObjStoreAdapter) Close() error {
    return a.store.Close()
}
```

## Usage in Higher-Level Applications

### Example: Using S3 Storage with go-xkms

```go
package main

import (
    "github.com/jeremyhahn/go-xkms/pkg/xkms"
    "github.com/jeremyhahn/go-objstore/pkg/s3"

    "myapp/adapter" // Your adapter package
)

func main() {
    // Create go-objstore S3 backend
    s3Backend := s3.New()
    s3Backend.Configure(map[string]string{
        "region": "us-west-2",
        "bucket": "my-xkms-storage",
    })

    // Wrap with adapter to implement go-xkms's Backend interface
    storageBackend := adapter.NewObjStoreAdapter(s3Backend)

    // Use with go-xkms
    kc, err := xkms.New(&xkms.Config{
        Storage: storageBackend,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer kc.Close()

    // Now go-xkms stores everything in S3
}
```

### Example: Using Azure Blob Storage

```go
import (
    "github.com/jeremyhahn/go-objstore/pkg/azure"
)

// Create Azure backend
azureBackend := azure.New()
azureBackend.Configure(map[string]string{
    "account":   "myaccount",
    "container": "xkms-storage",
})

// Wrap with adapter
storageBackend := adapter.NewObjStoreAdapter(azureBackend)
```

### Example: Using Google Cloud Storage

```go
import (
    "github.com/jeremyhahn/go-objstore/pkg/gcs"
)

// Create GCS backend
gcsBackend := gcs.New()
gcsBackend.Configure(map[string]string{
    "project": "my-project",
    "bucket":  "xkms-storage",
})

// Wrap with adapter
storageBackend := adapter.NewObjStoreAdapter(gcsBackend)
```

## Built-in Storage Backends

go-xkms includes these storage backends out of the box:

### File Storage

```go
import "github.com/jeremyhahn/go-xkms/pkg/storage/file"

storage, err := file.New("/var/lib/xkms")
```

### Memory Storage

```go
import "github.com/jeremyhahn/go-xkms/pkg/storage"

storage := storage.NewMemory()
```

### PebbleDB Storage

```go
import "github.com/jeremyhahn/go-xkms/pkg/storage"

storage, err := storage.NewPebble("/var/lib/xkms/metadata")
```

## Benefits of This Architecture

1. **No Vendor Lock-in**: go-xkms doesn't depend on any specific storage library
2. **Flexibility**: Use any storage backend by implementing a simple adapter
3. **Simplicity**: go-xkms's interface is minimal and easy to implement
4. **Composability**: Higher-level applications choose their storage strategy
5. **Testability**: Use memory storage for tests, cloud storage for production

## go-objstore Backends

When using go-objstore through an adapter, these backends are available:

| Backend | Use Case |
|---------|----------|
| Local | Development, testing, local archives |
| Amazon S3 | AWS object storage |
| MinIO | Self-hosted S3-compatible storage |
| Google Cloud Storage | GCP object storage |
| Azure Blob Storage | Azure object storage |
| AWS Glacier | Long-term cold storage |
| Azure Archive | Long-term cold storage |

## See Also

- [Storage Architecture](./storage.md)
- [go-objstore Repository](https://github.com/jeremyhahn/go-objstore)
- [Getting Started Guide](../usage/getting-started.md)
