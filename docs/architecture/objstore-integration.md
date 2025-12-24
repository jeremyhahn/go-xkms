# Storage Interface Compatibility with go-objstore

## Overview

go-keychain uses its own `storage.Backend` interface for all storage operations. This interface is intentionally designed to be **compatible** with external object storage libraries like [go-objstore](https://github.com/jeremyhahn/go-objstore), enabling higher-level applications to compose both libraries together.

**Key Design Principles:**
- go-keychain has **no direct dependency** on go-objstore
- go-keychain provides built-in file and memory storage backends
- The `storage.Backend` interface is simple and adapter-friendly
- Higher-level applications can create adapters to use any storage backend

## go-keychain Storage Interface

```go
// storage.Backend - go-keychain's storage abstraction
type Backend interface {
    Get(key string) ([]byte, error)
    Put(key string, data []byte, opts *Options) error
    Delete(key string) error
    List(prefix string) ([]string, error)
    Exists(key string) (bool, error)
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

| Operation | go-keychain | go-objstore |
|-----------|-------------|-------------|
| Read | `Get(key) ([]byte, error)` | `GetWithContext(ctx, key) (io.ReadCloser, error)` |
| Write | `Put(key, data, opts) error` | `PutWithContext(ctx, key, reader) error` |
| Delete | `Delete(key) error` | `DeleteWithContext(ctx, key) error` |
| List | `List(prefix) ([]string, error)` | `ListWithContext(ctx, prefix) ([]string, error)` |
| Exists | `Exists(key) (bool, error)` | `ExistsWithContext(ctx, key) (bool, error)` |
| Close | `Close() error` | `Close() error` |

The main differences:
- go-keychain uses `[]byte` for data, go-objstore uses `io.Reader/io.ReadCloser`
- go-objstore includes `context.Context` for cancellation and timeouts
- go-keychain includes `Options` for permissions and metadata

## Creating an Adapter

A higher-level application can create an adapter to use go-objstore backends with go-keychain:

```go
package adapter

import (
    "bytes"
    "context"
    "io"

    "github.com/jeremyhahn/go-keychain/pkg/storage"
    "github.com/jeremyhahn/go-objstore/pkg/common"
)

// ObjStoreAdapter wraps go-objstore's Storage to implement go-keychain's Backend
type ObjStoreAdapter struct {
    store common.Storage
    ctx   context.Context
}

// NewObjStoreAdapter creates an adapter from a go-objstore backend
func NewObjStoreAdapter(store common.Storage) storage.Backend {
    return &ObjStoreAdapter{
        store: store,
        ctx:   context.Background(),
    }
}

// NewObjStoreAdapterWithContext creates an adapter with custom context
func NewObjStoreAdapterWithContext(store common.Storage, ctx context.Context) storage.Backend {
    return &ObjStoreAdapter{
        store: store,
        ctx:   ctx,
    }
}

func (a *ObjStoreAdapter) Get(key string) ([]byte, error) {
    reader, err := a.store.GetWithContext(a.ctx, key)
    if err != nil {
        return nil, err
    }
    defer reader.Close()
    return io.ReadAll(reader)
}

func (a *ObjStoreAdapter) Put(key string, data []byte, opts *storage.Options) error {
    return a.store.PutWithContext(a.ctx, key, bytes.NewReader(data))
}

func (a *ObjStoreAdapter) Delete(key string) error {
    return a.store.DeleteWithContext(a.ctx, key)
}

func (a *ObjStoreAdapter) List(prefix string) ([]string, error) {
    return a.store.ListWithContext(a.ctx, prefix)
}

func (a *ObjStoreAdapter) Exists(key string) (bool, error) {
    return a.store.ExistsWithContext(a.ctx, key)
}

func (a *ObjStoreAdapter) Close() error {
    return a.store.Close()
}
```

## Usage in Higher-Level Applications

### Example: Using S3 Storage with go-keychain

```go
package main

import (
    "github.com/jeremyhahn/go-keychain/pkg/keychain"
    "github.com/jeremyhahn/go-objstore/pkg/s3"

    "myapp/adapter" // Your adapter package
)

func main() {
    // Create go-objstore S3 backend
    s3Backend := s3.New()
    s3Backend.Configure(map[string]string{
        "region": "us-west-2",
        "bucket": "my-keychain-storage",
    })

    // Wrap with adapter to implement go-keychain's Backend interface
    storageBackend := adapter.NewObjStoreAdapter(s3Backend)

    // Use with go-keychain
    kc, err := keychain.New(&keychain.Config{
        Storage: storageBackend,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer kc.Close()

    // Now go-keychain stores everything in S3
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
    "container": "keychain-storage",
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
    "bucket":  "keychain-storage",
})

// Wrap with adapter
storageBackend := adapter.NewObjStoreAdapter(gcsBackend)
```

## Built-in Storage Backends

go-keychain includes these storage backends out of the box:

### File Storage

```go
import "github.com/jeremyhahn/go-keychain/pkg/storage/file"

storage, err := file.New("/var/lib/keychain")
```

### Memory Storage

```go
import "github.com/jeremyhahn/go-keychain/pkg/storage"

storage := storage.NewMemory()
```

## Benefits of This Architecture

1. **No Vendor Lock-in**: go-keychain doesn't depend on any specific storage library
2. **Flexibility**: Use any storage backend by implementing a simple adapter
3. **Simplicity**: go-keychain's interface is minimal and easy to implement
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
