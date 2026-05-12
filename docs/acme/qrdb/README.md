# QRDB Package

`pkg/qrdb` integrates go-trusted-ca with [QRDB](https://github.com/jeremyhahn/go-qrdb) for distributed key-value storage via the [go-qrdb SDK](https://github.com/jeremyhahn/go-qrdb/sdk/go). It wraps the SDK client behind a `Service` interface that exposes typed accessors for all QRDB subsystems.

## Purpose

QRDB serves as the persistence layer for all ACME server state: accounts, orders, authorizations, challenges, certificates, nonces, tenants, and external account bindings.

## Dependency Model

go-trusted-ca imports only from the go-qrdb SDK:

| Import Path | Alias | Provides |
|-------------|-------|----------|
| `github.com/jeremyhahn/go-qrdb/sdk/go` | `qrdbsdk` | `QRDBKVStore`, `NewDAO`, `QRDBGenericDAO`, `DatabaseError`, `ErrNotFound` |
| `github.com/jeremyhahn/go-qrdb/sdk/go/db` | `db` | `KVClient`, `AdminClient`, `SDKClient`, `NewClient`, `Transport`, `KeyNotFoundError` |

go-qrdb is the direct dependency for KV storage, RBAC, and cluster management.

## Service Interface

The `Service` interface provides access to seven QRDB subsystem clients:

| Method | Client Type | Purpose |
|--------|------------|---------|
| `KV()` | `db.KVClient` | Data-plane key-value CRUD and scan |
| `Admin()` | `db.AdminClient` | Control-plane cluster operations |
| `Watch()` | `db.WatchClient` | Event streaming on key changes |
| `Lease()` | `db.LeaseClient` | Distributed lease management |
| `Batch()` | `db.BatchClient` | Atomic batch operations |
| `Transaction()` | `db.TransactionClient` | Compare-and-swap transactions |
| `Index()` | `db.IndexClient` | Secondary index management |

Additional methods: `Config()`, `Healthy(ctx)`, `Close()`.

## Operating Modes

| Mode | Description |
|------|-------------|
| `standalone` | Single QRDB node, no Raft consensus |
| `raft` | Distributed replication via Raft consensus |

## Transport Protocols

| Protocol | Description |
|----------|-------------|
| `embedded` | In-process, no network overhead |
| `grpc` | Remote via gRPC |
| `rest` | Remote via HTTP/2 REST |
| `quic` | Remote via QUIC |
| `unix` | Local via Unix domain socket |
| `mcp` | Remote via MCP protocol |

## Construction

Use functional options to create a service:

```go
import (
    qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
    db "github.com/jeremyhahn/go-qrdb/sdk/go/db"
)

// With a pre-configured SDK client
svc, err := qrdb.New(
    qrdb.WithConfig(cfg),
    qrdb.WithQRDBClient(client), // db.SDKClient
)

// With a direct QRDBKVStore for embedded mode
svc, err := qrdb.New(
    qrdb.WithConfig(cfg),
    qrdb.WithKVStore(store), // qrdbsdk.QRDBKVStore
)
```

## Key Components

- **Service** (`service.go`) -- Production implementation wrapping `db.SDKClient` with atomic health/closed tracking.
- **KVStoreAdapter** (`kvstore_adapter.go`) -- Bridges `db.KVClient` to `qrdbsdk.QRDBKVStore` for DAO compatibility.
- **IAMPolicyStorage** (`iam_storage.go`) -- Implements `pkgiam.PolicyStorage` using QRDB KV. Build tag: `iam`.
- **DAO layer** (`dao/`) -- Factory pattern producing tenant-scoped DAOs for all ACME entities.

## Related Documentation

- [Architecture](architecture.md)
- [Configuration Reference](configuration.md)
