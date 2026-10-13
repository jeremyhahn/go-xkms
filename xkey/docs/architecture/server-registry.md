# Server Registry

> **Status: REFERENCE** · Last verified: 2026-10-13
> The `serverregistry` package API; server trust and pinning are owned by the [platform-trust](../platform-trust/) feature folder.

Tracks registered xkms server connections and the pin each one is trusted by.

**Package:** `xkey/pkg/serverregistry/`

## Overview

When `xkey auth` registers an xkms server, the entry records its URL, protocol, and `CAFingerprint`. Later `xkey auth` commands pass that fingerprint as the SPKI pin of the client connection (`xkey/cmd/xkey/cmd/auth_session.go:136`, `auth_piv.go:177`), so a registered server is reached without manual certificate management.

```
Request URL -> ServerRegistry.Lookup(url) -> CAFingerprint -> SPKI pin -> TLS config
```

## API

### Types

| Type | Description |
|------|-------------|
| `ServerEntry` | Registered server: URL, Name, CAFingerprint, Protocol, RegisteredAt, LastConnectedAt (`types.go:30`) |
| `ServerRegistry` | Persistence interface (`types.go:48`) |
| `BackendServerRegistry` | Persistence via `xkms.StorageBackend`, used by the CLI (`backend_store.go:29`) |
| `DAOStore` | Persistence via a go-qrdb `GenericDAO` keyed by a hash of the URL (`dao_store.go:28`) |
| `MemoryServerRegistry` | In-memory store, used by the GUI (`memory_store.go:24`) |

### Protocol Constants

| Constant | Value |
|----------|-------|
| `ProtocolREST` | `"rest"` |
| `ProtocolGRPC` | `"grpc"` |
| `ProtocolQUIC` | `"quic"` |
| `ProtocolMCP` | `"mcp"` |

### ServerRegistry Interface

| Method | Signature | Description |
|--------|-----------|-------------|
| `Register` | `Register(ctx, entry) error` | Store new entry (fails if URL exists) |
| `Lookup` | `Lookup(ctx, url) (*ServerEntry, error)` | Retrieve entry by URL |
| `Update` | `Update(ctx, entry) error` | Modify existing entry (sets LastConnectedAt) |
| `List` | `List(ctx) ([]*ServerEntry, error)` | All entries sorted by URL |
| `Delete` | `Delete(ctx, url) error` | Remove entry by URL |
| `Close` | `Close() error` | Mark registry closed |

## Configuration

`BackendServerRegistry` requires an `xkms.StorageBackend` and a key prefix (`backend_store.go:42`). When backed by a barrier, server entries are encrypted at rest. `xkey auth` uses the prefix `servers/` (`xkey/cmd/xkey/cmd/auth.go:1146`). `DAOStore` is built with `NewDAOStore(kvStore)` (`dao_store.go:40`).

```go
registry, err := serverregistry.NewBackendServerRegistry(barrierBackend, "servers/")
// Storage keys: servers/https_kms.example.com_8443.json
```

### Automatic Timestamps

- `RegisteredAt` is set automatically on `Register()`
- `LastConnectedAt` is set automatically on `Update()`

## Errors

| Error | Description |
|-------|-------------|
| `ErrNilBackend` | Nil storage backend provided |
| `ErrNilKVStore` | Nil kvstore passed to `NewDAOStore` |
| `ErrStoreClosed` | Registry has been closed |
| `ErrServerNotFound` | No entry for the given URL |
| `ErrInvalidURL` | Empty server URL |
| `ErrNilEntry` | Nil server entry provided |
| `ErrServerExists` | URL already registered |
| `ErrDAOCreation` | `NewDAOStore` could not build the DAO |

Errors are declared in `xkey/pkg/serverregistry/errors.go:24-46`.

## Cross-References

- [Token Store](token-store.md) - Tokens keyed by server URL
- [Platform Trust](../platform-trust/) - Server trust and pinning
