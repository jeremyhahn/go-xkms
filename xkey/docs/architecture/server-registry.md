# Server Registry

Tracks registered xkms server connections and their CA certificate fingerprints, enabling automatic TLS trust resolution via the Trust Store.

**Package:** `xkey/pkg/serverregistry/`

## Overview

When xkey connects to an xkms server, the server entry is recorded with its URL, protocol, and the SHA-256 fingerprint of its CA certificate. This fingerprint is used to look up the correct CA in the Trust Store, enabling automatic mTLS configuration without manual certificate management.

CA cert resolution chain:

```
Request URL -> ServerRegistry.Lookup(url) -> CAFingerprint -> Trust Store -> CA cert -> TLS config
```

## API

### Types

| Type | Description |
|------|-------------|
| `ServerEntry` | Registered server: URL, Name, CAFingerprint, Protocol, RegisteredAt, LastConnectedAt |
| `ServerRegistry` | Persistence interface |
| `BackendServerRegistry` | Barrier-encrypted persistence via `storage.Backend` |
| `MemoryServerRegistry` | In-memory store for testing/ephemeral use |

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

`BackendServerRegistry` requires a `storage.Backend` and a key prefix. When backed by a barrier, server entries are encrypted at rest.

```go
registry, err := serverregistry.NewBackendServerRegistry(barrierBackend, "servers/")
// Storage keys: servers/https_xkms_company_com_8443.json
```

### Automatic Timestamps

- `RegisteredAt` is set automatically on `Register()`
- `LastConnectedAt` is set automatically on `Update()`

## Errors

| Error | Description |
|-------|-------------|
| `ErrNilBackend` | Nil storage backend provided |
| `ErrStoreClosed` | Registry has been closed |
| `ErrServerNotFound` | No entry for the given URL |
| `ErrInvalidURL` | Empty server URL |
| `ErrNilEntry` | Nil server entry provided |
| `ErrServerExists` | URL already registered |

## Cross-References

- [Token Store](tokenstore.md) - JWT tokens keyed by server URL
- [API Explorer](api-explorer.md) - Uses registry for TLS resolution
- [Trust Store](gui/README.md) - CA certificate storage
