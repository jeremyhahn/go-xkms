# Token Store

> **Status: REFERENCE** · Last verified: 2026-10-13
> The `tokenstore` package API for login tokens; cross-cutting, no feature folder.

Unified JWT token storage for xkey. All tokens obtained from OIDC, FIDO2, PIV and bootstrap logins are persisted through a single interface, keyed by normalized server URL.

**Package:** `xkey/pkg/tokenstore/`

## Overview

The token store decouples token acquisition (OIDC, FIDO2, bootstrap) from token consumption (API Explorer, CLI commands). Tokens are stored as JSON entries keyed by normalized server URL (lowercase, trailing slash stripped), so `https://KMS.Example.Com/` and `https://kms.example.com` resolve to the same entry (`xkey/pkg/tokenstore/dao_store.go:26`).

## API

### Types

| Type | Description |
|------|-------------|
| `TokenEntry` | JWT with metadata: ServerURL, TokenType, Source, Token, RefreshToken, ExpiresAt, IssuedAt, Issuer, Subject, ServerID, ServerName (`types.go:41`) |
| `TokenStore` | Persistence interface (`types.go:96`) |
| `DAOStore` | Persistence via a go-qrdb `GenericDAO` over a `qrdbsdk.KVStore` (`dao_store.go:43`) |
| `FileStore` | File-backed store opened by `Open(dir)` (`login.go:34`) |
| `MemoryTokenStore` | In-memory store for testing/ephemeral use (`memory_store.go:34`) |

`ServerID` is qrdb's SPKI SHA-256 thumbprint of the server's TLS leaf.
`LoginToken(ctx, store, ref)` (`login.go:77`) selects the newest login for a
server by `ServerID`, or by `ServerName` on a transport without TLS.

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `SourceOIDC` | `"oidc"` | Token from OIDC login |
| `SourceFIDO2` | `"fido2"` | Token from FIDO2 authentication |
| `SourceBootstrap` | `"bootstrap"` | Token from bootstrap flow |
| `SourcePIV` | `"piv"` | Token from PIV authentication |
| `TypeBearer` | `"bearer"` | Access token |
| `TypeRefresh` | `"refresh"` | Refresh token |

### TokenStore Interface

| Method | Signature | Description |
|--------|-----------|-------------|
| `Save` | `Save(ctx, entry) error` | Persist token keyed by server URL |
| `Load` | `Load(ctx, serverURL) (*TokenEntry, error)` | Retrieve token for server |
| `Delete` | `Delete(ctx, serverURL) error` | Remove token for server |
| `List` | `List(ctx) ([]*TokenEntry, error)` | All entries sorted by URL |
| `Close` | `Close() error` | Mark store closed (shared backend not closed) |

### TokenEntry Methods

| Method | Description |
|--------|-------------|
| `IsExpired()` | Returns true if token has expired (zero ExpiresAt = never expires) |
| `Validate()` | Checks required fields (ServerURL, Token) |
| `HasRefreshToken()` | Returns true if a refresh token is stored |

## Configuration

`DAOStore` requires a `qrdbsdk.KVStore` (built from a `storage.Backend` via `xkms.NewKVStoreAdapter`). When the backend is backed by a barrier, all token data is encrypted at rest. Construct the KV adapter and the DAO store directly:

```go
kvStore, err := xkms.NewKVStoreAdapter(barrierBackend)
store, err := tokenstore.NewDAOStore(kvStore)
```

### URL Normalization

All server URLs are normalized before storage:
1. Converted to lowercase
2. Trailing slash stripped

This ensures consistent key derivation regardless of how the URL is provided.

## Errors

| Error | Description |
|-------|-------------|
| `ErrNilBackend` | Nil storage backend provided |
| `ErrStoreClosed` | Store has been closed |
| `ErrTokenNotFound` | No token for the given URL |
| `ErrInvalidServer` | Empty server URL |
| `ErrNilEntry` | Nil token entry provided |
| `ErrTokenExpired` | Token has expired |
| `ErrInvalidDir` | Empty directory passed to `Open` |
| `ErrDAOCreation` | `NewDAOStore` could not build the DAO |

Errors are declared in `xkey/pkg/tokenstore/errors.go:22-87`.

## Cross-References

- [Barrier Architecture](../seal/architecture.md) - Encryption at rest
- [Server Registry](server-registry.md) - Maps server URLs to CA fingerprints
- [API Explorer](../gui/api-explorer.md) - Reads tokens from the store (`xkey/pkg/gui/services/api_explorer_service.go:133`)
