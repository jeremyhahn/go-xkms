# Token Store

Unified JWT token storage for xkey. All tokens obtained from OIDC login, FIDO2 authentication, and bootstrap flows are persisted through a single interface, keyed by normalized server URL.

**Package:** `xkey/pkg/tokenstore/`

## Overview

The token store decouples token acquisition (OIDC, FIDO2, bootstrap) from token consumption (API Explorer, CLI commands). Tokens are stored as JSON entries keyed by normalized server URL (lowercase, trailing slash stripped), so `https://XKMS.Company.Com/` and `https://xkms.company.com` resolve to the same entry.

## API

### Types

| Type | Description |
|------|-------------|
| `TokenEntry` | JWT with metadata: ServerURL, TokenType, Source, Token, ExpiresAt, IssuedAt, Issuer, Subject |
| `TokenStore` | Persistence interface |
| `BackendTokenStore` | Barrier-encrypted persistence via `storage.Backend` |
| `MemoryTokenStore` | In-memory store for testing/ephemeral use |

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `SourceOIDC` | `"oidc"` | Token from OIDC login |
| `SourceFIDO2` | `"fido2"` | Token from FIDO2 authentication |
| `SourceBootstrap` | `"bootstrap"` | Token from bootstrap flow |
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

## Configuration

`BackendTokenStore` requires a `storage.Backend` and a key prefix. When the backend is backed by a barrier, all token data is encrypted at rest with AES-256-GCM.

```go
store, err := tokenstore.NewBackendTokenStore(barrierBackend, "tokens/")
// Storage keys: tokens/https_xkms_company_com_8443.json
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

## Cross-References

- [Barrier Architecture](../../docs/seal/tenant-barriers.md) - Encryption at rest
- [Server Registry](serverregistry.md) - Maps server URLs to CA fingerprints
- [API Explorer](api-explorer.md) - Automatic JWT injection from token store
