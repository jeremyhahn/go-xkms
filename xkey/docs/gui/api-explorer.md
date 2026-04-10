# API Explorer

GUI service for executing authenticated HTTP requests against xkms servers. Automatically injects JWT tokens and resolves TLS configuration.

**Package:** `xkey/pkg/gui/services/api_explorer_service.go`

## Overview

The API Explorer integrates the Token Store and Server Registry to provide a zero-configuration HTTP client for xkms APIs. When a request is sent, the service:

1. Extracts the server base URL (scheme + host)
2. Looks up a JWT from the Token Store and injects it as `Authorization: Bearer`
3. Looks up the server entry in the Registry for TLS configuration
4. Executes the request with a 30-second timeout
5. Records the request/response pair in barrier-encrypted history

## API

### Types

| Type | Description |
|------|-------------|
| `ExplorerRequest` | HTTP request: Method, URL, Headers, Body |
| `ExplorerResponse` | HTTP response: StatusCode, Status, Headers, Body, DurationMs, Error |
| `HistoryEntry` | Request/response pair with ID and timestamp |
| `ExplorerConfig` | Dependencies: Logger, TokenStore, Registry, TrustStore, HistoryStore |
| `APIExplorerService` | Service that executes and records requests |

### Valid HTTP Methods

`GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS`

### APIExplorerService Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `Execute` | `Execute(ctx, req) (*ExplorerResponse, error)` | Send HTTP request with auto JWT/TLS |
| `GetHistory` | `GetHistory(ctx) ([]*HistoryEntry, error)` | History sorted by timestamp (newest first) |
| `ClearHistory` | `ClearHistory(ctx) error` | Delete all history entries |
| `DeleteHistoryEntry` | `DeleteHistoryEntry(ctx, id) error` | Delete single history entry |
| `Close` | `Close() error` | Mark service closed (idempotent) |

## Configuration

```go
svc, err := services.NewAPIExplorerService(&services.ExplorerConfig{
    Logger:       logger,
    TokenStore:   tokenStore,      // JWT auto-injection
    Registry:     serverRegistry,  // TLS resolution
    TrustStore:   trustBackend,    // CA certificate lookup
    HistoryStore: historyBackend,  // barrier-encrypted history
})
```

### Limits

| Parameter | Value |
|-----------|-------|
| Response body max | 10 MB |
| HTTP timeout | 30 seconds |
| History key prefix | `api_explorer_history/` |

## Errors

| Error | Description |
|-------|-------------|
| `ErrExplorerNilConfig` | Nil configuration |
| `ErrExplorerClosed` | Service closed |
| `ErrExplorerInvalidURL` | Empty or malformed URL |
| `ErrExplorerInvalidMethod` | Unrecognized HTTP method |
| `ErrExplorerRequestFailed` | HTTP execution failed |
| `ErrExplorerBodyTooLarge` | Response exceeds 10 MB |
| `ErrExplorerHistoryNotFound` | History entry not found |
| `ErrExplorerNilTokenStore` | Nil token store dependency |
| `ErrExplorerNilRegistry` | Nil server registry dependency |
| `ErrExplorerNilTrustStore` | Nil trust store dependency |
| `ErrExplorerNilHistoryStore` | Nil history store dependency |
| `ErrExplorerInvalidRequest` | Nil or invalid request |

## Cross-References

- [Token Store](tokenstore.md) - Source of JWT tokens for auto-injection
- [Server Registry](serverregistry.md) - Server lookup for TLS configuration
