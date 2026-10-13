# API Explorer

> **Status: REFERENCE** · Last verified: 2026-10-13
> Superseded background: the GUI feature folder, starting with [architecture.md](architecture.md), is normative.

GUI service for executing authenticated HTTP requests against xkms servers. Automatically injects JWT tokens from the Token Store.

**Package:** `xkey/pkg/gui/services/api_explorer_service.go`

## Overview

The API Explorer integrates the Token Store and Server Registry to provide a zero-configuration HTTP client for xkms APIs. When a request is sent, `Execute` (`api_explorer_service.go:237`):

1. Refuses the request when enterprise policy sets `api_explorer_enabled` to false (`requireExplorerEnabled`, `:210`)
2. Extracts the server base URL (scheme + host, lowercased)
3. Looks up a JWT from the Token Store and injects it as `Authorization: Bearer`
4. Looks up the server in the Registry; this is best-effort, a failure is only logged and the result is not applied to the request (`:294`)
5. Executes the request with a 30-second timeout
6. Records the request/response pair in the history store

User-visible failures (validation, network errors, the body limit) are returned in `ExplorerResponse.Error`; only system errors such as `ErrExplorerClosed` come back as Go errors.

## API

### Types

| Type | Description |
|------|-------------|
| `ExplorerRequest` | HTTP request: Method, URL, Headers, Body |
| `ExplorerResponse` | HTTP response: StatusCode, Status, Headers, Body, DurationMs, Error |
| `HistoryEntry` | Request/response pair with ID and timestamp |
| `AvailableToken` | A token offered to the frontend token picker (source `oidc`, `fido2` or a token-store source) |
| `ExplorerConfig` | Dependencies: Logger, TokenStore, Registry, TrustStore, HistoryStore, OIDCService, FIDO2Service |
| `APIExplorerService` | Service that executes and records requests |

### Valid HTTP Methods

`GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS` (`validMethods`, `api_explorer_service.go:53`)

### APIExplorerService Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `Execute` | `Execute(req) (*ExplorerResponse, error)` | Send HTTP request with auto JWT |
| `ListAvailableTokens` | `ListAvailableTokens() []AvailableToken` | Tokens from the token store, OIDC service and FIDO2 responses, sorted by source then label |
| `GetHistory` | `GetHistory() ([]*HistoryEntry, error)` | History sorted by timestamp (newest first) |
| `ClearHistory` | `ClearHistory() error` | Delete all history entries |
| `DeleteHistoryEntry` | `DeleteHistoryEntry(id) error` | Delete single history entry |
| `Close` | `Close() error` | Mark service closed (idempotent) |

## Configuration

```go
svc, err := services.NewAPIExplorerService(&services.ExplorerConfig{
    Logger:       logger,
    TokenStore:   tokenStore,      // JWT auto-injection
    Registry:     serverRegistry,  // server lookup
    TrustStore:   trustBackend,
    HistoryStore: historyBackend,  // request history
    OIDCService:  oidcService,     // optional: OIDC tokens for the picker
    FIDO2Service: fido2Service,    // optional: FIDO2 tokens for the picker
})
```

`TokenStore`, `Registry`, `TrustStore` and `HistoryStore` are required (`NewAPIExplorerService`, `api_explorer_service.go:154`).

### Limits

| Parameter | Value |
|-----------|-------|
| Response body max | 10 MB (`maxResponseBodySize`, `:43`) |
| HTTP timeout | 30 seconds (`defaultHTTPTimeout`, `:49`) |
| History key prefix | `api_explorer_history/` (`historyKeyPrefix`, `:46`) |

## Errors

Declared in `xkey/pkg/gui/services/api_explorer_errors.go`:

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
| `ErrExplorerTokenListFailed` | Listing available tokens failed |

## Cross-References

- [Token Store](../architecture/token-store.md) - Source of JWT tokens for auto-injection
- [Server Registry](../architecture/server-registry.md) - Server lookup
