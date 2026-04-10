# Key Share Persistence

The `pkg/sharestore` package provides encrypted persistence for Shamir secret shares received from go-xkms servers. Shares are stored per server+group composite key and can be backed by a barrier-encrypted storage backend.

## Architecture

```
  xkey / CLI client
       |
  ShareStore interface
       |
  +----+----+
  |         |
  Backend   Memory
  Store     Store
  |
  storage.Backend (barrier-encrypted)
```

## ShareEntry

| Field | Type | Description |
|-------|------|-------------|
| `ServerURL` | `string` | xkms server the share came from |
| `GroupID` | `string` | Custodian group ID |
| `GroupName` | `string` | Human-readable group name |
| `ShareIndex` | `int` | 1-based index within the group |
| `ShareData` | `[]byte` | Raw share bytes |
| `Purpose` | `string` | `"barrier"`, `"signing-key"`, `"backup"` |
| `ReceivedAt` | `time.Time` | When the share was received |
| `TenantID` | `string` | Tenant scope (empty = system-level) |

Composite key: `ServerURL + "/" + GroupID`

## ShareStore Interface

| Method | Description |
|--------|-------------|
| `Save(ctx, entry)` | Stores a share; returns `ErrShareExists` if duplicate |
| `Load(ctx, serverURL, groupID)` | Retrieves a share by composite key |
| `Delete(ctx, serverURL, groupID)` | Removes a share |
| `List(ctx)` | Returns all shares (sorted by composite key) |
| `ListByServer(ctx, serverURL)` | Returns shares for a specific server |
| `Close()` | Closes the store |

## Implementations

### BackendShareStore

Production implementation backed by `storage.Backend`. When the backend is a barrier, all share data is encrypted at rest.

```go
store, _ := sharestore.NewBackendShareStore(barrier, "shares/")

store.Save(ctx, &sharestore.ShareEntry{
    ServerURL:  "https://xkms.company.com:8443",
    GroupID:    "barrier-custodians",
    ShareIndex: 1,
    ShareData:  shareBytes,
    Purpose:    "barrier",
})

entry, _ := store.Load(ctx, "https://xkms.company.com:8443", "barrier-custodians")
```

Storage keys are normalized from the server URL and group ID (e.g., `shares/https_xkms.company.com_8443_barrier-custodians.json`).

### MemoryShareStore

In-memory implementation for testing and ephemeral use. Same interface, no persistence.

## Error Reference

| Error | Condition |
|-------|-----------|
| `ErrShareNotFound` | No share for server+group |
| `ErrShareExists` | Share already stored for server+group |
| `ErrEmptyShare` | Share data is empty |
| `ErrInvalidServerURL` | Empty server URL |
| `ErrInvalidGroupID` | Empty group ID |
| `ErrNilBackend` | Nil storage backend |
| `ErrNilEntry` | Nil share entry |
| `ErrStoreClosed` | Operation on closed store |

## Cross-References

- [Custodian Groups](../custodian/README.md) -- server-side custodian and share management
- [Barrier Encryption Architecture](../seal/README.md) -- Shamir secret sharing, barrier unsealing
