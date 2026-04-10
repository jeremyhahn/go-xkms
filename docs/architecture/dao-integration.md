# DAO Integration

This document describes how go-xkms uses go-qrdb's DAO layer for typed entity persistence, the KVStore adapter that bridges the two systems, and the entity stores that have been migrated to use this pattern.

## Overview

go-xkms stores cryptographic material and metadata through its `storage.Backend` interface, a simple key-value abstraction over memory, file, PebbleDB, or external backends. While `storage.Backend` works well for raw bytes, it lacks typed entity operations such as auto-ID generation, pagination, and cross-store atomicity.

go-qrdb's `dao.GenericDAO` provides these features on top of any `kvstore.KVStore` implementation. The `kvadapter` package bridges the two interfaces, enabling go-xkms stores to use DAO-backed typed persistence without changing their underlying storage backend.

Three entity stores have been migrated to the DAO pattern:

| Store | Package | Entity | ID Strategy |
|-------|---------|--------|-------------|
| TPM2 BlobStore | `pkg/tpm2/store` | `BlobEntry` | `FieldHashGenerator("Name")` |
| SignerStore | `pkg/tpm2/store` | `SignerEntry` | Custom `signerEntryIDGenerator` (xxhash64 of CN) |
| ShareStore | `pkg/sharestore` | `ShareEntry` | Custom `shareEntryIDGenerator` (xxhash64 of composite key) |

## KVStore Adapter (`pkg/storage/kvadapter`)

The `KVStoreAdapter` wraps a `storage.Backend` to satisfy `kvstore.KVStore`, the interface required by `dao.GenericDAO`.

```go
kvStore, err := kvadapter.New(backend)
```

### Semantic Differences Handled

The two interfaces have different error and iteration semantics. The adapter translates between them:

| Operation | storage.Backend | kvstore.KVStore | Adapter Behavior |
|-----------|-----------------|-----------------|------------------|
| Get (missing key) | returns `storage.ErrNotFound` | returns `dberrors.DragonError{Code: ErrNotFound}` | Wraps the error so `dao.IsNotFound()` works |
| Delete (missing key) | returns `storage.ErrNotFound` | returns `nil` (idempotent) | Swallows the not-found error |
| Scan | returns `map[string][]byte` | callback-based `func(key, value) error` | Sorts keys, iterates in order, calls callback per entry |

All adapter errors are typed (`PutError`, `GetError`, `DeleteError`, `ScanError`, `ListError`, `ExistsError`) and implement `Unwrap()` for error chain inspection.

## Entity Store Pattern

To create a DAO-backed entity store in go-xkms:

1. **Define an entity struct** implementing `dao.Entity`:

```go
type BlobEntry struct {
    ID   uint64 `json:"id"`
    Name string `json:"name"`
    Data []byte `json:"data"`
}

func (b *BlobEntry) EntityID() uint64      { return b.ID }
func (b *BlobEntry) SetEntityID(id uint64) { b.ID = id }
```

2. **Choose an ID generation strategy** (see below).

3. **Create the DAO** using the adapter:

```go
kvStore, err := kvadapter.New(backend)

blobDAO, err := dao.New[*BlobEntry](
    kvStore,
    "blobs",                                       // entity type namespace
    func() *BlobEntry { return &BlobEntry{} },     // zero-value factory
    dao.WithIDGenerator(dao.NewFieldHashGenerator("Name")),
)
```

4. **Use standard DAO operations** (`Save`, `Get`, `Delete`, `Page`, `ForEachPage`, `Count`).

### ID Generation Strategies

The DAO layer auto-generates an ID when `EntityID()` returns 0 during `Save`. go-xkms uses deterministic ID generators so entities can be looked up by their natural key without secondary indexes.

**FieldHashGenerator** -- Hashes a single struct field using xxhash64 64-bit. Used when the entity has one natural key field:

```go
dao.WithIDGenerator(dao.NewFieldHashGenerator("Name"))
```

**Custom IDGenerator** -- Implements `dao.IDGenerator` for composite keys or multi-entity support. The generator type-asserts the entity and hashes the appropriate fields:

```go
type shareEntryIDGenerator struct{}

func (g *shareEntryIDGenerator) NextID(entity dao.Entity) uint64 {
    entry, ok := entity.(*ShareEntry)
    if !ok {
        return 0
    }
    return xxhash.Sum64String(entry.CompositeKey()) // "serverURL/groupID/shareIndex"
}
```

Both approaches produce the same ID for the same input, enabling direct lookup by computing the hash at query time rather than scanning.

## Migrated Stores

### TPM2 BlobStore (`pkg/tpm2/store`)

Stores binary blobs (sealed secrets, TPM key blobs) by name. Uses `FieldHashGenerator("Name")` so that `Read("ek-cert")` computes the hash of `"ek-cert"` and performs a direct DAO `Get` without scanning.

- Entity: `BlobEntry` (ID, Name, Data)
- Operations: `Read(name)`, `Write(name, data)`, `Delete(name)`

### SignerStore (`pkg/tpm2/store`)

Persists `crypto.Signer` instances as PEM-encoded PKCS8 private keys. Uses a custom `signerEntryIDGenerator` that hashes the CN field, supporting both `SignerEntry` (signers) and `SignatureEntry` (audit signatures) through the same generator.

- Entity: `SignerEntry` (ID, CN, KeyPEM, Algorithm)
- Operations: `Get(attrs)`, `Save(attrs, signer)`, `Delete(attrs)`, `SaveSignature(opts, sig, digest)`
- Supports RSA, ECDSA, and Ed25519 key types with PKCS8/PKCS1/EC fallback parsing

### ShareStore (`pkg/sharestore`)

Persists Shamir secret shares with a composite key of `ServerURL/GroupID/ShareIndex`. Uses a custom `shareEntryIDGenerator` that hashes the composite key string.

- Entity: `ShareEntry` (ID, ServerURL, GroupID, ShareIndex, ShareData, Purpose, ReceivedAt, TenantID)
- Operations: `Save(entry)`, `Load(serverURL, groupID, shareIndex)`, `Delete(...)`, `List()`, `ListByServer(url)`, `ListByGroup(id)`
- Enforces uniqueness: `Save` checks for existing entries before writing
- Uses `atomic.Bool` for lock-free close state tracking

## UnitOfWork for Cross-Store Atomic Operations

When operations must span multiple DAOs atomically, the `dao.UnitOfWork` queues operations and commits them in a single batch with compensation-based rollback on failure.

```go
uow := dao.NewUnitOfWork(kvStore)

// Queue operations across different DAOs
dao.RegisterSave(uow, signerDAO, signerEntry)
dao.RegisterSave(uow, signatureDAO, signatureEntry)
dao.RegisterDelete(uow, oldEntryDAO, expiredEntry)

// Commit atomically -- rolls back on failure
err := uow.Commit(ctx)
```

On commit, the UnitOfWork snapshots existing values before each write. If any operation fails, it compensates already-applied operations in reverse order: saves restore the previous value (or delete the key if it did not exist), and deletes restore the previously read value.

Key properties:
- Operations apply in registration order
- 30-second default timeout (configurable via `WithUnitOfWorkTimeout`)
- Single-use: closed after `Commit` or `Rollback`
- Best-effort compensation (not two-phase commit)

## Stores Not Migrated (and Why)

**PlatformStore** (`pkg/tpm2/store`) -- Stores raw sealed secrets and platform-specific byte blobs that map directly to TPM NV indices and file paths. These are not structured entities with identifiable fields; they are opaque byte buffers whose storage key is determined by the caller. The existing `BlobStorer` abstraction is a better fit than DAO entity modeling.

**User Store** (`pkg/user`) -- Maintains a dual-index structure (by username and by user ID) with integrated session management and WebAuthn credential storage. The store has a working, well-tested implementation with complex query patterns (session expiry, credential lookup by handle) that do not map cleanly to single-entity DAO operations.

**StaticPassword Store** (`pkg/password`) -- Uses a hierarchical folder structure with multi-tenant scoping (`tenantID/folder/name`). Passwords are organized into user-defined folders, and the store supports recursive listing by folder prefix. This tree-structured access pattern is more naturally served by the existing `storage.Backend` prefix scan than by flat DAO entity persistence.

## See Also

- [Storage Architecture](./storage.md)
- [go-objstore Integration](./objstore-integration.md)
- [Adapter Framework](./adapter-framework.md)
