# DAO Integration

This document describes how go-xkms uses go-qrdb's DAO layer for typed entity persistence, the KVStore adapter that bridges the two systems, and the entity stores that have been migrated to use this pattern.

## Overview

go-xkms stores cryptographic material and metadata through its `storage.Backend` interface, a simple key-value abstraction over memory, file, PebbleDB, or external backends. While `storage.Backend` works well for raw bytes, it lacks typed entity operations such as auto-ID generation, pagination, and cross-store atomicity.

go-qrdb's `dao.GenericDAO` provides these features on top of any `kvstore.KVStore` implementation. The `kvadapter` package bridges the two interfaces, enabling go-xkms stores to use DAO-backed typed persistence without changing their underlying storage backend.

Three entity stores have been migrated to the DAO pattern:

| Store | Package | Entity | ID Strategy |
|-------|---------|--------|-------------|
| TPM2 BlobStore | `pkg/tpm2/store` | `BlobEntry` | `FieldHashGenerator("Name")` |
| SignerStore | `pkg/signing/store` | `SignerEntry`, `SignatureEntry` | `NewCryptoFieldHashGenerator("CN")` / `("Key")` |
| PIV certificate store | `pkg/pivcert/file` | `certEntity` | `NewCryptoFieldHashGenerator("Slot")` |

## KVStore Adapter (`pkg/storage/kvadapter`)

The `KVStoreAdapter` wraps a `storage.Backend` to satisfy `kvstore.KVStore`, the interface required by `dao.GenericDAO`.

```go
kvStore, err := kvadapter.New(backend)
```

### Semantic Differences Handled

The two interfaces have different error and iteration semantics. The adapter translates between them:

| Operation | storage.Backend | kvstore.KVStore | Adapter Behavior |
|-----------|-----------------|-----------------|------------------|
| Get (missing key) | returns `storage.ErrNotFound` | returns `qrdbsdk.QRDBError{Code: ErrNotFound}` | Wraps the error so `dao.IsNotFound()` works |
| Delete (missing key) | returns `storage.ErrNotFound` | returns `nil` (idempotent) | Swallows the not-found error |
| Scan | returns `map[string][]byte` | callback-based `func(key, value) error` | Sorts keys, iterates in order, calls callback per entry |

All adapter errors are typed (`PutError`, `GetError`, `DeleteError`, `ScanError`, `ListError`, `ExistsError`) and implement `Unwrap()` for error chain inspection.

### Guarded operations, and why the returned type varies

go-qrdb's DAO layer discovers the guarded operations — `PutIfAbsent`, `CompareAndDelete`, `CompareAndSwap` — by asserting `AtomicKVStore` on the store it was given, and fails closed when the assertion does not hold. The assertion is therefore the capability contract: a type that satisfies it is claiming all three work.

`kvadapter.New` returns `qrdbsdk.KVStore`, and the concrete type behind it depends on the wrapped backend:

| Wrapped backend | Returned store | Effect on a DAO |
|---|---|---|
| implements `CompareAndSwapper` **and** `CompareAndDeleter`, and reports its guarded writes available (the engine backends behind `NewMemory`/`NewFile`, and any of those behind `PrefixBackend`) | satisfies `AtomicKVStore` | guarded writes available |
| implements neither, or only one | satisfies `KVStore` only | the DAO takes its non-atomic path instead of failing at call time |
| implements both but reports them **unavailable** — the QRDB backends from `pkg/storage/qrdb`'s embedded constructors, whose transport carries no transaction service (#125) | satisfies `KVStore` only | same: the DAO does not take a guarded path that would fail on the first write |

Declaring the methods is not the same as being able to perform them, which is why the last row exists. `storage.GuardedWriteReporter` is the optional interface a backend implements to answer the question, and `storage.GuardedWritesUsable(b)` is how a caller asks: it requires both halves, the two guarded interfaces and the report. A backend that does not implement the reporter is taken at its word, so an in-process store needs no change.

`PrefixBackend` is the case that needs both halves. It declares `CompareAndSwap` and `CompareAndDelete` unconditionally — a decorator cannot add a method depending on what it wraps — and answers `ErrCompareAndSwapUnsupported` when the inner backend has neither, so its own method set says nothing about whether a guarded write will work. Its report is therefore the inner backend's usability, not merely the inner backend's availability.

The two contracts agree on the guard: `storage.CompareAndSwapper.CompareAndSwap`
and `kvstore.AtomicKVStore.CompareAndSwap` both refuse on an absent key
regardless of `expected` — a swap edits, it does not create, and a nil
`expected` is compared like any other value rather than read as "require
absent" (#186). A guarded create is `PutIfAbsent`, on the same interface, on
both sides.

One difference remains, in the return shape rather than the guard:

| Operation | `storage.Backend` | `kvstore.AtomicKVStore` | Adapter behaviour |
|---|---|---|---|
| `CompareAndSwap` return | `(swapped, current, error)` | `(swapped, error)` | The observed `current` value is dropped; a caller that needs it reads the store. |

So the adapter's `CompareAndSwap` is a straight delegation, the same shape
`CompareAndDelete` already had.

A decorator over a `KVStore` inherits this rule. `pkg/acme/storage/objstore`'s tenant-scoped wrapper namespaces keys and adds no writer of its own, so it forwards the three guarded operations under the prefixed key when the inner store offers them, and does not claim `AtomicKVStore` when the inner store does not.

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

### SignerStore (`pkg/signing/store`)

Persists `crypto.Signer` instances as PEM-encoded PKCS8 private keys, and signature records for integrity checks. `NewSignerStore(logger, daos)` takes the injected go-qrdb DAO factory and opens the `signing` database with two entity types: `signers` (ID = `NewCryptoFieldHashGenerator("CN")`) and `signatures` (ID = `NewCryptoFieldHashGenerator("Key")`). Lookups use `GetByNaturalKey`. See `docs/signing/`.

- Entities: `SignerEntry` (ID, CN, KeyPEM, Algorithm), `SignatureEntry` (ID, Key, Data)
- Operations: `Get(attrs)`, `Save(attrs, signer)`, `Delete(attrs)`, `SaveSignature(opts, sig, digest)`, `GetSignature(opts)`, `Checksum(opts)`
- Supports RSA, ECDSA, and Ed25519 key types with PKCS8/PKCS1/EC fallback parsing

### PIV certificate store (`pkg/pivcert/file`)

Persists the certificate in each PIV slot. `NewFileBackend(&pivcert.FileStorageConfig{DAOs: daos})` opens the `pivcert` database with one entity type, `piv_certificates` (ID = `NewCryptoFieldHashGenerator("Slot")`). Lookups use `GetByNaturalKey`; `Delete` is `DeleteIfMatch` and reports `ErrConflict` when the slot was replaced concurrently. See `docs/piv-smartcard/`.

- Entity: `certEntity` (ID, Slot, DER, StoredAt)
- Operations: `Store(slot, cert)`, `Retrieve(slot)`, `Delete(slot)`, `List()`, `Import`, `Export`

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
