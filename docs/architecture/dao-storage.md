# DAO Storage Architecture

This document covers the Data Access Object (DAO) pattern used across go-xkms for persistent entity storage, including entity design, indexing, and KVStore adapter chains.

## Entity Interface Pattern

All DAO-managed entities implement a simple interface:

```go
// Entity interface required by go-qrdb DAO
type Entity interface {
    EntityID() uint64
    SetEntityID(id uint64)
}
```

Entities are Go structs with JSON serialization tags and optional index tags:

```go
type PasswordEntity struct {
    ID         uint64    `json:"id"`
    Name       string    `json:"name" index:"unique,ci"`  // unique, case-insensitive
    FolderPath string    `json:"folder_path" index:"true"` // indexed for lookup
    CreatedAt  time.Time `json:"created_at"`
    UpdatedAt  time.Time `json:"updated_at"`
}

func (e *PasswordEntity) EntityID() uint64     { return e.ID }
func (e *PasswordEntity) SetEntityID(id uint64) { e.ID = id }
```

Index tag options:
- `index:"true"` - basic indexed field
- `index:"unique"` - unique constraint
- `index:"unique,ci"` - unique, case-insensitive

## GenericDAO Pattern

The DAO layer uses go-qrdb's `GenericDAO[T]` for type-safe persistence:

```go
// Create a DAO with deterministic ID generation
idGen := dao.NewFieldHashGenerator("Name")
pwDAO, err := dao.New[*PasswordEntity](
    kvStore,
    "passwords",  // namespace
    func() *PasswordEntity { return &PasswordEntity{} },
    dao.WithIDGenerator(idGen),
)

// Basic operations
entity, err := pwDAO.Get(ctx, entityID)
err = pwDAO.Save(ctx, entity)
err = pwDAO.Delete(ctx, entity)

// Pagination
result, err := pwDAO.Page(ctx, dao.PageQuery{Page: 1, PageSize: 100})

// Scan with callback
err = pwDAO.ForEachPage(ctx, query, func(result dao.PageResult[*PasswordEntity]) error {
    for _, entity := range result.Entities {
        // process
    }
    return nil
})
```

## KVStore Adapter Chain

Storage backends are wrapped through an adapter chain. The chain enables transparent encryption, indexing, and caching:

```
TenantBarrier (storage.Backend - encrypts with tenant DEK)
  -> kvadapter.KVStoreAdapter (bridges storage.Backend to kvstore.KVStore)
    -> GenericDAO[T] (typed entity persistence)
```

Example: creating a password store for a tenant:

```go
// Get the tenant's encrypted backend from barrier registry
tenantBackend, err := registry.GetTenantBarrier(tenantID)

// Wrap it in a KVStore adapter
kvStore, err := kvadapter.New(tenantBackend)

// Create the DAO store
pwStore, err := NewDAOStore(kvStore)
```

The `kvadapter.KVStoreAdapter` implements `kvstore.KVStore` by delegating to storage.Backend's Put/Get/Delete/Keys methods.

## Creating a New DAO Store

Step-by-step to add a new entity type:

1. **Define the entity struct:**
   ```go
   type MyEntity struct {
       ID        uint64    `json:"id"`
       Name      string    `json:"name" index:"unique"`
       CreatedAt time.Time `json:"created_at"`
       UpdatedAt time.Time `json:"updated_at"`
   }

   func (e *MyEntity) EntityID() uint64     { return e.ID }
   func (e *MyEntity) SetEntityID(id uint64) { e.ID = id }
   ```

2. **Create a Store interface:**
   ```go
   type Store interface {
       Create(ctx context.Context, item *MyEntity) error
       Get(ctx context.Context, id uint64) (*MyEntity, error)
       List(ctx context.Context) ([]*MyEntity, error)
       Delete(ctx context.Context, id uint64) error
       Close() error
   }
   ```

3. **Implement DAOStore:**
   ```go
   type DAOStore struct {
       closed atomic.Bool
       dao    dao.GenericDAO[*MyEntity]
   }

   func NewDAOStore(kvStore kvstore.KVStore) (*DAOStore, error) {
       daoInstance, err := dao.New[*MyEntity](
           kvStore,
           "my_entities",  // unique namespace
           func() *MyEntity { return &MyEntity{} },
       )
       if err != nil {
           return nil, err
       }
       return &DAOStore{dao: daoInstance}, nil
   }

   func (s *DAOStore) Create(ctx context.Context, item *MyEntity) error {
       if s.closed.Load() {
           return ErrStoreClosed
       }
       item.CreatedAt = time.Now()
       item.UpdatedAt = time.Now()
       return s.dao.Save(ctx, item)
   }

   func (s *DAOStore) Get(ctx context.Context, id uint64) (*MyEntity, error) {
       if s.closed.Load() {
           return nil, ErrStoreClosed
       }
       return s.dao.Get(ctx, id)
   }
   ```

## Migration from Old Stores to DAO

The old store pattern used simple put/get methods without proper indexing. DAO migration:

1. **Define entities** with proper index tags
2. **Create DAOStore** wrapper around the kvstore.KVStore
3. **Add data migration** if needed: scan old store, convert to entities, save via DAO
4. **Update handlers** to use the new Store interface

Example migration:

```go
// Old way (no indexing)
kvStore.Put(ctx, key, value)

// New way (indexed, searchable)
entity := &MyEntity{Name: "value"}
daoStore.Create(ctx, entity)

// Can now scan by index
daoStore.List(ctx)
```

## Multi-Tenant DAO Factory

For multi-tenant deployments, use `TenantDAOFactory`:

```go
factory, err := NewTenantDAOFactory(systemKVStore, barrierRegistry)

// Get per-tenant stores
pwStore, err := factory.PasswordStoreForTenant(tenantID)
teamStore, err := factory.TeamStoreForTenant(tenantID)

// Get system-level stores
sysPwStore, err := factory.SystemPasswordStore()
sysTeamStore, err := factory.SystemTeamStore()

// Invalidate tenant cache if barrier is re-sealed
factory.InvalidateTenant(tenantID)
```

The factory caches KVStore adapters per tenant using a lock-free `sync.Map` for efficient concurrent access.

## Best Practices

1. **Always close stores** - call `store.Close()` when done
2. **Use context.Background()** for non-request operations
3. **Handle ErrStoreClosed** - store can be closed asynchronously
4. **Index by usage patterns** - add `index:"true"` to fields used in lookups
5. **Validate before saving** - let the service layer handle validation
6. **Use transactions carefully** - some backends may not support them; use DAO callbacks instead
