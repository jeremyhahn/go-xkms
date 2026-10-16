# Datastore — Engineering Contract

> **Status: NORMATIVE** · Feature: `datastore` · Repo: `go-xkms` · Last verified: 2026-10-12

## Exported surface

### `pkg/storage` — the interface every subsystem programs against

```go
type Backend interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Put(ctx context.Context, key string, value []byte) error
	PutIfAbsent(ctx context.Context, key string, value []byte) (stored bool, err error)
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, prefix string) ([]string, error)
	Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error
	Exists(ctx context.Context, key string) (bool, error)
	Close() error
}
```

(`pkg/storage/interface.go`.) `Put` implementations **must not retain** the
value slice past the call — secret key material stored through this
interface is wiped by the caller immediately after a successful `Put`, and
an implementation that aliased the slice would have it zeroed out from under
it.

Guarded writes are **optional capabilities**, not methods on `Backend`:

```go
type CompareAndSwapper interface {
	CompareAndSwap(ctx context.Context, key string, expected, newValue []byte) (bool, []byte, error)
}
type CompareAndDeleter interface {
	CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error)
}
```

(`pkg/storage/guardedwrites.go`, `compareandswap.go`, `compareanddelete.go`.)
A caller that needs the guarantee type-asserts for it and handles absence —
`GuardedWriteReporter` lets a backend explicitly report the capability as
unavailable rather than silently defeating the guard.
`storage.GuardedWritesUsable(b)` (`pkg/storage/guardedwrites.go:88`) is how a
caller asks: it needs both interfaces **and** the report, and a backend that
does not implement the reporter is taken at its word. `PrefixBackend` declares
`CompareAndSwap` unconditionally (`pkg/storage/prefix_compareandswap.go:24`,
answering `ErrCompareAndSwapUnsupported` when the inner backend cannot), so its
report is the inner backend's usability (`pkg/storage/prefix_guardedwrites.go:32`).
The go-qrdb-backed `pkg/storage/qrdb.Backend` reports available when its client
is a `GuardedKVClient` or a `TransactionClient` (`pkg/storage/qrdb/backend.go:89`).

### `pkg/storage/kvadapter` — a `storage.Backend` as a go-qrdb `KVStore`

`kvadapter.New(backend)` (`pkg/storage/kvadapter/adapter.go:71`) wraps a
`storage.Backend` so go-qrdb's DAO layer can run over it. It returns
`NilBackendError` for a nil backend, and an `AtomicKVStore`
(`atomicKVStoreAdapter`, `atomic.go:40`) only when
`storage.GuardedWritesUsable` holds; otherwise a plain `KVStore`, so a DAO
takes its non-atomic path instead of failing on the first guarded write. The
semantic translations:

| Operation | Adapter behaviour | Source |
|---|---|---|
| `Get` of a missing key | `storage.ErrNotFound` becomes `*qrdbsdk.QRDBError{Code: ErrNotFound}`, so the DAO's not-found check works | `adapter.go:96` |
| `Delete` of a missing key | swallowed — `KVStore.Delete` is idempotent | `adapter.go:115` |
| `Scan` | collects, sorts keys, then calls back in key order | `adapter.go:128` |
| `CompareAndSwap` | delegates; the backend's observed `current` value is dropped | `atomic.go:87` |
| index registration and queries | `*IndexingNotSupportedError`, which matches go-qrdb's `ErrIndexUnsupported` so the DAO plans full scans | `indexes.go:47`, `errors.go:154` |

Other failures are typed and unwrap to the backend error: `PutError`,
`GetError`, `DeleteError`, `ScanError`, `ScanCallbackError`, `ListError`,
`ExistsError` (`pkg/storage/kvadapter/errors.go`). A decorator over a
`KVStore` follows the same rule: `pkg/acme/storage/objstore`'s tenant prefix
wrapper claims `AtomicKVStore` only when its inner store does
(`pkg/acme/storage/objstore/tenant_aware_factory.go:185`).

### `pkg/server` — the one datastore seam every xkms subsystem uses

```go
func (s *Server) createStorage(subdir string) (storage.Backend, error)
func (s *Server) createStorageAt(path string) (storage.Backend, error)
func (s *Server) initializeQRDBStorage() error   // pkg/server/qrdb_storage.go
```

(`pkg/server/storage_factory.go`.) Both `createStorage` and `createStorageAt`
are now unconditional: they always return
`storage.NewPrefixBackend(s.qrdbStorage, <namespace>+"/")` — a key-prefixed
view over the single shared datastore `initializeQRDBStorage` built. There is
no switch on an engine or backend name at this layer, and **neither function
can return an error anymore**; the two-value return is kept for interface
stability with earlier revisions and because `storage.NewPrefixBackend`'s own
signature returns one, not because either call has a failure mode today.

`createStorage` derives the key namespace from `subdir` directly;
`createStorageAt` derives it from `filepath.Base(path)` — used for backend
key-storage paths configured independently of the datastore root (e.g.
`Backends.Software.Path`, `Backends.PKCS8.Path`).

```go
func (s *Server) initializeQRDBStorage() error
```

Must run once, early in `Server.New`, before the first `createStorage` call.
Switches on `config.Datastore.Mode` (defaulted by `config.Validate`):

- `"standalone"` → `initEmbeddedQRDBNode()` hosts the qrdb engine in this
  process (identity, bootstrap, barrier, optional Raft clustering), and
  `s.datastore = datastore.New(s.qrdbClient, s.config.Datastore, datastore.WithCallContext(s.qrdbNode.ServiceContext))`
  borrows the node's client, and runs the datastore's own calls as the
  node's service principal.
- `"remote"` → `s.datastore = datastore.Open(s.ctx, s.config, s.logger)`,
  which dials `Datastore.Remote.Address` over `Datastore.Remote.Transport`
  (`rest` or `grpc`) with `Datastore.Remote.TLS` (`datastore.DialRemote`,
  `pkg/datastore/remote.go`) and owns the dialed client. An unrecognized
  transport returns `*datastore.ErrUnsupportedStorageBackend{Backend: "qrdb:" + transport}`.
  `DialRemote` is the single remote-dial implementation in the stack.
- anything else → `*datastore.ErrUnsupportedDatastoreMode{Mode}` —
  unreachable through `config.Validate`, defense-in-depth for an embedded
  caller that constructs a `*config.Config` without validating it.

Either way `s.qrdbStorage = qrdbstorage.NewBackend(s.datastore.Client().KV(), s.storageCallContext()...)`:
the shared `storage.Backend` sits on the client's KV, not on the DAO
factory, because the seal barrier's views need fenced creates
(`storage.FencedCreator`) and the SDK's `KVStore` does not carry them.
`storageCallContext` (`pkg/server/qrdb_storage.go`) is
`qrdbstorage.WithCallContext(s.qrdbNode.ServiceContext)` in standalone mode
and nothing in remote mode: see *The service principal* below.
`closeQRDBStorage` closes the backend, then the datastore (which closes a
dialed client), then the embedded node.

### `pkg/embeddednode` — mapping the datastore onto go-qrdb's own config

```go
func EmbeddedNodeStorageConfig(cfg *config.Config, sealRes ResolvedNodeSeal) *qrdbsdk.DaemonConfig
func OpenEmbeddedNode(ctx context.Context, opts EmbeddedNodeOptions) (*qrdbnode.Node, ResolvedNodeSeal, error)
```

The single place `Datastore.Engine`/`Datastore.Path` become go-qrdb's own
`qrdbsdk.DaemonDatabaseConfig`:

```go
qcfg.Raft.DataDir = cfg.Datastore.Path
qcfg.Databases = []qrdbsdk.DaemonDatabaseConfig{
	{Name: "default", Engine: "mvcc", Backend: cfg.Datastore.Engine}, // memory | file | pebble
}
```

`(*Server).initEmbeddedQRDBNode` (`xkmsd run`), `xkmsd init`'s
`openDurableInitNode`, and `pkg/datastore.Open`'s `"standalone"` case all
derive their qrdb daemon config through this one package (`ResolveNodeSeal`
+ `EmbeddedNodeStorageConfig`, and for the latter two, `OpenEmbeddedNode`),
and every one of them constructs the node through `embeddednode.NewNode`,
the single node builder, so the different opens of one on-disk datastore can never
disagree about the database engine or the seal strategy. `pkg/embeddednode`
was split out of `pkg/server` in go-xkms#1345 batch 2 specifically so
`pkg/datastore` (which `pkg/server` also imports) could
reach it without an import cycle back through `pkg/server`.

### The service principal — xkms's own calls on the embedded node

Since go-qrdb v0.46 the embedded node's client refuses a call whose context
carries no identity (`qrdbsdk.ErrUnauthenticated`). xkms's own calls — the
ones it makes on its own behalf, not for an authenticated request — run as
the node's service principal:

```go
// pkg/embeddednode/serviceprincipal
const Name = "xkms"                       // audited as "qrdb-service:xkms", system tenant
func Grant() []qrdbsdk.Permission         // copy of the grant below
func Option() qrdbnode.NodeOption         // registers the grant once, then WithServicePrincipal(Name)
```

`embeddednode.NewNode` appends `serviceprincipal.Option()` to every node it
builds, standalone and clustered. The grant, registered process-wide with
`qrdbsdk.RegisterPermissionRoleGrant`, is exactly what those calls exercise
and holds no wildcard:

| Permission | Used by |
|---|---|
| `kv:get`, `kv:put`, `kv:delete`, `kv:list`, `kv:exists` | `pkg/storage/qrdb.Backend`, the shared datastore every subsystem persists through |
| `lease:grant`, `lease:revoke`, `lease:keepalive` | `pkg/oidc/credential`: refresh locks and the scheduler's leadership lease |
| `transaction:execute` | go-qrdb takes a lease with a compare-and-swap transaction; the backend's guarded writes fall back to one |
| `databases:create` | `pkg/datastore.DatabaseKVStore` ensures a feature's named database exists |
| `index:create`, `index:query` | a feature DAO registers its entity's indexes and looks entities up through them |
| `kv:range` | a feature DAO's paged listing (`ForEachPage`), such as `pkcs11state.Store.List` |

A call outside it is refused with `*qrdbsdk.PermissionDeniedError`.

The call sites that bind it, each through an injected
`func(context.Context) (context.Context, error)` so neither package knows
about nodes:

- `qrdbstorage.WithCallContext(bind)` — every `Backend` method derives its
  context through `bind` before calling the client; a bind failure is a
  `*qrdbstorage.BackendError` and the call never reaches the client.
- `credential.WithLeaseContext(bind)` (`compose.OIDCCredentialParams.LeaseContext`)
  — refresh-lock acquire and release, and the scheduler's acquire, renew and
  release. Provider requests and barrier access keep the caller's context.
- `datastore.WithCallContext(bind)` — the database ensure in
  `DatabaseKVStore` and every operation of a store the DAO factory serves,
  default and named databases alike. The SDK's `KVStore` adapter registers
  a DAO's indexes on a background context, so the binding wraps the
  transport clients beneath the adapter; a bind failure is a
  `*datastore.ErrCallContext`. It is the one binding every feature DAO over
  the server's datastore runs under -- the named databases (key versions,
  AEAD nonces, PKCS#11 state, TPM policies, the CA) and the default one
  (ACME) -- so a feature store takes no binding of its own.

All three are wired from `s.qrdbNode.ServiceContext` and only in standalone
mode; `datastore.Open` binds its own embedded node's `ServiceContext` the
same way. In remote mode the dialed client already runs as xkms's own mTLS
identity.

A request-scoped call keeps the request's identity: the REST host's refresh
store, user resolver and WebAuthn user lookups run on the request's context
and are never bound to the principal, so the principal cannot widen what a
caller can do. A feature DAO is xkms persisting what it has already
authorized, exactly as the storage backend is, so it runs bound. `Node.ServiceContext` on a node built without the option
returns `qrdbnode.ErrNoServicePrincipal`.

### `pkg/datastore` — the go-qrdb client and the DAO factory

```go
func Open(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*Datastore, error)
func New(client *qrdbsdk.Client, cfg config.DatastoreConfig, opts ...Option) (*Datastore, error)
func WithCallContext(bind qrdbstorage.CallContext) Option
func DialRemote(ctx context.Context, cfg config.DatastoreRemoteConfig) (*qrdbsdk.Client, error)

func (d *Datastore) Client() *qrdbsdk.Client
func (d *Datastore) DAOFactory() *qrdbsdk.DAOFactory
func (d *Datastore) DatabaseKVStore(ctx context.Context, name string) (qrdbsdk.KVStore, error)
func (d *Datastore) Close() error
```

(`pkg/datastore/datastore.go`, `callcontext.go`, `database.go`, `remote.go`.)

- **`Open`** builds the datastore for `cfg.Datastore`: `"standalone"`
  (the default for an empty mode) opens the embedded node through
  `embeddednode.OpenEmbeddedNode`; `"remote"` calls `DialRemote`. The
  datastore owns what `Open` built, and `Close` releases it.
- **`New`** builds a datastore over a client the caller owns; its `Close`
  is a no-op. `pkg/server` (standalone) and the API-module host use it.
- **`DAOFactory`** is `qrdbsdk.NewDAOFactoryWithConfig` with
  `KVStoreProvider` → `Client().KVStore()` (the `"default"` database) and
  `PartitionedProvider` → the named databases opened so far. A name this
  datastore has not opened yields a nil store, never the default one.
  With `WithCallContext`, each store is the SDK's
  `qrdbsdk.NewKVStoreAdapter` over the client's KV and index clients bound
  to the call context.
- **`DatabaseKVStore(ctx, name)`**:
  1. returns the cached store when `name` is already open;
  2. scopes: `client.DatabaseScoped(name)`. A transport with no database
     plane fails here with `*ErrDatabaseScope` (wrapping
     `*transport.DatabaseScopeUnsupportedError`) before step 3 reaches for
     the plane it lacks;
  3. ensures `name` exists, on the call context:
     `client.Database().GetDatabase(ctx, name)`; on
     any error, creates it with `client.Database().CreateDatabase` using
     `EngineKV` and `resolveDatabaseBackend`'s resolved backend. A
     `*qrdbsdk.DBAlreadyExistsError` from `CreateDatabase` (a concurrent
     composition root ensuring the same database) is treated as success —
     the postcondition is "the database exists", not "this call created it";
  4. caches the scoped client's `.KVStore()`, after which the DAO factory
     serves it.

`resolveDatabaseBackend(cfg, name)` returns `cfg.Databases`' matching
entry's `Backend` when one is configured non-empty, and `cfg.Engine`
(already defaulted by `config.Validate`) otherwise.

Only a composition root calls `DatabaseKVStore` — never a feature package,
which declares its database name as a constant (e.g. `oidc.DatabaseName`).
See "Feature-owned databases" in architecture.md.

### `pkg/dao` — the one way to build a DAO from the factory

```go
func New[E qrdbsdk.Entity](factory *qrdbsdk.DAOFactory, database, entityType string,
	newEntity func() E, opts ...qrdbsdk.DAOOption) (qrdbsdk.GenericDAO[E], error)
```

(`pkg/dao/dao.go`.) The go-qrdb SDK builds a `GenericDAO` only from a
`KVStore` (`qrdbsdk.NewDAO`). `dao.New` takes the factory, looks up the
store for `database` (`""` is the default database), and builds the DAO, so
that lookup lives in one place. A named database the factory does not serve
— not opened, or a factory with no partitioned provider — is refused with
`*dao.DatabaseUnavailableError` instead of silently using the default
database.

```go
func NewStoreFactory(store qrdbsdk.KVStore) *qrdbsdk.DAOFactory
```

A host with no go-qrdb node (xkey) or a test builds its factory with
`dao.NewStoreFactory`: one `KVStore` serves the default database and every
named one. A nil store serves none, so `dao.New` refuses every DAO of that
factory with `*dao.DatabaseUnavailableError`. The SDK re-exports it as
`NewStoreDAOFactory`; `testutil.NewMemoryDAOFactory` is it over a fresh
memory store.

An entity is a JSON-tagged struct with `EntityID()`/`SetEntityID()` and
optional `index:` tags — `pkg/oidc/entity.go:20` (`index:"unique,ci"`) and
`:31`. Feature stores derive the ID from the natural key so a lookup needs no
scan: `qrdbsdk.NewCryptoFieldHashGenerator(<field>)` (for example
`pkg/signing/store/store.go:74`, `pkg/pivcert/file/file.go:91`) or
`NewFieldHashGenerator` (`pkg/tpm2/store/blob.go:69`).

### `pkg/compose` — the databases a root opens

```go
func Databases(d Deps) []string
```

(`pkg/compose/compose.go`.) The go-qrdb databases the DAO-backed features
`Build` would compose from `d` persist in: always `keyversion.DatabaseName`,
`certstore.DatabaseName` when `d.CA` is set, and `tpmpolicy.DatabaseName`
when `d.TPMBackend` is set. A root opens each
(`pkg/server` `daoFactory`; the API-module host's `hostStorage`) and passes
the factory as `Deps.DAOs`; over an embedded node the datastore's
`WithCallContext` runs the stores' calls as the service principal. A host whose client cannot open them leaves `Deps.DAOs` nil, so only those
features are off.

### `pkg/compose` — `storage.Backend` over the factory

```go
func FactoryBackend(daos *qrdbsdk.DAOFactory) (storage.Backend, error)
func FactoryStorage(daos *qrdbsdk.DAOFactory, prefix string) (StorageFactory, error)
```

(`pkg/compose/storage.go`.) For features not yet converted to DAOs.
`FactoryBackend` wraps the factory's default store in
`qrdbstorage.NewKVStoreBackend`; `FactoryStorage` returns a
`StorageFactory` whose each feature view is `prefix+name+"/"` over one shared
`FactoryBackend`. The backend carries `PutIfAbsent`, `CompareAndSwap` and
`CompareAndDelete`, but no fenced create. The API-module host
(`pkg/apimodule/module_host.go`, prefix `"xkms/"`) opens its stores this way.

### `pkg/storage/qrdb` — the shared datastore's `storage.Backend` wrapper

```go
func NewBackend(client transport.KVClient) *Backend
```

(`pkg/storage/qrdb/backend.go`.) Reads use follower-read consistency
(`transport.WithConsistency(transport.ConsistencyFollower)`) so a read on
any replica reflects all committed entries without blocking on a leader
`ReadIndex` round trip. A `guardedWrites` flag, set once at construction,
reports whether `PutIfAbsent`/`CompareAndSwap`/`CompareAndDelete` can
execute against this client.

```go
func NewKVStoreBackend(store qrdbsdk.KVStore) (*KVStoreBackend, error)
```

(`pkg/storage/qrdb/kvstore_backend.go`.) The same contract over a
`qrdbsdk.KVStore` — the store a DAO factory serves — for
`compose.FactoryBackend`. A nil store is refused with `ErrNilKVStore`. The
SDK's `KVStore` offers no read-consistency option, so reads take the
store's default consistency rather than follower reads, and it carries no
fenced create.

### `pkg/storage` — a bare go-qrdb engine as a `Backend`

```go
func OpenEngine(cfg EngineConfig) (Backend, error)
```

(`pkg/storage/engine.go:397-436`.) Opens one go-qrdb storage engine directly,
with no node, barrier or Raft above it. This is a library seam (the file
engine below wraps it); `xkmsd` never selects an engine through it.
`EngineConfig.Kind` (`pkg/storage/engine.go:354-369`) is one of:

| Kind | Opens | Needs |
|---|---|---|
| `file` (also the empty kind) | `qrdbsdk.NewFileStorage(Path)` | `Path` |
| `pebble` | `qrdbsdk.NewPebbleStorage(DefaultPebbleConfig(Path))` | `Path` |
| `memory` | `qrdbsdk.NewMemoryStorage()` | nothing |
| `objstore` | `qrdbsdk.NewObjStoreStorage(Provider, Options)` | `Provider` (empty = `"local"`); `Options` go verbatim to go-objstore (`pkg/storage/engine.go:375-388`) |

A missing `Path` is `ErrEnginePathRequired`, an unknown kind wraps
`ErrUnknownEngine` (`pkg/storage/errors.go:49-54`), and an open failure is
`*EngineError`, rendered `storage: engine <op> "<path or provider>": <cause>`
(`pkg/storage/engine.go:39-41`).

### CA blob storage

`pkg/ca` keeps its non-certificate blobs in a go-qrdb storage engine, the
`qrdbsdk.Storage` the embedder passes as `ca.Params.ObjectStore` or builds
per CA with `ca.Params.ObjectStoreFactory` (`pkg/ca/ca.go:144,172`,
`pkg/ca/constructors.go:82`). go-xkms imports go-objstore nowhere: the
backend is chosen by configuration through go-qrdb. `sdk/go` exposes the
engine as `ObjectStorage`, opened by `NewObjectStorage(provider, settings)`
(`qrdbsdk.NewObjStoreStorage`; `"local"` needs no build tag, cloud providers
need go-objstore's tag) or `NewObjectStorageMemory()`
(`sdk/go/storage.go:70,131,135`). The engine is optional; a CA without one
refuses only the blob operations, with `ca.ErrObjectStoreRequired`
(`pkg/ca/errors.go:163`).

| Blob | Key |
|---|---|
| Cross-signed certificates (PEM) | `cross-signed/<issuer CN>/<subject CN>.pem` (`pkg/ca/cross_signing.go:41`) |
| Distribution-point CRLs | `crls/distribution/<sha256(url)>.crl` (`pkg/ca/crl_import.go:55`) |
| Attestation evidence | `attestation/<AK key>/{data,signature,digest}` and `attestation/<AK CN>/ak-cert.{der,digest,sig}` (`pkg/ca/attestation.go:56,109-111,146-166`) |

A missing key is `ca.ErrObjectNotFound` and any engine failure wraps
`ca.ErrStorageError` (`pkg/ca/object_store.go:24-47`,
`pkg/ca/errors.go:167`). Certificates, chains, serials and revocations are
not blobs: they live in the CA's go-qrdb database (see
`docs/certificate-authority/engineering.md`).

### `pkg/storage/file` — the file engine's validation and permission wrapper

```go
func New(rootDir string) (storage.Backend, error)
```

(`pkg/storage/file/storage.go`.) Wraps `OpenEngine(EngineConfig{Kind: EngineFile})`
with storage-key validation (blocks path traversal and null bytes) and
prefix-based file permissions (`keys/*` = 0600, `certs/*` = 0644, default
0600). It is the constructor the PKCS#11 module's `StorageTypeFile` opens
directly (`pkg/pkcs11/module/module.go:initializeStorage`), rather than going
through `storage.NewFile` (which builds the embedded qrdb stack instead — see
`pkg/storage/qrdb` above).

**Every write this type performs — `Put`, `Delete`, `PutIfAbsent`,
`PutIfAllAbsent`, `CompareAndSwap`, `CompareAndDelete` — and the engine open
in `New` hold an advisory `flock` on the store root directory itself for the
whole call** (`pkg/storage/file/lock.go`, #1157). The open is locked because
go-qrdb's file engine initialises a fresh directory and sweeps its own temp
files when it opens, which would otherwise delete another process's in-flight
temp file. The lock targets the directory rather than a lock file inside it
because the engine refuses to initialise a directory holding anything but its
format marker. `OpenEngine`'s `engineBackend` (`pkg/storage/engine.go`) already
guards every write with its own `writeMu`, but that guard is genuine only
within one process: it is a Go `sync.Mutex`, invisible to a second process
holding a second `*os.File` over the same directory. Two processes sharing
one file-token directory — the scenario the PKCS#11 module's PIN attempt
counter (#1144) runs under when several module instances open the same
token — could interleave a guarded read-compare-write before this fix and
both report success, silently undercounting the shared value. The lock
covers the unconditional `Put`/`Delete` too, for the same reason `writeMu`
does (see its doc in `engine.go`): a plain `Put` from another process
landing inside a guarded operation's read-compare-write would defeat the
guard exactly as an unguarded write would in-process.

A fresh file description is opened and `flock`'d for every call rather than
one held for the store's lifetime, because `flock(2)` locks are scoped to the
open file description: two descriptions opened by the *same* process contend
for the lock exactly like two different processes would. That single
mechanism is what serializes this process's own concurrent goroutines calling
`FileStorage` methods, as well as every other process, without a second
in-process mutex to keep paired with it. Plain reads (`Get`, `Exists`, `List`,
`Scan`) are not locked, matching `engineBackend`'s own read path — this closes
the write/write race the guarded verbs exist for, not general
read/write linearizability.

## Invariants

- **One datastore, one shared instance.** `initializeQRDBStorage` must run
  once, before the first `createStorage` call; every subdirectory is a
  key-prefixed view (`storage.NewPrefixBackend`) over the one
  `s.qrdbStorage`, and a view's `Close` is a no-op — only `Server.Shutdown`
  (via `closeQRDBStorage`) closes the real, shared backend.
- **No subsystem builds its own storage engine.** `pkg/server` has no code
  path that constructs `storage.NewPebble`, `storage.NewMemoryBackend`, or
  `file.New` for the daemon's own metadata store; every one of those
  private-engine call sites in `storage_factory.go` was deleted
  (go-xkms#1345). A future subsystem that "just needs its own KV store" is
  the same defect this batch removed and must not be reintroduced.
- **`config.Validate` fully enumerates the datastore configuration space.**
  Unlike the old `storage.backend` switch — which accepted any non-empty
  string as long as `Storage.Path` was set, and only failed later at
  `createStorage` — `Datastore.Engine` and `Datastore.Mode` are validated
  exhaustively at config-parse time: `memory | file | pebble` for `Engine`,
  `standalone | remote` for `Mode`, with mode-specific requirements
  (`standalone` needs `Path`, unconditionally -- every `Engine` including
  `"memory"`; `remote` needs `Remote.Address` and a `Remote.Transport` of
  `rest` or `grpc`). A config that parses is now a config that will open its
  datastore.
- **Guarded writes are advertised, not assumed.** A caller performing a
  cross-node-safe compare-and-swap must type-assert for `CompareAndSwapper`
  and handle its absence, never assume every `Backend` has it.

## Error semantics

| Error | Where | Meaning |
|---|---|---|
| `*config.ErrUnknownDatastoreEngine{Engine}` | `pkg/config/datastore.go:24`, from `config.Validate` and `embeddednode.OpenEmbeddedNode` | `datastore.engine` not one of memory/file/pebble |
| `*config.ErrUnknownDatastoreMode{Mode}` | `pkg/config/datastore.go:36`, from `config.Validate` | `datastore.mode` not one of standalone/remote |
| `*errs.Message` from `config.Validate` | `pkg/config/config.go` | `datastore.path` unset for `mode: standalone` (every engine, `memory` included -- go-qrdb roots the node's on-disk state under it regardless of the primary KV engine, so there is no engine choice that waives this), or a `mode: remote` requirement (address, transport) unmet |
| `*datastore.ErrUnsupportedStorageBackend{Backend: "qrdb:" + transport}` | `pkg/datastore/remote.go`, used by both `pkg/server/qrdb_storage.go` and `pkg/datastore.Open` | `datastore.remote.transport` names a transport `DialRemote` does not implement (only reachable by bypassing `config.Validate`) |
| `*datastore.ErrUnsupportedDatastoreMode{Mode}` | `pkg/datastore/errors.go` | `datastore.mode` is neither `standalone` nor `remote` (only reachable by bypassing `config.Validate`) |
| `*datastore.ErrOpenDatastore{Mode, Err}` | `pkg/datastore/datastore.go` | `Open` failed to build the standalone datastore; `Err` is the underlying cause |
| `*datastore.ErrDialRemote{Transport, Address, Err}` | `pkg/datastore/remote.go` | `DialRemote` could not build or connect the remote client; nothing is left open |
| `datastore.ErrNilConfig` / `ErrNilClient` / `ErrDatabaseNameRequired` | `pkg/datastore/errors.go` | `Open` got a nil config, `New` a nil client, or `DatabaseKVStore` an empty name |
| `dao.ErrNilFactory` / `*dao.DatabaseUnavailableError{Database}` / `*dao.NewDAOError{EntityType, Err}` | `pkg/dao/dao.go` | `dao.New` got no factory, a named database the factory does not serve, or go-qrdb refused the DAO |
| `compose.ErrNilDAOFactory` / `qrdbstorage.ErrNilKVStore` | `pkg/compose/errors.go`, `pkg/storage/qrdb/kvstore_backend.go` | `FactoryBackend` got no factory, or the factory serves no default store |
| `*datastore.ErrEnsureDatabase{Name, Err}` | `pkg/datastore/database.go` | `DatabaseKVStore` could not confirm or create the named database; `Err` is go-qrdb's underlying cause (not `*qrdbsdk.DBAlreadyExistsError`, which is treated as success) |
| `*datastore.ErrDatabaseScope{Name, Err}` | `pkg/datastore/database.go` | the database exists but `Client.DatabaseScoped(name)` failed |
| `*embeddednode.NodeSealError{Reason, Err}` | `pkg/embeddednode/errors.go` | the node barrier is configured to encrypt the data plane but the required auto-unseal material cannot be resolved |
| `*embeddednode.ErrDatastorePathRequired{Reason}` | `pkg/embeddednode/errors.go` | `Datastore.Path` is unset for a standalone datastore -- either generally (`Open`'s own check, `Reason: "the standalone datastore"`) or specifically to derive the TPM2 node-barrier seal strategy's key directory (`Reason: "the TPM2 seal key directory"`) |
| go-qrdb's `lifecycle.EmptyVectorDataDirError` | go-qrdb `pkg/server/lifecycle` (not an xkms type; this repository never constructs or catches it directly) | the underlying go-qrdb failure `datastore.path` being required prevents: go-qrdb's node builder unconditionally roots its vector-storage subsystem under the node's data directory regardless of the primary KV engine, so an empty directory fails the node build outright. `config.Validate` and `pkg/datastore.Open` both refuse an empty `Datastore.Path` for `mode: standalone` before this can be reached, adopting the constraint rather than working around it -- see "Configuration" below |
| `ErrNotFound` | `pkg/storage/errors.go` | `Get`/`Delete` against an absent key |
| `ErrClosed` | `pkg/storage/errors.go` | an operation reached a closed go-qrdb engine |
| `ErrAlreadyExists` | `pkg/storage/errors.go:41` | a create found the key already present |
| `ErrCompareAndSwapUnsupported` / `ErrCompareAndDeleteUnsupported` / `ErrFencedCreateUnsupported` | `pkg/storage/errors.go:28`, `:33`, `:38` | the backend cannot perform that guarded write (see `GuardedWritesUsable` above) |

## Configuration

`Config.Datastore` (`pkg/config/config.go`), yaml key `datastore:`:

```go
type DatastoreConfig struct {
	Engine    string                     `yaml:"engine"` // "memory" | "file" | "pebble" (default)
	Path      string                     `yaml:"path"`
	Mode      string                     `yaml:"mode"`   // "standalone" (default) | "remote"
	Remote    DatastoreRemoteConfig      `yaml:"remote"`
	Databases []qrdbsdk.DaemonDatabaseConfig `yaml:"databases"` // go-qrdb's own per-database config; per-feature backend overrides
}
type DatastoreRemoteConfig struct {
	Address   string    `yaml:"address"`   // remote cluster endpoint, e.g. "https://localhost:63002"
	Transport string    `yaml:"transport"` // "rest" or "grpc"
	TLS       TLSConfig `yaml:"tls"`
}
```

`Config.Validate` (`pkg/config/config.go`, top of `Validate`, so every later
check reads an already-defaulted `Datastore`):

- An empty `Engine` defaults to `"pebble"` — production paths must never
  silently fall back to a non-durable store.
- An empty `Mode` defaults to `"standalone"`.
- `Mode == "standalone"`: `Path` is required for every `Engine`, `"memory"`
  included. go-qrdb roots the node's on-disk state (its vector-storage
  subsystem in particular) under this directory regardless of the primary
  KV engine, so there is no engine choice that lets a standalone node run
  with no directory at all — this adopts that go-qrdb contract exactly
  rather than working around it (e.g. with an xkms-managed temp directory).
  A deployment that wants ephemeral state still names a real directory
  (a temp directory it owns and cleans up itself, or `t.TempDir()` in
  tests) with `engine: memory`, which still leaves the primary KV data
  non-durable.
- `Mode == "remote"`: `Remote.Address` is required, and `Remote.Transport`
  must be `"rest"` or `"grpc"`.
- `Engine` and `Mode` are trimmed and lowercased before the check, and
  `Validate` stores the normalised values (`pkg/config/config.go:1482-1496`).
  Any other value is a hard error, `*config.ErrUnknownDatastoreEngine` or
  `*config.ErrUnknownDatastoreMode`, naming the value and the accepted ones
  (`pkg/config/datastore.go:24-45`). The accepted engines are go-qrdb's SDK
  backend constants `BackendMemory`, `BackendFile` and `BackendPebble`; the
  SDK has no list of them, so `config.DatastoreEngines`
  (`pkg/config/datastore.go:13`) is that one list.
- `embeddednode.OpenEmbeddedNode` repeats the engine check
  (`pkg/embeddednode/embedded_node.go:429`), so a caller that skips
  `Validate`, such as `datastore.Open`, cannot hand go-qrdb an unknown
  engine.
- `Databases`: each entry needs a non-empty `Name`, names must not repeat,
  and a non-empty `Backend` must be `memory`, `file`, `pebble`, `raft`, or
  `objstore` (`pkg/config/config.go:1537-1539`). An empty `Backend` is valid
  — it defers to `Engine`.

Two other `Validate` rules key off `Datastore.Mode` and matter for this
feature's neighbors:

- Network protocols (REST/gRPC/QUIC/MCP) require `Datastore.Mode ==
  "standalone"` — "the embedded qrdb node is the unified API server".
- `Cluster.Enabled` requires `Datastore.Mode == "standalone"` — see
  [`../clustering/architecture.md`](../clustering/architecture.md).

Environment variables follow the general `XKMS_<PATH>` rule (nesting joined
by underscores — `pkg/config/load.go`): `XKMS_DATASTORE_ENGINE`,
`XKMS_DATASTORE_PATH`, `XKMS_DATASTORE_MODE`,
`XKMS_DATASTORE_REMOTE_TRANSPORT`, `XKMS_DATASTORE_REMOTE_ADDRESS`.

Real examples from this repository:

```yaml
# configs/xkmsd.yaml — durable single-node default
datastore:
  engine: "pebble"
  path: "xkms-data/storage"
```

```yaml
# a remote datastore, dialing an already-running qrdb cluster
datastore:
  mode: "remote"
  remote:
    address: "https://qrdb.example.com:63002"
    transport: "rest"
```

There is **no built-in default for `Datastore.Path`** (`Defaults()` in
`pkg/config/load.go` does not set it); every `"standalone"` deployment, for
every `Engine` including `"memory"`, requires it explicitly, from the file,
`XKMS_DATASTORE_PATH`, or (for `xkmsd init` specifically) the `--data-dir`
flag (`cmd/xkmsd/init_node.go`).

## Genuinely pre-datastore material

A small set of state must exist *before* the datastore itself is available
to open, and stays outside it by construction, not by omission:

| What | Where | Why it cannot live in the datastore |
|---|---|---|
| The qrdb node's own Raft data directory | `Datastore.Path` itself, via `Raft.DataDir` | It IS the datastore's on-disk root; nothing is "above" it to store it in |
| TPM-sealed pre-barrier blobs (PKCS#11 PIN, cluster CA signing key) | `pkg/trust/clusterca`, under `Datastore.Path` | Sealed before the barrier exists, so they can unseal it or the node that hosts it; they promote into the replicated datastore once it is up (go-xkms#677) |
| Bootstrap TLS certificate cache | `pkg/server/unified_tls.go`, under `Datastore.Path` | Served before the CA (which lives in the datastore) has composed, so the unified API server has *something* to present |
| First-boot administrator credential | `pkg/server/firstboot.go`, under `Datastore.Path` | Persisted by `xkmsd init`, a one-shot ceremony that runs before `xkmsd run` ever opens the datastore for API traffic |
| TPM2 node-barrier seal strategy's own key | `embeddednode.KeyDirSubdir` ("tpm2-keys"), under `Datastore.Path` (`embeddednode.ResolveTPM2KeyDir`); also `pkg/seal/autodetect.go`'s `TPM2ProbeConfig.KeyDir` for the same strategy's autodetect probe (xkey, cluster CA key protection, quicbaas) | This key seals (and can unseal) the datastore's own barrier; it cannot itself live inside the store it protects |

All four resolve their root from `cfg.Datastore.Path`, not a separate
configuration knob — there is still exactly one path an operator names.

## Secrets that intentionally leave the server, not a datastore gap

go-xkms#1323's audit of hand-rolled file writes also found a second category,
distinct from "genuinely pre-datastore material" above: material whose job
*is* to leave the server as a file, for a consumer that is never xkms itself.
Moving these into the datastore would not close a gap — it would strand the
consumer, since nothing would still write the file the consumer needs. Per
the owner's 2026-09-30 ruling, these stay files and will move onto
go-qrdb's exported atomic-write helper once it ships, same as every other
file write in this repository; they do not become datastore entities.

| What | Where | Who reads the file |
|---|---|---|
| `--output` exports (a Shamir share, a CA/key/cert PEM, a decrypted key) | `cmd/xkmsctl/{init,ca,cert,key,platform}.go`, `xkey/cmd/xkey/cmd/{share,ca,seal_store}.go`, `xkey/pkg/gui/services/key_service.go` | The operator who explicitly asked for the file with `--output`; the datastore already holds the canonical copy (where one exists) |
| ACME client certificate/key deploy | `pkg/acme/client/service/deploy.go` | A third-party web server (nginx, Apache, ...) that `TLSConfig.Certificates` or an equivalent loads certificates from a filesystem path, not from xkms |
| First-boot administrator credential | `pkg/server/firstboot.go` `PersistAdminCredential` | The bootstrap operator, by the same generate-and-distribute contract qrdbd uses: once issued, the private key is handed over and must not also persist server-side — a server that retained a copy of the admin's own authentication key would defeat the credential's purpose. (This item is also genuinely pre-datastore in the timing sense documented above: `xkmsd init` persists it before `xkmsd run` ever opens the datastore for API traffic.) |

xkey (the desktop module) has no datastore of its own to receive anything
moved out of a file: it has no embedded qrdb node (it is a `sdk/go`-only
client; see `CLAUDE.md`'s SDK boundary) and, where it talks to one, it is the
*remote* `xkmsd` server's datastore, reached over the wire — not a local
store xkey could write "internal state" into unilaterally. xkey's own
offline-capable analogue is `pkg/gui/services.BarrierService`'s local,
seal-strategy-protected KV (`xkey/docs/seal/architecture.md`), which several
services (`SealService`, `OIDCService`) already route through when a barrier
is open, falling back to a plaintext file only when no barrier was ever
initialized on the host (`xkey/docs/seal/architecture.md`'s "sealed-blob
store" section, and the `device_barrier_shared.go` #42 ruling for the Noise
pairing key in `devices.yaml`). `xkey/cmd/xkey/cmd/device_enroll.go`'s
agent mTLS enrollment material is a further pre-reach exception of its own:
it is the credential xkey needs to reach the remote server at all, so it
cannot itself live behind that server's datastore.

## The SDK/library composition path (`pkg/xkms`, `pkg/datastore`, `pkg/embeddednode`)

`pkg/xkms`'s `AutoInitialize`/`register_*` backend factories build a
standalone `*xkms.XKMSService` without a `*Server`, so they never reach
`createStorage`. They take their storage from a caller-supplied handle
instead, and never resolve a directory or open a file/memory engine
themselves:

```go
type AutoConfig struct {
	Datastore      storage.Backend // nil = in-memory for every backend
	DefaultBackend string
	BackendConfigs map[BackendType]map[string]interface{}
}
```

(`pkg/xkms/auto.go`.) `AutoInitialize` derives each backend's storage as a
key-prefixed view over `Datastore` (`storage.NewPrefixBackend(config.Datastore,
"<backend>/")`, mirroring `createStorage`) and passes it to the backend's
factory as `config["key_storage"]` (a `storage.Backend`) — the SDK-facing
equivalent of `"key_dir"` before this batch, which every `register_*.go`
factory (`register_pkcs8`, `register_software`, `register_symmetric`,
`register_tpm2`) now reads instead. `pkg/backend/tpm2.Config` has exactly
ONE key store: `Keys`, a `pkg/tpm2/store.BlobStore` keeping every blob as a
`TPMBlob` entity (natural key `<tenant>/<CN>/<ext>`) in the `tpm2` database
(`store.DatabaseName`). `register_tpm2` builds it over `key_storage` with
`store.NewBackendBlobStore` (`pkg/tpm2/store/factory.go`). `pkg/server`'s
TPM2 crypto-backend wiring (`initTPM2Backend`, `backend_tpm2.go`) opens the
`tpm2` database on the shared datastore (`Server.daoFactory`) and builds the
store with `store.NewBlobStore`, so the backend's key blobs live behind the
barrier with every other subsystem's state. The sole exception is
`NewBackendWithTPM`/`ExternalTPMConfig` (sharing an already-open TPM
connection with the node-barrier seal strategy or the platform store): it
reuses the opener's `KeyBackend()`, which for the node barrier is the
pre-datastore key directory (see "Genuinely pre-datastore material" above
and `pkg/seal/autodetect.go`'s `openTPM2Backend`, which builds a
`NewBackendBlobStore` over a file-based `storage.Backend` there).

`pkg/xkms` cannot import `pkg/config`, `pkg/datastore` or `pkg/server`
directly (`pkg/config` already transitively imports `pkg/xkms` via
`pkg/ca`, and `pkg/server` imports `pkg/xkms` directly) — this is why the
seam is a plain `storage.Backend` handle, not a `config.DatastoreConfig`
parameter: the caller (`pkg/server`, `sdk/go`, `xkey`, `cmd/xkmsd`) opens the
datastore and hands over a `storage.Backend` over it —
`compose.FactoryBackend(ds.DAOFactory())` for a `pkg/datastore` caller.

```go
func Open(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*Datastore, error)
```

(`pkg/datastore/datastore.go`.) The Server-independent way to open the
datastore: `"standalone"` hosts an embedded qrdb node via
`embeddednode.OpenEmbeddedNode`; `"remote"` dials via `datastore.DialRemote`
— `Server.initializeQRDBStorage`'s remote branch calls `Open` too, so there
is exactly one remote-dial implementation. `"standalone"`
requires `cfg.Datastore.Path` (adopting go-qrdb's own data-directory
contract exactly rather than working around it — see "Error semantics"
above): `Open` refuses an empty `Path` itself, with
`*embeddednode.ErrDatastorePathRequired`, before calling
`embeddednode.OpenEmbeddedNode` at all. A caller that only wants an
ephemeral node (unit tests) still names a real, typically temporary
directory (`t.TempDir()`) — `Open` never creates or manages one on the
caller's behalf.

```go
func OpenEmbeddedNode(ctx context.Context, opts EmbeddedNodeOptions) (*qrdbnode.Node, ResolvedNodeSeal, error)
func EmbeddedNodeStorageConfig(cfg *config.Config, sealRes ResolvedNodeSeal) *qrdbsdk.DaemonConfig
func ResolveNodeSeal(cfg *config.Config, logger *slog.Logger) (ResolvedNodeSeal, error)
```

(`pkg/embeddednode/embedded_node.go`, moved out of `pkg/server` in this
batch.) The shared, Server-independent embedded-qrdb-node builder both
`pkg/server` (`xkmsd run`'s heavier node with modules/TLS/cluster/barrier
adoption, and `xkmsd init`, both via `qrdb_node.go`/`cmd/xkmsd/init_node.go`)
and `pkg/datastore` build on, so the engine-mapping and seal-resolution logic
has exactly one implementation. It has no dependency on `pkg/factor` (which
imports `pkg/xkms`): `EmbeddedNodeOptions.FactorRegistry` is nil by default
(no factor registry — fine for a caller that only wants a KV store); a
caller running a real ceremony builds one explicitly via
`pkg/server.NewNodeFactorRegistry` (kept in `pkg/server`, the only caller
that both needs it and can afford the `pkg/factor` dependency) and passes it
through.

`sdk/go` re-exports `Datastore`, `OpenDatastore(ctx, DatastoreConfig, logger)
(*Datastore, error)` and `DatastoreStorage(daos) (StorageBackend, error)`
(`compose.FactoryBackend`; `sdk/go/datastore.go`), and `NewTPMBlobStore =
store.NewBlobStore` (`sdk/go/tpm.go`), so an embedder configures the identical
datastore an `xkmsd`-hosted deployment uses without importing `pkg/config`/
`pkg/datastore` directly, and feeds `AutoConfig.Datastore` from
`DatastoreStorage(ds.DAOFactory())`.

xkey's `initLocalKeyStore` (`xkey/pkg/gui/app.go`) sources every backend's
key storage from the same barrier-backed `storage.Backend`
(`barrierService.GetBackend()`, under `"keys/"`) every other xkey subsystem
already used (oath, FIDO2, static-password, trust store, OIDC, shares,
sealed blobs, SSH) — not a private file store under the data directory. With
no barrier active, key storage is in-memory/session-only, matching
`AutoInitialize`'s own default, rather than a persisted plaintext fallback.
`registerPKCS11XKMSBackend` (the dynamic PKCS#11 registration path) follows
the identical rule for both its key and certificate storage: the
barrier-backed store when a barrier is active, in-memory/session-only
otherwise — never a dataDir file path either way, so there is no
unencrypted-on-disk fallback anywhere in this function.

The `xkey fido2` CLI's software backend under `--storage barrier`
(`createFIDO2XKMSSoftwareKeyBackend`, `xkey/cmd/xkey/cmd/fido2.go`) opens
the SAME barrier via `openBarrierBackend` (`barrier_store.go`) — the one
low-level unseal every barrier-aware CLI command shares (`oath`, `backup`,
`device oath-sync`, `xkey fido2 ... --storage barrier` itself for its
credential store, via `createBarrierStorage`) — and derives its key storage
from it the same way the GUI does (`"keys/"` prefix). This function is only
reached when the operator explicitly selected barrier storage, so there is
no barrier-absent case to handle: `--storage memory`/`--storage file`
(`createFIDO2SoftwareKeyBackend`'s other branch) already uses a plain
in-memory `storage.Backend` for the non-barrier cases, independent of
`AutoInitialize`.

## Test strategy

- **Unit** — `pkg/config/config_test.go` (`TestValidate_Datastore`,
  `TestDatastoreConfig_Remote`), `pkg/server/storage_factory_qrdb_test.go`,
  `pkg/server/server_coverage_test.go`
  (`TestServer_CreateStorage_DistinctPrefixesOverOneStore`);
  `pkg/embeddednode/embedded_node_test.go`;
  `pkg/datastore/datastore_test.go` (`TestOpen_StandaloneYieldsClientAndDAOFactory`,
  `TestOpen_RejectsBadConfig`, `TestNew_BorrowsTheClient`);
  `pkg/datastore/remote_test.go` (`TestOpen_RemoteYieldsClientAndDAOFactory`
  — REST and gRPC datastores against an in-process TLS node, each reading
  what the other's DAO wrote, in the default and a named database);
  `pkg/datastore/database_test.go` (`TestDatabaseKVStore_CreatesAndScopesDatabase`,
  `TestDatabaseKVStore_Idempotent`, `TestDatabaseKVStore_DAOFactoryServesOpenedDatabase`,
  `TestDatabaseKVStore_BackendOverrideHonoured`, `TestDatabaseKVStore_Refusals`);
  `pkg/dao/dao_test.go`; `pkg/compose/storage_test.go`;
  `pkg/storage/qrdb/kvstore_backend_test.go`;
  `pkg/storage/file/crosslock_test.go` (re-exec'd processes race
  CompareAndSwap on one directory, #1157); `pkg/xkms/auto_test.go` (`TestAutoInitialize_WithDatastore`,
  `TestResolveBackendConfig_WithDatastore`); `pkg/tpm2/store/store_test.go`
  (`TestStorageFactory_NewFactory`); `sdk/go/datastore_test.go`.
- **Integration** (`test/integration/storage/`) — `file_storage_integration_test.go`,
  `memory_storage_integration_test.go`, and the hardware-adapter suites that
  exercise `pkg/storage/hardware` — a distinct certificate-storage adapter,
  not a `Datastore.Engine` choice.
- **Makefile targets** — `test-datastore`, `test-dao`, `test-compose`,
  `test-storage`; `integration-test-storage`.

## Observability

No datastore-specific metrics or audit events exist; engine and mode
selection are logged once at startup
(`s.logger.Info("Initialized standalone datastore", ...)` /
`"Initialized remote datastore"` in `pkg/server/qrdb_storage.go`).
Confidentiality and seal/unseal events are the barrier's audit surface —
see
[`../sealing-and-barrier/engineering.md`](../sealing-and-barrier/engineering.md).
