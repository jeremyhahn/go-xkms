# Storage Engines — Engineering Contract

> **Status: NORMATIVE** · Feature: `storage-engines` · Repo: `go-xkms` · Last verified: 2026-09-29

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
value slice past the call — secret key material stored through this interface
is wiped by the caller immediately after a successful `Put`, and an
implementation that aliased the slice would have it zeroed out from under it.
Every in-tree engine (memory, file, pebble, the qrdb/raft engine, and
objstore) satisfies this; see the doc comment on `Put` for the audited list.

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

### `pkg/storage/engine.go` — the general engine constructor

```go
type EngineKind string
const (
	EngineFile     EngineKind = "file"
	EnginePebble   EngineKind = "pebble"
	EngineMemory   EngineKind = "memory"
	EngineObjstore EngineKind = "objstore"
)

type EngineConfig struct {
	Kind     EngineKind
	Path     string            // required for file/pebble
	Provider string            // objstore only: "local" (default), "memory", "s3", "gcs", ...
	Options  map[string]string // objstore only: provider-specific
}

func OpenEngine(cfg EngineConfig) (Backend, error)
```

`OpenEngine` is the mechanism behind `Server.createStorage`'s `file`/`pebble`/
`memory` cases (indirectly, via `storage.NewPebble`/`NewMemoryBackend`/
`file.New`, which are themselves thin wrappers), and is also called directly
by other composers in this repository:

| Caller | Kind used | Purpose |
|---|---|---|
| `pkg/server/storage_factory.go` (via `storage.NewPebble`/`NewMemoryBackend`/`file.New`) | file / pebble / memory | xkmsd's own metadata store |
| `sdk/go/storage_engine.go` (`StorageOpenEngine` re-export) | file (typically) | downstream SDK consumers |
| `xkey/pkg/sshstore/store.go`, `xkey/pkg/gui/app.go`, `xkey/pkg/gui/services/barrier_service.go`, `xkey/pkg/gui/services/pin_strategy.go` | file / configurable | xkey's own local state (SSH known-hosts, barrier service, PIN strategy) |
| `pkg/acme/client/service/account_manager.go:createStateBackend` | **objstore** | the ACME client's account/order state — the only in-tree caller of `EngineObjstore` |

**`EngineObjstore` is never reached from `config.Storage.Backend`.**
`Server.createStorage` (`pkg/server/storage_factory.go`) has no `"objstore"`
case; setting `storage.backend: objstore` in `xkmsd.yaml` passes
`Config.Validate` (which does not enumerate backend names — see
Configuration below) and then fails at server construction with
`*ErrUnsupportedStorageBackend{Backend: "objstore"}`.

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
`pkg/storage/qrdb` below).

**Every write this type performs — `Put`, `Delete`, `PutIfAbsent`,
`CompareAndSwap`, `CompareAndDelete` — holds an advisory `flock` on a
`.lock` file in the store root for the whole call** (`pkg/storage/file/lock.go`,
#1157). `OpenEngine`'s `engineBackend` (`pkg/storage/engine.go`) already
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

### `pkg/storage/qrdb` — the `"qrdb"` backend's wrapper

```go
func NewBackend(client transport.KVClient) *Backend
```

(`pkg/storage/qrdb/backend.go`.) Reads use follower-read consistency
(`transport.WithConsistency(transport.ConsistencyFollower)`) so a read on any
replica reflects all committed entries without blocking on a leader
`ReadIndex` round trip — the correct level for a key-existence check or health
probe that must never hang on a follower. A `guardedWrites` flag, set once at
construction, reports whether `PutIfAbsent`/`CompareAndSwap`/`CompareAndDelete`
can execute against this client; a clustered backend must implement guarded
writes through Raft consensus, not process-local locking.

### `pkg/server` — the xkmsd-specific factory

```go
func (s *Server) createStorage(subdir string) (storage.Backend, error)
func (s *Server) createStorageAt(path string) (storage.Backend, error)
func (s *Server) initializeQRDBStorage() error   // pkg/server/qrdb_storage.go
```

`createStorage` roots a subsystem's store under `Storage.Path`; `createStorageAt`
opens an absolute path (used for backend key-storage paths configured
independently of the metadata root, e.g. `Backends.Software.Path`). Both
switch on `config.Storage.Backend` with the same four recognized values.

## Invariants

- **One interface, invisible engine choice.** No xkms subsystem above
  `pkg/storage` branches on which engine backs it.
- **The `"qrdb"` backend is a single shared instance.** `initializeQRDBStorage`
  must run once, before the first `createStorage` call; every subdirectory is
  a key-prefixed view (`storage.NewPrefixBackend`) over one backend, and a
  view's `Close` is a no-op — only `Server.Shutdown` closes the real backend.
- **`Config.Validate` does not enumerate storage backend names.** The
  `switch` in `Validate` (see Configuration) only special-cases `"qrdb"`;
  every other value — including a typo, or `"objstore"` — is accepted at
  config-parse time as long as `Storage.Path` is non-empty, and only fails
  later, at server construction, in `createStorage`'s `default` case. This is
  a genuine gap between config-time and runtime validation; do not assume a
  config that parses is a config that will start.
- **Guarded writes are advertised, not assumed.** A caller performing a
  cross-node-safe compare-and-swap must type-assert for `CompareAndSwapper`
  and handle its absence, never assume every `Backend` has it.

## Error semantics

| Error | Where | Meaning |
|---|---|---|
| `*ErrUnsupportedStorageBackend{Backend}` | `pkg/server/errors.go` | `config.Storage.Backend` (or `Storage.QRDB.Transport`, prefixed `"qrdb:"`) names an engine `createStorage`/`initializeQRDBStorage` does not implement |
| `ErrNotFound` | `pkg/storage/errors.go` | `Get`/`Delete` against an absent key |
| `ErrClosed` | `pkg/storage/errors.go`, `engine.go:mapErr` | an operation reached a closed go-qrdb engine; translated from `*qrdbsdk.StorageClosedError` so `errors.Is(err, ErrClosed)` holds across the adapter |
| `*EngineError{Op, Key, Err}` | `pkg/storage/engine.go` | any other go-qrdb engine failure, wrapped with the operation and key for diagnosis; unwraps to the engine's own error |
| `ErrEnginePathRequired` | `pkg/storage/errors.go` | `OpenEngine` called with `Kind` file/pebble and an empty `Path` |
| `ErrUnknownEngine` | `pkg/storage/errors.go` | `OpenEngine` called with an unrecognized `Kind` |

## Configuration

`Config.Storage` (`pkg/config/config.go`), yaml key `storage:`:

```go
type StorageConfig struct {
	Backend string     `yaml:"backend"`
	Path    string     `yaml:"path"`
	QRDB    QRDBConfig `yaml:"qrdb"`
}
type QRDBConfig struct {
	Address   string    `yaml:"address"`   // remote cluster endpoint, e.g. "https://localhost:63002"
	Transport string    `yaml:"transport"` // "embedded" (default), "rest", or "grpc"
	TLS       TLSConfig `yaml:"tls"`
}
```

`Config.Validate` (`pkg/config/config.go`, ~line 1456):

- An empty `Backend` defaults to `"pebble"` — the comment is explicit that a
  production path must never silently fall back to a non-durable store.
- `Backend == "qrdb"`: `QRDB.Transport` defaults to `"embedded"`.
  `"embedded"` requires `Storage.Path` non-empty (the node persists under it).
  `"rest"`/`"grpc"` require `QRDB.Address` non-empty (a remote cluster is
  dialed instead of hosting a node). Any other transport value is a hard
  error.
- Every other `Backend` value (including one `createStorage` will later
  reject) only requires `Storage.Path` non-empty.

Two other Validate rules key off `Storage.Backend` directly and matter for
this feature's neighbors:

- Network protocols (REST/gRPC/QUIC/MCP) require `Storage.Backend == "qrdb"`
  — "the embedded qrdb node is the unified API server" (`config.go` ~line
  1343). A `file`/`pebble`/`memory` deployment is Unix-socket-only.
- `Cluster.Enabled` requires `Storage.Backend == "qrdb"` (`config.go` ~line
  1585) — see [`../clustering/architecture.md`](../clustering/architecture.md).

Environment variables follow the general `XKMS_<PATH>` rule (nesting joined
by underscores — `pkg/config/load.go`): `XKMS_STORAGE_BACKEND`,
`XKMS_STORAGE_PATH`, `XKMS_STORAGE_QRDB_TRANSPORT`,
`XKMS_STORAGE_QRDB_ADDRESS`.

Real examples from this repository:

```yaml
# configs/xkmsd.yaml — durable single-node default
storage:
  # Durable embedded PebbleDB by default. Use "file" for one plain file per key
  # (human-inspectable), "qrdb" to share the hosted node, or "memory" for tests.
  backend: "pebble"
  path: "xkms-data/storage"
```

```yaml
# test/integration/cluster/config.node.yaml — the qrdb backend, embedded transport
storage:
  backend: "qrdb"
```

There is **no built-in default for `Storage.Path`** (`Defaults()` in
`pkg/config/load.go` does not set it); every non-empty-string backend
requires it explicitly, from the file, `XKMS_STORAGE_PATH`, or (for
`xkmsd init` specifically) the `--data-dir` flag
(`cmd/xkmsd/init_node.go`).

## Persistence

All persistent xkms state — keys, users, CA serials and revocations, audit
records, seal blobs, and everything else — goes through the same `Backend`
interface, so the shape of what is stored never depends on which engine
backs it. The `file` engine writes one file per key in a flat
`<path>/<key>` layout, matching xkms's historical on-disk format (no
migration needed when adopting it). `pebble` maintains its own internal
LSM files under `<path>`; do not hand-edit that directory. `memory` persists
nothing. `qrdb`'s persistence is the embedded or remote node's own — see
[`../clustering/architecture.md`](../clustering/architecture.md).

**Switching `storage.backend` on an existing deployment does not migrate
data.** Nothing in this repository reads one engine's format and writes
another's; a changed backend starts a new, empty store.

## Test strategy

- **Unit** — `pkg/storage/engine_test.go`, `engine_objstore_test.go`,
  `engine_compareanddelete_faults_test.go`; `pkg/server/storage_factory_qrdb_test.go`;
  `pkg/config/storage_default_test.go`; `pkg/storage/file/crosslock_test.go`
  (`TestFileStorage_CompareAndSwap_ConcurrentAccumulates` for the
  single-process case, `TestFileStorage_CompareAndSwap_CrossProcessAccumulates`
  re-execing worker processes for the cross-process guarantee, #1157);
  `pkg/pkcs11/module/storage_crossprocess_test.go`
  (`TestModuleStorage_FailedAttemptCounter_CrossProcessAccumulates`, the same
  property against the PIN attempt counter itself).
- **Integration** (`test/integration/storage/`) — `file_storage_integration_test.go`,
  `memory_storage_integration_test.go`, and the hardware-adapter suites
  (`hardware_storage_integration_{pkcs11,tpm2}_test.go` and their `_hw_` and
  `_nopkcs11` variants) that exercise `pkg/storage/hardware` — a distinct
  certificate-storage adapter, not a `Storage.Backend` engine choice.
- **Makefile targets** — `test-storage`; `integration-test-storage`
  (`integration-test-storage-file`, `-memory`, `-hardware`,
  `-hardware-pkcs11`, `-hardware-tpm2`).

## Observability

No storage-engine-specific metrics or audit events exist; engine selection is
logged once at startup (`s.logger.Info("Initialized ... storage", ...)` in
`pkg/server/qrdb_storage.go` for the `qrdb` backend). Confidentiality and
seal/unseal events are the barrier's audit surface — see
[`../sealing-and-barrier/engineering.md`](../sealing-and-barrier/engineering.md).
