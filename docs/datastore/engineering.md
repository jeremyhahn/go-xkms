# Datastore — Engineering Contract

> **Status: NORMATIVE** · Feature: `datastore` · Repo: `go-xkms` · Last verified: 2026-09-29

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
  process (identity, bootstrap, barrier, optional Raft clustering) and
  `s.qrdbStorage` wraps the node's own KV client
  (`qrdbstorage.NewBackend(s.qrdbClient.KV())`).
- `"remote"` → `datastore.DialRemote(s.ctx, s.config.Datastore.Remote)`
  (`pkg/datastore/remote.go`) dials `Datastore.Remote.Address` over
  `Datastore.Remote.Transport` (`rest` or `grpc`) with `Datastore.Remote.TLS`,
  and `s.qrdbStorage` wraps the remote KV client. An unrecognized transport
  returns `*datastore.ErrUnsupportedStorageBackend{Backend: "qrdb:" + transport}`.
  `DialRemote` is the single remote-dial implementation in the stack: the
  SDK/library composition path's `pkg/datastore.Open` calls the SAME
  function for its own `"remote"` case.
- anything else → `*datastore.ErrUnsupportedDatastoreMode{Mode}` —
  unreachable through `config.Validate`, defense-in-depth for an embedded
  caller that constructs a `*config.Config` without validating it.

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
+ `EmbeddedNodeStorageConfig`, and for the latter two, `OpenEmbeddedNode` +
`daemon.NewNode`), so the different opens of one on-disk datastore can never
disagree about the database engine or the seal strategy. `pkg/embeddednode`
was split out of `pkg/server` in go-xkms#1345 batch 2 specifically so
`pkg/datastore` (which `pkg/server` also imports, for `DialRemote`) could
reach it without an import cycle back through `pkg/server`.

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
| `*errs.Message` from `config.Validate` | `pkg/config/config.go` | `datastore.engine` not one of memory/file/pebble, `datastore.mode` not one of standalone/remote, `datastore.path` unset for `mode: standalone` (every engine, `memory` included -- go-qrdb roots the node's on-disk state under it regardless of the primary KV engine, so there is no engine choice that waives this), or a `mode: remote` requirement (address, transport) unmet |
| `*datastore.ErrUnsupportedStorageBackend{Backend: "qrdb:" + transport}` | `pkg/datastore/remote.go`, used by both `pkg/server/qrdb_storage.go` and `pkg/datastore.Open` | `datastore.remote.transport` names a transport `DialRemote` does not implement (only reachable by bypassing `config.Validate`) |
| `*datastore.ErrUnsupportedDatastoreMode{Mode}` | `pkg/datastore/errors.go` | `datastore.mode` is neither `standalone` nor `remote` (only reachable by bypassing `config.Validate`) |
| `*datastore.ErrOpenDatastore{Mode, Err}` | `pkg/datastore/datastore.go` | `Open` (the SDK/library path) failed to build the datastore in the named mode; `Err` is the underlying cause |
| `*embeddednode.NodeSealError{Reason, Err}` | `pkg/embeddednode/errors.go` | the node barrier is configured to encrypt the data plane but the required auto-unseal material cannot be resolved |
| `*embeddednode.ErrDatastorePathRequired{Reason}` | `pkg/embeddednode/errors.go` | `Datastore.Path` is unset for a standalone datastore -- either generally (`Open`'s own check, `Reason: "the standalone datastore"`) or specifically to derive the TPM2 node-barrier seal strategy's key directory (`Reason: "the TPM2 seal key directory"`) |
| go-qrdb's `lifecycle.EmptyVectorDataDirError` | go-qrdb `pkg/server/lifecycle` (not an xkms type; this repository never constructs or catches it directly) | the underlying go-qrdb failure `datastore.path` being required prevents: go-qrdb's node builder unconditionally roots its vector-storage subsystem under the node's data directory regardless of the primary KV engine, so an empty directory fails the node build outright. `config.Validate` and `pkg/datastore.Open` both refuse an empty `Datastore.Path` for `mode: standalone` before this can be reached, adopting the constraint rather than working around it -- see "Configuration" below |
| `ErrNotFound` | `pkg/storage/errors.go` | `Get`/`Delete` against an absent key |
| `ErrClosed` | `pkg/storage/errors.go` | an operation reached a closed go-qrdb engine |

## Configuration

`Config.Datastore` (`pkg/config/config.go`), yaml key `datastore:`:

```go
type DatastoreConfig struct {
	Engine string                `yaml:"engine"` // "memory" | "file" | "pebble" (default)
	Path   string                `yaml:"path"`
	Mode   string                `yaml:"mode"`   // "standalone" (default) | "remote"
	Remote DatastoreRemoteConfig `yaml:"remote"`
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
- Any other `Engine` or `Mode` value is a hard error naming the field and
  the accepted values.

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
ONE storage path: `KeyStorage storage.Backend` (required; `Validate` returns
`ErrKeyStorageRequired` when nil), not a `KeyDir` string this package
resolves a private, directory-based engine from itself. `pkg/server`'s TPM2
crypto-backend wiring (`initTPM2Backend`, `backend_tpm2.go`) passes a
`createStorage("tpm2")` view as `KeyStorage`, so this backend's key blobs
are a key-prefixed view over the SAME shared datastore every other
subsystem uses, not a second, private engine. `Backend.ListKeys` enumerates
via `KeyStorage.List` accordingly. The sole exception is
`NewBackendWithTPM`/`ExternalTPMConfig` (sharing an already-open TPM
connection with the node-barrier seal strategy or the platform store):
`ExternalTPMConfig.KeyDir` stays a real, optional directory hint for
enumeration, because that key material is genuinely pre-datastore (the
node-barrier seal strategy's own key, which must exist before -- and can
seal -- the datastore it protects; see "Genuinely pre-datastore material"
above and `pkg/seal/autodetect.go`'s `openTPM2Backend`, which resolves that
directory to a file-based `storage.Backend` before handing it to `Config`
as `KeyStorage`). `pkg/tpm2/store.NewFactory(logger, backend)` builds a
`StorageFactory` over any `storage.Backend` (`NewStorageFactory`/
`NewMemoryStorageFactory` now call it internally instead of duplicating the
blob/key-backend wiring).

`pkg/xkms` cannot import `pkg/config`, `pkg/datastore` or `pkg/server`
directly (`pkg/config` already transitively imports `pkg/xkms` via
`pkg/ca`, and `pkg/server` imports `pkg/xkms` directly) — this is why the
seam is a plain `storage.Backend` handle, not a `config.DatastoreConfig`
parameter: the caller (`pkg/server`, `sdk/go`, `xkey`, `cmd/xkmsd`) opens the
datastore and hands over the resulting handle.

```go
func Open(ctx context.Context, cfg *config.Config, logger *slog.Logger) (storage.Backend, error)
```

(`pkg/datastore/datastore.go`.) The Server-independent counterpart to
`Server.initializeQRDBStorage` for exactly this caller-without-a-`*Server`
case: `"standalone"` hosts an embedded qrdb node via
`embeddednode.OpenEmbeddedNode`; `"remote"` dials via `datastore.DialRemote`
— the SAME function `Server.initializeQRDBStorage`'s own remote branch now
calls, so there is exactly one remote-dial implementation. `"standalone"`
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

`sdk/go` re-exports `OpenDatastore(ctx, DatastoreConfig, logger)
(StorageBackend, error)` (`sdk/go/datastore.go`) and `NewTPMFactory =
store.NewFactory` (`sdk/go/tpm.go`) so an embedder configures the identical
datastore an `xkmsd`-hosted deployment uses without importing `pkg/config`/
`pkg/datastore` directly; `AutoConfig`/`AutoInitialize` already aliased
`pkg/xkms`'s types, so `Datastore` needed no SDK-side change.

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
  `pkg/embeddednode/embedded_node_test.go`; `pkg/datastore/datastore_test.go`; `pkg/storage/file/crosslock_test.go` (re-exec'd processes race
  CompareAndSwap on one directory, #1157)
  (`TestOpen_StandaloneMemoryEngine`, remote-dial and unsupported-mode
  cases); `pkg/xkms/auto_test.go` (`TestAutoInitialize_WithDatastore`,
  `TestResolveBackendConfig_WithDatastore`); `pkg/tpm2/store/store_test.go`
  (`TestStorageFactory_NewFactory`); `sdk/go/datastore_test.go`.
- **Integration** (`test/integration/storage/`) — `file_storage_integration_test.go`,
  `memory_storage_integration_test.go`, and the hardware-adapter suites that
  exercise `pkg/storage/hardware` — a distinct certificate-storage adapter,
  not a `Datastore.Engine` choice.
- **Makefile targets** — `test-storage`; `integration-test-storage`.

## Observability

No datastore-specific metrics or audit events exist; engine and mode
selection are logged once at startup
(`s.logger.Info("Initialized standalone datastore", ...)` /
`"Initialized remote datastore"` in `pkg/server/qrdb_storage.go`).
Confidentiality and seal/unseal events are the barrier's audit surface —
see
[`../sealing-and-barrier/engineering.md`](../sealing-and-barrier/engineering.md).
