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
- `"remote"` → `newRemoteQRDBStorage(transport)` dials
  `Datastore.Remote.Address` over `Datastore.Remote.Transport` (`rest` or
  `grpc`) with `Datastore.Remote.TLS`, and `s.qrdbStorage` wraps the remote
  KV client. An unrecognized transport returns
  `*ErrUnsupportedStorageBackend{Backend: "qrdb:" + transport}`.
- anything else → `*ErrUnsupportedDatastoreMode{Mode}` — unreachable through
  `config.Validate`, defense-in-depth for an embedded caller that constructs
  a `*config.Config` without validating it.

### `pkg/server/embedded_node.go` — mapping the datastore onto go-qrdb's own config

```go
func EmbeddedNodeStorageConfig(cfg *config.Config, sealRes ResolvedNodeSeal) *qrdbsdk.DaemonConfig
```

The single place `Datastore.Engine`/`Datastore.Path` become go-qrdb's own
`qrdbsdk.DaemonDatabaseConfig`:

```go
qcfg.Raft.DataDir = cfg.Datastore.Path
qcfg.Databases = []qrdbsdk.DaemonDatabaseConfig{
	{Name: "default", Engine: "mvcc", Backend: cfg.Datastore.Engine}, // memory | file | pebble
}
```

Both `(*Server).initEmbeddedQRDBNode` (`xkmsd run`) and `xkmsd init`'s
`openDurableInitNode` derive their qrdb daemon config through this one
function (`ResolveNodeSeal` + `EmbeddedNodeStorageConfig` +
`daemon.NewNode`), so the two opens of one on-disk datastore can never
disagree about the database engine or the seal strategy.

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
  (`standalone` needs `Path` unless `Engine == "memory"`; `remote` needs
  `Remote.Address` and a `Remote.Transport` of `rest` or `grpc`). A config
  that parses is now a config that will open its datastore.
- **Guarded writes are advertised, not assumed.** A caller performing a
  cross-node-safe compare-and-swap must type-assert for `CompareAndSwapper`
  and handle its absence, never assume every `Backend` has it.

## Error semantics

| Error | Where | Meaning |
|---|---|---|
| `*errs.Message` from `config.Validate` | `pkg/config/config.go` | `datastore.engine` not one of memory/file/pebble, `datastore.mode` not one of standalone/remote, or a mode-specific requirement (path, remote address/transport) unmet |
| `*ErrUnsupportedStorageBackend{Backend: "qrdb:" + transport}` | `pkg/server/errors.go`, `qrdb_storage.go` | `datastore.remote.transport` names a transport `newRemoteQRDBStorage` does not implement (only reachable by bypassing `config.Validate`) |
| `*ErrUnsupportedDatastoreMode{Mode}` | `pkg/server/errors.go`, `qrdb_storage.go` | `datastore.mode` is neither `standalone` nor `remote` (only reachable by bypassing `config.Validate`) |
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
- `Mode == "standalone"`: `Path` is required unless `Engine == "memory"`.
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
`pkg/config/load.go` does not set it); a `"standalone"` deployment with a
non-`"memory"` engine requires it explicitly, from the file,
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

All four resolve their root from `cfg.Datastore.Path`, not a separate
configuration knob — there is still exactly one path an operator names.

## What is explicitly OUT of scope for this feature (tracked as follow-up)

The SDK/library composition path builds a standalone `*xkms.XKMSService`
without a `*Server`, so it never reaches `createStorage`, and still
hardcodes `pkg/storage/file.New` directly:

- `pkg/xkms/register_pkcs8.go`, `register_software.go`,
  `register_symmetric.go`, `register_tpm2.go`
- `pkg/xkms/auto.go` (`AutoInitialize`)

Unifying these onto the one configurable datastore needs an API these
callers can receive a `storage.Backend`/KV-store handle through — most
naturally, a `datastore.Backend` (or similar) parameter threaded into
`AutoInitialize`/the `register_*` constructors, sourced from the same
`config.DatastoreConfig` this feature defines, so a library consumer gets
the identical engine/mode choice an `xkmsd`-hosted deployment gets. That is
a signature change to a public constructor surface and is left to a
follow-up batch.

## Test strategy

- **Unit** — `pkg/config/config_test.go` (`TestValidate_Datastore`,
  `TestDatastoreConfig_Remote`), `pkg/server/storage_factory_qrdb_test.go`,
  `pkg/server/server_coverage_test.go`
  (`TestServer_CreateStorage_DistinctPrefixesOverOneStore`).
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
