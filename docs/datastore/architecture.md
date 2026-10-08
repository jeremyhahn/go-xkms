# Datastore — Architecture

> **Status: NORMATIVE** · Feature: `datastore` · Repo: `go-xkms` · Last verified: 2026-10-08

## The problem

Every xkmsd process needs somewhere to persist keys, users, RBAC state, CA
serials and revocations, audit records, ACME state, and everything else the
server owns. Before this feature, `storage.backend` let an operator pick
`"file"`, `"pebble"`, or `"memory"` as an alternative to `"qrdb"` — and each
of those alternatives built its **own private, unreplicated storage engine
per xkms subsystem** (`pkg/server/storage_factory.go`'s old `createStorage`
switch), bypassing the barrier, RBAC's identity plane, and clustering
entirely, and writing to disk in the clear by default. `"qrdb"` was the odd
one out: the only choice that went through go-qrdb at all.

That was backwards. Per this repository's ownership boundary (`CLAUDE.md`
"Layer Ownership"), go-xkms ships **no state machine or KV store of its
own** — that is go-qrdb's — so a "storage backend" that skips go-qrdb was
always a second, parallel, unreplicated database the daemon happened to
carry. This feature deletes it: xkms now has exactly **one global datastore**,
always go-qrdb-backed, and every subsystem stores through it.

## Shape chosen: one datastore, a configurable local engine, two topologies

`config.DatastoreConfig` (`pkg/config/config.go`, yaml key `datastore:`)
describes the single datastore the whole server uses:

```go
type DatastoreConfig struct {
	Engine string                 `yaml:"engine"` // "memory" | "file" | "pebble" (default)
	Path   string                 `yaml:"path"`
	Mode   string                 `yaml:"mode"`   // "standalone" (default) | "remote"
	Remote DatastoreRemoteConfig  `yaml:"remote"`
}
```

- **`Engine`** selects the local storage engine go-qrdb uses when this
  process hosts the datastore. It maps directly onto go-qrdb's own
  per-database engine vocabulary (`qrdbsdk.DaemonDatabaseConfig.Backend`,
  itself `"memory" | "file" | "pebble"`) — xkms never invents a parallel
  engine enum, and never selects an engine anywhere except through this one
  field (`pkg/embeddednode/embedded_node.go`'s `EmbeddedNodeStorageConfig`).
  Only meaningful when `Mode` is `"standalone"`. `Path` is required for
  every `Engine`, `"memory"` included — see `Path` below; this is go-qrdb's
  own contract, adopted exactly, not an xkms-invented requirement.
- **`Mode`** selects the datastore's topology:
  - `"standalone"` (default) hosts the qrdb engine in this process — the
    single core that also serves identity, bootstrap, and (optionally, via
    `Cluster.Enabled`) Raft clustering. See
    [`../clustering/architecture.md`](../clustering/architecture.md).
  - `"remote"` dials an already-running, externally-hosted qrdb cluster
    instead of hosting one here (`Datastore.Remote`: address, transport
    `rest`/`grpc`, TLS).
- **Barrier encryption-at-rest is a separate, orthogonal axis**
  (`config.BarrierConfig`) that layers over the datastore regardless of
  `Engine` or `Mode` — see
  [`../sealing-and-barrier/architecture.md`](../sealing-and-barrier/architecture.md).

```
datastore.mode: "standalone" (default)
  → Server hosts the embedded qrdb node in-process
  → datastore.engine ("memory" | "file" | "pebble") picks the node's
    local database engine (EmbeddedNodeStorageConfig → Databases[0].Backend)
  → optionally a Raft cluster member (cluster.enabled: true)

datastore.mode: "remote"
  → Server dials datastore.remote.address over datastore.remote.transport
    (rest | grpc), with datastore.remote.tls
  → no local engine: this process hosts no node, the remote cluster does
```

## What the datastore hands out: the go-qrdb client and a DAO factory

`datastore.Open` (`pkg/datastore/datastore.go`) returns a `*Datastore`, in
both modes, carrying exactly two things:

```go
func Open(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*Datastore, error)
func New(client *qrdbsdk.Client, cfg config.DatastoreConfig, opts ...Option) (*Datastore, error)

func (d *Datastore) Client() *qrdbsdk.Client
func (d *Datastore) DAOFactory() *qrdbsdk.DAOFactory
func (d *Datastore) DatabaseKVStore(ctx context.Context, name string) (qrdbsdk.KVStore, error)
func (d *Datastore) Close() error
```

- **`Client()`** is the go-qrdb SDK client: the embedded node's own client
  in standalone mode, the dialed REST or gRPC client in remote mode.
- **`DAOFactory()`** is go-qrdb's DAO factory
  (`qrdbsdk.NewDAOFactoryWithConfig`). Its default store is
  `Client().KVStore()` — the `"default"` database. Its partitioned provider
  serves each named database this datastore has opened
  (`DatabaseKVStore`), and nothing else.

Features depend on persistence only through that factory and go-qrdb's
`GenericDAO[E]` — never through a KV store or raw keys — so the storage
underneath a feature can change (a SQL-backed DAO, say) without touching
the feature. The one constructor is `dao.New` (`pkg/dao/dao.go`):

```go
func New[E qrdbsdk.Entity](factory *qrdbsdk.DAOFactory, database, entityType string,
	newEntity func() E, opts ...qrdbsdk.DAOOption) (qrdbsdk.GenericDAO[E], error)
```

It exists because the go-qrdb SDK builds a `GenericDAO` only from a
`KVStore` (`qrdbsdk.NewDAO`); it has no constructor that takes the factory.
`dao.New` keeps that one `KVStore` lookup in one place. It refuses an
unopened named database (`*dao.DatabaseUnavailableError`) instead of
falling back to the default database, which is what the factory itself
would do.

`New` builds a `Datastore` over a client someone else owns: `pkg/server`
hands it the embedded node's client, and the API-module host hands it the
host's client. `Close` releases only what `Open` built — the node or the
dialed client — and is a no-op for `New`.

## Feature-owned databases: one node, more than one named database

"One datastore" above is a statement about **engines and nodes**, not about
go-qrdb's own database count: there is exactly one go-qrdb node (one
barrier, one RBAC plane, one Raft cluster membership), and a feature that
wants isolation from the shared `"default"` database gets it by asking that
ONE node for another go-qrdb-native database, by name — never by building a
second engine, node, or client outside go-qrdb. This is narrower than, and
does not reopen, the invariant in "What this feature deliberately does not
do" below: it is still true that no subsystem builds `storage.NewPebble`,
`storage.NewMemoryBackend`, or `file.New` directly, and still true that
`pkg/server` has no per-subsystem engine switch.

A feature package (e.g. `pkg/oidc`) names its database as a code constant
(`oidc.DatabaseName == "oidc"`). The composition root opens it with
`Datastore.DatabaseKVStore(ctx, name)`, which:

1. ensures the named database exists, creating it through go-qrdb's own
   `Client.Database().CreateDatabase` with the backend `Datastore.Databases`
   names for it, or `Datastore.Engine` otherwise;
2. scopes the client to it (`Client.DatabaseScoped(name).KVStore()`);
3. caches the store, so a second call returns the same one and the DAO
   factory serves it from then on.

`Client.DatabaseScoped` is a capability of the go-qrdb SDK client itself,
implemented by the embedded transport and by every network transport, so a
feature never branches on standalone vs. remote: the same DAO code runs
either way.

**Not every subsystem needs this.** Most of xkms's state (keys, users, RBAC,
CA serials, audit) has no reason to leave the shared `"default"` database
and stays exactly where "Component boundaries" below describes. A named
database is for a feature whose DAO/entity shape benefits from living apart
from that shared keyspace (its own entity namespace, its own backend
override for operational reasons) — today, `pkg/oidc`'s token cache; see
[`../oidc-credentials/architecture.md`](../oidc-credentials/architecture.md).

xkey, which hosts no go-qrdb node (see "What this feature deliberately does
not do" below), has no `Datastore`. It reaches go-qrdb's DAO layer a
different way: adapting its own barrier-backed `storage.Backend` to a
`qrdbsdk.KVStore` (`sdk/go.NewKVStoreAdapter`, wrapping
`pkg/storage/kvadapter`) and serving that one store as a DAO factory for
every database (`sdk/go.NewStoreDAOFactory`, i.e. `dao.NewStoreFactory`),
which it hands to the feature's DAO constructor. Same DAO code, same
factory seam, no go-qrdb node required — see
`xkey/pkg/gui/services/oidc_service.go`'s `SetBackend`.

## Features still on `storage.Backend`

Features not yet converted to DAOs persist through a `storage.Backend`. Two
bridges serve them, both over the same datastore:

- **`pkg/server`** keeps `qrdbstorage.NewBackend(Client().KV())` as the
  one shared backend under `createStorage`. It sits on the client's KV
  rather than the DAO factory because the seal barrier's views need fenced
  creates (`storage.FencedCreator`), and the SDK's `KVStore` does not carry
  them.
- **`compose.FactoryBackend` / `compose.FactoryStorage`**
  (`pkg/compose/storage.go`) build a `storage.Backend` over the DAO
  factory's default store (`qrdbstorage.NewKVStoreBackend`), and per-feature
  prefixed views over it. The API-module host's `"xkms/"` stores and the
  SDK's `DatastoreStorage` use this bridge.

## Component boundaries

| Piece | Where | Owner |
|---|---|---|
| `storage.Backend` interface, guarded-write capability interfaces | `pkg/storage/interface.go`, `guardedwrites.go` | go-xkms |
| `config.DatastoreConfig` / `DatastoreRemoteConfig` (the `datastore:` section; `databases:` entries are go-qrdb's own `qrdbsdk.DaemonDatabaseConfig`) | `pkg/config/config.go` | go-xkms |
| `Server.createStorage` / `createStorageAt` — ALWAYS a prefixed view over the one shared datastore, never a private engine | `pkg/server/storage_factory.go` | go-xkms |
| `datastore.Datastore` — the go-qrdb client plus the DAO factory; `Datastore.DatabaseKVStore` is a feature's one way to reach its own named go-qrdb database, within the SAME node/barrier/cluster | `pkg/datastore/` | go-xkms (composition root) / go-qrdb (the client, the DAO factory, the database and `DatabaseScoped`) |
| `dao.New` — the one place a `GenericDAO` is built from the DAO factory | `pkg/dao/dao.go` | go-xkms |
| `compose.FactoryBackend` / `FactoryStorage` — a `storage.Backend`, and prefixed per-feature views, over the DAO factory for features not yet on DAOs | `pkg/compose/storage.go` | go-xkms |
| `Server.initializeQRDBStorage` — builds the one shared datastore (standalone or remote) for an xkmsd-hosted deployment | `pkg/server/qrdb_storage.go` | go-xkms |
| `datastore.Open` / `datastore.DialRemote` — the Server-independent way to open the datastore (the SDK/library composition path); `Server.initializeQRDBStorage`'s remote branch calls `Open` too, so there is exactly one remote-dial implementation | `pkg/datastore/` | go-xkms |
| `embeddednode.OpenEmbeddedNode` / `EmbeddedNodeStorageConfig` — maps `Datastore.Engine`/`Path` onto the qrdb node's own daemon config; the shared embedded-node builder `pkg/server` and `pkg/datastore` both build on | `pkg/embeddednode/` | go-xkms |
| The embedded qrdb node itself, its local engines, and all clustering | go-qrdb SDK, `pkg/server/qrdb_node*.go`, `pkg/embeddednode` | go-xkms composes; go-qrdb implements — see [`../clustering/architecture.md`](../clustering/architecture.md) |
| Prefix / namespace / sealed adapter views over a `Backend` | `pkg/storage/prefix.go`, `namespace.go`, `pkg/storage/sealed` | go-xkms |
| `pkg/xkms.AutoConfig.Datastore` / `register_*` factories' `"key_storage"` key — the SDK/library composition path's own storage seam, fed a `storage.Backend` handle (e.g. `compose.FactoryBackend` over an open datastore's DAO factory) by its caller | `pkg/xkms/auto.go`, `register_*.go` | go-xkms |

## Data flow

```
xkmsd boot:
  cfg.Validate() defaults and validates datastore.engine / datastore.mode
    → Server.initializeQRDBStorage() runs ONCE, early, before any
      createStorage call:
        mode standalone → hosts the embedded qrdb node (identity, bootstrap,
                           barrier, optional Raft); s.datastore borrows its
                           client (datastore.New)
        mode remote      → dials the external cluster (datastore.Open);
                           s.datastore owns the dialed client
        either way       → s.qrdbStorage wraps s.datastore.Client().KV();
                           standalone binds each call to the node's
                           service principal, remote runs as xkms's mTLS
                           client identity
    → every xkms subsystem calls Server.createStorage("<subdir>") (keys,
      users, RBAC, CA serials/revocations, audit, seal
      blobs, ACME state, ...)
    → each call returns a key-prefixed view (storage.NewPrefixBackend) over
      the SAME s.qrdbStorage — never a private, per-subsystem engine
```

`createStorage`/`createStorageAt` cannot fail on an unrecognized engine or
backend name anymore — there is nothing left to switch on. An invalid
`datastore.engine` or `datastore.mode` is refused earlier, at
`config.Validate()`, with a typed `*errs.Message` (see engineering.md).

## Trust boundaries

- **The engine choice is not a security boundary by itself.** Confidentiality
  at rest comes from the barrier
  ([`../sealing-and-barrier/architecture.md`](../sealing-and-barrier/architecture.md)),
  which layers over the datastore however it is configured. An unsealed
  barrier over any engine still yields keys in the clear; a sealed one
  protects them regardless of engine.
- **`memory` is non-durable by design** and every key, user, and certificate
  in it disappears on process exit — appropriate for tests, never for a
  deployment that must survive a restart. `Path` is still required with
  `engine: memory` (see above): go-qrdb roots the node's on-disk state under
  it regardless of the primary KV engine, so a memory-engine deployment
  still resolves `Path`, points it at a real (typically ephemeral, e.g.
  `t.TempDir()`) directory, and gets non-durable KV data with that
  directory as the only trace left behind.
- **Network protocols and RBAC no longer require a specific engine or
  mode combination the way the old `"qrdb"` backend did — they require the
  datastore to be hosted in this process.** REST/gRPC/QUIC/MCP require
  `datastore.mode == "standalone"` (`pkg/config/config.go` `Validate`, via
  `NetworkServing`) because the embedded qrdb node is the unified API
  server; RBAC's authorizer is now always buildable, in either mode, because
  every deployment is qrdb-backed (`config.ComplianceGaps` no longer reports
  the old "RBAC without an identity plane" gap — see engineering.md).
  `Cluster.Enabled` requires `datastore.mode == "standalone"` for the same
  reason — see [`../clustering/architecture.md`](../clustering/architecture.md).
- **xkms's own calls run as a named, least-privilege principal, never as
  an ambient one.** The embedded node refuses a call that carries no
  identity. xkms's own persistence and coordination run as the node's
  service principal `xkms`, whose grant is exactly what they use. Calls made
  for a request keep the request's identity, so the principal never widens
  what a caller can do. The grant and call sites are in engineering.md.
  Persisting through the shared backend as the principal mirrors remote
  mode, where the same calls already run as xkms's own client certificate.
  Rejected: wrapping the SDK `KVStore`, which would hide go-qrdb's optional
  guarded-write interfaces.

## What this feature deliberately does not do

- **It does not implement a consensus engine, a state machine, or a KV
  store.** Every engine byte is go-qrdb's; xkms selects and opens one.
- **It does not let a subsystem opt out of the shared datastore.** There is
  no per-subsystem storage configuration left in `pkg/server` that builds a
  private engine, node, or client outside go-qrdb — a feature that needs
  one is a design smell this feature closed the door on (go-xkms#1345). A
  feature's own NAMED go-qrdb DATABASE within the one shared node
  ("Feature-owned databases" above) is not that: it is still the one node,
  one barrier, one RBAC plane, one cluster, reached through go-qrdb's own
  multi-database primitive, with an operator override confined to the one
  thing go-qrdb itself lets a database choose independently (its backend) —
  never a second storage engine, config language, or construction path.
- **It does not migrate data between engines or modes.** Switching
  `datastore.engine` or `datastore.mode` on an existing deployment starts a
  new, empty store; nothing in this repository reads one engine's on-disk
  format and writes another's.
- **It does not cover the small set of genuinely pre-datastore material.**
  The node's own Raft data directory, the TPM-sealed pre-barrier blobs under
  `pkg/trust/clusterca`, the bootstrap TLS certificate cache
  (`pkg/server/unified_tls.go`), and the first-boot administrator credential
  (`pkg/server/firstboot.go`) all still resolve paths directly under
  `Datastore.Path` — they exist *before* the datastore they eventually
  promote into is available to open, by construction, not by choice. See
  engineering.md's "Genuinely pre-datastore material" section.
- **It does not absorb secrets whose job is to leave the server as a file**
  (`--output` exports, ACME client cert/key deploy to a web-server path, the
  first-boot admin credential's generate-and-distribute copy) — go-xkms#1323,
  2026-09-30 ruling. See engineering.md's "Secrets that intentionally leave
  the server" section.
- **The SDK/library composition path (`pkg/xkms/register_*.go`,
  `pkg/xkms/auto.go`) is unified onto the same shared datastore as of
  go-xkms#1345 batch 2** — but through a `storage.Backend` handle
  (`AutoConfig.Datastore`), not a `config.DatastoreConfig` parameter: that
  path builds a standalone `*xkms.XKMSService` without a `*Server`, and
  `pkg/xkms` cannot import `pkg/config` (which already transitively imports
  `pkg/xkms` via `pkg/ca`) or `pkg/server` (which imports `pkg/xkms`
  directly). The caller opens the datastore (`pkg/datastore.Open`, or
  `sdk/go`'s `OpenDatastore` re-export) and hands over a `storage.Backend`
  over its DAO factory (`compose.FactoryBackend`, or `sdk/go`'s
  `DatastoreStorage`);
  see engineering.md's "The SDK/library composition path" section.
