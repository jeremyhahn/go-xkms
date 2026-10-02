# Datastore — Architecture

> **Status: NORMATIVE** · Feature: `datastore` · Repo: `go-xkms` · Last verified: 2026-10-02

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

```go
func DatabaseKVStore(ctx context.Context, backend storage.Backend, cfg *config.Config, name string) (qrdbsdk.KVStore, error)
```

(`pkg/datastore/database.go`.) A feature package (e.g. `pkg/oidc`) declares
its database's name as a code constant (`oidc.DatabaseName == "oidc"`) and
accepts a `qrdbsdk.KVStore` in its DAO's constructor
(`qrdbsdk.NewDAO[E](store, entityType, ...)`) — it never resolves a
`KVStore` itself. Only a composition root calls `DatabaseKVStore`:
`pkg/compose` for `xkmsd`, resolving the `storage.Backend`
`initializeQRDBStorage` already built down to the underlying go-qrdb client
(`ClientBackend`), ensuring the named database exists (creating it via
go-qrdb's own `Client.Database().CreateDatabase` when it does not, with the
backend `Datastore.Databases` names for it or `Datastore.Engine` otherwise),
and scoping to it (`Client.DatabaseScoped(name).KVStore()`).

`Client.DatabaseScoped` is a capability of the go-qrdb SDK client itself —
`sdk/go/transport/embedded/database_scope.go` for the embedded (standalone)
transport, backed by `node.go`'s `DatabaseServiceRegistry`, and every
network transport (REST, gRPC, ...) implements it identically over the
wire. A feature downstream of `DatabaseKVStore` never branches on
standalone vs. remote: the same DAO code runs either way.

**Not every subsystem needs this.** Most of xkms's state (keys, users, RBAC,
CA serials, audit) has no reason to leave the shared `"default"` database
and stays exactly where "Component boundaries" below describes. A named
database is for a feature whose DAO/entity shape benefits from living apart
from that shared keyspace (its own entity namespace, its own backend
override for operational reasons) — today, `pkg/oidc`'s token cache; see
[`../oidc-credentials/architecture.md`](../oidc-credentials/architecture.md).

xkey, which hosts no go-qrdb node (see "What this feature deliberately does
not do" below), cannot use `DatabaseKVStore` — there is no `ClientBackend`
to resolve one from. It reaches go-qrdb's DAO layer a different way: adapting
its own barrier-backed `storage.Backend` directly to a `qrdbsdk.KVStore`
(`sdk/go.NewKVStoreAdapter`, wrapping `pkg/storage/kvadapter`) and handing
that to the feature's DAO constructor. Same DAO code, same `KVStore`
interface, no go-qrdb node required — see `xkey/pkg/gui/services/oidc_service.go`'s
`SetBackend`.

## Component boundaries

| Piece | Where | Owner |
|---|---|---|
| `storage.Backend` interface, guarded-write capability interfaces | `pkg/storage/interface.go`, `guardedwrites.go` | go-xkms |
| `config.DatastoreConfig` / `DatastoreRemoteConfig` (the `datastore:` section; `databases:` entries are go-qrdb's own `qrdbsdk.DaemonDatabaseConfig`) | `pkg/config/config.go` | go-xkms |
| `Server.createStorage` / `createStorageAt` — ALWAYS a prefixed view over the one shared datastore, never a private engine | `pkg/server/storage_factory.go` | go-xkms |
| `datastore.DatabaseKVStore` / `ClientBackend` — a feature's one way to reach its own named go-qrdb database, within the SAME node/barrier/cluster | `pkg/datastore/database.go` | go-xkms (composition root) / go-qrdb (the database and `DatabaseScoped` client) |
| `Server.initializeQRDBStorage` — builds the one shared datastore (standalone or remote) for an xkmsd-hosted deployment | `pkg/server/qrdb_storage.go` | go-xkms |
| `datastore.Open` / `datastore.DialRemote` — the Server-independent counterpart for callers without a `*Server` (the SDK/library composition path); `Server.initializeQRDBStorage`'s own remote branch calls `DialRemote` too, so there is exactly one remote-dial implementation | `pkg/datastore/` | go-xkms |
| `embeddednode.OpenEmbeddedNode` / `EmbeddedNodeStorageConfig` — maps `Datastore.Engine`/`Path` onto the qrdb node's own daemon config; the shared embedded-node builder `pkg/server` and `pkg/datastore` both build on | `pkg/embeddednode/` | go-xkms |
| The embedded qrdb node itself, its local engines, and all clustering | go-qrdb SDK, `pkg/server/qrdb_node*.go`, `pkg/daemon` | go-xkms composes; go-qrdb implements — see [`../clustering/architecture.md`](../clustering/architecture.md) |
| Prefix / namespace / sealed adapter views over a `Backend` | `pkg/storage/prefix.go`, `namespace.go`, `pkg/storage/sealed` | go-xkms |
| `pkg/xkms.AutoConfig.Datastore` / `register_*` factories' `"key_storage"` key — the SDK/library composition path's own storage seam, fed a `storage.Backend` handle (e.g. from `pkg/datastore.Open`) by its caller | `pkg/xkms/auto.go`, `register_*.go` | go-xkms |

## Data flow

```
xkmsd boot:
  cfg.Validate() defaults and validates datastore.engine / datastore.mode
    → Server.initializeQRDBStorage() runs ONCE, early, before any
      createStorage call:
        mode standalone → hosts the embedded qrdb node (identity, bootstrap,
                           barrier, optional Raft), s.qrdbStorage wraps its KV
        mode remote      → dials the external cluster, s.qrdbStorage wraps
                           the remote KV client
    → every xkms subsystem calls Server.createStorage("<subdir>") (keys,
      users, RBAC, custodian, shares, CA serials/revocations, audit, seal
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
  `sdk/go`'s `OpenDatastore` re-export) and hands over the resulting handle;
  see engineering.md's "The SDK/library composition path" section.
