# Datastore — Architecture

> **Status: NORMATIVE** · Feature: `datastore` · Repo: `go-xkms` · Last verified: 2026-09-29

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
  field (`pkg/server/embedded_node.go`'s `EmbeddedNodeStorageConfig`). Only
  meaningful when `Mode` is `"standalone"`.
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

## Component boundaries

| Piece | Where | Owner |
|---|---|---|
| `storage.Backend` interface, guarded-write capability interfaces | `pkg/storage/interface.go`, `guardedwrites.go` | go-xkms |
| `config.DatastoreConfig` / `DatastoreRemoteConfig` (the `datastore:` section) | `pkg/config/config.go` | go-xkms |
| `Server.createStorage` / `createStorageAt` — ALWAYS a prefixed view over the one shared datastore, never a private engine | `pkg/server/storage_factory.go` | go-xkms |
| `Server.initializeQRDBStorage` — builds the one shared datastore (standalone or remote) | `pkg/server/qrdb_storage.go` | go-xkms |
| `EmbeddedNodeStorageConfig` — maps `Datastore.Engine`/`Path` onto the qrdb node's own daemon config | `pkg/server/embedded_node.go` | go-xkms |
| The embedded qrdb node itself, its local engines, and all clustering | go-qrdb SDK, `pkg/server/qrdb_node*.go`, `pkg/daemon` | go-xkms composes; go-qrdb implements — see [`../clustering/architecture.md`](../clustering/architecture.md) |
| Prefix / namespace / sealed adapter views over a `Backend` | `pkg/storage/prefix.go`, `namespace.go`, `pkg/storage/sealed` | go-xkms |

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
  deployment that must survive a restart.
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
  no per-subsystem storage configuration left in `pkg/server`; a feature
  that needs its own storage knob is a design smell this feature closed the
  door on (go-xkms#1345).
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
- **It does not (yet) migrate the SDK/library composition path
  (`pkg/xkms/register_*.go`, `pkg/xkms/auto.go`) off `pkg/storage/file.New`.**
  That path builds a standalone `*xkms.XKMSService` without a `*Server` at
  all, so it never reaches `createStorage`; unifying it onto one configurable
  datastore is tracked as follow-up work, not part of this feature.
