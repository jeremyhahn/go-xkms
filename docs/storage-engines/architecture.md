# Storage Engines — Architecture

> **Status: NORMATIVE** · Feature: `storage-engines` · Repo: `go-xkms` · Last verified: 2026-09-24

## The problem

Every xkmsd process needs somewhere to persist keys, users, RBAC state, CA
serials and revocations, audit records, and everything else the server owns.
Deployments disagree on what "somewhere" should mean: a single flat directory
for a development box, an embedded LSM-tree for a production single node, an
in-memory store for a test, or the replicated datastore of a full qrdb node
when clustering or a shared identity plane is required.

Per this repository's ownership boundary (`CLAUDE.md` "Layer Ownership"),
go-xkms ships **no state machine or KV store of its own** — that is go-qrdb's.
What xkms owns is the *configuration surface* that selects and opens one of
go-qrdb's SDK-exposed storage engines, and the thin `storage.Backend`
interface (`pkg/storage/interface.go`) every xkms subsystem programs against
so the choice of engine is invisible above this layer.

## Shape chosen: one interface, four configurable engines, one general one

`storage.Backend` (`pkg/storage/interface.go`) is the single interface every
xkms subsystem depends on: `Get`, `Put`, `PutIfAbsent`, `Delete`, `List`,
`Scan`, `Exists`, `Close`. Guarded compare-and-swap/compare-and-delete are
**optional capabilities** (`CompareAndSwapper`, `CompareAndDeleter` in
`pkg/storage/guardedwrites.go`), reached by type assertion rather than always
present — a backend that cannot make the guarantee simply does not implement
the method, instead of shipping one that always errors.

Two entry points build a `storage.Backend`, at two different layers:

| Entry point | Where | Who calls it |
|---|---|---|
| `Server.createStorage` / `createStorageAt` | `pkg/server/storage_factory.go` | xkmsd's own metadata store, keyed by `config.Config.Storage` |
| `storage.OpenEngine` | `pkg/storage/engine.go` | the lower-level, general-purpose constructor; xkmsd's factory calls into it indirectly for three of its four choices, and other composers (`xkey`, the SDK, the ACME client) call it directly |

`Server.createStorage` switches on `config.Storage.Backend` and recognizes
exactly four values: `"memory"`, `"pebble"` (the default, including an empty
string), `"file"`, and `"qrdb"`. Anything else is refused at construction time
with `*ErrUnsupportedStorageBackend` (`pkg/server/errors.go`) — **not** at
config-parse time; see engineering.md's Configuration section for the gap
between what `Config.Validate` accepts and what the factory actually opens.

```
storage.backend: "memory" ─┐
storage.backend: "pebble" ─┼─→ storage.NewPebble / NewMemoryBackend / file.New
storage.backend: "file"   ─┘        (pkg/storage, pkg/storage/file)

storage.backend: "qrdb"   ──→ initializeQRDBStorage (pkg/server/qrdb_storage.go)
                                 transport "embedded" → hosts an in-process qrdb
                                   node (see ../clustering/architecture.md)
                                 transport "rest"/"grpc" → dials a REMOTE qrdb
                                   cluster this xkmsd does not host
```

`storage.OpenEngine` (`pkg/storage/engine.go`) is a separate, more general
constructor reached only through go-qrdb's SDK (`qrdbsdk.NewFileStorage`,
`NewPebbleStorage`, `NewMemoryStorage`, `NewObjStoreStorage` — never an
internal go-qrdb package). It recognizes a fifth kind, `EngineObjstore`,
backed by go-qrdb's object-storage engine (in turn backed by go-objstore
providers: `local`, `memory`, and cloud providers under their own build
tags). **`EngineObjstore` is real and implemented, but `Server.createStorage`
never calls `OpenEngine` with it** — the xkmsd metadata store cannot be
pointed at object storage today. The only in-tree caller of
`EngineObjstore` is the ACME client's account/order state backend
(`pkg/acme/client/service/account_manager.go:createStateBackend`), which has
its own, separate `StorageConfig{Backend, Options}` (`pkg/acme/client/service/config.go`)
belonging to `cmd/acme-client`, not to xkmsd. See engineering.md for the
precise boundary — this distinction is the one a previous documentation pass
got wrong by describing object storage as an `xkmsd` `storage.backend` value.

## Component boundaries

| Piece | Where | Owner |
|---|---|---|
| `storage.Backend` interface, guarded-write capability interfaces | `pkg/storage/interface.go`, `guardedwrites.go` | go-xkms |
| `storage.OpenEngine`, `EngineConfig`, `EngineKind` | `pkg/storage/engine.go` | go-xkms (thin wrapper over go-qrdb engines) |
| File / Pebble / Memory / Objstore engines themselves | go-qrdb SDK (`qrdbsdk.NewFileStorage` et al.) | **go-qrdb** |
| `Server.createStorage` / `createStorageAt` (the `storage.backend` switch) | `pkg/server/storage_factory.go` | go-xkms |
| The `qrdb` backend's three transports (embedded / rest / grpc) | `pkg/server/qrdb_storage.go` | go-xkms (composes a go-qrdb node or client) |
| The embedded qrdb node itself, and all clustering | `pkg/server/qrdb_node*.go`, `pkg/daemon` | go-xkms composes; go-qrdb implements — see [`../clustering/architecture.md`](../clustering/architecture.md) |
| Prefix / namespace / sealed adapter views over a `Backend` | `pkg/storage/prefix.go`, `namespace.go`, `pkg/storage/sealed` | go-xkms |
| ACME client's own object-storage-backed state | `pkg/acme/client/service/account_manager.go` | go-xkms, but a distinct config surface (`cmd/acme-client`) |

## Data flow

```
xkmsd boot:
  config.Storage.Backend chosen (file | pebble | memory | qrdb)
    → Server.createStorage("<subdir>") called once per xkms subsystem
        (keys, users when backend=="qrdb" is qrdb's own identity plane,
         CA serials, audit, seal blobs, ...)
    → each subsystem gets a storage.Backend scoped to its own key
      namespace: a subdirectory (file/pebble) or a key-prefixed view
      over the single shared qrdb backend (storage.NewPrefixBackend)
```

For the `"qrdb"` backend specifically, `initializeQRDBStorage`
(`pkg/server/qrdb_storage.go`) must run once, early, before any
`createStorage` call: every subdirectory becomes a prefixed view
(`subdir+"/"`) over the **one** shared `s.qrdbStorage`, whose `Close` is a
no-op — only the server's own shutdown path closes the real, shared backend.

## Trust boundaries

- **The engine choice is not a security boundary by itself.** Confidentiality
  at rest comes from the barrier (see
  [`../sealing-and-barrier/architecture.md`](../sealing-and-barrier/architecture.md)),
  which layers over whichever engine is selected here. An unsealed barrier
  over any engine still yields keys in the clear; a sealed one protects them
  regardless of engine.
- **`memory` is non-durable by design** and every key, user, and certificate
  in it disappears on process exit — appropriate for tests, never for a
  deployment that must survive a restart.
- **`qrdb` is required, not optional, for two other features**: network
  protocols (REST/gRPC/QUIC/MCP all require `storage.backend: "qrdb"` —
  `pkg/config/config.go` Validate) and RBAC (`auth.enable_rbac` requires the
  qrdb identity plane — see [`../rbac/architecture.md`](../rbac/architecture.md)).
  A `file`, `pebble`, or `memory` backend is therefore a **local, unix-socket-only,
  RBAC-disabled** deployment shape; it is not a smaller version of the same
  server with networking turned off elsewhere.

## What this feature deliberately does not do

- **It does not implement a consensus engine, a state machine, or a KV
  store.** Every engine byte is go-qrdb's; xkms selects and opens one.
- **It does not expose object storage for xkmsd's own metadata.**
  `EngineObjstore` exists and works, but only for the ACME client's separate
  state store — not reachable via `storage.backend`.
- **It has no CLI surface.** See cli.md for why.
- **It does not migrate data between engines.** Switching `storage.backend`
  on an existing deployment starts a new, empty store at the new engine; nothing
  in this repository reads one engine's on-disk format and writes another's.
