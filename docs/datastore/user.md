# Datastore — User Guide

> **Status: NORMATIVE** · Feature: `datastore` · Repo: `go-xkms` · Last verified: 2026-09-29

## What this is

Every persistent thing `xkmsd` owns — keys, users, certificates, audit
records — is written through one global datastore, chosen once when the
server is configured. This page is for the operator making that choice; it
is not something an end user or API caller interacts with directly.

Unlike older releases, there is no way to configure a subsystem to skip the
datastore: `xkmsd` always stores through it, so encryption-at-rest (the
barrier), RBAC's identity plane, and (when enabled) Raft replication apply
uniformly to everything the server persists — nothing is written to disk in
the clear or outside the barrier by default.

## Choosing the local engine

Set `datastore.engine` in `xkmsd.yaml` (or `XKMS_DATASTORE_ENGINE`):

| Value | What it is | When to use it |
|---|---|---|
| `pebble` (default) | An embedded LSM-tree database in one directory | Production, single node. This is what you get if you set nothing. |
| `file` | One plain file per key, human-inspectable | Development, or when you want to look at what is stored without a tool |
| `memory` | Nothing survives a restart | Tests only |

```yaml
datastore:
  engine: "pebble"
  path: "/var/lib/xkms/data"
```

A `"standalone"` server with `datastore.path` unset and a non-`memory`
engine will not start — there is no built-in default directory. Set it
explicitly.

## Choosing standalone vs. remote

Set `datastore.mode`:

| Value | What it is | When to use it |
|---|---|---|
| `standalone` (default) | This process hosts the qrdb engine itself | The normal case — a single node, or a Raft cluster member (see [`../clustering/user.md`](../clustering/user.md)) |
| `remote` | This process dials an already-running qrdb cluster | A fleet of `xkmsd` API servers sharing one externally-hosted datastore |

```yaml
datastore:
  mode: "remote"
  remote:
    address: "https://qrdb.example.com:63002"
    transport: "rest"
```

## The one combination to know about

If you want `xkmsd` reachable over the network, `datastore.mode` must be
`"standalone"` — the embedded qrdb node is the unified API server. A
`"remote"` deployment only serves the local Unix socket. This is not a
missing feature to work around; it is because the network API server is
built on the node this process hosts, and a `"remote"` deployment does not
host one. See [`../clustering/user.md`](../clustering/user.md).

RBAC has no such restriction: it works in either mode, because every
deployment is qrdb-backed now. See [`../rbac/user.md`](../rbac/user.md).

## Switching engines or modes

Nothing migrates your data automatically. If you change `datastore.engine`
or `datastore.mode` on a deployment that already has data, the server starts
a **new, empty** store — your existing keys and certificates stay in the
old configuration's files, untouched and unreachable through the new one.
Plan a switch as a fresh deployment (or a manual, out-of-band export/import
if one is needed), never as a config edit on a running system.

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| server refuses to start: "datastore.path must be specified for datastore.engine ..." | `datastore.path` is empty and the engine is not `memory` | Set `datastore.path` (or `XKMS_DATASTORE_PATH`) |
| server refuses to start: "network protocols require datastore.mode \"standalone\"" | you enabled REST/gRPC/QUIC/MCP with `datastore.mode: remote` | switch to `standalone`, or disable those protocols and use the Unix socket |
| server refuses to start: "invalid datastore.engine" / "invalid datastore.mode" | a typo in `datastore.engine`/`datastore.mode` | use one of `memory`/`file`/`pebble` for engine, `standalone`/`remote` for mode |
| "storage: engine open-pebble: database already open" | two `xkmsd` processes pointed at the same `pebble` path | use separate `path` values, or run one server |
| data from before a `datastore.engine`/`.mode` change is gone | expected — see "Switching engines or modes" above | restore the old configuration, or plan a real migration |
