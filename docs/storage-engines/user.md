# Storage Engines — User Guide

> **Status: NORMATIVE** · Feature: `storage-engines` · Repo: `go-xkms` · Last verified: 2026-09-24

## What this is

Every persistent thing `xkmsd` owns — keys, users, certificates, audit
records — is written through one storage engine, chosen once when the server
is configured. This page is for the operator making that choice; it is not
something an end user or API caller interacts with directly.

## Choosing an engine

Set `storage.backend` in `xkmsd.yaml` (or `XKMS_STORAGE_BACKEND`):

| Value | What it is | When to use it |
|---|---|---|
| `pebble` (default) | An embedded LSM-tree database in one directory | Production, single node. This is what you get if you set nothing. |
| `file` | One plain file per key, human-inspectable | Development, or when you want to look at what is stored without a tool |
| `memory` | Nothing survives a restart | Tests only |
| `qrdb` | Hosts (or connects to) a full qrdb node — the embedded identity plane | **Required** if you want networked APIs (REST/gRPC/QUIC/MCP), RBAC, or clustering |

```yaml
storage:
  backend: "pebble"
  path: "/var/lib/xkms/data"
```

A server with `storage.path` unset will not start — there is no built-in
default directory. Set it explicitly.

## The one combination to know about

If you want `xkmsd` reachable over the network, or you want role-based
access control, `storage.backend` must be `"qrdb"`. Everything else —
`pebble`, `file`, `memory` — only serves the local Unix socket. This is not a
missing feature to work around; it is because RBAC and the network API
server are both built on the identity plane that only the `qrdb` backend
provides. See [`../rbac/user.md`](../rbac/user.md) and
[`../clustering/user.md`](../clustering/user.md).

## What object storage is, and is not, for

You may see `EngineObjstore` referenced in the code or in commit history —
it is real, and it does let something in this stack write to S3-compatible
object storage. That something is the **ACME client's** own account state
(`cmd/acme-client`), not `xkmsd`'s key and certificate store. Setting
`storage.backend: objstore` in `xkmsd.yaml` will not work: it passes
validation and then fails when the server actually tries to open it. There
is currently no way to point `xkmsd`'s own metadata store at S3, GCS, or
Azure Blob storage.

## Switching engines

Nothing migrates your data automatically. If you change `storage.backend`
on a deployment that already has data, the server starts a **new, empty**
store at the new engine — your existing keys and certificates stay in the
old engine's files, untouched and unreachable through the new configuration.
Plan a switch as a fresh deployment (or a manual, out-of-band export/import
if one is needed), never as a config edit on a running system.

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| server refuses to start: "storage path must be specified" | `storage.path` is empty | Set `storage.path` (or `XKMS_STORAGE_PATH`) |
| server refuses to start: "network protocols require storage.backend \"qrdb\"" | you enabled REST/gRPC/QUIC/MCP without `storage.backend: qrdb` | switch to `qrdb`, or disable those protocols and use the Unix socket |
| "storage: engine open-pebble: database already open" | two `xkmsd` processes pointed at the same `pebble` path | use separate `path` values, or run one server |
| data from before a `storage.backend` change is gone | expected — see "Switching engines" above | restore the old `path`, or plan a real migration |
