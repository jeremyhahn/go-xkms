# Backup — API

> **Status: NORMATIVE** · Feature: `backup` · Repo: `go-xkms` · Last verified: 2026-09-30

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped".

All six verbs are `RouteAuthPermission` on REST and carry the matching
`(qrdb.v1.permission)` proto option on gRPC and `methodPermissions` entry on
MCP — the three are cross-checked by golden tests (see
[`engineering.md`](engineering.md) §"Permission model") so they cannot
drift apart silently. Unlike custodian/share routes, the backup routes are
**always registered**, not conditioned on a host feature flag: a standalone
node answers every call with the embedded go-qrdb node's own typed
unsupported-operation error rather than a missing route.

## Capability matrix

| Capability | REST | gRPC (`XKMSService.`) | MCP | Embedded (`BackupService.`) | Permission |
|---|---|---|---|---|---|
| Create | `POST /api/v1/backups` | `CreateBackup` | `xkms.createBackup` | `CreateBackup` | `backup:create` |
| List | `GET /api/v1/backups` | `ListBackups` | `xkms.listBackups` | `ListBackups` | `backup:list` |
| Get | `GET /api/v1/backups/{id}` | `GetBackup` | `xkms.getBackup` | `GetBackup` | `backup:read` |
| Delete | `DELETE /api/v1/backups/{id}` | `DeleteBackup` | `xkms.deleteBackup` | `DeleteBackup` | `backup:delete` |
| Restore | `POST /api/v1/backups/restore` | `RestoreBackup` | `xkms.restoreBackup` | `RestoreBackup` | `backup:restore` |
| Verify | `POST /api/v1/backups/{id}/verify` | `VerifyBackup` | `xkms.verifyBackup` | `VerifyBackup` | `backup:verify` |

Unix and QUIC are not independently listed: Unix carries the same
protobuf-shaped RPCs as gRPC (over a domain socket), and QUIC carries the
same JSON request/response bodies as REST (over HTTP/3) — see
[`../key-management/api.md`](../key-management/api.md) for why those two
transports mirror gRPC and REST respectively rather than having their own
wire shape.

Restore is `POST /api/v1/backups/restore` rather than a method on the
backup's own path (`/api/v1/backups/{id}/restore`), matching go-qrdb's own
REST shape: the request selects target shards and carries a decryption key —
it reads as an operation on the cluster that takes a backup as input, not as
a sub-resource of the backup record.

## Schemas

All request/response types are direct aliases of `go-qrdb/sdk/go/transport`
(`pkg/api/transport/types_backup.go`) — see
[`engineering.md`](engineering.md) §"Transport types" for the full list.

`POST /api/v1/backups` — `BackupRequest`:

```json
{ "destination": "s3://acme-backups/qrdb",
  "compression": "zstd",
  "encryption": "aes256",
  "encryption_key": "<base64>",
  "metadata": { "schedule": "nightly" },
  "shard_ids": [1, 2, 3] }
```

`destination` is required. `shard_ids` empty means **all shards**.
`encryption_key` is **required** when `encryption` is not `none`.

Response — `BackupInfo`:

```json
{ "id": "bkp-20260930-0300", "timestamp": "2026-09-30T03:00:00Z",
  "size": 4823945216, "shard_count": 3, "status": "complete",
  "checksum": "sha256:…", "destination": "s3://acme-backups/qrdb",
  "compression": "zstd", "encryption": "aes256",
  "metadata": { "schedule": "nightly" },
  "duration": 184000000000, "error_message": "" }
```

`status`: `pending` · `running` · `complete` · `failed` (with
`error_message`). A failed create is **recorded**, not discarded, so it
appears in `list`.

`GET /api/v1/backups` returns `BackupInfo` entries **sorted by timestamp
descending**, under `{"backups": [...]}}`.

`POST /api/v1/backups/restore` — `RestoreRequest`:

```json
{ "backup_id": "bkp-20260930-0300",
  "target_shards": [1, 2],
  "validate_first": true,
  "decryption_key": "<base64>" }
```

Response — `RestoreResult`:

```json
{ "backup_id": "bkp-20260930-0300", "shards_restored": 2,
  "duration": 96000000000,
  "errors": [ { "shard_id": 3, "message": "…" } ] }
```

**Restore reports per-shard errors** rather than collapsing a partial
restore into one failure.

`POST /api/v1/backups/{id}/verify` — `VerifyResult`:

```json
{ "valid": true, "checksum_match": true,
  "expected_checksum": "sha256:…", "actual_checksum": "sha256:…",
  "errors": [] }
```

## Compression and encryption

| Compression | Meaning |
|---|---|
| `none` | default |
| `zstd` | high ratio, fast decompression |
| `snappy` | fast compression, moderate ratio |

| Encryption | Meaning |
|---|---|
| `none` | default |
| `aes256` | AES-256-GCM, authenticated |

The checksum provides **integrity**; authenticated encryption provides
**authenticity**. They are different properties and only the first is on by
default.

## Status and error mapping

| Condition | REST | gRPC | MCP |
|---|---|---|---|
| Success | 200 / 201 | `OK` | `result` |
| Empty destination / empty ID | 400 | `InvalidArgument` | `-32602` |
| Encryption requested without a key | 400 | `InvalidArgument` | `-32603` (wrapped `BackupCreateError`) |
| Encrypted backup restored without a decryption key | 400 | `InvalidArgument` | `-32603` (wrapped `BackupRestoreError`) |
| Backup not found | 404 | `NotFound` | `-32001` |
| Checksum mismatch under `validate_first` or `verify` | 409 | `FailedPrecondition` | `-32603` |
| Standalone node (no shard-snapshot capability) | 500, underlying message names the cause | `Internal`, underlying message names the cause | `-32603`, underlying message names the cause |
| Missing permission | 403 | `PermissionDenied` | error object |
| Backup client not configured (no embedded qrdb node reachable) | 503 | `FailedPrecondition` | `-32004` |

A standalone node's refusal is not a distinct status code: go-qrdb's
`BackupUnsupportedError` arrives wrapped inside a create/restore error and is
reported through the generic-failure path, with the message naming the
cause — see [`engineering.md`](engineering.md) §"Error semantics".

## Pagination

`ListBackups` returns every backup, newest first, and is not paginated. The
set is bounded by operator retention, which is external to this API.

## Versioning

Backup REST paths are under `/api/v1/`. gRPC package `xkmsv1`. Nothing here
is deprecated.

## Per-key export/import

Per-key export and import — wrapping one key under an operator-supplied
wrapping key or KEM recipient, refused outright for a non-exportable
hardware-bound key — is a different capability with its own permission
(`keys:export` / `keys:import`) and its own documentation:
[`../key-management/api.md`](../key-management/api.md).
