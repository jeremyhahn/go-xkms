# Backup — Architecture

> **Status: NORMATIVE** · Feature: `backup` · Repo: `go-xkms` · Last verified: 2026-09-30

## The problem

Two different things get called "backup" and they need different answers.

**Disaster recovery** asks: if this node's storage is destroyed, can the
cluster's whole state — every key, user, role, barrier-encrypted secret and
piece of RBAC metadata — be recovered on different hardware? That needs a
point-in-time, consistent capture of the replicated state the barrier
protects, taken below the application layer.

**Key portability** asks: can one specific key move to another system, under
an operator's control, without ever touching the wire or disk in the clear?
That is a per-key operation gated by the key's own exportability policy, not
a node-wide snapshot.

go-xkms answers both, but owns neither primitive: whole-node backup is
go-qrdb's shard-snapshot capability, consumed as-is; per-key export is the
existing wrap/import machinery documented in
[`../key-management/`](../key-management/architecture.md). This folder
covers the first. It does not duplicate the second.

## Shape chosen: consume go-qrdb's backup client, add nothing underneath

The embedded go-qrdb node already implements backup end to end — shard
snapshot capture, SHA-256 checksum, optional AES-256-GCM encryption, and
restore with pre-restore verification — behind `go-qrdb/sdk/go`'s
`transport.BackupClient`. xkms wires that client into the unified
`XKMSService` exactly the way it already wires the node's custodian, share
and tenant clients (`SetBackupClient`, mirroring `SetCustodianClient`), and
re-exposes the six verbs under its own REST, gRPC and MCP surfaces so a
caller never has to reach the node directly.

```
qrdb node's BackupService (pkg/service, go-qrdb)
        │  shard snapshot, checksum, encrypt/decrypt
        ▼
transport.BackupClient (go-qrdb/sdk/go/transport)
        │  Client.Backup()
        ▼
XKMSService.{Create,List,Get,Delete,Restore,Verify}Backup  (pure pass-through)
        │
        ├── REST    POST/GET/DELETE /api/v1/backups...
        ├── gRPC    CreateBackup / ListBackups / ... (xkmsv1.XKMSService)
        ├── MCP     xkms.createBackup / xkms.listBackups / ...
        └── xkmsctl backup create / list / show / delete / restore / verify
```

No shard capture, checksum computation, compression or encryption logic
lives in go-xkms. The service layer's only jobs are: resolve the client,
guard against a nil request, and translate the client's typed errors into
each transport's native error shape.

### Rejected alternatives

- **A parallel key-level backup archive in go-xkms** (the previous
  `pkg/backup` package: `BackupAdapter`, `BackupData`, a file-based AES-GCM
  archive). Rejected and deleted (go-xkms#728, closing go-xkms#1326 item 4):
  it had zero importers, its `KeyRestorer` was never implemented, and its
  JSON encoding of `BackupKey` serialized private key material in the
  clear whenever the archive format was `BackupFormatJSON` rather than
  `BackupFormatEncrypted` — the exact plaintext-key-material defect the
  owner ruling exists to close. There is no good reason to keep a second,
  go-xkms-local backup format when the node already has one with real
  encryption and a real restore path.
- **Reimplementing shard snapshot/restore in go-xkms.** Rejected on the SDK
  boundary: xkms composes `go-qrdb/sdk/go`, never `go-qrdb/pkg/*`, and a
  local copy of snapshot logic would drift from the node's own the moment
  go-qrdb changed its on-disk shard format.
  See `../../CLAUDE.md`'s SDK Boundary section.
- **One combined "backup" verb that captures both the node snapshot and a
  key.** Rejected: a node snapshot already contains every key the barrier
  protects — including non-exportable hardware-bound ones represented only
  by their handle/attributes, which an export can never release. Collapsing
  them into one verb would hide that a "key included in a snapshot" and "a
  key you can carry away and use elsewhere" are different claims.

## Component boundaries

| Piece | Package | Owner |
|---|---|---|
| Shard snapshot capture, checksum, compression, encryption, restore | `pkg/service` (`BackupService`) | **go-qrdb** |
| SDK client surface | `sdk/go` (`transport.BackupClient`, `Client.Backup()`) | **go-qrdb** |
| Pass-through service layer | `pkg/xkms/servicer_backup.go` | go-xkms |
| REST / gRPC / MCP transports | `pkg/api/{rest,grpc,mcp}/*backup*.go` | go-xkms |
| CLI | `cmd/xkmsctl/backup.go` | go-xkms |
| Per-key export/import (BYOK, wrap/unwrap) | `pkg/xkms/servicer_wrapkey.go`, `pkg/backend/*/[...]_importexport.go` | go-xkms — see [`../key-management/`](../key-management/architecture.md) |

## Run-mode dependency

**Shard backup and restore are a Raft-mode capability in go-qrdb.** A
standalone (non-raft) xkms node's embedded qrdb node has no shard snapshot
provider — `pkg/service.NewHostShardSnapshotProvider` wraps a
`service.Host`, and the standalone `LocalBackend` is not shard-replicated —
so every verb refuses with go-qrdb's own typed
`BackupUnsupportedError`, surfaced through xkms unmodified. go-xkms performs
no capability check of its own and offers no workaround: the restriction is
qrdb's, inherited verbatim. A clustered (`-tags raft`) xkms node reaches the
real capability because its embedded node is the same `NewClusteredNode`
go-qrdb's own daemon uses.

See [`../clustering/`](../clustering/architecture.md) for the `raft` build
tag and standalone-vs-clustered node construction
(`pkg/daemon/node_standalone.go`, `pkg/daemon/node_cluster.go`).

## Data flow

```
create:
  xkmsctl backup create --destination s3://bucket/prefix \
      [--compression zstd] [--encryption aes256 --encryption-key $K]
      → qrdb captures every shard, computes one SHA-256 over them,
        optionally compresses then encrypts, writes to destination

inspect:
  xkmsctl backup list                    → every backup, newest first
  xkmsctl backup show --id bkp-...       → one backup's metadata
  xkmsctl backup verify --id bkp-...     → recomputed checksum vs. stored

restore (the destructive one):
  xkmsctl backup restore --id bkp-... [--validate] [--decryption-key $K]
      → optional pre-restore verification, then every named shard
        (or all of them) is overwritten from the backup

delete:
  xkmsctl backup delete --id bkp-...     → removes the backup and its artifact
```

## Trust boundaries

- **A backup leaves the barrier's protection the moment it leaves the
  process.** Encryption is a data-classification decision, not a
  convenience: an unencrypted backup of a barrier-encrypted store is
  plaintext wherever it lands. `--encryption aes256` requires
  `--encryption-key`; omitting the key when encryption is requested is
  refused before anything is written (`BackupEncryptionKeyRequiredError`).
- **Restore is the most destructive operation this feature exposes.** It
  overwrites live shard state. `backup:restore` is accordingly a distinct
  permission from `backup:create`/`backup:read`, mirroring go-qrdb's own
  split, and `backup:delete` is separate again.
- **The checksum is integrity, not authenticity.** SHA-256 detects
  corruption and truncation; it does not detect a deliberately substituted
  backup signed by nothing. Authenticated encryption (AES-256-GCM) is what
  detects tampering, and like the checksum it is only checked when the
  caller asks (`validate_first` on restore, or an explicit `verify` call) —
  restore never silently skips verification, but it also never forces it;
  see `../engineering.md` for the exact refusal conditions.
- **A hardware-bound key inside a snapshot is not an exported key.** The
  snapshot carries whatever the barrier-encrypted store carries for that
  key — for a TPM- or PKCS#11-resident key, that is a handle/attribute
  record, not usable key material outside the hardware it was bound to.
  Restoring the snapshot onto the *same* hardware recovers access; restoring
  it elsewhere does not hand anyone the key. This is why "the node was
  backed up" is never sufficient grounds to also claim "the keys were
  exported" — see [`../key-management/architecture.md`](../key-management/architecture.md)
  for what export actually requires per backend.

## What this feature deliberately does not do

- **No scheduling.** There is no built-in cron; an external scheduler drives
  `backup create`.
- **No retention policy.** Deleting old backups is `backup delete`, driven
  externally.
- **No incremental or differential backups.** Each backup is a full capture
  of the shards it names, exactly as go-qrdb's own CLI produces.
- **No per-key backup format.** A key leaves the system only through
  export/import, under its own exportability policy — see
  [`../key-management/`](../key-management/).
- **No standalone-mode shard snapshot.** This is qrdb's restriction, not a
  gap xkms works around; see "Run-mode dependency" above.
- **No reimplementation of go-qrdb's snapshot or restore logic.** Every byte
  of shard data, every checksum, every encrypt/decrypt call happens inside
  `go-qrdb/sdk/go`.
