# Backup — CLI

> **Status: NORMATIVE** · Feature: `backup` · Repo: `go-xkms` · Last verified: 2026-09-30

Binary: `xkmsctl`. Command group: `xkmsctl backup`. Source:
`cmd/xkmsctl/backup.go`. Global flags:
[`../key-management/cli.md`](../key-management/cli.md).

For backing up or restoring an individual key — as opposed to the whole
node's replicated state — use `xkmsctl key export` / `xkmsctl key import`
instead; see [`../key-management/cli.md`](../key-management/cli.md). There is
no `xkey` CLI verb for whole-node backup: `xkey backup` is a distinct,
pre-existing feature (the desktop app's own local-data backup — trust store,
CA data, OATH credentials, static passwords; see `xkey/docs/`) and this
feature does not reuse or extend it. `xkey`'s per-key export reaches this
feature's sibling, `key export`/`key import`, through the same SDK client
every xkmsctl verb uses.

**Requires a Raft-mode node.** On a standalone (non-raft) node every verb
below reports the embedded go-qrdb node's own typed unsupported-operation
error.

## `xkmsctl backup create`

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--destination` | string | — | storage path or URI, e.g. `/backups/daily` or `s3://bucket/prefix` (**required**) |
| `--compression` | string | `none` | `none \| zstd \| snappy` |
| `--encryption` | string | `none` | `none \| aes256` |
| `--encryption-key` | string | — | **required when `--encryption` is not `none`** |

```bash
xkmsctl backup create --destination /backups/daily

xkmsctl backup create --destination s3://acme-backups/qrdb \
    --compression zstd --encryption aes256 --encryption-key "$BACKUP_KEY"
```

Creating with encryption but no key is refused before anything is written.
The response carries the backup's `id` and `checksum` — record both.

## `xkmsctl backup list`

List all backups, newest first. No flags.

```bash
xkmsctl backup list -o json
```

## `xkmsctl backup show`

| Flag | Type | Required |
|---|---|---|
| `--id` | string | **yes** |

```bash
xkmsctl backup show --id bkp-20260930-0300 -o json
```

Reports size, shard count, status, checksum, destination, compression,
encryption and (if the backup failed) the error message.

## `xkmsctl backup delete`

| Flag | Type | Required |
|---|---|---|
| `--id` | string | **yes** |

```bash
xkmsctl backup delete --id bkp-20260930-0300
```

## `xkmsctl backup restore`

**This overwrites live shard state.** Gated by `backup:restore`, a permission
distinct from `backup:create`/`backup:read` for exactly that reason.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--id` | string | — | backup ID to restore from (**required**) |
| `--decryption-key` | string | — | **required for encrypted backups** |
| `--validate` | bool | `false` | verify integrity **before** restoring |

```bash
# Verify then restore
xkmsctl backup restore --id bkp-20260930-0300 --validate

# Restore an encrypted backup
xkmsctl backup restore --id bkp-20260930-0300 \
    --decryption-key "$BACKUP_KEY" --validate
```

With `--validate`, a checksum mismatch aborts before any shard is touched.
Without it, restore proceeds unconditionally — the flag exists because
verification has a cost on a large backup, not because the default is to
skip a check that matters less.

## `xkmsctl backup verify`

| Flag | Type | Required |
|---|---|---|
| `--id` | string | **yes** |

```bash
xkmsctl backup verify --id bkp-20260930-0300 -o json
```

Recomputes the checksum and compares it to the one stored at creation,
without touching any shard. The result reports both the expected and actual
checksum, so a mismatch is diagnosable rather than a bare failure.

## Exit codes

`0` on success. Non-zero for a missing/invalid backup ID, a missing
encryption/decryption key where one is required, a checksum mismatch under
`--validate`, insufficient `backup:*` permission, or (on a standalone node)
the node's own unsupported-operation refusal.
