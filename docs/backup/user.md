# Backup — User Guide

> **Status: NORMATIVE** · Feature: `backup` · Repo: `go-xkms` · Last verified: 2026-09-30

## What this is for

If the machine running your xkms node were destroyed today, could you bring
the whole thing back on different hardware — every key, every user and role,
every piece of RBAC metadata? That is what whole-node backup answers.

If instead you need to hand one specific key to another system — a partner's
KMS, a disaster-recovery site that runs its own xkms, an HSM migration — that
is a different question with a different answer: **key export**, covered in
[`../key-management/user.md`](../key-management/user.md), not this feature.

## Before you start

Whole-node backup needs a **clustered (Raft-mode) deployment**. If your node
is standalone, every command below reports the node's own refusal rather
than doing nothing silently — this is a real limitation of the clustered
state the backup captures, not a bug.

You also need the `backup:*` permission for whichever action you're taking.
System and tenant administrators hold it by default; see
[`cli.md`](cli.md) and [`api.md`](api.md) for the exact grant each verb
needs.

## Making a backup

```bash
xkmsctl backup create --destination /backups/daily
```

For anything leaving the machine — an object store, a shared filesystem,
tape — encrypt it:

```bash
xkmsctl backup create --destination s3://acme-backups/qrdb \
    --encryption aes256 --encryption-key "$BACKUP_KEY"
```

**Save that key somewhere other than next to the backup.** An unencrypted
backup of an encrypted system is plaintext the moment it leaves the barrier's
protection; an encrypted backup whose key sits beside it offers no better
protection.

Record the `id` the command prints — you need it for every other operation.

## Checking what you have

```bash
xkmsctl backup list
xkmsctl backup show --id bkp-20260930-0300
```

## Verifying a backup before you need it

Don't wait for a disaster to find out a backup is corrupted:

```bash
xkmsctl backup verify --id bkp-20260930-0300
```

This recomputes the checksum and compares it to the one recorded at
creation. Run it on a schedule, separately from restore — a backup you have
never verified is a backup you do not actually have.

## Restoring

**This overwrites live state. There is no undo.**

```bash
xkmsctl backup restore --id bkp-20260930-0300 --validate
```

`--validate` checks the backup's integrity before touching anything and
aborts if the check fails — always use it unless you have a specific reason
not to. For an encrypted backup, supply the same key you encrypted it with:

```bash
xkmsctl backup restore --id bkp-20260930-0300 \
    --decryption-key "$BACKUP_KEY" --validate
```

## Removing old backups

```bash
xkmsctl backup delete --id bkp-20260930-0300
```

There is no built-in retention policy — deciding how long to keep a backup,
and deleting it when that time passes, is yours to automate.

## What this does not do

- It does not schedule itself. Drive `backup create` from cron, a CI
  pipeline, or whatever already schedules your other backups.
- It does not back up one key at a time. For that, see
  [`../key-management/user.md`](../key-management/user.md)'s key export.
- It does not work on a standalone (non-raft) node. See "Before you start."
- It is not the same thing as `xkey backup` on the desktop app — that backs
  up xkey's own local data (your trust store, OATH codes, saved passwords),
  not an xkms node.

## Common mistakes

| What happened | Why |
|---|---|
| `backup create` succeeded but `backup restore` later fails with an unsupported-operation error | the node you restored to is standalone, not clustered |
| `backup create --encryption aes256` was refused | you didn't pass `--encryption-key` |
| `backup restore` was refused with a checksum mismatch | the backup was corrupted or tampered — do not retry without investigating; restore from a different, verified backup instead |
| `backup restore` succeeded without complaint even though I expected it to check integrity first | you omitted `--validate`; it is opt-in, not the default |
