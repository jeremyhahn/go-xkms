# xkey backup

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: `xkey backup` (`xkey/cmd/xkey/cmd/backup.go`, `backup_device.go`) and the envelope format (`xkey/pkg/backup/`).

Encrypted backup and restore of xkey data: trust store certificates, OATH
credentials, and static passwords.

## Commands

| Command | Purpose |
|---------|---------|
| `xkey backup create` | Collect the data stores and write a sealed `.xkb` file |
| `xkey backup list` | List `.xkb` files in `backups/` under the xkey home (`~/.xkey/backups/` by default) |
| `xkey backup contents <file>` | Decrypt and print the manifest without restoring |
| `xkey backup restore <file>` | Decrypt and write the contents back into the stores |
| `xkey backup to-device` | Send a backup to a paired phone (`ble` builds) |
| `xkey backup from-device` | Restore a backup from a paired phone (`ble` builds) |

`create` writes to `--output`/`-o`, by default
`<xkey home>/backups/backup-{timestamp}.xkb` (`xkey/cmd/xkey/cmd/backup.go:1395`).
`to-device` and `from-device` take `--device` and `--timeout` (default `1m0s`)
as well as the store and credential flags below.

## Credentials

The backup password is read from standard input (`--password-stdin`) or the
`XKEY_BACKUP_PASSWORD` environment variable, in that order. There is no
`--password` value flag: a value on the command line is visible to every
process on the host through `ps` (the same rule as `--pin`,
`xkey/cmd/xkey/cmd/backup.go:1403`). The password bytes are wiped once the
key is derived.

When `create` gets no password a random 256-bit key is generated and printed
once in hex:

```
Generated encryption key (save this):
  9f2c...<64 hex chars>
```

`contents` and `restore` accept the backup password or a raw key (the 32 hex
bytes) supplied through `--key-stdin` or the `XKEY_BACKUP_KEY` environment
variable, the same convention as the password; a password takes precedence.
There is no `--key` value flag either.

A password is stretched with Argon2id (t=3, m=64 MiB, p=4) under a fresh
32-byte random salt, or PBKDF2-SHA256 when the Go FIPS 140 module is
enabled — the canonical go-xkms password hasher, reached through
`backup.NewPasswordKey` (`xkey/pkg/backup/key.go:63`). The salt and parameters
are stored in the file (see [File format](#file-format)), so the same
password gives a different key for every backup.

A wrong password or key fails with
`backup: decryption failed: incorrect password or key` and nothing is written.

## Data sources

By default the commands read and write the stores under the xkey data
directory (`$XKEY_HOME/data`, normally `~/.xkey/data`) — the same locations
the xkey GUI uses when the barrier is not active. The OATH store is
barrier-aware: when a barrier is initialized, `create`, `restore` and the
device verbs open the barrier-encrypted OATH store, unsealed with
`--barrier-password-stdin`, `--barrier-password-file` or
`XKEY_BARRIER_PASSWORD` (`xkey/cmd/xkey/cmd/backup.go:618`):

| Category | Default location | Override |
|----------|------------------|----------|
| `trust-store` | `{data}/trust` | `--trust-store` |
| `oath-credentials` | barrier store, else `{data}/oath.json` | `--oath-store` (bypasses the barrier) |
| `static-passwords` | `{data}/staticpw` | `--password-store` |

Each default resolves through the same feature-directory constant the owning
command uses (`trustDataSubdir`, `oathStoreFilename`,
`passwordStoreFeature` in `xkey/cmd/xkey/cmd`), so backup and the command
that actually reads or writes the store can never drift apart.

Note that `xkey oath` and `xkey password` default their own `--store` flag to
a path relative to the current working directory. Pass the paths above to
those commands (or pass `--oath-store`/`--password-store` to `backup`) when
the two must refer to the same store.

`ca-data` is never included: xkey has no local CA store, and CA material is
served by the `xkmsd` daemon. `create` and `to-device` also report, under the
same `Not included:` heading, any source whose default location has never
been written to -- rather than silently opening (and thereby creating) an
empty store and reporting a zero count with no explanation. An explicit
`--trust-store`/`--oath-store`/`--password-store` path that does not exist is
a hard error instead: the operator named that path deliberately, so backup
never auto-creates it. `restore` and `from-device` are unaffected: a
destination store that does not exist yet is created normally.

## Failure modes

| Situation | Behavior |
|-----------|----------|
| Every store empty | Fails with `backup: no data available to back up`; no file is written |
| Barrier initialized and no explicit `--trust-store` or `--password-store` | Fails with `backup: xkey data directory is barrier-encrypted`: those two stores have no barrier-backed CLI path yet. Pass explicit paths for both (`xkey/cmd/xkey/cmd/backup.go:636`) |
| Default source never written to (`create`/`to-device`) | Not an error: the category is listed under `Not included:` and left out, instead of being auto-created empty |
| `--trust-store`/`--oath-store`/`--password-store` names a path that does not exist (`create`/`to-device`) | Fails with `backup: source does not exist`, naming the category and path |
| Store cannot be opened | Fails with `backup: data store unavailable`, naming the category and path |
| Wrong password/key, tampered header or ciphertext, or truncated file | Fails with `backup: decryption failed` |
| Version 1 file (unsalted SHA-256 password key) | Fails with `backup: decryption failed: unsalted version 1 backup format is no longer supported; re-create the backup` (`backup.ErrLegacyBackupFormat`); never migrated |
| KDF parameters in the file altered | Fails with `backup: decryption failed: the backup's key-derivation record is invalid or has been altered`, before any key is derived |
| Password given for a random-key backup | Fails with `backup: decryption failed: backup was sealed with a raw key; supply it with --key-stdin or XKEY_BACKUP_KEY` |
| Backup holds a category the CLI cannot write | Restores the rest, then exits with `backup: restore incomplete` |
| Trust-store entry with no recorded purpose, or one that is not a trust-store purpose | Fails with `backup: restore failed`, naming the certificate and purpose (`backup.RecordedPurposeError`); no certificate is written. Restored certificates keep their recorded purpose, source and tags; none is re-classified |
| Trust-store certificate whose metadata cannot be read (`create`/`to-device`) | Fails with `backup: data collection failed`; an archive never records a certificate without its purpose |

Entries that already exist in a target store are reported per category as
`skipped`, and the command ends with
`Restore completed with N skipped item(s).`

## File format

A `.xkb` file is the JSON encoding of the backup envelope:

```json
{
  "magic": "XKBK",
  "version": 3,
  "kdf": {
    "version": 1,
    "algorithm": "Argon2id",
    "salt": "<base64, 32 bytes>",
    "time": 3,
    "memory_kib": 65536,
    "threads": 4,
    "key_length": 32
  },
  "nonce": "<base64, 12 bytes>",
  "ciphertext": "<base64>"
}
```

`kdf` is absent for a backup sealed with a random or `--key-stdin`/`XKEY_BACKUP_KEY` key. The
ciphertext is the archive — manifest, certificates, credentials, and
passwords — serialized to JSON and sealed with AES-256-GCM under the
password-derived or supplied key, with a fresh random 96-bit nonce per backup
(`cipher.NewGCMWithRandomNonce`, NIST SP 800-38D §8.2.2;
`xkey/pkg/backup/service.go:1151`), so the format is FIPS 140-3 approved. The
header (`magic`, `version`, `kdf`) is the AEAD additional data, so editing
any of it makes decryption fail. A `kdf` record whose costs differ from the
ones its version pins is refused before derivation, so a crafted file cannot
weaken the KDF or demand unbounded memory. The archive carries a SHA-256
checksum of its own payload, verified on decrypt. Only the header and nonce
are readable without the key.

Version 1 files, keyed with an unsalted SHA-256 of the password, are refused
(`xkey/pkg/backup/service.go:1196`). Version 2 files, sealed with
XChaCha20-Poly1305, are refused with `backup.ErrVersionMismatch`
(`xkey/pkg/backup/service.go:1199`); neither is migrated.

## Example

```bash
# Back up to an explicit path, password from a file on stdin
xkey backup create --password-stdin --output ~/.xkey/backups/laptop.xkb < backup-password.txt

# Inspect without restoring
xkey backup contents ~/.xkey/backups/laptop.xkb --password-stdin < backup-password.txt

# Restore onto a new machine
xkey backup restore ~/.xkey/backups/laptop.xkb --password-stdin < backup-password.txt
```
