# xkey backup

Encrypted backup and restore of xkey data: trust store certificates, OATH
credentials, and static passwords.

## Commands

| Command | Purpose |
|---------|---------|
| `xkey backup create` | Collect the data stores and write a sealed `.xkb` file |
| `xkey backup list` | List `.xkb` files in `~/.xkey/backups/` |
| `xkey backup contents <file>` | Decrypt and print the manifest without restoring |
| `xkey backup restore <file>` | Decrypt and write the contents back into the stores |

## Credentials

`create` takes `--password`; when it is omitted a random 256-bit key is
generated and printed once in hex:

```
Generated encryption key (save this):
  9f2c...<64 hex chars>
```

`contents` and `restore` accept either `--password` or `--key <hex>`. The key
is the SHA-256 of the password, or the 32 raw bytes decoded from `--key`.

A wrong password or key fails with
`backup: decryption failed: incorrect password or key` and nothing is written.

## Data sources

By default the commands read and write the stores under the xkey data
directory (`$XKEY_HOME/data`, normally `~/.xkey/data`) — the same locations
the xkey GUI uses when the barrier is not active:

| Category | Default location | Override |
|----------|------------------|----------|
| `trust-store` | `{data}/trust` | `--trust-store` |
| `oath-credentials` | `{data}/oath.json` | `--oath-store` |
| `static-passwords` | `{data}/staticpw` | `--password-store` |

Each default resolves through the same feature-directory constant the owning
command uses (`trustDataSubdir`, `oathStoreFilename`,
`passwordStoreFeature` in `xkey/cmd/xkey/cmd`), so backup and the command
that actually reads or writes the store can never drift apart. Prior to
go-xkms#936, backup's copy of the password default was `{data}/passwords`
while `xkey password`'s store lived at `{data}/staticpw`: a default backup
silently captured zero passwords.

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
destination store that does not exist yet is created normally, the same as
before go-xkms#936.

## Failure modes

| Situation | Behavior |
|-----------|----------|
| Every store empty | Fails with `backup: no data available to back up`; no file is written |
| Data directory barrier-encrypted | Fails with `backup: xkey data directory is barrier-encrypted`; unseal in the GUI or pass explicit store paths |
| Default source never written to (`create`/`to-device`) | Not an error: the category is listed under `Not included:` and left out, instead of being auto-created empty |
| `--trust-store`/`--oath-store`/`--password-store` names a path that does not exist (`create`/`to-device`) | Fails with `backup: source does not exist`, naming the category and path |
| Store cannot be opened | Fails with `backup: data store unavailable`, naming the category and path |
| Wrong password/key, tampered ciphertext, or truncated file | Fails with `backup: decryption failed` |
| Backup holds a category the CLI cannot write | Restores the rest, then exits with `backup: restore incomplete` |

Entries that already exist in a target store are reported per category as
`skipped`, and the command ends with
`Restore completed with N skipped item(s).`

## File format

A `.xkb` file is the JSON encoding of the backup envelope:

```json
{
  "magic": "XKBK",
  "version": 1,
  "nonce": "<base64, 24 bytes>",
  "ciphertext": "<base64>"
}
```

The ciphertext is the archive — manifest, certificates, credentials, and
passwords — serialized to JSON and sealed with XChaCha20-Poly1305 under the
password-derived or supplied key. The archive carries a SHA-256 checksum of
its own payload, verified on decrypt. Only the magic value, format version,
and nonce are readable without the key.

## Example

```bash
# Back up to an explicit path
xkey backup create --password 'correct horse battery staple' \
  --output ~/.xkey/backups/laptop.xkb

# Inspect without restoring
xkey backup contents ~/.xkey/backups/laptop.xkb --password 'correct horse battery staple'

# Restore onto a new machine
xkey backup restore ~/.xkey/backups/laptop.xkb --password 'correct horse battery staple'
```
