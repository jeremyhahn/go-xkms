# LUKS2 Encrypted Storage — CLI

> **Status: NORMATIVE** · Feature: `luks` · Module: `go-xkms/xkey` · Last verified: 2026-09-27

Binary: `xkey`. Parent command: `xkey luks2` (`cmd/xkey/cmd/luks2.go`).
Every subcommand requires root; run under `sudo`.

## `xkey luks2 seal`

Creates a new LUKS2 container and, if `~/.xkey/` already holds data, migrates
it in.

| Flag | Default | Description |
|---|---|---|
| `--size` | `100M` | Container size (`100M`, `1G`, …) |
| `--path` | `~/.xkey.luks` | Custom container path |
| `--mount-point` | `~/.xkey` | Custom mount point |
| `--unseal` | `false` | Unlock and mount immediately after creating |
| `--skip-migrate` | `false` | Create the container without migrating existing data |

```
sudo xkey luks2 seal
sudo xkey luks2 seal --size 500M
sudo xkey luks2 seal --path /secure/xkey.luks
sudo xkey luks2 seal --unseal
```

Prompts for a passphrase (with confirmation) on a terminal, or reads two
newline-separated lines from piped stdin for automation:

```
echo -e "mypassphrase\nmypassphrase" | sudo xkey luks2 seal
```

## `xkey luks2 unseal`

| Flag | Default | Description |
|---|---|---|
| `--path` | `~/.xkey.luks` | Custom container path |
| `--mount-point` | `~/.xkey` | Custom mount point |

```
sudo xkey luks2 unseal
sudo xkey luks2 unseal --path /secure/xkey.luks
echo "mypassphrase" | sudo xkey luks2 unseal
```

Already-mounted is a no-op success, not an error.

## `xkey luks2 lock`

| Flag | Default | Description |
|---|---|---|
| `--path` | `~/.xkey.luks` | Custom container path |
| `--mount-point` | `~/.xkey` | Custom mount point |

```
sudo xkey luks2 lock
```

## `xkey luks2 migrate`

Moves to a new or larger container.

| Flag | Default | Description |
|---|---|---|
| `--size` | 2x current | New container size |
| `--path` | same as current | New container path |
| `--source-path` | `~/.xkey.luks` | Source container path |
| `--keep-old` | `false` | Keep the old container as `<path>.old` |
| `--wipe` | `false` | Securely wipe the old container instead of a plain remove |
| `--wipe-standard` | `dod3` | `nist`, `dod3`, or `dod7` |

```
sudo xkey luks2 migrate                             # double the size
sudo xkey luks2 migrate --size 500M
sudo xkey luks2 migrate --keep-old
sudo xkey luks2 migrate --wipe --wipe-standard dod7
sudo xkey luks2 migrate --path /new/location.luks
```

Prompts for the current container's passphrase, then a new one (pressing
Enter reuses the current one). Runs the kernel-keyring preflight before
renaming the source container, so a blocked keyring leaves the original
container untouched — see
[architecture.md](architecture.md#kernel-keyring-preflight).

## `xkey luks2 wipe`

Irreversibly destroys a container.

| Flag | Default | Description |
|---|---|---|
| `--standard` | `dod3` | `nist`, `dod3`, or `dod7` |
| `--force` | `false` | Skip the `DESTROY` confirmation prompt |
| `--path` | `~/.xkey.luks` | Container path |
| `--mount-point` | `~/.xkey` | Mount point (locked first if open) |

```
sudo xkey luks2 wipe
sudo xkey luks2 wipe --standard nist
sudo xkey luks2 wipe --standard dod7
sudo xkey luks2 wipe --force
```

Without `--force`, requires typing `DESTROY` at a prompt that also shows the
container path, size, standard and pattern.

## `xkey luks2 import-data`

Copies an existing plaintext directory into an already-created LUKS
container, using a temporary mount point so it works even while xkey is
actively using the source directory.

| Flag | Default | Description |
|---|---|---|
| `--path` | `~/.xkey.luks` | LUKS container path |
| `--source` | `~/.xkey` | Source directory to import from |
| `--mount-point` | `~/.xkey` | Final mount point for `--unseal` |
| `--cleanup` | `false` | Remove the plaintext source after a successful import |
| `--backup` | `false` | With `--cleanup`, rename the source to `<source>-backup` instead of deleting it |
| `--unseal` | `false` | Unlock at the final mount point after import (and cleanup, if requested) |

```
sudo xkey luks2 import-data --source ~/.xkey --path ~/.xkey.luks --cleanup
sudo xkey luks2 import-data --source ~/.xkey --path ~/.xkey.luks --cleanup --backup
sudo xkey luks2 import-data --source ~/.xkey --path ~/.xkey.luks --cleanup --unseal --mount-point ~/.xkey
```

## Wipe standards

| Value | Name | Pattern |
|---|---|---|
| `nist` | NIST SP 800-88 Rev 1 | Random, 1 pass (fastest) |
| `dod3` | DoD 5220.22-M 3-pass | Zeros → Ones → Random (default) |
| `dod7` | DoD 5220.22-M ECE 7-pass | (Z→O→R) + R + (Z→O→R), most thorough |

`wipe --standard` and `migrate --wipe-standard` accept the same three values
and run the same overwrite implementation.

## Common errors

| Message | Cause |
|---|---|
| `luks: permission denied (requires root)` | Not running as root |
| `luks: encrypted container already exists - use 'xkey luks2 wipe' first to destroy existing data` | `seal` against an existing container path |
| `luks: volume not found` | `unseal`/`lock` against a path with no container |
| `luks: volume already mounted` | `unseal` when already mounted (reported as success, not this error, by `unseal` itself) |
| `luks: kernel keyring preflight failed: ...` | `add_key`/`keyctl`/`request_key` blocked — see [architecture.md](architecture.md#kernel-keyring-preflight) |

## Automation

```
echo -e "mypassphrase\nmypassphrase" | sudo xkey luks2 seal
echo "mypassphrase" | sudo xkey luks2 unseal
sudo xkey luks2 wipe --force
```

An example systemd unit for unlocking at boot (not installed by xkey):

```ini
[Unit]
Description=xkey LUKS Unlock
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/xkey luks2 unseal
StandardInput=tty-force

[Install]
WantedBy=multi-user.target
```
