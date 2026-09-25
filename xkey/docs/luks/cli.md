# LUKS2 Encrypted Storage — CLI

> **Status: NORMATIVE** · Feature: `luks` · Module: `go-xkms/xkey` · Last verified: 2026-09-25

All LUKS commands live under `xkey luks2` and require root (directly, or via
`sudo`). They are exempt from the ordinary unlock gate described below —
they *are* the commands that manage the volume the gate checks.

## The unlock gate (every other command)

Every `xkey` command **other than** `luks2 *`, `barrier *`, `pin *`, and `usb
*` (see `luksExemptGroups`, `cmd/xkey/cmd/root.go`) passes through
`checkLUKSVolume()` before it runs:

- No container configured (`~/.xkey.luks` does not exist): no-op, the
  command runs against the plain data directory exactly as it always has.
- Container exists and is already mounted: no-op, the command runs.
- Container exists, is not mounted, and the process is not root:

  ```
  Encrypted storage detected at /home/you/.xkey.luks
  Run with sudo to unlock: sudo xkey luks2 unseal
  ```

  and the command exits with an error matching
  `errors.Is(err, xkms.ErrLUKSVolumeLocked)` — the same sentinel the GUI
  reports for the identical condition. `errors.Is(err,
  luks.ErrPermissionDenied)` also matches, for the more specific cause.
- Container exists, is not mounted, process is root: prompts for the
  passphrase on stderr, unlocks and mounts, then the command runs.

## seal — create an encrypted container

```bash
sudo xkey luks2 seal [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--size` | Container size (e.g. `100M`, `1G`, `500M`) | `100M` |
| `--path` | Custom LUKS file path | `~/.xkey.luks` |
| `--mount-point` | Custom mount point | `~/.xkey` |
| `--unseal` | Unlock immediately after creating | `false` |
| `--skip-migrate` | Do not migrate existing plaintext data into the new container | `false` |

```bash
sudo xkey luks2 seal                              # 100MB, default paths
sudo xkey luks2 seal --size 500M
sudo xkey luks2 seal --size 1G --path /secure/mydata.luks
sudo xkey luks2 seal --mount-point /mnt/xkey
echo -e "mypassphrase\nmypassphrase" | sudo xkey luks2 seal   # scripted (passphrase + confirmation)
```

Process: prompts for passphrase with confirmation → creates a sparse file of
the requested size → formats it LUKS2 → creates an ext4 filesystem inside →
migrates existing plaintext data from the mount point unless
`--skip-migrate` → locks the container (unless `--unseal`).

## unseal — unlock and mount

```bash
sudo xkey luks2 unseal [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--path` | Custom LUKS file path | `~/.xkey.luks` |
| `--mount-point` | Custom mount point | `~/.xkey` |

```bash
sudo xkey luks2 unseal
sudo xkey luks2 unseal --path /secure/mydata.luks
echo "mypassphrase" | sudo xkey luks2 unseal   # scripted
```

## lock — unmount and close

```bash
sudo xkey luks2 lock [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--path` | Custom LUKS file path | `~/.xkey.luks` |
| `--mount-point` | Custom mount point | `~/.xkey` |

```bash
sudo xkey luks2 lock
```

## import-data — copy existing data into an already-created container

```bash
sudo xkey luks2 import-data [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--source` | Source directory to import from | `~/.xkey` |
| `--path` | LUKS file path | `~/.xkey.luks` |
| `--cleanup` | Remove the original plaintext data after a successful import | `false` |
| `--backup` | With `--cleanup`, rename the source directory to `<source>-backup` instead of deleting it | `false` |
| `--unseal` | Unlock the volume at `--mount-point` after import/cleanup, in the same elevated command | `false` |
| `--mount-point` | Final mount point used with `--unseal` | `~/.xkey` |

```bash
sudo xkey luks2 import-data --source ~/.xkey --path ~/.xkey.luks --cleanup
sudo xkey luks2 import-data --source ~/.xkey --path ~/.xkey.luks --cleanup --backup
sudo xkey luks2 import-data --source ~/.xkey --path ~/.xkey.luks --cleanup --unseal --mount-point ~/.xkey
```

Unlike `seal`, which migrates data into a container it just created,
`import-data` targets a container that already exists: it unlocks the
volume at a temporary mount point (not `--mount-point`), copies `--source`
into it with `Volume.CopyDataToVolume`, and locks it again before any
`--cleanup`/`--unseal` step runs — this ordering closes the window in which
a still-running application could recreate plaintext data in `--source`
between cleanup and the final mount. Fails with `ImportDataError` if
`--source` does not exist or is empty, or if the LUKS volume at `--path`
does not exist yet (create it first with `luks2 seal`). Requires root.

## migrate — move to a new or larger container

```bash
sudo xkey luks2 migrate [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--size` | New container size | 2x current |
| `--path` | New container path | same as current |
| `--source-path` | Source container path | `~/.xkey.luks` |
| `--keep-old` | Keep old container as `.old` backup | `false` |
| `--wipe` | Securely wipe the old container after migration | `false` |
| `--wipe-standard` | `nist` \| `dod3` \| `dod7` | `dod3` |

```bash
sudo xkey luks2 migrate                        # double the size
sudo xkey luks2 migrate --size 500M
sudo xkey luks2 migrate --path /new/location.luks
sudo xkey luks2 migrate --keep-old
sudo xkey luks2 migrate --wipe --wipe-standard dod7
```

## wipe — securely destroy a container

```bash
sudo xkey luks2 wipe [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--standard` | `nist` \| `dod3` \| `dod7` | `dod3` |
| `--force` | Skip the "type DESTROY to confirm" prompt | `false` |
| `--path` | Custom LUKS file path | `~/.xkey.luks` |
| `--mount-point` | Custom mount point | `~/.xkey` |

```bash
sudo xkey luks2 wipe                     # DoD 3-pass, prompts for confirmation
sudo xkey luks2 wipe --standard nist     # fastest
sudo xkey luks2 wipe --standard dod7     # most thorough
sudo xkey luks2 wipe --force             # scripting
```

Wipe standards: `nist` (NIST SP 800-88 Rev 1, single random pass — fastest,
recommended for SSDs with TRIM), `dod3` (DoD 5220.22-M, zeros → ones →
random — default), `dod7` (DoD 5220.22-M ECE, extended 7-pass — slowest,
most thorough).

## Automation

```bash
# systemd unit to auto-unlock on boot (stdin-fed passphrase)
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

For an unattended, hardware-backed alternative see the GUI's TPM
auto-unseal (`xkey/docs/seal/`, `AutoUnsealService`) — it does not use this
systemd unit.

## Troubleshooting

- **"Encrypted storage detected ... Run with sudo to unlock"** — expected
  when a non-root invocation hits a locked, configured volume; run the
  suggested `sudo xkey luks2 unseal`, or re-run your original command as
  root.
- **"No encrypted volume found"** — no container at the expected path;
  check `ls -la ~/.xkey.luks` or pass `--path`.
- **"Device or resource busy"** — the container is already open/mounted
  (possibly by another process); run `xkey luks2 lock` first, or — if a
  second process legitimately needs to use an already-mounted volume —
  that is exactly what `Backend.Attach` (architecture.md) is for; no
  command-line action needed.
- **"Wrong passphrase"** — self-explanatory; retry.
- **"kernel keyring preflight failed"** — every operation that creates or
  unlocks a volume needs `add_key`/`keyctl`/`request_key`, which a
  container's default seccomp profile (Docker) blocks even with
  `--cap-add SYS_ADMIN`; allow those three syscalls in a custom profile or
  run on the host.
