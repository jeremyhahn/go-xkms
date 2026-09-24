# LUKS2 Encrypted Storage — Architecture

> **Status: NORMATIVE** · Feature: `luks` · Module: `go-xkms/xkey` · Last verified: 2026-09-27

## Scope: `xkey/pkg/luks`, not `pkg/storage/luks`

**This document covers `xkey/pkg/luks`** — the volume lifecycle (`Volume`,
its create/unlock/lock methods, the secure-wipe helper, and the kernel
keyring preflight) that backs the `xkey luks2` command group.

The go-xkms root module has a *different* package,
`go-xkms/pkg/storage/luks`, which implements the `storage.Backend` interface
(`Get`/`Put`/`Delete`/`CompareAndSwap`, etc.) over an already-mounted LUKS
volume via a `VolumeOperator` abstraction. It is a storage backend consumed
by xkmsd, not a volume-lifecycle CLI, and is documented separately under
`../../docs/`. The two packages share no code; do not conflate the two when
reading `xkey luks2 --help` against a `storage.Backend` question.

## The problem

xkey stores configuration, OIDC/session tokens, and other credential
material on disk under its home directory. The [Barrier](../seal/) already
encrypts individual values with AES-256-GCM before they touch storage. LUKS
adds a second, independent, kernel-enforced layer *beneath* that: full-volume
encryption that also protects file names, directory structure, and anything
the barrier's per-value model does not cover, for operators who want
defense in depth or need the data unreadable at rest even before the barrier
opens.

## Shape chosen: LUKS2 as an optional base layer

```
Without LUKS:  App --> Barrier (AES-256-GCM) --> filestorage --> ~/.xkey/
With LUKS:     App --> Barrier (AES-256-GCM) --> filestorage --> ~/.xkey/  (LUKS-mounted)
```

LUKS is optional and orthogonal to the barrier, not a replacement for it:
turning LUKS on changes where `~/.xkey/` is backed (a mounted encrypted
volume instead of a plain directory), not what writes into it. The barrier
still encrypts every value it protects regardless of which one sits
underneath.

## Built on go-luks2; xkey owns only the volume lifecycle

`xkey/pkg/luks.Volume` is a thin wrapper around
`github.com/jeremyhahn/go-luks2` (loop-device setup, LUKS2 format/unlock/
lock, ext4 filesystem creation, mount/unmount). The cipher and KDF are
**go-luks2's own defaults**, not something this package chooses or exposes a
flag for: `luks2.FormatOptions` falls back to `DefaultCipher`/
`DefaultCipherMode` (AES in XTS mode) when unset, and go-luks2's KDF default
is Argon2id (`luks2.KDFTypeArgon2id`, `pkg/luks2/kdf.go` in the go-luks2
module). If those defaults ever need to change, that is a go-luks2 change,
not an `xkey/pkg/luks` one.

What this package adds on top of go-luks2:

- **Path resolution** through `xhome.Home` (`LUKSPath()`/`MountPoint()`), so
  `xkey luks2 seal` without flags lands in the same place every other xkey
  command resolves its data directory to. See
  [architecture/xhome.md](../architecture/xhome.md).
- **A kernel-keyring preflight** (`EnsureKeyringAvailable`) run before every
  operation that will hand dm-crypt a volume key — see *Kernel keyring
  preflight* below.
- **Ownership handoff back to the invoking user** under `sudo`/`pkexec`
  (`ChownToCallingUser`, `chownTreeToCallingUser`) so root-only LUKS
  operations do not leave an unprivileged process locked out of its own
  mounted data.
- **Secure wipe** (`Wipe`, `WipeStandard`) as a standalone file-overwrite
  utility, independent of go-luks2, used by `luks2 wipe` and `luks2 migrate
  --wipe`.

## Kernel keyring preflight

go-luks2 hands dm-crypt the volume key by kernel-keyring reference, so every
create or unlock needs the `add_key`, `keyctl` and `request_key` syscalls.
`Volume.Create` and `Volume.Unlock` both call `EnsureKeyringAvailable`
*before* touching a loop device or container file
(`xkey/pkg/luks/volume.go:91,177`), and `luks2 migrate` runs the same check
explicitly, before it renames the source container, so a blocked keyring
never leaves the source touched (`migrateKeyringPreflight`,
`cmd/xkey/cmd/migrate.go:112`). A `KeyringError` (`Is` `ErrKeyringUnavailable`)
names the syscall class and, through its `Unwrap`, go-luks2's finer
classification (`luks2.ErrKeyringBlocked` for a seccomp policy,
`luks2.ErrKeyringUnsupported`, `luks2.ErrKeyringQuotaExhausted`).

The usual trigger is a container seccomp profile that blocks the three
syscalls (Docker's default profile does; `--cap-add SYS_ADMIN` does not lift
it) or a kernel built without `CONFIG_KEYS`.

## Data flow

```
seal:        create container (Volume.Create) -> optionally migrate existing
              ~/.xkey/ contents in -> optionally leave unlocked (--unseal)
unseal:      Volume.Unlock -> mount at ~/.xkey/
lock:        unmount -> Volume.Lock (close + detach loop device)
migrate:     lock current -> rename to .old -> create new (larger) container
              -> copy all data across -> lock both -> remove/wipe/keep .old
wipe:        lock if open -> overwrite with the selected standard -> remove file
import-data: unlock at a temp mount point -> copy an existing plaintext
              directory in -> lock -> optional cleanup of the plaintext source
              -> optional final unlock at the real mount point
```

## Trust boundaries

- **Every `xkey luks2` command requires `os.Geteuid() == 0`.** There is no
  privilege-escalation path inside the package; the CLI layer checks and
  returns `ErrPermissionDenied` before doing anything else (with one
  exception — see *Ordering note* below).
- **The container and mount-point directories are created with mode
  0700**; the LUKS container file inherits normal file creation permissions
  under the elevated process.
- **A wipe cannot be undone.** `luks2 wipe` requires typing `DESTROY` unless
  `--force` is passed; there is no confirmation bypass beyond that flag.
- **`--wipe` on `migrate` and the standalone `wipe` command share one
  overwrite implementation** (`wipeContainerWithStandard`), so the pattern
  sequence for a given `--standard`/`--wipe-standard` value is identical
  either way.

### Ordering note: `wipe`'s standard is validated before the privilege check

`runWipe` (`cmd/xkey/cmd/wipe.go`) validates `--standard` against
`wipeStandardMap` **before** checking `os.Geteuid()`, deliberately: an
unrecognised standard is a usage error and should be reported as such
regardless of who is running the command. `runMigrate`
(`cmd/xkey/cmd/migrate.go`) checks the privilege first, then validates
`--wipe-standard` only if `--wipe` was passed. Both are correct for their
own command; note the difference if you are relying on exit-code ordering
in a script.

## What this feature deliberately does not do

- **No GUI binding.** There is no LUKS entry under `pkg/gui/services`; every
  `xkey luks2` operation is CLI-only and requires an interactive or piped
  terminal for the passphrase prompt.
- **No incremental resize.** `migrate` always creates a fresh container at
  the target size and copies everything; there is no in-place grow.
- **No boot-time auto-unlock is shipped.** The systemd unit in
  [user.md](user.md) is an example an operator writes themselves; xkey does
  not install or manage one.
