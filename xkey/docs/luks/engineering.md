# LUKS2 Encrypted Storage — Engineering

> **Status: NORMATIVE** · Feature: `luks` · Module: `go-xkms/xkey` · Last verified: 2026-09-30

> **go-xkms#917:** `xkey/pkg/luks.Volume`'s `Create`/`Unlock`/`Mount`/
> `Lock`/`Unmount` delegate to a package-level `volumeExecutor
> sdkluks.Executor` (`sdkluks.NewLibExecutor()` by default), not to
> `github.com/jeremyhahn/go-luks2` directly. `Volume.IsMounted`/`IsOpen` read
> through `sdkluks.IsMounted`/`IsUnlocked` (package vars `checkMounted`/
> `checkUnlocked` in `detect.go`, kept for test substitution). `Volume`'s own
> method set, used throughout this document, is unchanged. See
> [`../../../docs/luks/engineering.md`](../../../docs/luks/engineering.md)
> for the shared `Executor`/`Manager`/`TPMSealer` contract this package now
> builds on.

## Exported surface

### go-xkms (`pkg/storage/luks`, re-exported via `sdk/go`)

| Symbol | Kind | Notes |
|---|---|---|
| `xkms.LUKSStorageBackend` | type alias → `luksstorage.Backend` | `storage.Backend` gated by a LUKS volume's lock state |
| `xkms.LUKSVolumeOperator` | type alias → `luksstorage.VolumeOperator` | `Exists/IsLUKS/IsMounted/IsOpen/GetMountPoint/Create/Unlock/Lock` |
| `xkms.NewLUKSStorageBackend(vol)` | func | starts locked |
| `(*LUKSStorageBackend).Initialize(sizeBytes, passphrase)` | method | create + unlock |
| `(*LUKSStorageBackend).Unlock(passphrase)` | method | performs a real LUKS open + mount |
| `(*LUKSStorageBackend).Attach()` | method | attaches to an already-mounted volume; no passphrase |
| `(*LUKSStorageBackend).Lock()` | method | closes delegate, locks volume |
| `(*LUKSStorageBackend).IsUnlocked()` | method | in-process state only — see architecture.md "Two processes, one volume" |
| `(*LUKSStorageBackend).Get/Put/Delete/List/Scan/Exists/Close` | methods | `storage.Backend`; each returns `ErrLUKSVolumeLocked` while locked |

### xkey

| Symbol | Kind | Notes |
|---|---|---|
| `xkey/pkg/luks.Volume` | type | satisfies `xkms.LUKSVolumeOperator` structurally; `NewVolume()`, `NewVolumeFromHome(h)`, `NewVolumeWithPaths(luksPath, mountPoint)` |
| `pkg/gui/services.StorageService` | type | GUI-facing; Wails-bound (see `api.md`) |
| `(*StorageService).RequireUnlocked() error` | method | the gate; see below |
| `cmd/xkey/cmd.checkLUKSVolume() error` | func (unexported) | the CLI's `PersistentPreRunE` gate |

## `RequireUnlocked` — invariants

```go
func (s *StorageService) RequireUnlocked() error
```

1. Returns `nil` if `luks.NewVolume()` cannot resolve `xhome` — a broken
   home resolution surfaces with more context at the data-directory open
   that follows, not here.
2. Returns `nil` if the volume's container file does not exist
   (`!vol.Exists()`) — **no LUKS configured, no-op**. This is the invariant
   that keeps a plain (no-LUKS) install byte-for-byte unchanged.
3. Returns `nil` if the service's own `LUKSStorageBackend.IsUnlocked()` is
   already `true`.
4. Otherwise, if the volume is mounted (`vol.IsMounted()`) but this
   process's backend hasn't unlocked it, calls `Backend.Attach()` and
   returns its result (normally `nil`).
5. Otherwise — configured, not mounted, not attachable — returns
   `xkms.ErrLUKSVolumeLocked`.

The same `*xkms.LUKSStorageBackend` instance is reused for the life of the
`StorageService` (`luksStorageBackend()`, guarded by `luksMu sync.Mutex`),
so state set by `CreateVolume`/`UnlockVolume`/`LockVolume`'s root-euid
branches is what step 3 sees on every subsequent call.

## Crash-safety invariants — `seal` migration and `import-data`

Both `xkey luks2 seal` (existing-data migration) and `xkey luks2
import-data` move a plaintext directory into an encrypted volume. Neither
may lose the only copy of that data if a step fails partway through
(`#1012`).

### `migrateExistingData` (`cmd/xkey/cmd/seal.go`)

Order of operations, each gated on the previous one succeeding:

1. Stage the existing directory (`vol.GetMountPoint()`) into a temp dir
   (`os.MkdirTemp("", "xkey-migrate-")`) via `copyDirContents`. Nothing has
   been touched yet; a failure here just discards the (unused) temp dir.
2. `vol.Unlock(passphrase)` — mounts the encrypted filesystem over the same
   path the plaintext data lives at. This hides the plaintext files, it
   does not delete them: they reappear once the volume is locked again.
3. `vol.CopyDataToVolume(tmpDir)` — copies the staged data into the
   now-mounted volume.
4. `verifyDirCopy(tmpDir, dataDir)` — a shallow integrity check (every file
   and directory in the staged copy exists in the volume with a matching
   size) run while the volume is still mounted, so `dataDir` resolves to
   the volume's content.
5. `vol.Lock()` — unmounts, which uncovers the original plaintext
   directory again, untouched since step 2.
6. Only now: `os.RemoveAll(dataDir)` deletes the plaintext source, followed
   by `os.RemoveAll(tmpDir)` to drop the now-redundant staging copy.

If any of steps 2–6 fails, the function returns before deleting the source
or the staging copy: the staging directory is left on disk and its path is
written to `out` (`"staged copy preserved at %s"`); on a copy or verify
failure a best-effort `vol.Lock()` is attempted and any failure of that is
also reported. The source directory is never removed before step 6, so a
failure at any earlier step leaves both the original plaintext *and* the
staging copy in place — the change deliberately favors two intact copies
over deleting either one early.

`migrateExistingData` takes a `migrateVolume` interface
(`GetMountPoint/Unlock/Lock/CopyDataToVolume`), not a concrete
`*luks.Volume`, purely so unit tests can fault-inject each step without a
real LUKS container or loop device (`cmd/xkey/cmd/seal_test.go`,
`fakeMigrateVolume`). `*luks.Volume` satisfies it structurally; production
code is unaffected.

`verifyDirCopy` failures are a typed `*DataVerificationError` (`Path`,
`Message`, wrapped `Err`), consistent with the "typed errors, not
`fmt.Errorf`" convention the rest of this package follows.

### `import-data` (`cmd/xkey/cmd/import_data.go`)

`runImportData` unlocks the volume at a temporary mount point
(`os.MkdirTemp("", "xkey-import-")`), copies the source directory into it,
and locks it again — all via `importDataToVolume`, which takes an
`importDataVolume` interface (`Unlock/Lock/CopyDataToVolume/IsMounted`) for
the same fault-injection reason as `migrateVolume` above.

The temporary mount point is removed by a deferred call to
`removeTempMount`, never by an unconditional `os.RemoveAll`:

```go
defer removeTempMount(cmd.OutOrStdout(), vol, tmpMount)
```

`removeTempMount` calls `vol.IsMounted()` first. If the volume is still
mounted there — because `Unlock` succeeded but `Lock` never ran or itself
failed — the directory is left in place and a warning is written to `out`
instead of being deleted; a still-mounted directory holds the copied data,
and removing it would delete that data. Only when `IsMounted()` is `false`
does it call `os.RemoveAll(tmpMount)`.

On a copy failure, `importDataToVolume` also attempts a best-effort
`vol.Lock()`; if that itself fails, it reports that `tmpMount` is still
mounted before returning, so the operator knows to inspect it rather than
assume the deferred cleanup handled it.

## Errors

All sentinels are typed values from `go-xkms/pkg/storage/luks`, re-exported
by `sdk/go` — never re-declared locally in xkey:

| Sentinel | Meaning |
|---|---|
| `xkms.ErrLUKSVolumeLocked` | operation refused; volume not mounted |
| `xkms.ErrLUKSVolumeAlreadyUnlocked` | `Unlock`/`Attach` called on an already-unlocked backend |
| `xkms.ErrLUKSVolumeNotInitialized` | container file does not exist |
| `xkms.ErrLUKSVolumeNotMounted` | `Attach` called with nothing mounted to attach to |
| `xkms.ErrLUKSInitializeRequiresPassphrase` | `Initialize` called with an empty passphrase |
| `xkms.ErrLUKSDelegateCreateFailed` | the mount point could not be opened as a file-storage root |
| `xkms.ErrLUKSVolumeLockFailed` | volume-level lock/unmount failed |

The CLI's `checkLUKSVolume` wraps `xkms.ErrLUKSVolumeLocked` together with
`xkey/pkg/luks.ErrPermissionDenied` via `&SentinelCauseError{Sentinel:
xkms.ErrLUKSVolumeLocked, Cause: luks.ErrPermissionDenied}` so both
`errors.Is(err, xkms.ErrLUKSVolumeLocked)` and `errors.Is(err,
luks.ErrPermissionDenied)` match.

## Configuration

No dedicated config schema. LUKS is selected as `StorageType == "luks"` in
the GUI's `GUIConfig` (set by the setup wizard) and detected on the CLI
purely from container-file presence (`vol.Exists()`) — there is no
"LUKS enabled" flag to fall out of sync with the container's actual
existence. Container and mount point paths come from `xhome.Home`
(`LUKSPath()`, `MountPoint()`), overridable via `$XKEY_HOME`.

## Tests

| Layer | File | What it proves |
|---|---|---|
| go-xkms `pkg/storage/luks` | `backend_test.go` | `Attach` succeeds against an already-mounted mock volume without calling `volume.Unlock`; fails with `ErrVolumeNotMounted`/`ErrVolumeNotInitialized`/`ErrVolumeAlreadyUnlocked` appropriately; full existing `Unlock`/`Lock`/`Initialize` suite unchanged |
| xkey `pkg/gui/services` | `storage_service_test.go` (`TestStorageService_RequireUnlocked_*`) | no-LUKS no-op; locked volume returns `ErrLUKSVolumeLocked`; idempotent across repeated calls |
| xkey `pkg/gui` | `init_data_dir_test.go` (`TestInitializeDataDir_LUKSLocked_*`, `TestInitializeDataDir_StorageServiceWired_NoLUKS_Unchanged`) | `initializeDataDir` fails closed with the sentinel and **asserts on the filesystem** that no `data/` subdirectory is created beneath an unmounted mount point; wiring `storageService` does not change the no-LUKS path |
| xkey `cmd/xkey/cmd` | `luks_cmds_test.go` (`TestCheckLUKSVolume_*`) | the CLI gate returns the same sentinel for a locked volume; no-op for no volume |
| xkey `cmd/xkey/cmd` | `seal_test.go` (`TestMigrateExistingData_*`, `TestVerifyDirCopy_*`) | unlock, copy, verify and lock failures during migration all preserve both the plaintext source and the staged copy (fault-injected via `fakeMigrateVolume`, no real LUKS device); a full success removes both |
| xkey `cmd/xkey/cmd` | `import_data_test.go` (`TestImportDataToVolume_*`, `TestRemoveTempMount_*`) | unlock, copy and lock failures during import are reported and, when the volume is still mounted, `removeTempMount` leaves the temp mount point (and its copied data) in place instead of deleting it |

A real cryptsetup/loop-device exercise (actually mounting, unlocking from a
second process, confirming ciphertext on the backing file) needs root and
belongs in the devcontainer integration target — see `xkey/test/integration/luks`
and `make integration-test-luks`, not this unit suite.

## Non-goals

- No change to the Barrier, which remains the only layer that encrypts
  individual values; LUKS is full-volume, not per-value.
- No per-store prefix-backend rewrite — see architecture.md's "Rejected
  alternative".
- No REST/gRPC surface — see `api.md`.
