# LUKS2 Encrypted Storage — Engineering

> **Status: NORMATIVE** · Feature: `luks` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

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
