# LUKS2 Encrypted Storage — Engineering

> **Status: NORMATIVE** · Feature: `luks` · Module: `go-xkms/xkey` · Last verified: 2026-09-27

## Exported surface — `xkey/pkg/luks`

`Volume` (`volume.go`): `LUKSPath`, `MountPoint`, `MapperName`,
`LoopDevice` fields; constructors `NewVolume()` (resolves paths via
`xhome.Resolve`), `NewVolumeWithPaths(luksPath, mountPoint string) *Volume`,
`NewVolumeFromHome(h *xhome.Home) *Volume` (`detect.go`); methods
`GetMountPoint()`, `Exists()`, `IsLUKS()`, `IsMounted()`, `IsOpen()`,
`Create(sizeBytes int64, passphrase string) error`, `Unlock(passphrase
string) error`, `Lock() error`, `CopyDataToVolume(sourceDir string) error`.

Keyring preflight (`keyring.go`): `EnsureKeyringAvailable() error`.

Wipe (`wipe.go`): `WipeStandard` (`StandardCustom`, `StandardNIST`,
`StandardDoD3Pass`, `StandardDoD7Pass`) with `String()`,
`GetPatternSequence() []WipePattern`; `WipePattern` (`PatternZeros`,
`PatternOnes`, `PatternRandom`); `WipeOptions{Path, Standard}`; `Wipe(opts
WipeOptions) error`.

Detection and paths (`detect.go`): `MapperName = "xkey"`, `IsLUKSVolume(path
string) bool`, `IsMounted(mountPoint string) bool`, `IsLUKSOpen(mapperName
string) bool`, `ExpandPath(path string) string` (expands a leading `~/`).

Ownership handoff (`volume.go`): `ChownToCallingUser(path string)` — chowns
a path tree to the real user under `sudo`/`pkexec` so the mounted volume
stays writable by the unprivileged process that will read it next.

Errors (`errors.go`): sentinels `ErrVolumeNotFound`,
`ErrVolumeAlreadyExists`, `ErrVolumeNotMounted`, `ErrVolumeAlreadyMounted`,
`ErrInvalidPassphrase`, `ErrPassphraseMismatch`, `ErrLoopDeviceSetup`,
`ErrLUKSFormat`, `ErrLUKSUnlock`, `ErrLUKSLock`, `ErrFilesystemCreate`,
`ErrMountFailed`, `ErrUnmountFailed`, `ErrDataCopyFailed`,
`ErrPermissionDenied`, `ErrKeyringUnavailable`; typed wrappers
`KeyringError{Err}` (`Is` reports `ErrKeyringUnavailable`; `Unwrap` returns
go-luks2's own classified error), `VolumeError{Operation, Path, Err}`,
`MessageError{Msg}`, `WrappedError{Msg, Err}`.

## Exported surface — `cmd/xkey/cmd` (luks2 group)

Each subcommand defines its own typed error carrying `Operation`
(`+Message`) `+ Err`, all with `Error()`/`Unwrap()`: `SealError`
(`seal.go`), `UnsealError` (`unseal.go`), `LockError` (`lock.go`),
`MigrateError` (`migrate.go`), `WipeError` (`wipe.go`), `ImportDataError`
(`import_data.go`). `wipeStandardMap` (`wipe.go`) maps the CLI's
`nist`/`dod3`/`dod7` flag values to `luks.WipeStandard` constants and is
reused by `migrate.go`'s `--wipe-standard`.

## Invariants

- Every subcommand refuses with `luks.ErrPermissionDenied` unless
  `os.Geteuid() == 0`.
- `Volume.Create` refuses if the container already exists
  (`ErrVolumeAlreadyExists`); `Volume.Unlock` refuses if the volume is
  already mounted (`ErrVolumeAlreadyMounted`) or the container does not
  exist (`ErrVolumeNotFound`); `Volume.Lock` refuses if neither open nor
  mounted (`ErrVolumeNotMounted`).
- `migrate` restores the renamed `.old` container back to its original path
  on every failure path after the rename (create, unlock, or copy failure),
  so a failed migration never leaves the operator without a working
  container at the original path.
- `import-data` performs cleanup of the plaintext source **before** the
  final unlock at the real mount point when both `--cleanup` and `--unseal`
  are given, specifically to avoid a window where a still-running
  application could recreate data in the plaintext directory between
  cleanup and mount (`runImportData`, `cmd/xkey/cmd/import_data.go`).

## Configuration

There is no config-file or environment-variable surface for `luks2` flags.
Every `luks2` subcommand registers its own local flags with
`cobra.Command.Flags().*Var` (not bound through Viper at all); the only
"configuration" is the resolved `xhome.Home` (`XKEY_HOME`, portable mode,
`~/.xkey/`, `/etc/xkey` — see [architecture/xhome.md](../architecture/xhome.md))
that supplies the default `--path`/`--mount-point` values when a command's
own flags are left empty.

| Command | Flags |
|---|---|
| `seal` | `--size` (default `100M`), `--path`, `--mount-point`, `--unseal`, `--skip-migrate` |
| `unseal` | `--path`, `--mount-point` |
| `lock` | `--path`, `--mount-point` |
| `migrate` | `--size`, `--path`, `--source-path`, `--keep-old`, `--wipe`, `--wipe-standard` (default `dod3`) |
| `wipe` | `--standard` (default `dod3`), `--force`, `--path`, `--mount-point` |
| `import-data` | `--path`, `--source`, `--mount-point`, `--cleanup`, `--backup`, `--unseal` |

## Tests

`cmd/xkey/cmd/luks_test.go`, `luks_cmds_test.go` exercise the CLI layer;
`xkey/pkg/luks/volume_test.go`, `volume_paths_test.go`, `keyring_test.go`,
`wipe_test.go`, `main_test.go` exercise the package. None of these tests
touch a real block device or the host kernel keyring by default — they run
against fakes/seams (`checkKeyringAvailable`, `geteuid` in `privilege.go`
are package-level `var`s for exactly this reason) so `make test` stays fast
and does not require root.
