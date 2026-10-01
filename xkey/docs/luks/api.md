# LUKS2 Encrypted Storage — API

> **Status: NORMATIVE** · Feature: `luks` · Module: `go-xkms/xkey` · Last verified: 2026-09-30

No REST or gRPC surface: LUKS is a local, host-filesystem feature reachable
only through the CLI (`cli.md`) and the desktop GUI's Wails IPC bridge.
There is no remote **xkmsd** capability for it.

## GUI IPC — `services.StorageService`

Bound to the Wails runtime (`pkg/gui/app.go` wires `storageSvc` into the
app's service set); every exported method below is callable from the
frontend as `window.go.services.StorageService.<Method>(...)`, and Wails
regenerates the TypeScript bindings (`frontend/wailsjs/go/services/
StorageService.*`) from these signatures on build.

| Method | Signature | Notes |
|---|---|---|
| `GetStatus` | `() (*StorageStatus, error)` | safe to call anytime, no root required |
| `CreateVolume` | `(CreateVolumeParams) error` | root: direct; non-root: elevated `luks2 seal --unseal` |
| `UnlockVolume` | `(passphrase string) error` | root: direct; non-root: elevated `luks2 unseal` |
| `LockVolume` | `() error` | root: direct; non-root: elevated `luks2 lock` |
| `MigrateToEncrypted` | `(sizeGB int, passphrase string, backupOriginal bool) error` | creates+imports+re-mounts; see architecture.md |
| `WipeVolume` | `(standard string) error` | `"nist" \| "dod3" \| "dod7"` |
| `RequireUnlocked` | `() error` | the gate `App.initializeDataDir` calls; exported for testability, not a frontend action — the frontend never needs to call this itself, since `App.InitializeDataDir` / `PostUnlockInitialize` already surface the same `xkms.ErrLUKSVolumeLocked` from their own call to it |

### `StorageStatus`

```go
type StorageStatus struct {
    VolumeExists       bool   `json:"volume_exists"`
    IsLUKS             bool   `json:"is_luks"`
    IsMounted          bool   `json:"is_mounted"`
    IsOpen             bool   `json:"is_open"`
    VolumePath         string `json:"volume_path"`
    MountPoint         string `json:"mount_point"`
    VolumeSizeBytes    int64  `json:"volume_size_bytes,omitempty"`
    ElevationAvailable bool   `json:"elevation_available"`
}
```

### `CreateVolumeParams`

```go
type CreateVolumeParams struct {
    SizeGB     int    `json:"size_gb"`
    Passphrase string `json:"passphrase"`
}
```

## Data-directory initialization

`App.InitializeDataDir()` and `App.PostUnlockInitialize()` — the Wails-bound
entry points the frontend calls from the setup wizard callback and the
unlock dialog respectively — both call the unexported
`App.initializeDataDir()`, whose first action is
`a.storageService.RequireUnlocked()`. A locked, configured volume makes
either call return `xkms.ErrLUKSVolumeLocked`; the frontend surfaces it as
an error from that IPC call exactly like any other Wails method error —
there is no separate error-shaped event for it.

## Events

| Event | Payload | When |
|---|---|---|
| `events.EventStorageLUKSLocked` | none | `App.startupReturningUser` finds a configured, unmounted volume at startup — before `initializeDataDir` would even be attempted. The frontend's response is to show the unlock dialog and, on success, call `PostUnlockInitialize`. |
| `events.EventDataDirInitialized` | `{DataDir: string}` | emitted by `InitializeDataDir`/`PostUnlockInitialize`/`PostBarrierUnseal` after `initializeDataDir` succeeds |
| `storage:auto_unseal_success` / `storage:auto_unseal_failed` | `AutoUnsealResult` | TPM-driven auto-unseal attempt at startup, before the manual-unlock check runs |
