- **xkey's LUKS-encrypted storage now fails closed instead of silently
  persisting to the plain, unencrypted data directory while the volume is
  locked.** `pkg/storage/luks.Backend` — a fail-closed `storage.Backend`
  gated by a LUKS volume's lock state, previously built but unwired into any
  product — is now re-exported through `sdk/go` (`xkms.LUKSStorageBackend`,
  `xkms.NewLUKSStorageBackend`, `xkms.ErrLUKSVolumeLocked` and siblings) and
  wired into both xkey front ends. The GUI's `App.initializeDataDir` now
  calls `StorageService.RequireUnlocked()` before opening any store; a
  configured-but-unmounted volume aborts immediately with
  `xkms.ErrLUKSVolumeLocked` and creates no data directory at all (verified
  on the filesystem by a new regression test), rather than relying solely on
  the startup-only check that previously guarded this path. The CLI's
  existing `checkLUKSVolume` gate (`cmd/xkey/cmd/root.go`,
  `PersistentPreRunE`) now reports the same `xkms.ErrLUKSVolumeLocked`
  sentinel (wrapping the prior `luks.ErrPermissionDenied` as its cause) so a
  locked volume is recognized identically from either front end.
  `StorageService.CreateVolume`/`UnlockVolume`/`LockVolume` now drive a
  shared `LUKSStorageBackend` instead of the volume directly, and a new
  additive `Backend.Attach` method lets a second process (for example the
  GUI attaching to a volume an elevated CLI child process already mounted)
  recognize an existing mount without a redundant LUKS open. A no-LUKS
  install is unaffected. go-xkms#722.
