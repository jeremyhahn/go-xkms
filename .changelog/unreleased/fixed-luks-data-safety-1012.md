- **`xkey luks2 seal`'s existing-data migration and `xkey luks2 import-data`
  can no longer destroy the only copy of a user's data on a failed unlock,
  copy or lock.** `migrateExistingData` deleted the plaintext source
  directory before unlocking the new volume; if `Unlock` or
  `CopyDataToVolume` then failed, the deferred cleanup deleted the staged
  copy too, leaving nothing. It now stages the source, unlocks the volume,
  copies into it, verifies the copy (`verifyDirCopy`, a new typed
  `*DataVerificationError`), and only then locks the volume and deletes the
  source; any failure along the way keeps the staged copy and reports its
  path instead. `import-data` unconditionally `RemoveAll`'d its temporary
  mount point on return, including when a copy or lock failure had left the
  volume mounted there; `removeTempMount` now checks `IsMounted()` first and
  leaves a still-mounted mount point in place, reporting it instead of
  deleting its contents. Both functions take small interfaces
  (`migrateVolume`, `importDataVolume`) instead of a concrete `*luks.Volume`
  so the failure paths are covered by fault-injection tests
  (`seal_test.go`, `import_data_test.go`) with no real LUKS device or root
  required. (go-xkms#1012)
