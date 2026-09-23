- **xkey: the TPM2 barrier re-unseal path is now verified against a real TPM
  after the inactivity auto-lock (#510, runtime half).** Item 1's setup-time
  guard (#510) landed separately and left this half explicitly open: the
  reported failure was an unlock, after the 15-minute auto-lock, that failed
  with `qrdb/seal: requested strategy not registered` and was then
  misreported to the operator as an invalid PIN. `BarrierService.Unseal`
  already reopens the barrier this process is still holding rather than
  rebuilding one from scratch and re-resolving the strategy against a
  possibly-empty or mismatched ID — the exact rebuild that produced the
  reported sentinel — but nothing exercised that path with the `tpm2`
  strategy specifically: the existing regression coverage
  (`barrier_reunseal_test.go`) only drove it with `passphrase`, and every
  `AppLockService`-level Lock/Unlock test substituted a fully mocked barrier
  double. Two new tests close that gap: `app_lock_tpm2_reunseal_test.go`
  drives a real `BarrierService` through `AppLockService.Lock`/`Unlock` with
  a TPM2 sealer (plus a credential-checking control proving the reopen still
  rejects a wrong credential), and `barrier_tpm2_integration_test.go`
  (`integration && tpm_simulator`) repeats the same lock/unlock cycle against
  the in-process TPM 2.0 reference simulator instead of a mock, so a
  regression in how `TPM2Strategy` is captured or reused across the
  lock/unlock boundary fails here even if it passed against a canned
  `Sealer`. No source change was needed: this closes out the runtime half of
  #510 by proving the fix already in place. Files:
  `xkey/pkg/gui/services/app_lock_tpm2_reunseal_test.go`,
  `xkey/pkg/gui/services/barrier_tpm2_integration_test.go`. Verified with
  `go test -tags 'ble codec_json' ./xkey/pkg/gui/services/... -run
  TestAppLock_TPM2Reunseal` and `go test -tags 'integration tpm_simulator ble
  codec_json' ./xkey/pkg/gui/services/... -run
  TestIntegration_BarrierService_TPM2ReunsealAfterAutoLock`.
