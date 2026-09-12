### Fixed

- **xkey GUI: an unlock that fails because the barrier seal strategy is
  unavailable no longer reports "invalid PIN".** On a TPM host configured with
  `barrier_strategy: tpm2`, unlocking after the idle auto-lock failed with
  `qrdb/seal: requested strategy not registered` and the CLI printed
  `app_lock: invalid PIN`. The PIN retry counter never moved, which is the
  proof that no PIN check ran — the unseal never reached the credential. An
  operator told a correct PIN is wrong will retry it, and on a backend that
  does count attempts that is a path into a lockout over a fault no PIN could
  fix.

  `AppLockService.Unlock` now classifies `ErrStrategyNotFound` and
  `ErrStrategyMismatch` (including wrapped) as the new
  `ErrAppLockUnsealUnavailable`, whose message states that the PIN was not
  checked. The GUI's own `*ErrBarrierStrategyUnavailable` — what
  `BarrierService.Unseal` returns on a host with no usable TPM sealer, and the
  shape that actually produces the reported failure — is classified with it;
  that type wraps no cause, so it needs `errors.As` and one shared predicate
  covers both. A corrupt barrier root key is now `ErrAppLockStorageCorrupt`
  rather than an invalid PIN, matching the data-loss classification gRPC and
  REST already give `ErrCorruptRootKey`. An unseal that genuinely failed on the
  credential still reports `ErrAppLockPINInvalid`.

- **xkey setup wizard: the hardware→passphrase barrier fallback no longer fires
  over a barrier that already exists.** The fallback is for a hardware strategy
  that cannot *initialize* a barrier, where nothing is stored yet and a retry
  costs nothing. It was also firing when a barrier already existed and would
  not unseal — where the retry reaches a different strategy than the one the
  data was sealed with, discards the real error on its way past, and reports
  either a bogus credential failure or a silent downgrade to a software
  barrier. On the reported host that ended the run with `setup_complete: false`,
  and the next launch re-ran the wizard and minted a **new User PIN**, pushing a
  new hash to the authenticator. `initBarrier` now reports the two failures
  distinctly and the fallback is gated on "nothing is stored yet".
