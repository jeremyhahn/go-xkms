- **`xkey unlock` now enforces its own 8-attempt budget on the PIN it
  carries over IPC, and the `--pin`/`--so-pin` value flags are gone (#272,
  #307).**
  The unlock IPC verb is the one PIN-carrying message the socket accepts,
  and until now nothing counted a wrong PIN against it: a sealed barrier's
  own credential counter is unreadable until the very PIN it protects has
  already succeeded, and the software PIN backend keeps no counter of its
  own at all, so any local process could drive `unlock` at machine speed.
  `AppLockService` now owns an independent, CTAP2-sized budget
  (`AppLockPINMaxAttempts = 8`), persisted outside the barrier at
  `<dataDir>/pin/unlock_attempts` (JSON, atomic temp-file-then-rename,
  `0600`) so it is readable and writable while the barrier stays sealed. A
  strategy fault or a corrupt root key (`ErrAppLockUnsealUnavailable`,
  `ErrAppLockStorageCorrupt`, `qrdbsdk.ErrPINNotSet` — the #510
  classifications) never spends an attempt; only an evaluated-and-rejected
  credential does. Once the budget reaches zero, `Unlock` refuses with the
  typed `ErrAppLockPINBlocked` *without evaluating the PIN*, and every
  rejection or refusal is wrapped in `*AppLockAttemptsError`, which carries
  the attempts remaining while still satisfying `errors.Is` against the
  underlying cause; the IPC `UnlockResult` gained a `RemainingAttempts
  *int` field so `xkey unlock --pin-stdin` reports the count in band, not
  only in its error string. A successful Security Officer PIN verification
  resets the budget: `PINService.ResetLockout` and `PINService.SetUserPIN`
  call a newly wired `AppLockService.ResetAttempts` when one is present
  (the GUI and the headless `xkey extension serve` daemon both wire it),
  and the equivalent CLI verbs — `xkey pin reset-lockout` and `xkey pin
  set-user` — call the new `services.ResetAppLockAttempts(dataDir)` to
  reach the same persisted file from a separate process, since the daemon
  whose `AppLockService` holds the live counter is not the process running
  the CLI.

  **Breaking:** the `--pin` and `--so-pin` VALUE flags (`xkey unlock`,
  `xkey auth register`, `xkey auth login`, `xkey device pair`, `xkey
  extension serve`) are removed. They were visible to every other process
  on the host via `ps`, which is a wider audience than the IPC socket the
  PIN is usually headed for, and their own help text said so. `--pin-stdin`
  / `--so-pin-stdin` and the `XKEY_PIN` / `XKEY_SO_PIN` environment
  variables are unaffected; any script still passing `--pin <value>` or
  `--so-pin <value>` now gets a cobra "unknown flag" error and must switch
  to one of those two.
