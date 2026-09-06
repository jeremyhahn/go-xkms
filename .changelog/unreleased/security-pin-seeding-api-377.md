- **`xkey fido2 --set-pin` seeded the daemon's PIN through
  `SetPINForTesting`, a helper documented as not-for-production, which wrote
  the PIN hash straight into state** (#377). `xkey/pkg/authenticator/
  cmd_clientpin.go`, `errors.go`, `xkey/cmd/xkey/cmd/fido2.go`.

  Measured against the CTAP `setPIN` path (`handleSetPIN`), the helper
  skipped four things: the "no PIN currently set" precondition, so a restart
  with `--set-pin` against a file or barrier store silently **replaced** the
  stored PIN; the retry-counter reset became a way to clear a partially
  exhausted counter without proving the PIN; the outstanding-`pinUvAuthToken`
  invalidation that #322 added to the real path (a token minted against
  built-in UV before any PIN existed stayed usable); and the typed
  `ErrStorageError` on persistence failure. Only the minimum-length check was
  shared. The wire-level `pinUvAuthParam` proof was also skipped, and that one
  is legitimate for an in-process caller — it exists to authenticate a remote
  platform.

  A first PIN now has one establishment path, `establishPINLocked`: the CTAP
  `setPIN` subcommand reaches it after its wire proof, and the new production
  API `Authenticator.SetInitialPIN` reaches it directly. Both enforce the
  minimum length, reset the retry counter, invalidate and wipe any outstanding
  `pinUvAuthToken` before persisting, and report persistence failure as
  `ErrStorageError` with the cause joined. `SetInitialPIN` refuses an
  authenticator that already has a PIN with the typed `ErrPINAlreadySet` — an
  existing PIN is replaced only by `changePIN`, which proves the current one.
  The daemon's `--set-pin` seeding calls `SetInitialPIN` and surfaces the
  already-set case as the distinct `ErrFIDO2PINAlreadySet`, telling the
  operator to drop the flag or change the PIN through a FIDO2 client, rather
  than starting with a rewritten PIN. `SetPINForTesting` is deleted; every
  test used it on a fresh authenticator, which is exactly `SetInitialPIN`'s
  contract, so the tests migrated to the production API.

  Verified by tests that fail with the defect re-introduced: removing the
  precondition turns the refused-when-set test and the daemon's file-store
  restart test red; dropping the shared invalidation turns the
  `SetInitialPIN` token test **and** #322's wire `setPIN` token test red,
  which is what proves the path is shared rather than duplicated. Also
  covered: establishment persists and the real `getPinUvAuthToken` ceremony
  accepts the PIN; a policy-violating PIN is refused and leaves no state or
  token damage; a storage failure is typed; the daemon seeds on a first start,
  refuses a short PIN, and comes back up with the persisted PIN when
  `--set-pin` is omitted.
