- **The xkey CTAP2 authenticator now spends and durably persists a PIN
  retry before comparing the guess, and fails closed if it cannot.**
  `changePIN`, `getPinToken`, and
  `getPinUvAuthTokenUsingPinWithPermissions` used to decrement the retry
  counter and call `storage.SaveState` *after* verifying the PIN hash, and
  discarded `SaveState`'s error with `_ =`; a storage failure on that trailing
  save let the brute-force retry limit reset on the next restart, and the
  decrement itself happened only once the answer was already known, not
  before. All three now funnel through one helper,
  `verifyPinHashAndConsumeRetryLocked`, that implements CTAP 2.1 §6.5.5.5's
  order exactly: decrement, persist, *then* compare; a decryption failure on
  `pinHashEnc` is treated as an automatic mismatch (still spends a retry)
  rather than a free-retry protocol error; and a correct guess resets the
  budget to its configured maximum and persists that too before returning. A
  failure to persist the spent retry now fails the whole operation closed
  with the typed `ErrStorageError` (mapped to `CTAP2_ERR_OTHER`) rather than
  silently letting the comparison proceed on unrecorded state —
  `xkey/pkg/authenticator/cmd_clientpin.go`. Separately,
  `KeyManager.UnlockWithSOPIN`'s deferred user-PIN sync (wiring a FIDO2 PIN
  set before the SO PIN existed onto CMK) called `InitializeUserPIN` /
  `ResetUserPIN` and discarded their errors too, while also unconditionally
  clearing the pending flag; a sync failure now clears the key material,
  propagates the error, and leaves the pending flag set so the next SO
  unlock retries the sync instead of silently leaving CMK never wired to the
  user PIN. This also fixes a latent deadlock: those two methods re-locked
  `KeyManager`'s non-reentrant `sync.RWMutex` that `UnlockWithSOPIN` was
  already holding when the sync path was reached (never exercised by any
  existing test); the locking logic now lives in unexported `*Locked`
  variants the exported methods and the sync path both call —
  `xkey/pkg/authenticator/key_manager.go`. go-xkms#686.
