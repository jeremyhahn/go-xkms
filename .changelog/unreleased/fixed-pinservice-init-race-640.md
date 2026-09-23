- **Fixed (xkey): the FIDO2 authenticator can no longer be published a
  `PINVerifier` before the PIN service behind it is populated.**
  `xkey/pkg/gui/app.go`'s `initializeDataDir` published `a.pinService` to the
  shared authenticator via `auth.SetPINVerifier` in `initializeAuthenticator`
  before `postDataDirStartup` called `initPINService` to wire the real
  `qrdbsdk.PINService` backend into it. Compat cleanup #638 deleted
  `verifyPINHashLocked`'s local-hash fallback, which had been silently
  masking this window; without it, a correct PIN presented to the virtual
  FIDO2 HID device or browser-extension autofill during that window was
  rejected outright (`PINService.VerifyFIDO2Hash`/`IsPINSet` return `false`
  while their internal `pinSvc` is unset), rather than the request racing a
  local hash comparison that happened to still succeed.

  `initPINService` is now called inside `initializeDataDir`, immediately
  before `initializeAuthenticator`, instead of afterwards in
  `postDataDirStartup`: the PIN service only needs `a.dataDir` (already set),
  `a.tpmAccessor` and `a.storageEngineKind()`, none of which depend on the
  authenticator or the barrier, so this reordering has no cost. The
  authenticator is therefore never handed a `PINVerifier` that is not yet
  fully populated — the race is closed by construction order, not by a
  typed not-ready error. `postDataDirStartup`'s now-redundant
  `initPINService` call is removed; every caller already runs
  `initializeDataDir` immediately beforehand.

  `TestPINService_ConcurrentSetPINServiceNeverReturnsWrongResult`
  (`xkey/pkg/gui/services/pin_service_test.go`) and
  `TestAuthenticator_PINVerifier_ConcurrentPublishNeverReturnsWrongResult`
  (`xkey/pkg/authenticator/pin_verifier_test.go`) drive `IsPINSet` /
  `VerifyFIDO2Hash` concurrently with the backend being populated under
  `-race`: an incorrect hash must never verify, and once the correct hash
  verifies it must never regress. Resolves go-xkms#640.
