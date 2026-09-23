- **BREAKING (xkey): `Authenticator.verifyPINHashLocked` no longer re-checks
  a locally persisted PIN hash after a configured `PINVerifier` rejects a
  hash.** `xkey/pkg/authenticator/authenticator.go`'s `verifyPINHashLocked`
  previously fell through to `hmac.Equal(hash, a.state.PINHash)` whenever
  `PINVerifier.VerifyFIDO2Hash` returned false, "for backward compatibility
  during lazy-init or sync race scenarios" (e.g. the PIN backend not yet
  re-initialized after a restart). That fallback let a second, potentially
  stale source of truth override a configured verifier's explicit negative
  result and is deleted: when a `PINVerifier` is set, its result is now
  final. The local `hmac.Equal` comparison against `a.state.PINHash` remains
  the verification mechanism for standalone mode (no `PINVerifier`
  configured at all — tests and offline authenticators), which is a
  different, still-supported case from a configured verifier's rejection.

  `TestAuthenticator_VerifyPINHash_FallbackAfterRestart` (a named regression
  test for the restart/lazy-init scenario the fallback existed to cover) is
  replaced by `TestAuthenticator_VerifyPINHash_VerifierRejectionIsFinal`,
  which asserts the opposite: the verifier's rejection now stands even
  though the persisted hash would itself have matched.
  `TestVerifyPINHashLocked_VerifierFailsFallsBackToState` is similarly
  replaced by `TestVerifyPINHashLocked_VerifierRejectionIsNotOverridden`. A
  new `TestAuthenticator_VerifyPINHash_NoVerifierUsesLocalState` covers the
  still-supported no-verifier-configured path explicitly.

  **Note for follow-up:** the deleted fallback existed to paper over a real
  scenario — a `PINVerifier` (e.g. `pkg/gui/services.PINService`) returning
  `false` because its own backend was not yet initialized after a restart,
  not because the PIN was wrong. `PINService.VerifyFIDO2Hash` still returns
  `false` when its internal `pinSvc` has not been loaded
  (`xkey/pkg/gui/services/pin_service.go`), so that race is structurally
  still possible; deleting the caller-side workaround did not touch it. If
  restart timing still allows a `PINVerifier` to answer before its own
  backend is ready, PIN verification can now fail transiently right after
  restart instead of silently succeeding via the deleted fallback. This
  needs verifying against current initialization ordering, or the
  `PINService` side needs to report "not ready" distinctly from "PIN
  incorrect" so callers can retry instead of treating it as a wrong PIN.