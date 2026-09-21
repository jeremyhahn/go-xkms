- **A `pinUvAuthToken` can no longer be spent by two concurrent CTAP2
  commands (#323).** `AuthorizePinUvAuthToken`'s check
  (`checkPinUvAuthTokenLocked`) and its spend (`consumePinUvAuthToken`,
  `xkey/pkg/authenticator/cmd_clientpin.go`) are two separate acquisitions of
  the authenticator's state lock, with a possible user-presence prompt in
  between, so two commands presenting the same token could both pass
  authorization before either consumed it — one PIN entry buying two
  registrations or assertions instead of one. This is a TOCTOU gap, not a
  data race: every individual access to the token state is correctly
  synchronized, which is why `go test -race` alone could not catch it (#328
  was the duplicate report of the same gap).

  `ProcessCBORWithContext` (`xkey/pkg/authenticator/authenticator.go`) now
  holds a dedicated `cmdMu` for the whole of a command, including any
  user-presence wait, so a second command cannot begin authorizing until the
  first has fully returned — closing the window by construction instead of
  narrowing it. This also makes the pre-existing `cmdCtx.Store`/`defer
  Store(nil)` single-command assumption true. The accepted trade: a command
  blocked on user presence blocks every other queued command for the whole
  wait, matching how a real CTAP authenticator (one outstanding command at a
  time) behaves; every `requestUserPresence` call site already released the
  state lock before blocking, so `cmdMu` is the only lock held across the
  wait.

  Files: `xkey/pkg/authenticator/authenticator.go`,
  `xkey/pkg/authenticator/pinuvauthtoken_toctou_test.go`,
  `xkey/docs/virtual-authenticator/engineering.md`. Verified by
  `TestConcurrentCommandsCannotBothConsumeOnePinUvAuthToken`, which mints one
  token and fires two goroutines through `ProcessCBOR` after a start barrier:
  exactly one `getAssertion` succeeds and the other fails with
  `ErrPINAuthInvalid`, stable across `go test -race -count=20`.
