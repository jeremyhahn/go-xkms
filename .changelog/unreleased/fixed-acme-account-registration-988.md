- **Every ACME order path registers the account first, and registration
  failures are no longer swallowed.** Certificate request and renew,
  `CrossSign`, `CrossSignWithChallenge` and `CreateOrderWithReplaces` created
  orders without registering the account, and relied on x/crypto/acme's lazy
  KID lookup. `EnrollDevice` and the device manager each registered inline
  and downgraded every error to a warning. `Client.authorizeOrder` is now the
  only path to `AuthorizeOrder`. It registers the account once per `Client`
  (idempotent per RFC 8555 §7.3.1) and returns real failures as typed errors,
  which are not cached, so the next order retries. `RegisterAccount` leaves
  out `Contact` when no email is configured. (go-xkms#988, #994)
