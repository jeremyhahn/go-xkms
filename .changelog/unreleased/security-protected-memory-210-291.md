- **The OATH TOTP shared secret and the FIDO2 key-unwrap transit are moved
  into protected memory: the secret is no longer an unwipeable Go string at
  rest or through normalization, and unwrapped keys no longer cross the
  ordinary Go heap on their way into protected buffers** (#210, #291). `xkey/pkg/oath/credential.go`, `xkey/pkg/oath/generator.go`,
  `xkey/pkg/oath/dao_store.go`, `xkey/pkg/authenticator/key_wrapper.go`,
  `xkey/pkg/authenticator/key_manager.go`, plus the consumers in
  `xkey/cmd/xkey/cmd/`.

  **#210** — `Credential.Secret` was an immutable Go string, copied through
  three more strings on every normalization (`strings.ToUpper`,
  `strings.Map`, `strings.TrimRight`); none of the intermediates could ever
  be wiped. The field is now an mlocked `secure.Buffer` behind
  `SetSecret`/`SecretString`/`HasSecret` accessors, normalization runs
  byte-wise IN PLACE on a caller-owned slice (the Base32 alphabet is ASCII,
  so the fold needs no rune decoding and mints no copies), and every scratch
  decode is wiped. The persisted JSON keeps the historical `"secret"` key via
  marshal hooks, so existing stores load unchanged; `SecretString` is
  documented as serialization-boundary-only, since a handed-out string is the
  caller's residue. An equivalence corpus proves the byte normalization
  computes exactly what the string implementation computed (one deliberate
  divergence, U+017F-style Unicode folds, is asserted as rejected).

  **#291** — `KeyWrapper.Unwrap(wrapped) ([]byte, error)` returned decrypted
  plaintext on the heap, and #285 then copied it into protected memory,
  leaving the transit copy for the GC. The interface can no longer express
  that: `UnwrapInto(wrapped, dst []byte)` decrypts in place into
  caller-owned memory (asserted, failing closed with a wipe if the cipher
  ever relocates), and `unwrapIntoProtected` sizes the destination from the
  ciphertext alone — `len(wrapped) − nonce − tag` — so the `secure.Buffer`
  is allocated BEFORE the borrow on the wrapping key, honouring go-qrdb's
  purge-lock nesting rule that made the heap hop look load-bearing. Every
  unlock path (SO, user, attestation, SO-PIN change) now decrypts straight
  into mlocked memory; the plaintext never exists on the ordinary Go heap.

  Verified by wipe tests (adoption zeroes the source; a replaced or cleared
  secret's buffer is destroyed; a failed unwrap leaves an all-zero
  destination), by round-trip tests through the new seam, and by deadlock
  regression tests that re-run every borrow-crossing path under the test
  timeout — re-introducing the nested-borrow allocation hangs them, which
  the timeout turns into a failure. Closes #210, #291.
