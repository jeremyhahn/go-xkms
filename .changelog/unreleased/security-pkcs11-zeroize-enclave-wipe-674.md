- **Every hand-rolled secret-wiping loop found across the tree moves to
  go-enclave's `enclave.Wipe`, closing the gap #623 left open.** A hand-rolled
  `for i := range b { b[i] = 0 }` has no `runtime.KeepAlive`, so the Go
  compiler is free to prove the store is dead (nothing reads `b` afterward)
  and eliminate the whole loop — the same class of silent-no-op risk #623
  retired `GuardedBuffer` over. `zeroizeOperation` in
  `pkg/pkcs11/module/session.go` (PKCS#11 v3.2 §5.2 terminal-result caching)
  now calls `enclave.Wipe(op.Result)`; a repo-wide grep for the same pattern
  found it duplicated in `pkg/pkcs11/module/module.go` (`releaseResult` and
  `restoreMessageOperation`), `pkg/pkcs11/module/token.go`
  (`Token.ClearUserPin`), and `pkg/pkcs11/module/object.go`
  (`Object.Zeroize`), all converted the same way. Outside pkcs11:
  `pkg/keyprovider/quantum/signer.go`'s four ML-KEM shared-secret defers,
  `pkg/keyprovider/frost/keygen.go`'s `SecretKeyShare.Zeroize`,
  `pkg/keyprovider/frost/nonce.go`'s `SigningNonces.Zeroize` (hiding and
  binding nonces), `pkg/types/types.go`'s `sealData.Clear`,
  `pkg/trust/clusterca/backends.go`'s keystore-password defer,
  `pkg/quantum/{mldsa65,dilithium2,mldsa87}`'s `Clean` (fixed-size seed
  arrays, wiped via `m.seed[:]`), `pkg/tpm2/symmetric.go`'s three
  key-material clears, and `pkg/tpm2/password.go`'s `PlatformPassword.Clear`
  and cache-refresh path. In the `xkey` module:
  `xkey/pkg/gui/services/elevation_sudo.go`'s shared `zeroBytes` helper,
  `xkey/pkg/oidc/store.go`'s `Store.Close` encryption-key clear,
  `xkey/pkg/authenticator/pin_protocol_v1.go`'s `ResetSharedSecret`/`Reset`,
  `xkey/pkg/authenticator/pin_protocol_v2.go`'s `hmacKey`/`aesKey` clears in
  both `ResetSharedSecret` and `Reset`, and
  `xkey/pkg/authenticator/cmd_clientpin.go`'s
  `stopUsingPinUvAuthTokenLocked`. `enclave.Wipe` is a no-op on a nil or
  empty slice, so every callsite's existing `!= nil` guard was dropped along
  with the loop rather than kept as dead code. Left unconverted, with reasons
  recorded at each site rather than silently skipped:
  `pkg/backend/software/zeroize.go`'s `zeroizeBigInt` wipes a `[]big.Word`
  (not `[]byte`), which `enclave.Wipe` cannot take without an unsafe
  reinterpret cast — out of scope for this change; the two test-only
  fixtures `xkey/pkg/oath/secret_protected_test.go` and
  `pkg/keyprovider/symmetric/backend_test.go`'s `mockPassword.Clear`, which
  zero scratch/mock buffers rather than production secret state; and
  `xkey/pkg/pairing/message_loop.go`'s `clear(r.retired)`, a bookkeeping map
  of retired request IDs with no secret material. Added
  `TestZeroizeOperation` / `TestZeroizeOperation_NilAndEmpty` to
  `pkg/pkcs11/module/session_test.go`, asserting the Result buffer is
  actually overwritten (not just dropped) and that a nil `OperationState`,
  nil `Result`, and empty `Result` are all handled without panicking.
  go-xkms#674.
