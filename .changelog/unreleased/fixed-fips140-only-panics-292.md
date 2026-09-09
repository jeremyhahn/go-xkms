- **The authenticated wrap verbs reported the `GODEBUG=fips140=only` GCM
  restriction as an internal fault (`CKR_FUNCTION_FAILED`) instead of an
  unavailable mechanism** (#292, FIPS conformance).
  `pkg/pkcs11/module/module_authwrap.go`, `pkg/crypto/aead/gcm_usable.go`.

  Under `fips140=only` Go's `crypto/cipher` refuses arbitrary-IV GCM — the
  construction every parameter form of `C_WrapKeyAuthenticated` /
  `C_UnwrapKeyAuthenticated` depends on, including the token-generated-IV
  form, which still hands `cipher.NewGCM` an IV from the module's own RNG.
  The refusal surfaced from inside the wrap as `CKR_FUNCTION_FAILED: failed
  to create GCM`, telling the application the token malfunctioned rather
  than that the regime withholds the operation. The verbs (wrap, size query
  and unwrap) now refuse at the mechanism check with
  `CKR_MECHANISM_INVALID`, before any handle is resolved, and the size query
  answers with the same code the wrap itself would.

  The gate is a runtime probe, `aead.ArbitraryIVGCMUsable` — a throwaway
  arbitrary-IV seal, performed once and cached — not a FIPS predicate,
  because no exported predicate separates `fips140=only` from `fips140=on`,
  where the identical construction works; gating on `fips140.Enabled()`
  (true under both) would have withdrawn a working mechanism. Same
  disposition as #303's `HashUsable`. The `CKM_AES_GCM` descriptor is
  deliberately still advertised: its `C_Encrypt`/`C_Decrypt`/`C_WrapKey`
  surface performs GCM in the service process, whose own FIPS posture
  governs it, so only the verbs that build GCM locally refuse. No ciphertext
  framing changed — `NewGCMWithRandomNonce` was ruled out in the issue
  because it cannot honour a caller-supplied IV and cannot open existing
  wrapped blobs. This closes the last of #292's three instances (the jwk
  thumbprint and the KDF hash set were fixed by #300 and #303).

  The one genuine panic the sweep recorded for this package was not in
  production but in a test oracle (`crypto_wrapnonce_test.go`), which
  panicked on the GCM construction error and aborted the test binary
  before every test after it ran; it now returns the error through the
  mock transport, so the suite under `fips140=only` reports the remaining
  non-approved-mechanism expectations as ordinary failures instead of
  hiding them.

  Verified by re-exec'd subprocess tests in both activated modes:
  `fips140=only` gets `CKR_MECHANISM_INVALID` from all three verbs with zero
  panics, and `fips140=on` completes the full wrap/size/unwrap round trip;
  the only-mode test fails against the unfixed code with
  `CKR_FUNCTION_FAILED`.
