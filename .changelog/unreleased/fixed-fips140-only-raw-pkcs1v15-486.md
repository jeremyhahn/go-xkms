- **A raw PKCS#1 v1.5 RSA signature (hash `NONE`) under `GODEBUG=fips140=only`
  now returns a typed error instead of panicking** (#486, fourth instance of
  the #292 class). `pkg/types/rawpkcs1v15.go`, `pkg/xkms/servicer_crypto.go`,
  `pkg/testing/pkcs11test/crypto_mock_client.go`.

  `Sign` and `Verify` accept the hash name `NONE` to sign or check caller-built
  bytes verbatim — what PKCS#11's `CKM_RSA_PKCS` sends for `C_Sign` and
  `C_SignRecover`. In the only mode `crypto/rsa` admits a PKCS#1 v1.5
  signature solely under a digest it can classify as approved, and at that
  site it calls `crypto.Hash(0).New()`, which *panics* ("requested hash
  function #0 is unavailable") rather than returning an error. The sweep found
  it in the `pkcs11test` mock backend, where it aborted the module conformance
  binary; the production service reaches the identical call for an in-process
  RSA key, on both the signing and the verifying side (verification is always
  in-process). The PKCS#11 backend is not affected: it builds its own
  `DigestInfo` and never enters `crypto/rsa`.

  `types.CheckRawPKCS1v15(key, hash)` refuses first with
  `types.ErrRawPKCS1v15Enforced` when the digest is `crypto.Hash(0)`, the key
  is an in-process `*rsa.PrivateKey` / `*rsa.PublicKey`, and
  `crypto/fips140.Enforced()` is set. That predicate — new in Go 1.26 — is the
  very variable `crypto/rsa` reads at the panicking site, so it cannot
  disagree with the runtime; it is not `fips140.Enabled()`, which is also true
  under `fips140=on`, where the raw form works and is left alone. The service
  wraps the refusal in `ErrSigningFailed` / `ErrVerificationFailed`; the mock
  returns it directly, and the module surfaces it as `CKR_FUNCTION_FAILED`.

  Verified by re-exec'd subprocess tests in `pkg/types`, `pkg/xkms` and
  `pkg/testing/pkcs11test`: under `fips140=only` all three get the typed error
  with zero panics and the SHA-256 form still round-trips; under `fips140=on`
  the raw form signs and verifies. Each package's in-process test asserts the
  check against the operation itself, so it holds in whichever mode the suite
  is run. Removing the guard in either the mock or the service brings the
  panic back in the corresponding test.
