- **`TestProcessHMACSecretExtensionDecryptionFailure` no longer feeds random
  bytes to a PKCS7 check, so it stops failing about one run in 256** (#417).
  `xkey/pkg/authenticator/ext_hmac_secret_test.go`. The "invalid padding in
  decrypted salts" case built `saltEnc` as raw randomness and relied on it
  decrypting to something PKCS7 rejects; AES-CBC decryption of random
  ciphertext yields random plaintext, which PKCS7 accepts whenever the final
  byte is an `n` in 1..16 whose last `n` bytes all equal `n` — dominated by
  `n = 1`. On those runs the request reached the salt-length check instead and
  failed with `ErrHMACSecretInvalidSaltEnc`, landing on unrelated PRs (#414)
  and reading as their regression. The test now encrypts a chosen plaintext
  under the established shared secret with the protocol-v1 zero IV, so the
  trailing byte — the one unpadding reads as the padding length — is fixed:
  `0x00` is not a legal length and must fail the padding check, while `0x01`
  is legal padding that leaves 47 bytes, neither one salt (32) nor two (64),
  and must fail the length check. That second case is a new subtest for a
  branch previously reached only by accident. Measured over 5120 consecutive
  runs of the test: 20 failures before, 0 after; swapping the two error
  returns in `decryptSalts` turns both subtests red. New `make
  test-authenticator` target.
