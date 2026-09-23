- **`GODEBUG=fips140=only` no longer crashes go-xkms processes; the FIPS-only
  gate is measurably closer to viable.** Continuing #613/#633: several
  production call sites reached Go 1.24+ crypto APIs that refuse a
  non-approved operation by **panicking** rather than returning an error
  under strict FIPS enforcement, which crashed the whole process instead of
  failing one request. Fixed to return typed errors instead:
  `pkg/crypto/kdf`, `pkg/crypto/ecdh`, `pkg/crypto/x25519`, `pkg/seal`,
  `pkg/trust/clusterca`, and `pkg/keyprovider/pkcs8` now call the stdlib
  `crypto/hkdf.Key` instead of the legacy `golang.org/x/crypto/hkdf.New`
  Reader, whose `Extract` step turns the stdlib's FIPS refusal into a panic.
  `pkg/ca`'s X.509 signature verifier (`verifyRSASignature`,
  `verifyECDSASignature`) and `pkg/acme/server/handlers`'s TPM event-log PCR
  extender (`extendPCR`) and EAB MAC verifier (`verifyMAC`) recover a
  same-cause panic from `crypto/sha1`/`crypto/hmac` at the point they call
  it and return the existing verification-failure error type instead —
  `pkg/ca.IsSelfSigned`'s RFC 5280 self-signed-anchor exemption now fails
  closed (does not grant the exemption) for a SHA-1-signed anchor it cannot
  verify under FIPS-only, rather than crashing. **A remote, ordinary,
  spec-compliant SHA-1 OCSP request (RFC 6960's original default) or a
  merely-short EAB HMAC key from ACME's External Account Binding (RFC 8555
  §7.3.4) could crash an xkms OCSP responder or ACME server process running
  under FIPS-only; both are now refused with a clean error instead
  (`pkg/ca/ocsp.go`, `pkg/acme/server/handlers/external_account_binding.go`).**
  `pkg/encoding.EncodePKCS8` and `pkg/keyprovider/pkcs8.PKCS8Backend`
  encrypt with an explicit 16-byte PBKDF2 salt instead of
  `github.com/youmark/pkcs8`'s 8-byte default, which crypto/pbkdf2 refuses
  under FIPS-only. `pkg/acme/client`'s OCSP client now requests SHA-256
  explicitly instead of relying on `golang.org/x/crypto/ocsp`'s SHA-1
  default. Deliberately non-approved algorithm coverage (X25519,
  ChaCha20-Poly1305, ML-KEM-512 via CIRCL) in `pkg/crypto/x25519`,
  `pkg/crypto/chacha20poly1305` and `pkg/quantum/mlkem512` now asserts the
  FIPS-only refusal instead of running the operation, closing a
  process-crashing gap an `Example` function and several ordinary tests left
  in `pkg/crypto/x25519` (go-xkms#23). The `fips` CI job stays withheld
  (go-xkms#23 remains open): `pkg/pkcs11/module`, `pkg/encoding/jwe`,
  `pkg/keyprovider/symmetric` and several more packages still need the same
  treatment, and TPM 2.0 session HMAC authorization and parameter encryption
  in `github.com/google/go-tpm` v0.9.8 panic under FIPS-only on ordinary,
  spec-compliant session use (`crypto/hmac`, `crypto/cipher` CFB) — an
  upstream dependency defect out of scope for this repository, tracked
  separately for go-tpm.
