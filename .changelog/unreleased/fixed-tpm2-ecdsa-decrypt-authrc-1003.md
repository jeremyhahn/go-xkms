- **TPM ECC encryption keys can do ECDH, and TPM auth errors are classified
  correctly.** `CreateECDSA` never set `Sign` or `Decrypt`, so every ECC key
  it created was sign-only and `ECDHZGen` could never succeed through the
  public API. `KeyTypeEncryption`/`KeyTypeEncapsulation` now produce a
  Decrypt, non-Sign template (scheme `TPM_ALG_NULL`), mirroring `CreateRSA`.
  `isTPMAuthError`'s typed path masked the response code with `0x0FF`, which
  never matched format-1 `BAD_AUTH`/`AUTH_FAIL` codes, so the function worked
  only through string matching. It and `isTPMBadAuth` now classify with
  `errors.Is(err, tpm2.TPMRC...)` (go-tpm's `TPMRC.Is`). (go-xkms#1003,
  #1004)
