- **Two xkey AES-GCM call sites and the PKCS#11 test token work under
  `GODEBUG=fips140=only` (go-xkms#23).** The password-vault backup envelope
  (`xkey/pkg/gui/services/staticpw_backup.go`) and the in-process key wrapper
  (`xkey/pkg/authenticator/key_wrapper.go`) now use
  `cipher.NewGCMWithRandomNonce`; FIPS mode refuses a caller-chosen GCM nonce
  even when it is random. `pkg/testing/pkcs11test`'s mock token selects its
  CKM_AES_GCM AEAD through `pkg/crypto/aead`, so a token-generated IV works
  in FIPS mode as it does on the real backends.
  - **Breaking:** the password backup envelope is now version 2, with the
    nonce folded into `ciphertext`. A version 1 backup is refused with
    `ErrRestoreUnsupportedVersion`. The key wrapper's format is unchanged.
