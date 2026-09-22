- **The default AES-GCM `Encrypt` path now works under `GODEBUG=fips140=only`
  instead of failing on every call.** `pkg/crypto/aead.NewGCM` built
  `cipher.NewGCM`, the arbitrary-IV construction Go's FIPS 140-only mode
  refuses outright ("use of GCM with arbitrary IVs is not allowed"), so the
  symmetric (`pkg/keyprovider/symmetric`), Azure Key Vault
  (`pkg/backend/azurekv`) and TPM2 (`pkg/tpm2`) `Encrypt` implementations
  could not produce a single AES-GCM ciphertext in that mode, caller-supplied
  nonce or not. New `aead.NewGCMForFreshEncrypt` substitutes
  `cipher.NewGCMWithRandomNonce` under `fips140=only` for the one combination
  it supports — no caller-supplied nonce, the default full 128-bit tag — and
  reports the substitution through a new `types.EncryptedData.GCMNonceMode`
  field so `aead.NewGCMForDecrypt` rebuilds the matching construction from the
  ciphertext's own recorded framing rather than from the decrypting process's
  FIPS posture: a `fips140=only`-written ciphertext still opens under
  `fips140=on`, and a legacy explicit-nonce ciphertext still opens wherever
  arbitrary-IV GCM is available. The on-disk TLV envelope
  (`pkg/keyprovider/symmetric.Marshal`/`Unmarshal`) only spends a wire-format
  version bump recording the mode when it is not the zero value, so every
  ciphertext written before this change is byte-identical version-1 output
  and keeps decoding unchanged. A caller that supplies its own nonce, or
  requests a truncated tag — combinations `NewGCMWithRandomNonce` cannot
  produce — still fails closed under `fips140=only` with the typed
  `aead.ErrArbitraryIVGCMUnavailable`, extended to Vault Transit's BYOK key
  wrap (`pkg/backend/vault/vault_importexport.go`), whose wire format
  mandates a fixed all-zero nonce, using the same gate #292 established for
  PKCS#11's authenticated-wrap verbs (refs #23, #292).
