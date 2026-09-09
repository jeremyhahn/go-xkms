- **`KeyWrapper.Wrap(plaintext []byte)` is replaced by
  `WrapFrom(src *secure.Buffer)`, so the interface can no longer express a
  wrap of key material staged on the ordinary Go heap** (#387). This is the
  mirror of the unwrap transit #291 closed: the plaintext is read through a
  borrow on a protected buffer the caller owns and streamed straight into the
  ciphertext, never copied. `InitializeSOPIN` now generates the Admin Key and
  Credential Master Key directly into mlocked memory and adopts them as they
  are, where previously both spent their first moments on the heap; the
  PKCS#8 attestation encoding, which `x509` can only marshal onto the heap, is
  moved into protected memory by `secure.NewBufferFromBytes`, which wipes the
  heap copy as it does so. `KeyManager.WrapCredentialKey` and
  `KeyManager.WrapAttestationKey` take a `*secure.Buffer` the caller destroys
  afterwards; `WrapFrom` refuses a nil or destroyed source with
  `ErrInvalidWrapSource`. Because protected-buffer borrows must not nest, every
  wrap of one protected key under another goes through `wrapFromProtected`,
  which releases the wrapping-key borrow before the plaintext borrow is taken;
  a regression test drives every wrap path under purge-class contention so a
  re-nested borrow hangs into the test timeout instead of passing by luck.
