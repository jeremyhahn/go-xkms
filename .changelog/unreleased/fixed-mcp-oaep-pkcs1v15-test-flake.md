- **Test: `TestHandler_Decrypt_OAEPHashArrives` no longer fails one run in
  ~700.** Its last assertion required PKCS#1 v1.5 decryption of an OAEP
  ciphertext to error, but v1.5 unpadding accepts the uniform bytes such a
  decrypt produces whenever they happen to carry its `00 02 … 00` frame
  (measured 432 of 300,000 attempts). The assertion now states the property
  that matters, that the paddings are not interchangeable: a v1.5 decrypt
  either fails or does not return the plaintext.
