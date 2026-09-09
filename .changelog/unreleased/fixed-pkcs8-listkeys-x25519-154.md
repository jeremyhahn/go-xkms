- **`PKCS8Backend.ListKeys` reports an X25519 key as X25519 and an
  unrecognised algorithm as unknown (#154).** The listing had no `x25519`
  case, and its defaults block rewrote every algorithm it did not recognise
  to RSA-2048, so an X25519 agreement key was described as an RSA key and a
  re-import driven off that listing failed for the wrong reason. An X25519
  key is now listed with `X25519Attributes` set and `KeyAlgorithm` unset,
  the shape `GenerateKey` accepts and the software backend's key-type
  validation requires; an algorithm the backend does not produce is listed
  with `KeyAlgorithm` unset and logged, never renamed. The `CopyKey` token
  mismatch the same issue records is separate and is not in this change.
