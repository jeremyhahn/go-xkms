- **TPM key attributes carry the key size and curve.** `KeyAttributes` read
  a key's public area but left `RSAAttributes` and `ECCAttributes` empty, so
  `xkey tpm lak show` (and every other reader of the generic attributes) never
  printed an RSA size or ECC curve. They are now filled from the public area's
  `TPMS_RSA_PARMS.keyBits` and `TPMS_ECC_PARMS.curveID`, and an object of any
  other type is refused with `ErrInvalidKeyAlgorithm` before it is parsed
  (`pkg/tpm2/key.go`, #704).
