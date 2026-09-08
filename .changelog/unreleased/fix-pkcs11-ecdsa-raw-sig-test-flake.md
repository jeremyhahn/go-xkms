- **Test: `TestCryptoManager_Sign_ECDSA_ProducesVerifiableRawSignature` no longer
  fails one run in 256.** It rejected any raw `r || s` signature whose first
  byte was `0x30`, the DER SEQUENCE tag, but `r` is uniform so that byte is
  `0x30` in one signature of every 256 (measured 82 of 20,000; the test failed
  4 of 600 runs on an unchanged tree). The 64-byte length already rules DER
  out, and the verification that follows proves the halves are the signature.
