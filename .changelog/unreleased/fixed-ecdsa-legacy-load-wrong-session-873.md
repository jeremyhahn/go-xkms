- **`CreateECDSA`'s legacy TPM2_Create+TPM2_Load fallback (taken only when a
  TPM lacks TPM2_CreateLoaded) authorized TPM2_Load's ParentHandle with a
  session built against the new child key instead of the parent SRK, so
  every ECDSA key creation on such a TPM failed TPM_RC_AUTH_FAIL against any
  SRK with a real (non-empty) auth value.** `pkg/tpm2/ecdsa.go` called
  `tpm.CreateKeySession(keyAttrs)` -- which resolves a session against the
  key's own (as yet nonexistent) auth -- where TPM2_Load needs a session
  authorizing `keyAttrs.Parent`'s handle; the identical fallback in
  `pkg/tpm2/rsa.go` already called the correct `tpm.CreateSession(keyAttrs)`,
  which resolves through `keyAttrs.Parent`. Fixed by making the ECDSA path
  match the RSA path. Regression test:
  `TestCreateECDSA_LegacyCreateLoadFallback_Succeeds`
  (`pkg/tpm2/create_key_legacy_fallback_simulator_test.go`), which forces the
  fallback with a transport double that answers the first TPM2_CreateLoaded
  with a synthetic TPM_RC 0xb0143 response and asserts the key is still
  created and loaded. (go-xkms#873)
