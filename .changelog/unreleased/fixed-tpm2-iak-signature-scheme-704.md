- **A reopened TPM signs with the IAK's own signature scheme.** The IAK is
  Restricted, so its public area fixes RSASSA or RSA-PSS (Template H-1, TCG
  "TPM 2.0 Keys for Device Identity and Attestation" section 7.3.4), but a
  restarted process described it by the configured algorithm instead. After
  `xkey tpm iak create --template rsa2048` on an RSA-PSS configuration the next
  `Quote` failed unpacking an RSASSA signature as RSA-PSS. `KeyAttributes` now
  reads the signature algorithm from the key's public area, and the
  configuration only names it for a key that fixes none, such as an RSA IDevID
  (`pkg/tpm2/key.go`, `pkg/tpm2/sigscheme.go`, #704).
