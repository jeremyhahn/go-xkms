- **`xkey tpm iak create` and `xkey tpm idevid create` honour `--template`.**
  The flag was validated and then ignored, so every key came from the
  configuration. An explicitly set `--template` now selects the key's suite,
  mapped in one place onto the TCG "TPM 2.0 Keys for Device Identity and
  Attestation" section 7.3.4 templates: `rsa2048` (H-1, RSASSA-PKCS1-v1_5),
  `rsa-pss` (H-1, RSASSA-PSS) and `ecc256` (H-2, P-256); left unset, the
  configuration decides as before (`xkey/cmd/xkey/cmd/tpm_devid_template.go`).
  `CreateIDevID` no longer forces an RSA IDevID on a device whose EK is RSA:
  the IDevID is its own configured algorithm (`pkg/tpm2/key.go`, #704).
