- **`xkey fido2 provision-attestation` turns on the device attestation
  identity, which was fully implemented at the CTAP layer with no path from
  an operator to it** (#231). The `replaceAttestKey` and `setAttestCert`
  vendor commands had no caller outside the authenticator package, so every
  device registered with `fmt: "none"` no matter how the subsystem was
  configured. The command drives the exchange as real CTAP2
  `authenticatorConfig` CBOR: SO PIN unlock → CA connect → CSR from the
  device → `SignCSR` at the xkms enterprise CA → chain install → read-back
  verification. The private key never leaves the device, a CA failure never
  touches it (the connect happens before key generation), re-provisioning is
  refused without `--rotate`, and the read-back proves the stored leaf
  certifies the key the device still holds — resolved through
  `KeyManager.AttestationSigner()`, since the persisted state carries only
  AES-GCM wrapped key copies. `xkey/cmd/xkey/cmd/fido2_provision_attestation.go`,
  `xkey/docs/configuration/README.md`. Verified by end-to-end tests driving
  the real authenticator and an in-process CA, including the CA-unreachable,
  CA-refuses, mis-issuance, rotation and locked/uninitialized-token paths.

