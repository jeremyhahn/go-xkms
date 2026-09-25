- **xkey's TPM attestation statements were broken; they now certify credential
  keys under the Platform SRK.**
  `TPM2AttestingBackend.GetAttestationStatement` loaded the credential key for
  `TPM2_Certify` under the Shared SRK. `BackendAdapter.GenerateCredentialKey`
  creates those keys under the Platform SRK, so every statement failed with
  `TPM_RC_INTEGRITY`. The simulator tests never caught this: their fixture
  never enrolled the PSRK, and CI never built xkey tests with
  `tpm_simulator`. Both are fixed, and CI now runs xkey's `tpm_simulator`
  tests. The simulator fixtures also release the process-global simulator on
  every exit path, so a failed assertion can no longer hang the next test.
  (go-xkms#985, #990)
