- **Certificate-chain integration fixtures no longer collide with the
  reserved chain-record id shape.** `pkg/storage/hardware` refuses any
  certificate id ending in `-chain` (or shaped like a chain member's
  `id-chain-<n>` CKA_ID) via `ErrIDReservedForChain`, because that shape
  names another record's chain. Several PKCS#11 and TPM2 integration
  fixtures named their certificate `test-chain`, `overwrite-chain`,
  `delete-chain`, `nitrokey-test-chain` or `empty-chain` — ids that
  themselves match the reserved shape — so every save/get/delete against
  them failed deterministically with `ErrIDReservedForChain` instead of
  exercising chain storage, masking `CertificateChainOperations` and its
  `SaveAndRetrieveChain`, `OverwriteChain` and `DeleteChain` subtests on
  every run (go-xkms#615). Fixtures are renamed to non-reserved ids
  (`chain-primary-cert`, `chain-overwrite-cert`, `chain-delete-cert`,
  `nitrokey-test-cert`, `empty-chain-cert`); no production code changed,
  the reservation itself is correct. `TestIsReservedChainID` and
  `TestReservedChainIDsAreRefusedByEveryStore` in `pkg/storage/hardware`
  gain a `test-chain` case pinning this exact regression. Files:
  `test/integration/pkcs11/pkcs11_cert_integration_test.go`,
  `test/integration/pkcs11/pkcs11_integration_test.go`,
  `test/integration/pkcs11/pkcs11_nitrokey_hsm_integration_test.go`,
  `test/integration/tpm2/tpm2_cert_integration_test.go`,
  `pkg/storage/hardware/chain_member_test.go`,
  `pkg/storage/hardware/backend_adapter_record_scope_test.go`.
