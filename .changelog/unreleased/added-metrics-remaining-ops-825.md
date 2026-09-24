- **Prometheus instrumentation now covers the rest of the `KeyServicer`/
  `CryptoServicer` surface: `CopyKey`, `WrapKey`, `UnwrapKey`, `WrapKeyByID`,
  `UnwrapKeyByID`, `ExportKeyMaterial`, `GetImportParameters`, `DeriveKey`,
  `DeriveKeyECDH`, and `AttestKey`.** go-xkms#720 instrumented `GenerateKey`,
  `ListKeys`, `GetKey`, `DeleteKey`, `ImportKey`, `ExportKey`, `RotateKey`,
  the certificate and CA methods, and `Sign`/`Verify`/`Encrypt`/`Decrypt`/
  `EncryptAsym`, leaving these ten `XKMSService` methods silently
  unmetered. Each now calls the same `recordServiceOp` helper
  (`pkg/xkms/metrics_instrumentation.go`) via `defer` on named returns, with
  ten new bounded-cardinality `Op*` constants (`OpCopyKey`, `OpWrapKey`,
  `OpUnwrapKey`, `OpWrapKeyByID`, `OpUnwrapKeyByID`, `OpExportKeyMaterial`,
  `OpGetImportParameters`, `OpDeriveKey`, `OpDeriveKeyECDH`, `OpAttestKey`)
  added to `pkg/metrics`, each with a real caller in the same change.
  `CopyKey` is metered under its destination backend, matching how
  `GenerateKey`/`ImportKey` meter the backend they write to; `WrapKeyByID`/
  `UnwrapKeyByID` are metered under the wrapping/unwrapping key's backend,
  matching how `Sign`/`Encrypt` meter the backend holding the operating key.
  `CopyKey` and `UnwrapKeyByID` are the two operations here that create a
  key, so both call `incrementKeysTotal` on a successful create the same
  direct `Inc()` way `GenerateKey`/`ImportKey` already do — `CopyKey` on its
  destination backend, `UnwrapKeyByID` on its target backend (which is not
  necessarily the backend the operation itself is metered under, since the
  cryptographic work and the storage effect can be different backends for
  this one). `WrapKey`, `UnwrapKey`, `WrapKeyByID`, `ExportKeyMaterial`, and
  `GetImportParameters` do not change the key count and correctly do not
  touch the gauge. New tests in
  `pkg/xkms/metrics_instrumentation_remaining_test.go` give every operation
  a success case (`OperationsTotal`/`OperationDuration`) and a failure case
  (`ErrorsTotal`), and reuse go-xkms#720's `countingBackend` to assert the
  `CopyKey`/`UnwrapKeyByID` gauge updates cost zero extra `ListKeys` calls.
  `docs/observability/engineering.md` gains the operation-to-servicer-method
  mapping table its own `pkg/metrics` doc comment already pointed readers
  at; `docs/observability/architecture.md` documents which backend labels a
  multi-backend operation and why. go-xkms#825.
