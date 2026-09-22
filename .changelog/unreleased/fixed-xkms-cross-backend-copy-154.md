- **Fixed**: `CopyKey` now wraps key material for the DESTINATION backend's
  own import parameters, so a copy between two independent backend instances
  actually unwraps (#154, #567). `ExportKey` wraps a key under a wrapping
  key the EXPORTING backend mints and tracks for itself, naming the result
  by that backend's own import token; handing that material to a different
  backend instance's `ImportKey` named a wrapping key it had never heard of.
  For the software backend this failed lookup silently (the destination's
  `importTokens` map holds no entry for a token another instance minted); for
  a token-checking backend it surfaced as an unwrap failure. `ExportBackend`
  gains `ExportKeyTo(ctx, attrs, dstParams)`, which wraps under
  caller-supplied `ImportParameters` — obtained from the destination's own
  `GetImportParameters` — instead of parameters the exporting backend mints
  itself. `CopyKey` (both `XKMSService.CopyKey` and the package-level SDK
  `CopyKey`) now calls the destination's `GetImportParameters` first and
  passes the result straight to the source's `ExportKeyTo`, so the material
  the destination's `ImportKey` unwraps was genuinely wrapped under its own
  key, never staged in plaintext in the service in between.

  Every backend implementing `ExportBackend` implements `ExportKeyTo` in this
  change: the software backend and the symmetric key-provider backend
  perform a real re-wrap, because their `WrapKey` is a pure cryptographic
  operation over the `ImportParameters` it is given and touches no backend-
  private state. PKCS#11, TPM2, AWS KMS, GCP KMS, Azure Key Vault, HashiCorp
  Vault, and the phone hardware backend return the new typed
  `backend.ErrExportToUnsupported` sentinel instead: their wrap primitives
  bind to a key object the backend itself manages (an HSM wrapping-key
  handle, a TPM object, a provider's BYOK ceremony), not an arbitrary public
  key a caller hands in, so they refuse rather than emulate a wrap their
  hardware or service does not actually perform.

  `pkg/migration`'s `defaultMigrator.importKey` carried the identical defect
  independently of `xkms.CopyKey`: it called the source's self-minted
  `ExportKey`, then overwrote the resulting `WrappedKeyMaterial.ImportToken`
  with the destination's own token, leaving the ciphertext wrapped under one
  key and named by another. `MigrateKey` (and therefore `MigrateAll`, which
  calls it per key) now calls the destination's `GetImportParameters` first
  and wraps through the source's `ExportKeyTo`, exactly as `CopyKey` does; the
  token-overwrite line is deleted rather than reconciled, since `ExportKeyTo`
  makes it unnecessary.
