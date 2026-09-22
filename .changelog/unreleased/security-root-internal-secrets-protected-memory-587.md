- **Four more root-module secrets that used to sit as plain `[]byte`/`string`
  now live in protected memory (`*secure.Buffer` / `*secure.Secret` /
  `types.SecretValue`), closing another slice of #587's inventory (refs
  #41).** `luks.TPMSealResult.Passphrase` (`pkg/luks/tpm.go`) is now a
  `*secure.Buffer`; `SealPassphrase` seals the random passphrase into it
  immediately after the TPM2_Create call consumes the plaintext, and the
  narrow `Seal()` wrapper — whose signature callers still depend on — borrows
  and copies out only at that one required `[]byte` boundary, then destroys
  the buffer.

  `pkcs11/module.ExportKeyMaterialResponse.KeyMaterial` and
  `ImportKeyMaterialRequest.KeyMaterial` (`pkg/pkcs11/module/crypto.go`) are
  now `*secure.Buffer`. The export path seals the backend's response the
  moment it crosses into the module's own response type; the import path
  seals `C_CreateObject`'s CKA_VALUE before handing it to the BYOK wrap
  ceremony. `Module.secretKeyValue` — which fills a revealable secret key's
  CKA_VALUE for `C_GetAttributeValue` — borrows and copies out at the one
  place that protection necessarily ends: PKCS#11's C ABI has no enclaved
  `CK_ATTRIBUTE.Value`, so only that last copy is unbounded Go-heap memory.

  `clusterca.KeyProtection.Passphrase` (`pkg/trust/clusterca/keyprotect.go`)
  is now a `*secure.Secret`, and its config source,
  `RaftEnrollmentConfig.CAKeyPassphrase` (`pkg/config/config.go`), is now a
  `types.SecretValue` rather than a plain string — the same protected-config
  pattern #41 established for CA identity passwords. `Server.
  resolveClusterCAKeyPassphrase` (`pkg/server/cluster_ca_strategy.go`)
  resolves any `credential://` reference through the server's secret
  registry and reseals the plaintext into the `*secure.Secret`
  `KeyProtection.Passphrase` needs; the tpm-kek strategy's seed-derived KEK
  (`kekProtection` in `pkg/trust/clusterca/keystrategy_tpmkek.go`) is sealed
  the same way, preserving the existing hex-string passphrase exactly so
  already-sealed keystores keep decrypting.

  `acme/client.CertificateResource` (`pkg/acme/client/types.go`) had no
  constructor or consumer anywhere in the tree outside its own coverage
  tests, so it — and its four methods (`GetCertificate`, `GetPrivateKey`,
  `GetTLSCertificate`, `SaveToFiles`) and the error values only they used —
  were deleted rather than converted; `encodePrivateKeyPEM` and
  `ErrUnsupportedKeyType`, which serve a different, still-live test path,
  were left in place.
