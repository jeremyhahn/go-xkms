- **`RevokeCert`'s `DeleteKeys` option now actually deletes the certificate's
  key instead of failing validation on every call.** `IssueCertificateWithProfile`
  now records the exact `KeyAttributes` (`StoreType`, `KeyType`, algorithm,
  CN, curve/key size, and tenant/partition/backend when set) a server-side
  key generation used, keyed by the issued certificate's serial number, in a
  new `issued-keys/<serial>` record alongside the existing `revocations/` and
  `crl/` rows in `ca.revocationStore` (`recordIssuedKey`,
  `pkg/ca/ca_extensions.go`). `RevokeCert` resolves that record
  (`resolveIssuedKeyAttributes`) instead of reconstructing an incomplete
  `types.KeyAttributes` from the certificate's CN and public key algorithm
  alone, which `types.KeyAttributes.Validate` rejected outright (missing
  `StoreType`) on every prior call — go-xkms#751, found during go-xkms#687.
  A CSR-signed certificate (`SignCSR`), whose key the CA never held, has no
  such record: `DeleteKeys` now treats that as a logged no-op rather than a
  failure. `RevokeCert` no longer calls `keyStore.DeleteCert`, which 404'd on
  every issued certificate because the keystore's certificate side is never
  populated for issuance (only `ImportCertificate`/`ImportCertificatePEM`
  call `keyStore.SaveCert`, best-effort) — `certStore` is the sole
  authoritative certificate store the cleanup now targets. Real cleanup
  failures (key deletion, issued-key record deletion, certificate deletion)
  are wrapped in typed errors and joined with `errors.Join` into `RevokeCert`'s
  return instead of discarded with `_ =`, matching go-xkms#687's rule; the
  revocation record itself is already durable before cleanup runs, so a
  cleanup failure never leaves a certificate un-revoked.
