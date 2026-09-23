- **Every operation that changes or persists security state now propagates
  its own write/persist error instead of discarding it with `_ =`.**
  `pkg/pkcs11/localseal.Controller.Rekey` no longer discards the reseal
  triggered on a `ChangePassword`/credential failure: it joins the reseal's
  error (`errors.Join`) onto the failure that triggered it. qrdb's
  `StorageBarrier.Seal` transitions to sealed state unconditionally before
  returning, so the barrier's observable state is never ambiguous — the
  join surfaces the reseal's error for visibility, not because the barrier
  might still be unsealed. `pkg/server/unified_tls.go`'s bootstrap
  TLS cert/key `os.WriteFile` failures are now logged (`slog.Warn`,
  `errors.Join` of both writes) instead of silently discarded; the
  documented degrade-to-ephemeral-certificate behavior is unchanged.
  `pkg/ca.CA.ImportCertificate`/`ImportCertificatePEM` now return the
  keystore `SaveCert` failure (joined with any certStore failure) instead
  of discarding it, while still attempting the authoritative certStore
  write regardless. `CA.RevokeCert`'s certStore `DeleteCertificate` failure
  during `DeleteKeys` cleanup now propagates; its keystore `DeleteKey`/
  `DeleteCert` calls remain intentionally best-effort and are documented as
  such — the `KeyAttributes` reconstructed from the revoked certificate
  alone cannot satisfy `KeyAttributes.Validate`'s `StoreType` requirement,
  so those two calls fail on every invocation today, a separate pre-existing
  gap called out for its own issue rather than papered over here. `CA.Init`
  no longer discards `initSecondaryKeys`' error: it is retained on
  `CA.secondaryKeyErr`, readable via the new `CA.SecondaryKeyInitError()`,
  while `Init` still succeeds off the primary key per its documented
  contract. `pkg/acme/admin.TenantAwareAdminService.DeleteTenant` now logs
  (rather than discards) a failed RBAC role deletion and default-CA KV
  deletion during tenant teardown; `CreateTenantIntermediateCA`'s global-CA
  parent-type path now fails the request instead of silently signing an
  intermediate CA certificate with a nil parent (missing chain data) when
  `TrustedRoot()` errors. In xkey: `TrustService.ExportBrowserTrustBundle`
  now returns the manifest sidecar's write/marshal failure (joined with the
  already-exported bundle count) instead of discarding it;
  `SecureBrowserService.syncIfChanged` now logs a genuine (non-`ErrNotExist`)
  trust-hash read failure while keeping the existing force-resync fallback;
  `TPMHandleAllocator.NextHandle` and `NVIndexAllocator.NextIndex` no longer
  hand out a handle/index whose counter update failed to persist — the
  in-memory counter has already advanced past it (from the CAS), so the
  withheld value is never reissued, at the cost of one skipped handle/index
  per persist failure; `PairingVerifier.loadLocked`'s legacy-format
  migration save failure is now audit-logged (`audit.OpPairingStateMigrated`)
  instead of discarded, while `load` still succeeds off the migrated
  in-memory state per its documented best-effort contract. go-xkms#687.
