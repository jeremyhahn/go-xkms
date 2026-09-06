- **`XKMSService.ImportKey` dropped the request's `TenantID`, so a tenant's
  key import bypassed tenant isolation and landed in the untenanted
  namespace** (#163; the read-path half of #162 for symmetric keys).
  `pkg/xkms/backend_importexport.go` (new), `pkg/xkms/backend_tenant.go`,
  `pkg/xkms/servicer_key.go`, `pkg/xkms/service.go`,
  `pkg/xkms/piv_keygen_backend.go`, `pkg/keyprovider/symmetric/metadata.go`,
  `pkg/keyprovider/symmetric/backend.go`.

  The service resolved a `TenantScopedBackend` from `req.TenantID` and then
  discarded it one line later: the import/export capability was only reachable
  through `KeyProvider()`, which returns the *base* provider and drops the
  wrapper — and with it `scopeAttrs`, the only thing that stamps the tenant.
  The one operation that takes key material from outside was the one the
  tenant wrapper did not cover: a tenant's import stored under the untenanted
  identifier (where it could collide with, and before #165 silently destroy,
  an untenanted key of the same name), and was invisible to the importing
  tenant's own `ListKeys`.

  The fix closes the seam once for every transport rather than per-caller.
  `TenantScopedBackend` now offers the capability itself — a new
  `ImportExporter` interface carrying the operational surface of
  `backend.ImportExportBackend` (the wrapper cannot satisfy the full
  interface: `Backend.RotateKey` and `types.KeyProvider.RotateKey` share a
  name with different signatures) — scoping every attribute set exactly as
  `GetKey`/`GenerateRSA` always have, and refusing with the existing typed
  `ErrBackendUnsupported`/`ErrImportExportNotSupported` when its base lacks
  the capability. All eighteen `KeyProvider().(backend.ImportExportBackend)`
  unwrap sites in `servicer_key.go`, `service.go` and `piv_keygen_backend.go`
  now resolve through one `importExportFor` helper that prefers the wrapper's
  own implementation; unscoped backends resolve through their provider
  exactly as before, so untenanted callers are byte-for-byte unchanged.

  The metadata half: an imported symmetric key's tenant was still lost on the
  way out, because the symmetric provider's metadata record carried no
  `TenantID`/`Partition` and its `ListKeys` reconstructs them from identifier
  segment count — which cannot tell `acme:software:secret:k:aes256-gcm` (a
  tenant) from a partition, and read the tenant back as a partition. The
  record gains both fields at schema version 3 and `ListKeys` prefers a v3
  record over the segment guess, mirroring what the PKCS#8 provider's record
  has done since its v1 (the asymmetric leg of #162 was fixed by ff630179;
  this change makes the tenant actually reach that record on import).

  Verified by tenant/untenanted same-name collision, tenant-visibility,
  asymmetric metadata round-trip, unsupported-provider and legacy-record
  tests in `pkg/xkms` and `pkg/keyprovider/symmetric`; each fix test was
  mutation-checked by re-introducing the unwrap, dropping the asymmetric
  metadata write, and ignoring the v3 record — every mutation turns the
  matching test red.
