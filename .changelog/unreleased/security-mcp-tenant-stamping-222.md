- **A tenant's MCP key import landed in the untenanted namespace, where the
  importing tenant's own reads could not find it, and every `copy_key` through
  a token-honouring backend produced a key that could not be unwrapped**
  (#222). `handleImportKeyMaterial` passed no `TenantID` to the service at all,
  so the import resolved the unscoped backend and wrote under an identifier
  carrying no tenant prefix — the #162/#163 family, a tenant's write going
  somewhere that tenant cannot read, not a cross-tenant disclosure. The
  withholding was deliberate while an imported key persisted no metadata record
  to be read back from; both key providers have persisted the tenant since
  #163, so the reason had lapsed and only the symptom remained. The import now
  runs under the caller's tenant through `tenantForRequest`, and
  `get_import_parameters` and `copy_key` take their tenant from the same helper
  rather than from `callerTenantID` directly, so a request that names a tenant
  of its own is refused with `ErrTenantIDNotAccepted` instead of having the
  field silently dropped by the decoder. Separately, `XKMSService.CopyKey`
  asked the destination backend for fresh import parameters and overwrote the
  exported material's import token with theirs: `ExportKey` wraps under a
  wrapping key the exporting backend mints for that export and names it by the
  token it returns, so the override pointed `ImportKey` at a different key than
  the material was wrapped under and the unwrap failed. The export's own token
  is now passed through untouched, the destination attributes carry the
  destination store type plus the source's digest and partition, and
  `ExportKeyResponse`/`WrapKeyResponse` no longer drop the import token and
  metadata that must travel with the blob. `pkg/api/mcp/handlers.go`,
  `pkg/api/mcp/types.go`, `pkg/api/transport/types.go`,
  `pkg/xkms/servicer_key.go`, `docs/multi-tenancy/`. Verified by
  `pkg/xkms/servicer_key_tenant_copy_test.go`, which asserts the copy holds the
  source's key material — provable only if the unwrap succeeded — and that it
  is visible to the copying tenant and to no other, and by
  `pkg/api/mcp/handlers_keyops_tenant_test.go`, which pins the import to the
  authenticated tenant and the refusal of a caller-supplied one.
