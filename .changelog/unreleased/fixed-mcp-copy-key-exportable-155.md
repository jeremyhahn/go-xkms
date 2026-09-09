- **The MCP `copy_key` tool no longer refuses every key at the export step
  (#155).** `handleCopyKey` built the source key's attributes by hand with
  the common name and store type only, so `Exportable` was always false and
  the backend refused every copy with "key is not exportable", whatever the
  key's real exportability; the error read as the caller's fault and the
  test that covered it passed for non-exportable and exportable keys alike.
  The handler now delegates to `XKMSService.CopyKey`, which resolves the
  source key's stored attributes from the backend's own listing, so what the
  key is decides whether it may leave, and a request cannot assert
  exportability of a key that has none (`CopyKeyParams` deliberately has no
  such field). A copy still does not complete: the software backend's
  `ExportKey` wraps under a wrapping key it mints itself while the service
  replaces the import token with the destination's (#154); that is now
  pinned by type as the only step allowed to fail for an exportable key.
