- **Key import can now say whether the key may leave again (#160).**
  Every import path hardcoded `Exportable=true` for symmetric material, so
  no transport could import a non-extractable secret key, and the plaintext
  stayed recoverable through `export-material`; REST set nothing at all, so
  a symmetric key imported over REST was stored non-exportable while the
  same import over gRPC or MCP was exportable. `ImportKeyRequest` gains
  `exportable` (optional; absent keeps the write-once default, symmetric
  exportable and asymmetric not) and `sensitive`, on the transport type,
  the gRPC proto (new fields 12 and 13), the MCP params, the REST body and
  `xkmsctl key import --exportable/--sensitive`. The three attribute
  builders apply the choice through one helper, `xkms.ApplyImportExportability`.
