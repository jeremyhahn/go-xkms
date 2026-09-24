- **`ListKeys` silently dropped a key's type on every cloud/HSM backend
  that stored it as a raw enum value instead of its name.** `azurekv`
  (`CreateKey`, `CreateSecretKey`, `importRSAKey`, `importECDSAKey`) and
  `gcpkms` (`GenerateRSA`, `GenerateECDSA`, `GenerateSymmetricKey`) wrote
  `key_type` as either the raw `types.KeyType` value (`json.Marshal`s as a
  JSON number) or `string(attrs.KeyType)` (a Go rune conversion, not the
  human-readable name), while `ListKeys` on both backends reads it back
  with `metadata["key_type"].(string)` followed by `types.ParseKeyType` —
  a mismatch that silently failed the type assertion and left every listed
  key's `KeyType` at its zero value (`UNKNOWN`). `vault`'s own `ListKeys`
  reads `key_type` as a JSON number (`.(float64)`), which its `CreateKey`
  already wrote correctly, but `ImportKey` and `GenerateSymmetricKey`
  wrote it with the same `string(attrs.KeyType)` bug, so any imported or
  symmetric Vault key was dropped the same way. All six write sites now
  serialize `key_type` in the form their own package's `ListKeys` actually
  reads (`attrs.KeyType.String()` for azurekv/gcpkms, `uint8(attrs.KeyType)`
  for vault). Regression tests pin the round trip through `ListKeys` for
  each affected backend (go-xkms#705).
