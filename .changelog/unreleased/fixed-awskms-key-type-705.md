- **awskms `ListKeys` reports symmetric and asymmetric key types correctly.**
  `GenerateSymmetricKey` stored `key_type` as `string(uint8)`, which is a
  single control character, and `ListKeys` silently dropped string values, so
  those keys came back as `UNKNOWN`. Both creation paths now write
  `KeyType.String()`, and `ListKeys` parses it with `types.ParseKeyType`,
  matching azurekv and gcpkms. Unused client-interface methods were removed
  from awskms, vault, gcpkms and azurekv. (go-xkms#705, #999)
