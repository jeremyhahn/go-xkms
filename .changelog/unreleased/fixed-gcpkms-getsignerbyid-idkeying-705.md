- **`gcpkms` `GetSignerByID`, `GetDecrypterByID` and `ListKeys` could never
  find a key's metadata.** `GetKey`'s metadata-existence check, and every
  metadata `storage.SaveKey`/`GetKey`/`DeleteKey` call in the package,
  keyed the per-key entry on `attrs.ID()` — a value that folds in `KeyType`
  and `KeyAlgorithm`, not just `CN`. `GetSignerByID`/`GetDecrypterByID`
  build a `KeyAttributes` with only `CN`, `KeyType` and `StoreType` set
  (never `KeyAlgorithm`) before calling `GetKey`, and `ListKeys`
  reconstructs each key's `KeyAttributes` from only its `CN` before
  reading the same metadata specifically to learn `KeyAlgorithm` — so
  neither caller could ever compute the same `ID()` the metadata was
  saved under, and both silently treated every real key as not found (or,
  for `ListKeys`, as having no metadata at all). All seven call sites now
  key on `attrs.CN` alone, matching the convention `pkg/backend/vault`
  already uses for the same per-key metadata store. A regression test
  exercises `GetSignerByID`/`GetDecrypterByID` and `ListKeys` against a
  key created through the normal `GenerateRSA` path (go-xkms#705).
