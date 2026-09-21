- **`pkg/xkms` backend resolution is now keyed by registry name, not by a
  parse of it** (#312, #297, #172). `BackendFor` and `getBackendForKID` used
  to resolve `GetBackend(string(attrs.StoreType))` — which worked only
  because every backend that existed had been registered under a name that
  was also a store-type keyword (`software`, `pkcs11`, `tpm2`, …); a backend
  registered under any other name, e.g. a second PKCS#11 token named
  `token-a`, resolved to `backend not found: unknown` on every path that
  read the key back through its stored attributes. `types.KeyAttributes`
  gains a `Backend` field carrying the exact registry name a key's operation
  ran against; `xkms.Backend` gains `Type() types.StoreType`, implemented by
  every backend and wrapper in the tree (the composite backend, the
  tenant-scoping wrapper, and every test fake), so a resolved backend can
  report what kind it is without unwrapping to `KeyProvider()` and losing
  tenant scope (#163). Every producer that used to write
  `StoreType: types.ParseStoreType(backendName)` now writes `Backend:
  backendName, StoreType: b.Type()` instead, so `StoreType` is a label the
  backend reports about itself, never a second name for the same registry
  entry. The last surviving `ParseStoreType` override, in MCP's
  `handleExportKey`, is replaced by the resolved backend's own `Type()` for
  the same reason, and the two independently-maintained copies of
  `ValidateBackendName` (`pkg/validation`, `pkg/api/rest`) are now one,
  imported from `pkg/validation`.

  **Migration**: keys persisted before this change carry no `Backend` value,
  and a backend's own `ListKeys` has no way to learn the registry name it
  was registered under, so this is not a one-time backfill — `BackendFor`
  and `getBackendForKID` permanently fall back to treating `StoreType` as
  the name when `Backend` is empty, which reproduces the exact resolution
  every caller depended on before this field existed. `KeyAttributes.ID()`
  is unaffected for every key that exists today: a backend registered under
  a store-type keyword reports that same keyword from `Type()`, so `ID()`'s
  `StoreType` segment is byte-identical to what `ParseStoreType(backendName)`
  produced. A backend registered under a non-keyword name now stores new
  keys under its real kind (e.g. `pkcs11`) instead of the `unknown` segment
  `ParseStoreType("token-a")` used to leave in `ID()` — a new-key
  improvement pinned by test, not a change to any key that already exists.
  The Simplified API's package-level `ListKeys` now stamps `Backend` onto
  every key it returns with the name it was listed under, so a caller that
  lists keys and then calls `Key`/`Signer`/`Decrypter`/`DeleteKey` with one
  of them (as the PIV slot lookups in `xkey/pkg/gui/services/piv_service.go`
  do) resolves the same backend the listing came from, including for
  non-keyword names.
