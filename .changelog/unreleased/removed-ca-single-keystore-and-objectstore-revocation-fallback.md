- **BREAKING: `pkg/ca` no longer falls back to a single shared keystore for
  every key, or to the object store for revocation/CRL persistence — both
  compat paths are deleted outright.** Every CA constructor (`New`,
  `NewParentCA`, `NewIntermediateCA`, `NewCA`, `NewFromMultiIdentityConfig`,
  `NewHierarchicalCA`) now requires `Params.BackendForStore` /
  `MultiIdentityParams.BackendForStore`; a nil factory returns the new
  `ErrBackendForStoreRequired` instead of silently routing every key to
  `Params.KeyStore` regardless of its declared `StoreType`. `resolveKeyBackend`
  and `buildKeystoreMap` no longer have a legacy path: a `StoreType` missing
  from the constructed `keystoreMap` returns `ErrKeyStoreRequired` rather than
  falling back. A caller with one uniform backend for every key now states
  that explicitly with a trivial factory (`func(cn string, st types.StoreType)
  (xkms.Backend, error) { return backend, nil }`) instead of relying on an
  implicit default.

  `Params.RevocationStore` / `MultiIdentityParams.RevocationStore` are now
  required; the new `ErrRevocationStoreRequired` replaces the silent fallback
  to the object store or to in-memory-only revocation tracking.
  `putRevocationBlob`, `getRevocationBlob`, `listRevocationBlobs`,
  `putCRLBlob`, and `getCRLBlob` (`pkg/ca/ca_extensions.go`,
  `pkg/ca/crl_persistence.go`) now talk to `revocationStore` unconditionally;
  the object-store branches, the `(persisted bool, err error)` return shape
  that reported an unpersisted write, and the directory-key skip guard that
  branch needed are gone.

  The redundant `Identity.KeystoreType` field (duplicated `Keys[0].StoreType`
  in every caller) is deleted; `Identity.GetStoreType()` now derives from
  `Keys[0].StoreType`, defaulting to `types.StoreSoftware` when unset.

  Fixed a latent bug found while making `RevocationStore` mandatory:
  `NewParentCA` and `NewIntermediateCA` (`pkg/ca/constructors.go`) built their
  inner `New(&Params{...})` call without forwarding `params.RevocationStore`,
  so any caller of those two constructors got in-memory-only revocation
  tracking regardless of what it passed in `Params.RevocationStore`.

  Production callers now wire `BackendForStore` explicitly:
  `cmd/xkmsd/init_ceremony.go` (single software backend), `pkg/server/server.go`
  (`s.backends[string(storeType)]`, extending the per-key routing the design
  already called for but no in-repo caller had wired), and
  `pkg/trust/clusterca/acme.go` (`p.opts.Backends(string(st))`).