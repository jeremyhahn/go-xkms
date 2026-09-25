- **`backends.tpm2.enabled: true` together with `barrier.strategy: tpm2` no
  longer fails to start.** `initTPM2Backend` (`pkg/server/backend_tpm2.go`)
  reuses the node-barrier flip's single TPM open via
  `tpm2backend.NewBackendWithTPM`, but never populated
  `ExternalTPMConfig.KeyBackend`, so the general TPM2 backend failed closed
  with a typed `*ErrBackendCreate` wrapping `*ErrInvalidConfig` ("KeyBackend
  is nil") on every boot with both settings enabled (go-xkms#795). The
  shared path now reuses `shared.KeyBackend()` — the exact `store.KeyBackend`
  the node-seal open already built over `<Storage.Path>/tpm2-keys` — instead
  of leaving it unset, matching the standalone path
  (`tpm2backend.NewBackend`) exactly: same TPM connection, same on-disk key
  store, keys parented to the same SRK, with all authorization sourced from
  `Backends.TPM2`/`KeyConfig`, never hardcoded.
