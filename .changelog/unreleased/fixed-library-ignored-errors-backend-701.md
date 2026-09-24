- **`pkg/crypto`, `pkg/backend`, `pkg/keyprovider`, `pkg/tpm2`, `pkg/pkcs11`,
  `pkg/pivcert` and `pkg/storage` no longer discard errors with `_ =`
  (go-xkms#701, batch 1).** PKCS#11 finalization is the sharpest case the
  issue calls out: `SessionPool.Close`, `Backend.Close` and the PIV
  `standalonePool`/`singleSessionProvider` equivalents now return the
  C_CloseSession/C_Finalize failures they used to swallow, so a session or
  library that failed to tear down is visible instead of silently "closed".
  `Backend.loginUser` also stopped unconditionally claiming Finalize
  ownership: a second backend attached to an already-initialized Cryptoki
  library (`CKR_CRYPTOKI_ALREADY_INITIALIZED`) no longer calls C_Finalize on
  the module a sibling backend still owns, a latent double-finalize bug this
  batch's error-surfacing exposed via `CKR_CRYPTOKI_NOT_INITIALIZED` on an
  unrelated backend's `Close`. `frost.KeyStore.DeleteKey` now joins every
  component delete's error instead of always returning nil, most
  importantly the secret share delete: a failed wipe of key material used to
  be reported as a successful delete. `NonceTracker.DeleteKeyNonces` and
  `FrostBackend.DeleteKey` likewise now surface delete failures instead of
  discarding them. `pivcert/file.Delete` no longer treats an `Exists` I/O
  failure as "certificate not found", and `List` now fails on a corrupt
  `StoredAt` timestamp instead of silently substituting the zero time.
  Session/search cleanup that runs after a primary result is already decided
  (`WithSession`, `WithSOSession`, `WithSearch`, `doSearch`, and several
  PKCS#11 manager and TPM session-close/logout paths) now joins the cleanup
  failure onto the primary error with `errors.Join` via named returns rather
  than discarding it; a few sites with no logger and a genuinely
  unactionable failure (e.g. mid-panic session discard) are left
  intentionally silent with a comment explaining why. `pkcs11/module.Initialize`'s
  three best-effort steps (load persisted state, auto-init token, load PIV
  objects) now record their failure via a new `Module.LastInitWarning`
  accessor, mirroring the existing `LastStorageError` pattern, instead of
  discarding the `CK_RV`/error entirely. Every behavior change ships a new
  test proving the previously-discarded error now surfaces (or, for the
  finalize-ownership fix, that it no longer incorrectly fires). Sites that
  discard a non-error second return (`pem.Decode`'s rest bytes, comma-ok type
  assertions, `sync.Map.LoadOrStore`'s `loaded` bool) are unchanged -- they
  were never ignoring an error.
