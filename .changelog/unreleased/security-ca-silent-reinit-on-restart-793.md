- **`xkmsd run` no longer silently mints a new root CA on every restart.**
  `pkg/server`'s `initializeCA` called `TrustedCA.Load` and treated *any*
  failure — not only a genuine "never initialized" signal — as license to
  call `TrustedCA.Init`, which always stores a fresh self-signed certificate.
  The root cause was in `pkg/ca.CA.Load`: it resolved a root or intermediate
  identity's key attributes through the bare `Identity.ToKeyAttributes`
  instead of the `KeyTypeCA`-defaulting `getCAKeyAttributes` that `Init`
  uses, so an identity whose `KeyConfig` left `key-type` unset (or set it
  under the YAML field `key_type`, which the struct tag does not bind —
  the shipped `configs/xkmsd.yaml` and `configs/xkmsd-dev.yaml` both did)
  failed `Load` with a `KeyAttributes.Validate` error, never a not-found,
  on every restart. `Load` also collapsed every `certStore.GetCertificate`
  failure — including a corrupt or unparseable persisted certificate — into
  `ErrCertificateNotFound`, so even a *damaged* existing CA record would
  have been silently treated as absent and replaced. Every restart on a
  qrdb-backed data directory therefore re-minted the root: a new serial and
  validity window every time, invalidating every certificate issued from
  the previous root and every client's pin to it.
  `pkg/ca.CA.Load` now shares `getCAKeyAttributes` with `Init` for the
  root, the selected issuing identity, and every other configured
  intermediate, and classifies a `GetCertificate` failure as
  `ErrCertificateNotFound` only when the underlying cause is a genuine
  `storage.ErrNotFound` (`wrapCertLookupError`) — any other cause returns a
  distinct error. `pkg/server`'s `initializeCA` now calls `Init` only when
  `errors.Is(loadErr, ca.ErrCertificateNotFound)`; any other `Load` failure
  fails server startup closed with `*server.ErrCAInit{Operation: "load
  existing CA"}` instead of replacing existing state.
  Tests: `pkg/ca/ca_reload_793_test.go`
  (`TestCA_Load_AfterInit_KeyTypeOmittedFromConfig`,
  `TestCA_Load_NeverInitialized_ReturnsErrCertificateNotFound`,
  `TestCA_Load_CorruptPersistedCertificate_DoesNotReportNotFound`) and
  `pkg/server/server_ca_reload_793_test.go`
  (`TestInitializeCA_QRDB_ReloadsPersistedCAAcrossRestarts`,
  `TestInitializeCA_QRDB_CorruptPersistedCertificateFailsClosed`).
