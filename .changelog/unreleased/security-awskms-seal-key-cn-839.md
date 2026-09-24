- **The `aws_kms` barrier strategy now provisions a real AWS KMS key instead
  of addressing the seal key's fixed label as if it were a key ID.**
  `EnsureSealKey`'s AWS branch unconditionally pre-seeded
  `awskms.Backend`'s in-process metadata with `{"key_id": "xkms-barrier-seal"}`
  before ever calling `GetSymmetricKey`/`GenerateSymmetricKey`; that seed
  made `GenerateSymmetricKey`'s own "already exists" guard succeed on the
  very first call, so AWS KMS's `CreateKey` never ran, and every later
  `Encrypt`/`Decrypt` addressed AWS KMS with the literal string
  `"xkms-barrier-seal"` as the key ID — not a valid key identifier on a real
  AWS account, so the `aws_kms` barrier failed closed outside a mock
  (go-xkms#839, found while stacked on go-xkms#757/#838's seal-key
  provisioning refactor). `EnsureSealKey` now seeds real key metadata only
  when the backend reports an operator-configured CMK (new
  `SealOperatorKeyProvider` interface, backed by `awskms.Config.KeyID`); with
  no such key configured, `EnsureSealKey` seeds nothing and lets
  `GenerateSymmetricKey` run `CreateKey` and persist the AWS-assigned key ID
  it returns, matching the design already documented for `xkey`'s side of
  the same composition path ("the seal key itself needs no configured
  identifier"). GCP KMS, Azure Key Vault and HashiCorp Vault were audited for
  the same class of bug and are unaffected: each lets the caller choose the
  key's own name, so using the seal key's CN as that name addresses the real
  resource directly, unlike AWS KMS's provider-assigned key IDs.

  Fixing the pre-seed alone would have traded a barrier that fails at init
  for one that fails later and loses data: `pkg/backend/awskms.Backend` kept
  its CN -> AWS-key-ID mapping in an in-process `map[string][]byte`, so a
  restarted process (or a second node) would see no metadata for the CN,
  call `CreateKey` again, and orphan the CMK data was already sealed under —
  worse than the original bug, which at least failed at init instead of
  after data was written. `Backend` now persists that mapping (and every
  other key it handles, symmetric or asymmetric) through
  `Config.KeyStorage`, using the same `storage.SaveKey`/`GetKey`/`KeyExists`/
  `DeleteKey`/`ListKeys` helpers `pkg/backend/vault` already used for this —
  finishing the design `Config.KeyStorage` was always documented for, not a
  new architecture. The in-process metadata map is gone entirely, not kept
  as a cache alongside the persisted copy. `Backend.Close` releases only the
  AWS client handle; `Config.KeyStorage`'s lifecycle belongs to the caller
  that constructed it (it may be shared, or outlive the `*Backend` across a
  restart) and is never closed here.

  With `Config.KeyStorage` now the sole source of truth for every other
  `*awskms.Backend` method that resolves a key by CN (`Get`, `Delete`,
  `Sign`, `Verify`, `Signer`, `Decrypter`, `RotateKey`,
  `GetImportParameters`, `ImportKey`, `SymmetricEncrypter`), the private
  `getKeyID` helper they all share was tightened to match: it used to
  swallow every `KeyStorage` error, JSON-decode failure, and missing-`key_id`
  case and silently address the `"alias/{cn}"` alias regardless, which would
  have let a transient storage failure make all ten callers talk to a
  possibly different KMS key with nothing surfaced. `getKeyID` is now
  `(string, error)`: only `storage.ErrNotFound` (verified safe because both
  `CreateKey` and `GenerateSymmetricKey` attempt to create that exact alias
  alongside every key they provision) still resolves to the alias; every
  other storage error, a corrupt record, or a record missing `key_id`
  returns a typed `ErrMetadataStorage`, propagated by every caller instead
  of guessed past.

  Tests (`awskms` tag): `cloud_provision_awskms_test.go` proves `CreateKey`
  runs exactly once on first provisioning against the real `*awskms.Backend`
  and its `MockKMSClient`, that every subsequent Encrypt/Decrypt addresses
  the AWS-assigned key ID (never the CN), that a second provisioning in the
  same process reuses the persisted key without a second `CreateKey`, that
  **a second `*awskms.Backend` built over the same `storage.Backend` — a
  simulated restart — resolves the key the first Backend's `CreateKey`
  already created and unseals data sealed before the restart, without
  `CreateKey` running again**
  (`TestBuildCloudKMSStrategy_AWSKMSBackend_RestartReusesPersistedKey`),
  that an operator-configured `Config.KeyID` is resolved and reused without
  ever calling `CreateKey`, and that a missing-credentials failure now
  surfaces from `BuildCloudKMSStrategy` itself rather than being deferred to
  the first seal/unseal call; `cloud_provision_test.go` and
  `pkg/server/server_extra2_test.go` cover the same operator-key-configured
  and no-operator-key branches against generic and `pkg/server`-local mock
  providers; new `pkg/backend/awskms/persistence_test.go` injects
  `Config.KeyStorage` failures (via a `failingStorage` wrapper) into
  `GenerateSymmetricKey`, `SymmetricEncrypter`, `CreateKey` (asymmetric),
  `GetKey`, `Save`, `Delete`, `ListKeys` and `Get`, proving each propagates
  the failure as an error, plus dedicated `getKeyID` coverage: a storage
  failure propagating through two representative callers (`Sign` and
  `Decrypter`) without ever reaching AWS KMS, a corrupt (non-JSON) record,
  and a record missing `key_id`; `TestClose` in `awskms_test.go` now proves
  `Close` leaves persisted metadata intact. Files:
  `pkg/seal/cloud_provision.go`, `pkg/seal/cloud_provision_test.go`,
  `pkg/seal/cloud_provision_awskms_test.go`, `pkg/backend/awskms/awskms.go`,
  `pkg/backend/awskms/awskms_symmetric.go`,
  `pkg/backend/awskms/awskms_test.go`,
  `pkg/backend/awskms/awskms_symmetric_test.go`,
  `pkg/backend/awskms/sealer_test.go`,
  `pkg/backend/awskms/persistence_test.go` (new),
  `pkg/server/server_extra2_test.go`, `docs/sealing-and-barrier/engineering.md`.
