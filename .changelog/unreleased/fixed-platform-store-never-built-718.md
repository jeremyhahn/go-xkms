- **`initializePlatformStore` now actually builds the platform sealed
  credential store instead of only logging that it did.** Every
  `credentials.seal_strategy` other than `manual`/`barrier` (`tpm2`,
  `pkcs11`, `awskms`, `gcpkms`, `azurekv`, `vault`, `passphrase`) made
  `credentials.New` return `ErrNilPlatformStore` and aborted startup, and
  every `SealStore` API call returned `ErrNotConfigured`
  (`pkg/xkms/servicer_seal_store.go`), because `s.platformStore` was never
  assigned. `initializePlatformStore` (`pkg/server/platform_store.go`, new
  file) now resolves a `types.Sealer` for the configured strategy, composes
  it into a `seal.PlatformSealer` with an explicit single-strategy
  preference order, wraps a qrdb-backed storage view
  (`s.createStorage("platform-store")`, the same seam every other daemon
  store uses) with `pkg/storage/sealed.New`, and assigns the resulting
  `seal.PlatformStore` to `s.platformStore`. A strategy that cannot build a
  sealer fails `Server.New` with a typed `*ErrServiceInit{Service: "platform
  store"}` instead of booting with a half-configured credential subsystem --
  never a silent skip.

  **`tpm2` seals under the Platform SRK only, never the Shared SRK (owner
  ruling; matches PR #681).** `buildTPM2PlatformSealer` reuses the node-seal
  flip's single TPM open (`s.nodeSealTPM`) when one exists, or opens its own
  via `seal.BuildBestStrategy` (closed at shutdown); either way it then
  requires `TPM.PlatformSRKAttributes()` to succeed and fails closed with a
  typed error naming `PlatformKeyStore.EnrollPlatformSRK` when the Platform
  SRK is not yet enrolled -- enrollment is a deliberate, separate
  operator/ceremony action this call never performs implicitly. A new
  `platformPolicySealer` adapter parents every seal/unseal to the enrolled
  Platform SRK and, when `Backends.TPM2.PlatformPolicy` is set, additionally
  binds the sealed object to the configured platform PCR, since
  `pkg/storage/sealed.Backend` always calls `Unseal` with nil options and so
  cannot otherwise carry either per-call. `pkg/tpm2` gained the exported
  `PlatformSRKAttributesFromConfig` (the existing internal
  `buildSRKAttrsFromConfig`, exported) and `pkg/backend/tpm2` gained
  `NewFileKeyBackend` (extracted from `NewBackend`'s inline construction),
  both purely to let external callers -- this package's tests, and the
  not-yet-merged go-xkms#681 -- share the construction instead of
  duplicating it. Fixing the reuse path also surfaced and fixed a real
  latent double-TPM-open hang: a standalone platform-store TPM open was
  invisible to `initTPM2Backend`'s own reuse check (it only looked at
  `s.nodeSealTPM`), so it opened a second, independent simulator/device --
  exactly the scenario `pkg/seal/autodetect.go`'s own doc warns hangs a
  swtpm emulator. `initTPM2Backend` now also checks the new
  `s.platformStoreTPM`, and a second, previously-latent bug the fix exposed
  (a `NewBackendWithTPM` reuse call site with no `KeyBackend`, never
  exercised by the existing test suite) is fixed alongside it.

  **`passphrase` fails closed; owner ruling pending.** There is no config
  field carrying an operator passphrase for `credentials.seal_strategy`
  today (`CredentialsConfig` has only `SealStrategy`), and a literal/inline
  secret in a protected `*types.SecretValue` field is refused by the qrdb
  secret-value contract. An earlier version of this change derived the
  strategy's seal key from a random secret persisted **unsealed** next to
  the data it protected as a stand-in -- that is not sealing, so it was
  removed; the strategy now fails closed with a typed
  `*ErrPlatformStoreStrategyUnavailable` until the owner rules on where the
  passphrase comes from.

  **`awskms`, `gcpkms` and `azurekv` are implemented, using ambient
  credentials.** Unlike `pkcs11`/`vault` (still blocked on go-xkms#677: the
  PIN/token is only resolvable through the credential service this call
  itself builds storage for), the cloud-KMS backends need no secret this
  phase of startup could fail to resolve -- with no static
  access-key/service-account/client-secret set, each authenticates via its
  SDK's ambient credential chain (IAM role, Application Default Credentials,
  `DefaultAzureCredential`), the same "optional" mode each backend's own
  `Config` already documents. Each new `pkg/server/platform_store_<cloud>.go`
  (behind the same `awskms`/`gcpkms`/`azurekv` build tags the general
  backends use, with a `_stub.go` counterpart returning the standard
  not-compiled-in error) resolves its symmetric wrapping key through the
  existing `seal_strategies.go` machinery (`sealKeyAttributesFor`,
  `ensureSealKey`) -- deliberately the *same* self-provisioned CMK/key the
  barrier's own cloud-KMS strategy would use when configured, not a second
  one -- and wraps it in a new `fixedKeyAttrsSealer` adapter for the same
  reason `platformPolicySealer` exists: `pkg/storage/sealed.Backend` always
  calls `Unseal` with nil options, so a backend that needs
  `opts.KeyAttributes` to identify its key cannot get it from the caller on
  the unseal side.

  Files: `pkg/server/platform_store.go`, `pkg/server/platform_store_awskms.go`,
  `pkg/server/platform_store_awskms_stub.go`,
  `pkg/server/platform_store_gcpkms.go`,
  `pkg/server/platform_store_gcpkms_stub.go`,
  `pkg/server/platform_store_azurekv.go`,
  `pkg/server/platform_store_azurekv_stub.go`, `pkg/server/server.go`,
  `pkg/server/errors.go`, `pkg/server/backend_tpm2.go`,
  `pkg/backend/tpm2/backend.go`, `pkg/tpm2/platform_keystore.go`. Fixes
  go-xkms#718.
