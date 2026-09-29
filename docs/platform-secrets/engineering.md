# Platform Secrets — Engineering Contract

> **Status: NORMATIVE** · Feature: `platform-secrets` · Repo: `go-xkms` · Last verified: 2026-09-28 (#1226)

## Exported surface — `pkg/seal`

```go
type PlatformStore interface {
	// Put stores a secret under the given name. If a secret already exists
	// with this name it is overwritten with a fresh seal operation.
	Put(ctx context.Context, name string, secret []byte) error

	// Get retrieves and unseals the secret. ErrSecretNotFound if absent.
	Get(ctx context.Context, name string) ([]byte, error)

	// Delete removes the secret. ErrSecretNotFound if absent.
	Delete(ctx context.Context, name string) error

	// Exists reports whether a secret with the given name is stored.
	Exists(ctx context.Context, name string) (bool, error)

	// List returns the names of all stored secrets (without the internal
	// storage prefix).
	List(ctx context.Context) ([]string, error)

	// Reseal reads the current plaintext, deletes the old sealed copy, and
	// writes it back sealed with the current backend state (e.g. fresh TPM
	// PCR values). Returns ErrResealFailed wrapping the cause on failure.
	Reseal(ctx context.Context, name string) error
}

var _ PlatformStore = (*SealedPlatformStore)(nil)

type SealedPlatformStore struct {
	mu      sync.RWMutex
	backend storage.Backend
	logger  *slog.Logger
}

func NewPlatformStore(backend storage.Backend, logger *slog.Logger) (*SealedPlatformStore, error)
```

Client contract — `sdk/go/transport`:

```go
type SealStoreService interface {
	SealStorePut(ctx, req *SealStorePutRequest) error
	SealStoreGet(ctx, req *SealStoreGetRequest) (*SealStoreGetResponse, error)
	SealStoreDelete(ctx, req *SealStoreDeleteRequest) error
	SealStoreList(ctx) (*SealStoreListResponse, error)
	SealStoreReseal(ctx, req *SealStoreResealRequest) error
	SealStoreStatus(ctx) (*SealStoreStatusResponse, error)
}
```

Note the asymmetry: the Go interface has `Exists`, the transport interface has
`SealStoreStatus`. They are not the same operation — `Exists` is per-name,
`SealStoreStatus` reports the store's own state.

## Invariants

- **Sealing belongs to the backend.** `SealedPlatformStore` never encrypts. With
  a `sealed.Backend` values are sealed; with a plain file or memory backend they
  are stored as-is. The store cannot tell you which you have — the deployment's
  configuration can.
- **`Put` overwrites with a fresh seal.** No versioning, no previous value.
- **`Get` can fail on a TPM-sealed backend after a platform state change**, and
  that is the intended behaviour, not a fault to route around.
- **`Reseal` is explicit and re-binds to current state.** Never call it
  automatically on a read: it would rebind a secret to whatever state the
  machine is in, including a compromised one.
- **`List` returns names without the internal storage prefix.** Callers must not
  reconstruct raw storage keys.
- **All operations take a read-write mutex** — safe for concurrent use.
- **The store is platform-scoped, and reached only through the service.**
  Every `XKMSService.SealStore*` method refuses a tenant-scoped caller with
  `*xkms.TenantBindingError` before the store is touched
  (`pkg/xkms/servicer_seal_store.go:40,54,75,89,106,120`, go-xkms#1226), and
  no transport holds the `PlatformStore`: REST
  (`pkg/api/rest/seal_store_handlers.go`), gRPC/Unix
  (`pkg/api/grpc/service_seal_store.go`) and MCP
  (`pkg/api/mcp/handlers_seal_store.go`) hold the service. `rest.Config` has
  no `PlatformStore` field. The routes' `keys:*` grants are self-scoped, so
  without this a tenant-local Admin could read and overwrite the platform's
  backend credentials. Tests: `pkg/xkms/platform_scope_test.go`, and the
  per-transport `platform_scope_test.go` in `pkg/api/rest`, `pkg/api/grpc`,
  `pkg/api/mcp`.
- **`ErrSecretNotFound` distinguishes absent from unreadable.** A sealed secret
  that will not unseal is not "not found", and code that collapses the two makes
  a PCR mismatch look like a missing configuration key.

## Error semantics

| Error | Condition |
|---|---|
| `ErrSecretNotFound` | the name is not present |
| `ErrResealFailed` | `Reseal` failed; wraps the underlying cause |
| unseal failure (from the backend) | the sealed value cannot be opened in the current state |

**Fail closed:** an unsealable value returns an error. Nothing returns
ciphertext as if it were the secret, and nothing falls back to an unsealed copy.

## Configuration

The only configuration that matters is **which `storage.Backend` the store is
constructed on**:

- `sealed.Backend` over a strategy-specific sealer — production.
- plain file or memory — tests. **Values are not sealed.**

For xkmsd's own (system) platform store, `pkg/server.initializePlatformStore`
is the composition root: `credentials.seal_strategy` (config) selects one
`types.Sealer` (`pkg/server/platform_store.go`'s `buildPlatformSealer`),
composed into a single-strategy `seal.PlatformSealer` and wrapped in
`pkg/storage/sealed.New` over `s.createStorage("platform-store")`. `manual`
and `barrier` skip building it (`manual` stores nothing; `barrier` is stored
directly in the qrdb barrier by `credentials.Service`, not here).

- **`tpm2`** reuses a shared TPM open (the node-seal flip's, or the general
  tpm2 backend's — never opens the device/simulator a second time) and
  seals under the Platform SRK only, never the Shared SRK (owner ruling;
  matches PR #681). It requires `TPM.PlatformSRKAttributes()` to succeed and
  fails closed with a typed error naming
  `PlatformKeyStore.EnrollPlatformSRK` when the Platform SRK is not yet
  enrolled. When `Backends.TPM2.PlatformPolicy` is set, `platformPolicySealer`
  additionally binds every seal/unseal to the platform PCR.
- **`awskms`/`gcpkms`/`azurekv`** authenticate with ambient credentials (IAM
  role, Application Default Credentials, `DefaultAzureCredential`) and
  resolve their symmetric wrapping key through `sealKeyAttributesFor`/
  `ensureSealKey` (`seal_strategies.go`, shared with the barrier's own
  cloud-KMS strategy), wrapped in `fixedKeyAttrsSealer` since
  `sealed.Backend` cannot carry `opts.KeyAttributes` through to `Unseal`.
- **`pkcs11`/`vault`** fail closed: their secret is only resolvable through
  the credential service this call builds the storage for (go-xkms#677).
- **`passphrase`** fails closed pending an owner ruling on where the
  operator passphrase comes from — `CredentialsConfig` has no field for one
  today, and the qrdb secret-value contract refuses an inline/literal secret
  in a protected field.

A strategy that cannot build a sealer aborts `Server.New` with a typed error
— never a silent skip.

Per-tenant stores are `pkg/seal/platform_store_tenant.go`; the sealer type is
`pkg/seal/platform_sealer.go`'s `PlatformSealer`, reused by both the system
and the per-tenant composition roots.

## Persistence

Names to sealed byte-blobs, through `pkg/storage`. Values are opaque to the
store. There is no schema, no versioning and no history — a `Put` over an
existing name is the only update path and it discards the previous value.

## Test strategy

- **Unit** — `pkg/seal/platform_store_test.go`,
  `platform_store_tenant_test.go`, `platform_sealer_test.go`.
- **Transport** — `pkg/api/rest/seal_store_handlers_test.go`.
- **Composition root** — `pkg/server/platform_store_test.go` covers every
  `credentials.seal_strategy` outcome end to end: the skip strategies, each
  fail-closed strategy's typed error, and a real Put/Get/Reseal round-trip
  for `tpm2` (Platform SRK enrolled via the same construction the
  not-yet-merged go-xkms#681's `tpm2test.EnrollPlatformSRK` uses) both with
  and without `Backends.TPM2.PlatformPolicy`. `platform_store_awskms_test.go`
  / `_gcpkms_test.go` prove the `awskms`/`gcpkms` composition
  (`sealKeyAttributesFor` + `ensureSealKey` + `fixedKeyAttrsSealer`) against
  each backend's own mock KMS client; `azurekv` has no equivalent mock
  round-trip because `pkg/backend/azurekv`'s mock client does not implement
  the Secrets API `GetSymmetricKey`/`GenerateSymmetricKey` resolve through
  (that package's own unit suite has the same gap and defers to the
  emulator-backed `test/integration/azurekv` suite).
- **Sealed-backend behaviour** — the TPM simulator suites under `pkg/tpm2`
  cover seal-with-PCR-policy, which is what makes `Get` fail after a state
  change.

The case worth an explicit test in any consumer: a `Get` that fails because the
platform state changed must be distinguishable from `ErrSecretNotFound`. A
second case worth remembering: `Reseal` cannot recover a secret whose `Get`
already fails — it reads the current plaintext first, so it fails identically
once the old seal is broken (see the architecture doc's Trust boundaries).

## Observability

`NewPlatformStore` takes an `*slog.Logger`. The events worth having are put,
delete and **reseal** — a reseal re-binds a secret to the machine's current
state, which is exactly the kind of change you want a record of afterwards.
Secret values never appear in logs; names do, and names are not secret.
