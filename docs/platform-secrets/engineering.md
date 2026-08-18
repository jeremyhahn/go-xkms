# Platform Secrets — Engineering Contract

> **Status: NORMATIVE** · Feature: `platform-secrets` · Repo: `go-xkms` · Last verified: 2026-08-19

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

- `sealed.Backend` over the barrier — production. Protection follows the
  barrier's strategy: TPM PCR binding, HSM, cloud KMS, passphrase.
- plain file or memory — tests. **Values are not sealed.**

Per-tenant stores are `pkg/seal/platform_store_tenant.go`; the sealer is
`pkg/seal/platform_sealer.go`.

## Persistence

Names to sealed byte-blobs, through `pkg/storage`. Values are opaque to the
store. There is no schema, no versioning and no history — a `Put` over an
existing name is the only update path and it discards the previous value.

## Test strategy

- **Unit** — `pkg/seal/platform_store_test.go`,
  `platform_store_tenant_test.go`, `platform_sealer_test.go`.
- **Transport** — `pkg/api/rest/seal_store_handlers_test.go`.
- **Sealed-backend behaviour** — the TPM simulator suites under `pkg/tpm2`
  cover seal-with-PCR-policy, which is what makes `Get` fail after a state
  change and `Reseal` recover it.

The case worth an explicit test in any consumer: a `Get` that fails because the
platform state changed must be distinguishable from `ErrSecretNotFound`.

## Observability

`NewPlatformStore` takes an `*slog.Logger`. The events worth having are put,
delete and **reseal** — a reseal re-binds a secret to the machine's current
state, which is exactly the kind of change you want a record of afterwards.
Secret values never appear in logs; names do, and names are not secret.
