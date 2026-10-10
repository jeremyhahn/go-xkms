# Signing — Engineering Contract

> **Status: NORMATIVE** · Feature: `signing` · Repo: `go-xkms` · Last verified: 2026-10-09

## Exported surface

### `types.VerifyOpts` and `types.ChecksumProvider` — `pkg/types/types.go`

```go
type ChecksumProvider interface {
	Checksum(opts *VerifyOpts) ([]byte, error)
}

type VerifyOpts struct {
	KeyAttributes    *KeyAttributes
	Hash             crypto.Hash
	PSSSaltLength    int
	PublicKey        crypto.PublicKey
	PSSOptions       *rsa.PSSOptions
	BlobCN           string
	IntegrityCheck   bool
	ChecksumProvider ChecksumProvider
}
```

`NewVerifier(opts) Verifier` returns a `*SimpleVerifier`. `Verify(pub, digest,
signature)` runs the RSA/ECDSA/Ed25519 check first; when it fails, that error
returns immediately and `IntegrityCheck` never runs. When `IntegrityCheck` is
true, a second check follows: `ChecksumProvider.Checksum(opts)` must return a
value `bytes.Equal` to `digest`.

### `xkms.SignOptions` / package-level `Sign`, `Verify` — `pkg/xkms/service.go`

```go
type SignOptions struct {
	Hash       crypto.Hash
	PSSOptions *rsa.PSSOptions
	BlobCN     string
}

func Sign(ctx context.Context, kid string, data []byte, opts *SignOptions) ([]byte, error)
func Verify(ctx context.Context, kid string, data, signature []byte, opts *types.VerifyOpts) error
```

`kid` is the four-segment key reference (`backend:type:algo:keyname`, with
optional segments) `getBackendForKID` already resolves for every other
package-level operation in this file.

`Sign` computes the digest exactly as before (SHA-256 default, or the raw
message for Ed25519), then, only when `opts.BlobCN != ""`, calls
`b.SignerStore().SaveSignature`. A `SaveSignature` failure is returned as-is
(a typed error from `pkg/signing/store`); the signature already produced is
discarded rather than returned as if persistence had never been requested.

`Verify` sets `opts.ChecksumProvider = b.SignerStore()` when
`opts.IntegrityCheck` is true and the caller left `ChecksumProvider` nil, and
sets `opts.KeyAttributes = attrs` (resolved from `kid`) when the caller left
it nil — `Checksum` keys its lookup by `KeyAttributes.CN`, and `kid`, not
`VerifyOpts`, is how a caller of this function names the key.

### `xkms.Backend.SignerStore()` — `pkg/xkms/keystore.go`

```go
SignerStore() store.SignerStorer
```

One per `Backend`, built in `New()` by `newSignerStore`: a
`dao.NewStoreFactory` over `kvadapter.New(BackendConfig.CertStorage)`, so the
records share the certificates' storage. `TenantScopedBackend.SignerStore()`
(`pkg/xkms/backend_tenant.go`) does **not** pass this through unchanged: it
wraps the base store in `tenantScopedSignerStore`, which prefixes
`KeyAttributes.CN` with `"{tenantID}/"` on every method before delegating —
the same mechanism `scopeCertKeyID` already applies to certificate key IDs.
Without it, two tenants signing under the same key CN and `BlobCN` against
one shared `compositeBackend` would silently overwrite each other's
signature record — a cross-tenant integrity denial of service, not merely a
mix-up, since it destroys the other tenant's ability to integrity-check its
own blob.

### `store.SignerStorer` — `pkg/signing/store/interfaces.go`

```go
type SignerStorer interface {
	Get(attrs *types.KeyAttributes) (interface{}, error)
	Save(attrs *types.KeyAttributes, signer interface{}) error
	Delete(attrs *types.KeyAttributes) error
	SaveSignature(opts *SignerOpts, signature, digest []byte) error
	GetSignature(opts *SignerOpts) (digest, signature []byte, err error)
	Checksum(opts *types.VerifyOpts) ([]byte, error)
}
```

### `store.NewSignerStore` — `pkg/signing/store/store.go`

```go
const DatabaseName = "signing"

func NewSignerStore(logger *slog.Logger, daos *qrdbsdk.DAOFactory) (*SignerStore, error)
```

The composition root injects the go-qrdb DAO factory; the store opens its own
`signing` database from it, with two entity types: `signers` (`SignerEntry`)
and `signatures` (`SignatureEntry`). A nil factory returns
`ErrNilDAOFactory`; a factory that cannot serve the database or entity types
returns `*StoreOpenError`, which unwraps to the cause (for example
`*dao.DatabaseUnavailableError`).

`pkg/signing/store` has no TPM (or other hardware) dependency: it is a plain
go-qrdb DAO client, distinct from `pkg/tpm2/store` (blob and PCR-policy
storage, genuinely TPM-specific, unaffected by this feature). The two
packages happen to share a `SignerOpts` type name for unrelated purposes —
`pkg/tpm2/store.SignerOpts` (`KeyAttributes`, `Backend`, `PSSOptions`,
`HashFunc()`) is TPM2's own `crypto.SignerOpts` implementation for
`TPM2.Sign`, and does not have `BlobCN`; do not confuse the two when reading
call sites named `store.SignerOpts` — check the import path.

`SaveSignature`/`GetSignature` key their record by
`fmt.Sprintf("%s.%s.sig", KeyAttributes.CN, BlobCN)` (or `"%s.sig"` when
`BlobCN` is empty) — `signatureKey` in `store.go` is the one place that
format is written, so the two operations cannot drift on it. That key is the
`SignatureEntry.Key` natural key; signers use `SignerEntry.CN`. Both entity
IDs are `qrdbsdk.NewCryptoFieldHashGenerator` hashes of those fields, and
every read goes through `GetByNaturalKey`. The record is
`"digest=%x\nsignature=%x\n"`; `parseSignatureData` is its only reader.
`KeyAttributes.TenantID` plays no part in this key: `pkg/signing/store` is
not itself multi-tenant-aware (see `tenantScopedSignerStore` above for where
that is handled).

## Invariants

- **The cryptographic check always runs, and always runs first.**
  `IntegrityCheck` is an additional gate, never a replacement: a digest that
  matches its checksum but fails RSA/ECDSA/Ed25519 verification is still
  rejected at that step, with `verifyIntegrity` never reached.
- **`IntegrityCheck` without `BlobCN` or without a resolvable
  `ChecksumProvider` is refused, not silently skipped.** A caller that meant
  to enable the check and forgot one of its two required inputs gets
  `types.ErrBlobCNRequired` or `types.ErrChecksumProviderRequired`, not a
  pass.
- **A `ChecksumProvider` failure is never treated as "no checksum to check
  against, so pass."** `verifyIntegrity` returns whatever error `Checksum`
  returned, unwrapped, so a store outage surfaces as that store's typed error
  (e.g. `*store.ErrSignatureGet`) rather than a false positive.
- **`SaveSignature`/`GetSignature`/`Checksum` are backend-agnostic.** They
  operate on go-qrdb DAOs, not on anything TPM2-specific; `Sign`/`Verify`
  reach them through `Backend.SignerStore()` for every `xkms.Backend`, not
  through a TPM2-only path.
- **Persistence is opt-in per call, not per key.** A key signed once with
  `BlobCN` and again without it has one persisted record (from the call that
  set `BlobCN`) and one call that left the `SignerStore` untouched; nothing
  about the key itself remembers "this key persists."
- **Signature records are tenant-isolated wherever key material is.** A
  `TenantScopedBackend`'s `SignerStore()` scopes every record to its tenant;
  two tenants sharing a `compositeBackend` and signing under the same CN and
  `BlobCN` never see each other's record.

## Error semantics

All new errors are typed values, `errors.Is`/`errors.As`-compatible:

| Error | Package | Meaning |
|---|---|---|
| `ErrBlobCNRequired` | `types` | `IntegrityCheck` set, `BlobCN` empty |
| `ErrChecksumProviderRequired` | `types` | `IntegrityCheck` set, no provider resolvable |
| `ErrIntegrityCheckFailed` | `types` | Digest does not match the persisted checksum (wrapped with the `BlobCN` via `errs.Detail`) |
| `ErrSignatureNotFound` | `pkg/signing/store` | No record for this `CN`/`BlobCN` |
| `ErrNilDAOFactory` | `pkg/signing/store` | `NewSignerStore` was given a nil DAO factory |
| `StoreOpenError` | `pkg/signing/store` | The factory could not open the `signing` database or its entity types |
| `ErrSignerNotFound` | `pkg/signing/store` | No signer for this `CN` |
| `ErrSignatureGet` | `pkg/signing/store` | The DAO read failed |
| `ErrSignatureParse` | `pkg/signing/store` | A persisted record's `digest=`/`signature=` fields did not hex-decode, wraps `ErrMalformedSignatureData` |
| `ErrSignatureSave` | `pkg/signing/store` | The DAO write failed |

## Configuration

None. `SignerStore()` requires no configuration beyond `BackendConfig` already
carrying `CertStorage storage.Backend` — every deployment that constructs a
`Backend` through `xkms.New` or `xkms.AutoInitialize` gets one.

## Persistence

Through go-qrdb DAOs in the `signing` database: `signers` entities for key
material and `signatures` entities for signature records. `xkms.New` serves
that database from the caller's `CertStorage` through `kvadapter`, so its
durability matches `CertStorage`. The KV store must support atomic
conditional writes (`CompareAndSwap` / `PutIfAbsent`); DAO creates fail
without them. A `TenantScopedBackend`'s records live in the same entity
types, under CNs prefixed `"{tenantID}/"`. There is no migration: records
written by the earlier raw-KV layout are not read.

## Test strategy

- `pkg/types/types_extended_test.go`: `SimpleVerifier` with `IntegrityCheck`
  set — untampered digest passes, a digest that verifies cryptographically
  but does not match the checksum fails with `ErrIntegrityCheckFailed`,
  `IntegrityCheck` unset leaves pre-existing behavior unchanged, a
  `ChecksumProvider` failure surfaces as that error rather than a pass, and
  the two required-input refusals.
- `pkg/signing/store/store_test.go`: `GetSignature`/`Checksum` round-trip a
  `SaveSignature` record with and without `BlobCN`, a missing record reports
  `ErrSignatureNotFound`, a KV read failure reports `ErrSignatureGet`,
  and a corrupted record reports `ErrSignatureParse`. Every store runs on a
  real in-process DAO factory over `qrdbsdk.NewMemoryKVStore()`;
  `TestSignerStore_PersistsAcrossStores` reads back through a second store
  what the first wrote, and `TestNewSignerStore_Refusals` covers the nil and
  unavailable factory.
- `pkg/xkms/service_test.go`: `Sign` with `BlobCN` persists a record readable
  back through `SignerStore().GetSignature`; without `BlobCN` it does not.
  `Verify` end to end: the exact blob signed under a `BlobCN` passes with
  `IntegrityCheck`; a different, validly-signed-by-the-same-key blob
  presented under the same `BlobCN` fails with `ErrIntegrityCheckFailed`;
  the same substitution passes when `IntegrityCheck` is unset; a
  never-persisted `BlobCN` surfaces `store.ErrSignatureNotFound`.
- `pkg/xkms/backend_tenant_test.go`: `TenantScopedBackend.SignerStore()`
  reaches the base store with a tenant-scoped CN (`_Delegates`); two tenants
  signing under the same CN and `BlobCN` against one shared store each read
  back — and integrity-check against — only their own record
  (`_IsolatesTenantsOnSameBlobCN`).

## Observability

None added. `store.SignerStore` logs `Debug` on save/read when constructed
with a non-nil `*slog.Logger`; `compositeBackend` constructs it with `nil`
today (`pkg/xkms/keystore.go newSignerStore`), matching `CertStorage`'s own lack of a
dedicated logger at that layer.
