# Sealing and Barrier — Engineering Contract

> **Status: NORMATIVE** · Feature: `sealing-and-barrier` · Repo: `go-xkms` · Last verified: 2026-09-24

## Exported surface — `pkg/seal`

### Type aliases (`strategy.go`)

Core types are **go-qrdb's**, aliased here so go-xkms code reads naturally
without redefining anything:

```go
type StrategyID         = qrdbsdk.StrategyID
type SealingStrategy    = qrdbsdk.SealingStrategy
type SymmetricEncrypter = qrdbsdk.SymmetricEncrypter
type Credentials        = qrdbsdk.Credentials
type SealedRootKey      = qrdbsdk.SealedRootKey
type ShamirConfig       = qrdbsdk.ShamirConfig
type ShamirInitResult   = qrdbsdk.ShamirInitResult
type QuorumProgress     = qrdbsdk.QuorumProgress
type BarrierStatus      = qrdbsdk.BarrierStatus
type RecoveryKeyResult  = qrdbsdk.RecoveryKeyResult
type RootToken          = qrdbsdk.RootToken
type MemoryBackend      = qrdbsdk.MemoryBackend
type NamespacedBackend  = qrdbsdk.NamespacedBackend
type ShamirStrategy     = qrdbsdk.ShamirStrategy
```

### Strategy identifiers

```go
// owned and implemented here
StrategyTPM2    StrategyID = "tpm2"
StrategyPKCS11  StrategyID = "pkcs11"
StrategyAWSKMS  StrategyID = "awskms"
StrategyGCPKMS  StrategyID = "gcpkms"
StrategyAzureKV StrategyID = "azurekv"
StrategyVault   StrategyID = "vault"

// re-exported, implemented elsewhere
StrategyShamir     = qrdbsdk.StrategyShamir      // go-qrdb
StrategyPassphrase = qrdbsdk.StrategyPassphrase  // go-quicraft L1
StrategyNone       = qrdbsdk.StrategyNone        // go-quicraft L1
DefaultQuorumTTL   = qrdbsdk.DefaultQuorumTTL    // go-quicraft, via go-qrdb
```

### Autodetection (`autodetect.go`) — opt-in

```go
func ProbeStrategies(opts AutodetectOptions) (available []StrategyID, result *AutodetectResult)
func BuildBestStrategy(opts AutodetectOptions) *AutodetectResult

func (r *AutodetectResult) HardwareAvailable() bool
func (r *AutodetectResult) Close() error
```

### Cloud KMS strategy composition (`cloud_provision.go`, go-xkms#757)

The ONE function `xkmsd` (`pkg/server/seal_strategies.go`) and `xkey`
(`go-xkms/xkey`, which has no backend/provider registry of its own) both
call to turn an already-constructed cloud KMS backend into a
`CloudKMSStrategy`:

```go
const SealKeyCN = "xkms-barrier-seal"

func SealKeyAttributes(store types.StoreType) *types.KeyAttributes
func IsCloudSealStrategy(id StrategyID) bool
func EnsureSealKey(ctx context.Context, id StrategyID, provider types.KeyProvider, keyAttrs *types.KeyAttributes) error
func BuildCloudKMSStrategy(ctx context.Context, id StrategyID, store types.StoreType, provider types.KeyProvider) (SealingStrategy, error)

type SealLoginProvider interface{ Login() error }
type SealMetadataSaver interface {
	Save(attrs *types.KeyAttributes, data []byte, extension types.FSExtension, overwrite bool) error
}
type ErrSealBackendUnavailable struct{ Strategy, Purpose string }
type ErrNotCloudSealStrategy struct{ Strategy string }
```

`BuildCloudKMSStrategy` accepts only `StrategyAWSKMS`/`StrategyGCPKMS`/
`StrategyAzureKV`/`StrategyVault` (`ErrNotCloudSealStrategy` otherwise); it
provisions (creates on first use, reuses thereafter, via `EnsureSealKey`)
the symmetric wrapping key identified by `SealKeyAttributes(store)` — the
fixed `SealKeyCN`, never an operator-supplied key identifier — and wraps the
provider's `types.Sealer` in a `CloudKMSStrategy`. `pkg/server`'s own
`buildHardwareSealStrategy` calls this for its four cloud IDs and continues
to wrap TPM2/PKCS11 (not shared with xkey) inline; see
`xkey/docs/seal/architecture.md` for xkey's side of the composition
(per-provider backend construction gated by that provider's build tag, then
this same call).

### Other components

`barrier_adapter.go`, `barrier_putifabsent.go` (CAS init),
`hardware_encryptor.go`, `platform_sealer.go`, `platform_store.go`,
`platform_store_tenant.go`, `secret_sealer.go`, `audit.go`, `config.go`,
`errors.go`, `policy/`.

`sealedRootKeyVersion` (`strategy.go`) is the format version stamped into
`SealedRootKey` blobs.

## Invariants

- **Strategy selection is always explicit.** The source states it:
  *"There is no implicit preference-order default."* Do not add one. A silent
  downgrade is the failure mode this rule exists to prevent.
- **Autodetection is a caller's request, not a default.** `ProbeStrategies` and
  `BuildBestStrategy` are called deliberately.
- **Barrier initialization is compare-and-swap.** `barrier_putifabsent.go`
  ensures two concurrent inits cannot produce two root keys.
- **Sealed blobs are versioned.** `sealedRootKeyVersion` governs the format;
  changing the layout without bumping it makes old blobs unreadable with no
  diagnosis.
- **Unseal fails closed.** Absent hardware, an unreachable provider, a wrong
  passphrase, or PCRs that no longer match all leave the barrier sealed. Nothing
  falls back to a weaker strategy.
- **`AutodetectResult.Close()` releases probe handles.** Probing a TPM or token
  opens sessions.
- **Tenant barriers are independent.** A tenant barrier's state does not affect
  the platform barrier.
- **Concurrency.** Strategies are safe for concurrent seal/unseal; device access
  serialises where the device requires it.

## Error semantics

`pkg/seal/errors.go`, plus the qrdb barrier vocabulary. The distinctions that
matter to a caller:

| Condition | Meaning |
|---|---|
| barrier sealed | not an error state — the normal state before unseal |
| strategy unavailable | the configured hardware/provider cannot be reached |
| credentials rejected | wrong passphrase, wrong PIN, insufficient shares |
| PCR mismatch (tpm2) | the machine's measured state changed since sealing |
| blob version unknown | a `SealedRootKey` written by a newer format |

**Fail-closed paths:** every unseal failure. There is no partial unseal, and no
degraded mode in which the barrier is "mostly" open.

## Configuration

Strategy is chosen at initialization and recorded with the sealed root key. The
CLI's `--barrier-strategy` defaults to `passphrase`
(`cmd/xkmsctl/barrier.go:1236`) — note that this is the *CLI's* default for an
interactive init, not an implicit library preference order.

Per-strategy credentials:

| Strategy | Credential |
|---|---|
| `tpm2` | platform/TPM authorization, plus PCR policy where configured |
| `pkcs11` | SO PIN and/or user PIN |
| `awskms` / `gcpkms` / `azurekv` / `vault` | the provider's own ambient credential chain by default, from the **process's** environment — `xkmsd`'s or `xkey`'s, whichever builds the strategy (go-xkms#757); an explicit credential is a `*types.SecretValue` config reference, never a literal |
| `passphrase` | a passphrase |
| `shamir` | M-of-N shares |
| `none` | none — encryption disabled |

Seal policy (PCR selection, rebinding rules) is `pkg/seal/policy`.

**TPM2 key directory.** Both the general TPM2 backend
(`pkg/server/backend_tpm2.go`) and the node-barrier flip's `tpm2` strategy
(`pkg/server/node_seal.go`'s `resolveNodeSeal`) persist sealed key blobs under
`<Storage.Path>/tpm2-keys`, resolved once by the shared
`Server.resolveTPM2KeyDir` helper. That directory is never resolved relative
to the process's working directory: a caller that constructs `*config.Config`
programmatically — an embedded/library use of `pkg/server` that never runs
`config.Config.Validate` — gets a typed `*ErrConfigRequired{Field:
"storage.path", Backend: "tpm2"}` (wrapped in `*NodeSealError` from
`resolveNodeSeal`, in `*ErrBackendCreate` from `initTPM2Backend`) instead of a
cwd-relative `tpm2-keys` directory (go-xkms#609).

## Persistence

The `SealedRootKey` blob is persisted by **go-qrdb**; go-xkms produces and
consumes it. `pkg/sealblobstore` holds sealed blobs for the secret-sealing
paths, and `pkg/seal/platform_store.go` holds platform secrets.

The seal store is **fully implemented** across all transports:
- **Embedded** (`BarrierService`, `SealService` in `pkg/seal`)
- **REST** (`/api/v1/barrier/*`, `/api/v1/seal`) with RBAC on every route
  (permissions: `seal:bootstrap`, `seal:unseal`, `seal:seal`, `seal:status`,
  `seal:initialize-shamir`, `barrier:unseal-share`, `seal:rekey`,
  `seal:generate-recovery`, `seal:recover-with-keys`, `seal:rotate-root-key`,
  `seal:enable-encryption`, `keys:encrypt`, `keys:decrypt`, `keys:get`)
- **gRPC / Unix** (`xkmsv1.KeystoreService.Barrier*` and `Seal*` methods)
- **QUIC** (same routes as REST)
- **MCP** (`barrier.initialize`, `barrier.unseal`, `barrier.seal`,
  `barrier.status`, `barrier.initializeShamir`, `barrier.unsealShare`,
  `barrier.unsealShares`, `barrier.rekey`, `barrier.generateRecoveryKeys`,
  `barrier.recoverWithKeys`, `barrier.deleteRecoveryKeys`,
  `barrier.hasRecoveryKeys`, `barrier.generateRootToken`,
  `barrier.enableEncryption`, `xkms.seal`, `xkms.unseal`, `xkms.canSeal`)
- **USB** — documented structural exception; not a native transport.

RBAC is applied on every route: barrier operations require `seal:*` and
`barrier:*` permissions; data sealing requires `keys:encrypt`/`keys:decrypt`.

Migration: bump `sealedRootKeyVersion` for any format change and handle the old
version on read. A root key that cannot be unsealed is unrecoverable data loss,
so this is the one compatibility rule in the repo with no workaround.

## Test strategy

- **Unit** — one suite per strategy (`strategy_tpm2_test.go`,
  `strategy_pkcs11_test.go`, `strategy_cloud_test.go`,
  `strategy_software_test.go`), plus `autodetect_test.go`,
  `barrier_adapter_test.go`, `platform_sealer_test.go`,
  `platform_store_test.go`, `platform_store_tenant_test.go`,
  `secret_sealer_test.go`, `hardware_encryptor_test.go`, `audit_test.go`.
- **Cloud KMS composition** — `cloud_provision_test.go` (no build tag: all
  four strategy IDs against a generic mock `types.KeyProvider` — key-exists,
  first-init create, idempotent-generate, login/metadata-seed branches,
  provider-not-sealer/not-symmetric errors); `cloud_provision_awskms_test.go`
  (`awskms` tag: the same composition against the real `*awskms.Backend` and
  its own `MockKMSClient`, an init→seal→unseal round trip, and a
  missing-credentials failure).
- **Composition** — `hardware_compose_test.go` covers registration into qrdb's
  registry.
- **Concurrency** — `mock_putifabsent_test.go` covers the CAS init path.
- **Tenant isolation** — `tenant_volume_isolation_test.go`,
  `tenant_metadata_store_test.go`.
- **Transport** — `pkg/api/rest/handlers_barrier_shamir.go` and
  `handlers_seal_test.go`; `pkg/api/grpc/service_barrier_shamir.go`.
- **Integration** — `test/integration/tpm2`, `awskms`, `gcpkms`, `azurekv`,
  `vault`, `pkcs11`, `storage`.

## Observability

`pkg/seal/audit.go` records seal and unseal events — the ones that matter most
in an incident. The chosen strategy should be visible at startup; a deployment
that believes it is on `tpm2` and is actually on `passphrase` has a materially
different security posture, and the audit trail is where that becomes visible.
