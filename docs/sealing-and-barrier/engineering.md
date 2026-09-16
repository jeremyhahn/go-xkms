# Sealing and Barrier — Engineering Contract

> **Status: NORMATIVE** · Feature: `sealing-and-barrier` · Repo: `go-xkms` · Last verified: 2026-08-19

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
| `awskms` / `gcpkms` / `azurekv` / `vault` | the provider's credentials, from the **server's** environment |
| `passphrase` | a passphrase |
| `shamir` | M-of-N shares |
| `none` | none — encryption disabled |

Seal policy (PCR selection, rebinding rules) is `pkg/seal/policy`.

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
