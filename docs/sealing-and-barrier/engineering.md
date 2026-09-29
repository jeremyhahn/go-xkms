# Sealing and Barrier — Engineering Contract

> **Status: NORMATIVE** · Feature: `sealing-and-barrier` · Repo: `go-xkms` · Last verified: 2026-09-28

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
type SealOperatorKeyProvider interface{ OperatorSealKeyID() string }
type ErrSealBackendUnavailable struct{ Strategy, Purpose string }
type ErrNotCloudSealStrategy struct{ Strategy string }
type ErrOperatorSealKeyNotFound struct{ Strategy, KeyID string; Err error }
```

`BuildCloudKMSStrategy` accepts only `StrategyAWSKMS`/`StrategyGCPKMS`/
`StrategyAzureKV`/`StrategyVault` (`ErrNotCloudSealStrategy` otherwise); it
provisions (creates on first use, reuses thereafter, via `EnsureSealKey`)
the symmetric wrapping key identified by `SealKeyAttributes(store)` — the
fixed `SealKeyCN` identifies the key's *purpose* (`"xkms-barrier-seal"`) to
every backend, but is never itself passed to a cloud KMS as a key ID — and
wraps the provider's `types.Sealer` in a `CloudKMSStrategy`. `pkg/server`'s
own `buildHardwareSealStrategy` calls this for its four cloud IDs and
continues to wrap TPM2/PKCS11 (not shared with xkey) inline; see
`xkey/docs/seal/architecture.md` for xkey's side of the composition
(per-provider backend construction gated by that provider's build tag, then
this same call).

**AWS KMS key lifecycle (go-xkms#839).** GCP KMS, Azure Key Vault and
HashiCorp Vault all let the caller choose the key's own name, so
`SealKeyCN` doubles as that name and `GetSymmetricKey` addresses the
provider directly by it. AWS KMS does not: `CreateKey` always returns a
provider-assigned key ID, so `pkg/backend/awskms.Backend` needs a durable
CN -> AWS-key-ID mapping. That mapping is persisted through
`Config.KeyStorage` (`storage.SaveKey`/`storage.GetKey`/`storage.KeyExists`/
`storage.DeleteKey`/`storage.ListKeys`, the same helpers `pkg/backend/vault`
uses) for every key the backend handles — symmetric and asymmetric alike —
never cached in an in-process map. A second `*Backend` built over the same
`Config.KeyStorage` (a process restart, or a second node sharing the same
metadata store) sees exactly what the first one persisted; `Backend.Close`
releases only the AWS client handle and never touches `Config.KeyStorage`,
whose lifecycle belongs to the caller that constructed it. `EnsureSealKey`'s
AWS branch resolves the CN -> key-ID mapping before the shared
check-and-skip runs:

- If the backend implements `SealOperatorKeyProvider` and
  `OperatorSealKeyID()` returns a non-empty key ID, ARN, or alias — for
  `*awskms.Backend`, `Config.KeyID` (go-xkms#842; format checked by
  `Config.Validate` against AWS's own key-ID/ARN/alias/alias-ARN shapes,
  returning `ErrInvalidKeyID` for anything else) — that real identifier
  seeds the persisted metadata via `SealMetadataSaver.Save`, and
  `GetSymmetricKey`'s `DescribeKey` call confirms it still exists before
  reuse. `CreateKey` is never called for an operator-configured key: if
  `DescribeKey` reports the key does not exist, `EnsureSealKey` fails closed
  with `ErrOperatorSealKeyNotFound` instead of falling through to
  `GenerateSymmetricKey` and silently provisioning a different, unrequested
  CMK in its place.
- Otherwise nothing is seeded. `GetSymmetricKey` reads `Config.KeyStorage`
  directly: on a truly fresh key it misses and `GenerateSymmetricKey` calls
  AWS KMS's `CreateKey`, persisting the AWS-assigned key ID it returns —
  never `SealKeyCN` itself. On a restart it hits the record the prior
  process (or Backend instance) persisted and resolves the same AWS key, so
  `CreateKey` runs exactly once for the seal key's whole lifetime, not once
  per process boot.

Before this fix (go-xkms#839, landed in two parts), `EnsureSealKey`
unconditionally seeded an in-process `Backend.metadata` map with
`{"key_id": SealKeyCN}`, which made `GenerateSymmetricKey`'s own "already
exists" guard succeed on the very first call — `CreateKey` never ran, and
every later `Encrypt`/`Decrypt` addressed AWS KMS with the literal string
`"xkms-barrier-seal"` as the key ID, which is not a valid key identifier on
a real AWS account; the `awskms` barrier strategy could not work outside a
mock. Fixing only that (part 1) without also persisting
`GenerateSymmetricKey`'s metadata (part 2) would have traded a barrier that
fails at init for one that fails later and loses data: with no
operator-configured key, every process restart would have seen an empty
in-process cache, called `CreateKey` again, and orphaned the CMK data was
already sealed under. See `cloud_provision_awskms_test.go`'s
`newAWSKMSMockBackend` doc comment and
`TestBuildCloudKMSStrategy_AWSKMSBackend_RestartReusesPersistedKey`.

**`getKeyID` error semantics.** The ten other `*awskms.Backend` methods that
resolve a key by CN outside the seal-key path (`Get`, `Delete`, `Sign`,
`Verify`, `Signer`, `Decrypter`, `RotateKey`, `GetImportParameters`,
`ImportKey`, and `SymmetricEncrypter`) all go through the private
`getKeyID(ctx, cn) (string, error)` helper, which returns exactly one
silent answer and errors on everything else:

- `storage.ErrNotFound` (no metadata record was ever written for `cn`)
  resolves to the `"alias/{cn}"` alias. This is safe specifically because
  both `CreateKey` (asymmetric) and `GenerateSymmetricKey` attempt to
  create that exact alias alongside every key they provision — best-effort
  in AWS terms (a failed `CreateAlias` only logs a warning and does not
  fail key creation), but always attempted. A CN that was never used to
  create a key has no alias either, so AWS KMS itself reports "alias not
  found" on the caller's next API call: an honest failure, not a masked
  one.
- Any other `Config.KeyStorage` error, a metadata record that fails to
  parse as JSON, or a record missing `key_id` all return `ErrMetadataStorage`
  (wrapped with `errs.Joined`/`errs.Detail` for context, reachable through
  `errors.Is`). None of these fall back to the alias: now that
  `Config.KeyStorage` is the sole source of truth for which AWS key a CN
  maps to, silently guessing on a transient storage failure would risk a
  caller addressing a different KMS key than the one actually recorded,
  with nothing surfaced to say so.

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
- **The system barrier and the PCR policies are platform-scoped** (go-xkms#1227).
  Every system-barrier method of `XKMSService` refuses a tenant-scoped caller
  with `*xkms.TenantBindingError` before the barrier is touched
  (`pkg/xkms/servicer_barrier.go:89,117,128,139,170,205,236,253,278,300,314,325,342`),
  and so does every `Policy*` method (`pkg/xkms/servicer_policy.go:42,66,84,106,120,138,160`).
  No transport holds the barrier or the policy manager: REST, gRPC/Unix and
  MCP call the service. REST's barrier initialize and unseal keep the secret in
  protected memory end to end through `BarrierInitializeWithCredentials` /
  `BarrierUnsealWithCredentials` (`pkg/xkms/servicer_barrier.go:88,116`), which
  take a `seal.Credentials` the caller owns. `BarrierEnableEncryption` binds
  its target instead (`pkg/xkms/servicer_barrier.go:384`).
- **A Shamir initialize request that states no shape uses the configured
  one.** `BarrierInitializeShamir` applies the request's threshold/total only
  when either is non-zero (`pkg/xkms/servicer_barrier.go:179`); the REST,
  gRPC and MCP wire forms carry only the secret, and routing them through the
  service must not overwrite the barrier's configured shape with zeros.
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

**Running the `tpm2` barrier strategy and `backends.tpm2.enabled: true`
together.** When both are configured, `resolveNodeSeal` opens the TPM exactly
once (via `pkg/seal.BuildBestStrategy`) and `initTPM2Backend` builds the
general-purpose TPM2 backend over that SAME open —
`tpm2backend.NewBackendWithTPM`, keyed off `Server.nodeSealTPM` — rather than
opening the device a second time; a swtpm-backed simulator hangs on a second
open within one process. Sharing the connection means the general backend also
reuses the node-seal backend's `store.KeyBackend` (`shared.KeyBackend()`)
instead of constructing a second file store over the identical
`<Storage.Path>/tpm2-keys` directory, so both the barrier and every key the
general backend creates read and write through the one on-disk key store and
are parented to the one Platform SRK the shared TPM connection resolved
(`resolveSRKAttributes`, whose authorization comes only from
`Backends.TPM2`/`KeyConfig`, never hardcoded; the TCG Shared SRK is never
used). Before go-xkms#795,
`ExternalTPMConfig.KeyBackend` was left unset on this path, so
`NewBackendWithTPM` failed closed with a typed `*ErrInvalidConfig` ("KeyBackend
is nil") wrapped in `*ErrBackendCreate`, and a deployment enabling both
settings could never start; that error is now reachable only from a genuinely
missing or invalid key-storage configuration (e.g. `storage.path` unset),
checked by `resolveTPM2KeyDir` before either code path touches the shared
backend.

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
  first-init create, idempotent-generate, login branches,
  provider-not-sealer/not-symmetric errors, and the AWS
  operator-key-configured/no-operator-key metadata-seed branches);
  `cloud_provision_awskms_test.go` (`awskms` tag: the same composition
  against the real `*awskms.Backend` and its own `MockKMSClient` — first
  provisioning calls `CreateKey` exactly once and every Encrypt/Decrypt
  addresses the AWS-assigned ID, a second provisioning in the same process
  reuses it without a second `CreateKey`, **a second `*awskms.Backend` built
  over the same `storage.Backend` — a simulated restart —
  (`TestBuildCloudKMSStrategy_AWSKMSBackend_RestartReusesPersistedKey`)
  resolves the persisted key and unseals data sealed before the restart,
  without calling `CreateKey` again**, an operator-configured `Config.KeyID`
  is resolved and reused without ever calling `CreateKey`, an init→seal→unseal
  round trip, a missing-credentials failure surfacing from
  `BuildCloudKMSStrategy` itself, and
  (`TestBuildCloudKMSStrategy_AWSKMSBackend_OperatorConfiguredKeyNotFound`,
  go-xkms#842) an operator-configured `Config.KeyID` that `DescribeKey`
  reports as not found fails closed with `ErrOperatorSealKeyNotFound`
  without ever calling `CreateKey`; `cloud_provision_test.go`'s generic mock
  carries the equivalent no-build-tag case
  (`TestEnsureSealKey_AWSKMSOperatorKeyNotFoundFailsClosed`)). `Config`'s own
  `TestIsValidKeyID`/`TestConfigValidate` (`config_test.go`, `awskms` tag)
  cover every AWS key-ID/ARN/alias/alias-ARN shape `Config.KeyID` accepts,
  plus the multi-Region (`mrk-`) and GovCloud/China-partition ARN forms, and
  the malformed-value `ErrInvalidKeyID` case.
- **AWS KMS metadata persistence** — `pkg/backend/awskms/persistence_test.go`
  (`awskms` tag): a `failingStorage` wrapper injects a `Config.KeyStorage`
  failure into one call at a time, proving `GenerateSymmetricKey`,
  `SymmetricEncrypter`, `CreateKey` (asymmetric), `GetKey`, `Save`,
  `Delete`, `ListKeys`, and `Get` all propagate a storage failure as an
  error instead of silently treating it as "not found" or panicking; the
  updated `TestClose` in `awskms_test.go` proves `Close` leaves persisted
  metadata intact.
- **`getKeyID` error semantics** — `TestGetKeyID` (`awskms_test.go`) covers
  the one silent fallback (no metadata record → the `alias/{cn}` alias);
  `persistence_test.go`'s
  `TestGetKeyID_StorageErrorPropagatesThroughSign` and
  `..._StorageErrorPropagatesThroughDecrypter` prove a `Config.KeyStorage`
  failure surfaces as `ErrMetadataStorage` through two representative
  callers without ever reaching AWS KMS with a guessed key ID;
  `TestGetKeyID_CorruptMetadataRecord` and `..._MissingKeyIDField` cover a
  record that fails to parse and one that parses but lacks `key_id`.
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
