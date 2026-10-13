# Sealing and Barrier — Engineering Contract

> **Status: NORMATIVE** · Feature: `sealing-and-barrier` · Repo: `go-xkms` · Last verified: 2026-10-13

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

The ONE function `xkmsd` (`pkg/embeddednode/node_seal_cloud.go`, for the
node seal) and `xkey` (`go-xkms/xkey`, which has no backend/provider
registry of its own) both call to turn an already-constructed cloud KMS
backend into a `CloudKMSStrategy`:

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
wraps the provider's `types.Sealer` in a `CloudKMSStrategy`.
`pkg/embeddednode` calls this for its four cloud node seals; see
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

### Barrier and registry (`barrier_adapter.go`)

The barrier and its registry are go-qrdb's types, aliased; go-xkms adds no
wrapper:

```go
type Barrier         = qrdbsdk.StorageBarrier
type TenantBarrier   = qrdbsdk.TenantBarrier
type BarrierRegistry = qrdbsdk.BarrierRegistry

func NewBarrier(logger *slog.Logger, base storage.Backend, config BarrierConfig, strategies ...SealingStrategy) (*Barrier, error)
func NewTenantBarrier(tenantID string, logger *slog.Logger, base storage.Backend, config BarrierConfig, strategies ...SealingStrategy) (*TenantBarrier, error)
func NewBarrierRegistry(system *Barrier, opts ...BarrierRegistryOption) (*BarrierRegistry, error)
func NewHardwareStrategyRegistry(strategies ...SealingStrategy) (StrategyRegistry, error)
func NewHardwareTenantService(store qrdbsdk.StorageBackend, registry *BarrierRegistry, logger *slog.Logger, strategies []SealingStrategy, opts ...TenantServiceOption) (TenantService, error)
```

`NewBarrier` and `NewTenantBarrier` accept an xkms `storage.Backend` and
guard it for go-qrdb's `StorageBackend` contract (the optional
compare-and-delete, compare-and-swap and fenced-create capabilities, and the
not-found sentinel); a nil base stays nil, so go-qrdb's own nil checks still
fire. `NewBarrierRegistry` refuses a nil system barrier with
`ErrNilSystemBarrier`. A running xkmsd builds none of these: it adopts the
node's `BarrierRegistry()`. They serve xkey and tests.

`BarrierConfig` (`pkg/seal/config.go:20`) carries four fields:

- `PreferenceOrder` is required. An empty list is `ErrNoStrategySpecified`.
- `RootKeyPath` is the storage key of the sealed root-key blob. It must be
  non-empty (`:28`).
- `AuditLogger`: a nil logger disables audit (`:32`).
- `Shamir` enables `InitializeShamir` and `UnsealWithShare`/`UnsealWithShares`
  (`:37`).

The passphrase and Shamir strategies are go-qrdb's, reached through two
re-exports. `NewSoftwareStrategy` is go-qrdb's *deferred* constructor
(`pkg/seal/strategy_software.go:46`): it reads the passphrase from
`Credentials.Secret` at each seal and unseal. The bound constructor is not
re-exported, because it ignores the credentials it is handed (go-qrdb#157).
`NewShamirStrategy(threshold, total)` delegates to go-qrdb
(`pkg/seal/barrier_adapter.go:250`).

A hardware or cloud strategy whose backend refuses to unseal the root key
returns `*RootKeyUnsealError{Strategy, Err}`. It unwraps to go-qrdb's
`ErrInvalidCredentials` and to the backend's own error, so a wrong TPM,
token or KMS key surfaces through `node.Unseal`, `UnsealTenant` and a
tenant barrier's `Unseal` as go-qrdb's typed credential error.

### Node seal wiring (`pkg/embeddednode`)

```go
type ResolvedNodeSeal struct {
	Enabled  bool
	Strategy seal.SealingStrategy
	TPM      types.Sealer
	Close    func() error
}

func ResolveNodeSeal(cfg *config.Config, logger *slog.Logger) (ResolvedNodeSeal, error)
func NodeSealOptions(res ResolvedNodeSeal) ([]qrdbnode.NodeOption, []qrdbsdk.ServerOption, error)
const CloudNodeSealSubdir = "node-seal"
```

`ResolveNodeSeal` returns `Enabled` only for a standalone datastore with
`barrier.enabled`. It builds the configured strategy: `tpm2` from the
platform TPM, `pkcs11` with the PIN released from the pre-barrier store,
the cloud strategies from their backend over
`<datastore.path>/node-seal/<strategy>`, and `vault` with its token released
from the pre-barrier store. `none`, `passphrase` and `shamir` leave
`Strategy` nil; go-qrdb builds those itself. A cloud strategy not compiled
into the binary (its build tag is absent) is a `*NodeSealError`.

`NodeSealOptions` is the only place a strategy reaches the node. For an
enabled seal it returns `node.WithTenantIsolation`,
`node.WithDefaultTenantEntitlements` (every isolation mode, dedicated Raft,
volume storage, dedicated WAL and system-managed auto-unseal) and, with a
strategy, `node.WithSealStrategy` plus the server option
`sdk.WithStrategyRegistry` holding the same strategy, so a per-tenant
barrier can be sealed by it. A registry failure is a `*NodeSealError`;
nothing is logged and skipped. `OpenEmbeddedNode` and `pkg/server` both
call it.

### `PlatformSealer`

`PlatformSealer` routes arbitrary data, not the barrier root key, across
xkms's sealers. The platform sealed-secret store is built on it
([`../platform-secrets/engineering.md`](../platform-secrets/engineering.md)).

- `NewPlatformSealer(logger, SealerConfig, map[StrategyID]types.Sealer)`
  returns `ErrNoAvailableStrategy` for an empty map
  (`pkg/seal/platform_sealer.go:43`). `SealWith` and `Unseal` name their
  strategy explicitly and need no preference order.
- `Seal` auto-selects through `BestStrategy`. That is the first strategy in
  `SealerConfig.PreferenceOrder` (`pkg/seal/config.go:42`) whose `CanSeal()`
  is true. It returns `ErrNoStrategySpecified` for an empty order and
  `ErrNoAvailableStrategy` when no listed strategy can seal
  (`platform_sealer.go:158`).
- `SealWith` returns `ErrStrategyNotFound` for a strategy that is not
  registered (`platform_sealer.go:143`).
- A successful seal tags `SealedData.Metadata["seal:strategy"]` with the
  strategy ID (`platform_sealer.go:26`, `:182`). `Unseal` routes on that tag
  (`platform_sealer.go:86`):
  - a missing tag gives a `SealedDataAuthenticationError` wrapping
    `ErrStrategyMismatch`;
  - an unregistered strategy gives one wrapping `ErrStrategyNotFound`.
- Every seal and unseal emits an audit event with subject `seal`, action
  `seal` or `unseal`, resource `platform_sealer`, the strategy ID as the
  resource ID, and outcome `allow` or `deny` (a denial carries an `error`
  detail) (`pkg/seal/audit.go:63`). **A failed audit write fails the
  operation:** its error is returned in place of the result.

### Sealed value decorator — `pkg/storage/sealed`

`sealed.Backend` wraps any `storage.Backend` and seals each value with a
`types.Sealer`; keys stay in the clear so `List` and `Exists` need no unseal.
It encrypts values, not a volume — for the volume see [`../luks/`](../luks/).
Production callers: the platform store over a `PlatformSealer`
(`pkg/compose/builders.go:144`) and the pre-barrier store over the PCR-policy
TPM sealer (`pkg/preseal/store.go:97`).

- `New(inner, sealer, sealOpts)` wraps `ErrSealerNotAvailable` when `inner`
  or `sealer` is nil, and returns it when `sealer.CanSeal()` is false, so a
  misconfigured sealer fails at construction rather than storing plaintext
  (`pkg/storage/sealed/backend.go:42`).
- `Put` seals with the constructor's `sealOpts`, JSON-marshals the
  `types.SealedData` envelope, and stores it under the caller's key
  (`backend.go:82`). `PutIfAbsent` and `PutIfAllAbsent` seal the same way
  before delegating (`backend_putifabsent.go:27`,
  `backend_fencedcreate.go:31`); the latter returns
  `storage.ErrFencedCreateUnsupported` when the inner backend is not a
  `storage.FencedCreator`.
- `Get` and `Scan` unmarshal and unseal every value before returning it
  (`backend.go:61`, `:109`). Inner-backend errors such as
  `storage.ErrNotFound` from `Get` pass through unchanged.
- `Delete`, `List`, `Exists` and `Close` delegate to the inner backend
  (`backend.go:97`–`131`).
- `CompareAndDelete` compares against the **stored** envelope, decrypted
  straight into locked go-enclave pages and compared in constant time; it
  needs a sealer implementing `types.UnsealerInto` and returns
  `ErrUnsealIntoUnsupported` otherwise, with no heap fallback
  (`backend_compareanddelete.go:237`).
- Sentinels (`pkg/storage/sealed/errors.go:20`–`53`): `ErrSealFailed`,
  `ErrUnsealFailed`, `ErrSealerNotAvailable`, `ErrMarshalFailed`,
  `ErrUnmarshalFailed`, `ErrGuardEnclaveFailed`, `ErrUnsealIntoUnsupported`,
  `ErrGuardEscapedEnclave`.

### go-enclave provider bridge — `pkg/enclaveprovider` (go-xkms#1415)

go-enclave (v0.8) defines the provider seam its `Sealer` keys sit behind and
ships only a software provider. This package is the hardware side of that
seam, over any `types.Sealer` — TPM 2.0, PKCS#11, AWS KMS, GCP Cloud KMS,
Azure Key Vault, Vault Transit or the software backend:

```go
func NewKeyProtector(sealer types.Sealer, attrs *types.KeyAttributes) (*KeyProtector, error)
func (*KeyProtector) Protect(ctx, key []byte) (blob []byte, err error)
func (*KeyProtector) Unprotect(ctx, blob, key []byte) error
func (*KeyProtector) Health() error // always nil: the key lives in the backend

func ProvisionRoot(ctx, sealer types.Sealer, attrs *types.KeyAttributes) (sealedRoot []byte, err error)
func NewRootUnsealer(sealer types.Sealer, attrs *types.KeyAttributes, sealedRoot []byte) (*RootUnsealer, error)
func (*RootUnsealer) UnsealRoot(ctx, dst []byte) error
```

`KeyProtector` is `enclave.KeyProtector` and `enclave.HealthReporter`
(`ModePerOperation`); `RootUnsealer` is `enclave.RootUnsealer`
(`ModeRootKey`). Neither implements the other's interface, so
`enclave.NewSealer` accepts each only for the mode it serves.
`ProvisionRoot` draws a 32-byte root into locked pages from
`enclave.ProcessAllocator()`, seals it from there and destroys the pages; the
caller persists the returned blob and builds a `RootUnsealer` from it at every
start.

**Envelope** (`pkg/enclaveprovider/envelope.go`). Every blob is
`"XKEP" ‖ version 1 ‖ purpose ‖ SealedData fields ‖ HMAC-SHA256 tag`, the
fields length-prefixed and the metadata names strictly ascending, parsed
strictly (no trailing bytes, nothing over 64 KiB). The purpose (protected key
or sealed root) is in the envelope and selects the AAD the sealer binds
(`go-xkms/enclaveprovider/v1/protected-key` or `.../sealed-root`), so neither
seam opens the other's blob. The tag is keyed by HKDF-SHA256-Expand from the
protected key itself and covers every envelope byte, so a field the backend
does not authenticate on unseal (a TPM handle in the metadata, a key version)
cannot be altered either. Expand, not Extract: Extract would hash the key as a
message and leave it in a SHA-256 block buffer on the heap.

Invariants:

- **Exactly the seam's contract.** An ended context is refused before the
  backend with an error matching `ctx.Err()`. `Unprotect` and `UnsealRoot`
  require a 32-byte destination and a 32-byte sealed key; either length
  mismatch is an authentication failure. On every failure the destination is
  untouched.
- **The backend's plaintext is wiped on every path** (`enclave.Wipe`), and
  `blob` is copied, never retained or modified.
- **Each call gets its own copy of the sealing key's attributes**, and of their
  `TPMAttributes`: the TPM 2.0 sealer stages the secret in the attributes it is
  handed, and go-enclave calls a provider concurrently.
- **`NewKeyProtector` and `ProvisionRoot` refuse a sealer whose `CanSeal` is
  false**; `NewRootUnsealer` refuses a blob that is not a sealed root before
  any backend call.

Errors (`pkg/enclaveprovider/errors.go`):

| Error | When |
|---|---|
| `ErrNilSealer`, `ErrNilKeyAttributes`, `ErrSealerUnavailable` | construction |
| `ErrInvalidKeyLength` | `Protect` given a key that is not 32 bytes |
| `ErrProtectFailed`, `ErrUnprotectFailed`, `ErrUnsealRootFailed`, `ErrProvisionRootFailed` | the backend or the context failed; the cause stays reachable |
| `ErrEnvelopeTooLarge` | the backend's sealed data does not fit the envelope |
| `enclave.ErrSealedAuthentication` with `ErrMalformedEnvelope`, `ErrWrongPurpose`, `ErrKeyLengthMismatch` or `ErrEnvelopeTag` | the blob is not one this provider wrote for this seam |
| `enclave.ErrSealedAuthentication` with `types.ErrSealedDataAuthentication` | the backend's own verdict (see the table below); the native cause stays reachable |

A backend failure that is not `types.ErrSealedDataAuthentication` is never
reported as `enclave.ErrSealedAuthentication`, so the PKCS#11 ambiguity below
(SoftHSM before 2.7.0) carries through unchanged.

### Process hardening — `sdk/go/secure.HardenProcess`

Locked, guard-paged memory does not stop a debugger or another process
running as the same user from reading it through `ptrace` or
`/proc/<pid>/mem`. `HardenProcess` (`sdk/go/secure/secure.go:128`, a
re-export of go-qrdb's) closes that gap. On Linux it sets
`prctl(PR_SET_DUMPABLE, 0)`: no ptrace attach or `/proc/<pid>/mem` read
without `CAP_SYS_PTRACE`, and no core file. On macOS it uses
`ptrace(PT_DENY_ATTACH)`; elsewhere it logs that no mechanism exists. It
then refuses to continue if a tracer is already attached.

Every binary calls it first thing in `main`, before any protected memory
exists, and treats any error as fatal (print, exit 1): `xkmsd`
(`cmd/xkmsd/main.go:56`), `xkmsctl` (`cmd/xkmsctl/main.go:26`),
`trusted-acme-client` (`cmd/acme-client/main.go:137`), `xkey`
(`xkey/cmd/xkey/main.go:42`) and `e2eprobe` (`xkey/cmd/e2eprobe/main.go:93`).

The PKCS#11 module has no `main`. It hardens the host application once, on
its first `C_Initialize` (`cmd/pkcs11-module/exports.go:216`,
`cmd/pkcs11-module/harden.go:38`), which returns `CKR_GENERAL_ERROR` on
failure (`harden.go:41`). `C_Initialize` is the call the standard requires
before any PIN or key reaches the module; a library constructor would run
in every process that merely loads it.

To attach a debugger, set `QRDB_SECURE_ALLOW_PROCESS_INSPECTION=true`
(`secure.AllowProcessInspectionEnv`, `secure.go:119`). The process stays
inspectable and logs a warning. In FIPS 140-3 mode the opt-out is refused
(`ProcessInspectionOptOutRefusedError`), and a value `strconv.ParseBool`
rejects is a `ProcessInspectionOptOutError` rather than either answer
(`secure.go:90`–`102`).

### Other components

`barrier_putifabsent.go` (CAS init),
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
- **Data-level sealing stays inside the caller's tenant** (go-xkms#1228).
  `XKMSService.Seal` / `Unseal` resolve the backend with
  `resolveTenantBackend` (`pkg/xkms/servicer_seal.go:157`, `:237`) and find
  a named key among that tenant's keys (`sealingKey`, `:131`). The tenant
  view stamps its tenant on the sealing key's attributes
  (`pkg/xkms/backend_tenant.go:243`, `:258`), so the default sealing key is
  per tenant with no configuration, storage or migration of its own, and
  refuses TPM 2.0, whose blobs are not bound to any key (`sealBound`,
  `pkg/xkms/backend_tenant.go:227`). REST, gRPC and MCP call the service and
  never a backend's `Seal` directly; the per-instance `SealWithBackend` /
  `UnsealWithBackend` pass-throughs they used are deleted.
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

### Sealed-data authentication — `types.ErrSealedDataAuthentication`

Every `types.Sealer` answers one question the same way: *was the sealed data
itself at fault?* `Unseal` (and `UnsealerInto.UnsealInto` /
`PlaintextLen`) returns an error matching
`types.ErrSealedDataAuthentication` exactly when the `SealedData` was forged,
tampered with, truncated or extended, produced under a different key or by a
different backend, is malformed (wrong backend type, a missing field, a
wrong-length nonce or tag), or was sealed under different AAD. It never
matches for the environment: an unreachable device or KMS, throttling, a
permission or credential failure, a missing key, a cancelled or expired
context, or a TPM authorization failure (a PCR policy the platform no longer
satisfies, a wrong UserAuth). Retrying an authentication failure is
pointless; an environment failure may succeed on retry.

**Presence is conclusive; absence is not.** A backend matches the sentinel
only when its native signal establishes that the data is at fault. Where the
signal is ambiguous -- a PKCS#11 module that answers both an AES-GCM tag
mismatch and a token fault with `CKR_GENERAL_ERROR`, as SoftHSM before 2.7.0
does (2.7.0 answers `CKR_ENCRYPTED_DATA_INVALID`) -- the failure is reported
with the native error and without the sentinel, because the contract's first
rule is that an outage is never reported as an attack. A caller that sees no
sentinel must not conclude the environment failed; it can conclude only that
the backend could not prove the data bad.

The error is built by `types.SealedDataAuthenticationError(detail, cause)`,
an `errs.Joined` of the sentinel and the backend's own error, so
`errors.Is` / `errors.As` still reach the native cause (an
`InvalidCiphertextException`, a `pkcs11.Error`, a `tpm2.TPMRC`, a
`*vaultapi.ResponseError`). The SDK re-exports the sentinel as
`xkms.ErrSealedDataAuthentication`. A nil `*SealedData` is a caller bug and
keeps each backend's own argument error. Every `Unseal` checks `ctx.Err()`
first, so a cancelled context is reported as itself even for sealed data that
would also fail authentication.

| Backend (file) | Authentication — matches the sentinel | Environment — does not |
|---|---|---|
| AWS KMS (`pkg/backend/awskms/sealer.go`) | backend type or `KeyID` mismatch; empty ciphertext or one over the 6144 bytes `Decrypt` accepts; `Decrypt` → `InvalidCiphertextException` (tamper, truncation, extension, encryption-context/AAD mismatch) or `IncorrectKeyException` (another KMS key) | `NotFound`, `Disabled`, `KMSInvalidState`, `KMSInternal`, `DependencyTimeout`, `LimitExceeded`/throttling, AccessDenied, network, missing key metadata |
| GCP KMS (`pkg/backend/gcpkms/sealer.go`) | backend type or `KeyID` mismatch; empty ciphertext; `Decrypt` → `codes.InvalidArgument` (the key is resolved with `GetCryptoKey` first, so `InvalidArgument` names the ciphertext or AAD) | an `InvalidArgument` reporting a request `crc32c` mismatch (corruption in transit, which Google says to retry); every other status (`Unavailable`, `DeadlineExceeded`, `ResourceExhausted`, `PermissionDenied`, `Unauthenticated`, `FailedPrecondition`, `NotFound`, `Internal`), a response failing its plaintext CRC32C |
| Azure Key Vault (`pkg/backend/azurekv/sealer.go`) | backend type or `KeyID` mismatch; an unknown `azurekv:gcm_nonce_mode`; `azurekv.ErrCiphertextRejected` from the local AES-GCM open (wrong-length tag or nonce, `gcm.Open` failure) | the key secret not retrievable (503, 429, 403, 404, network), key material that is not an AES key, a GCM construction the FIPS mode refuses |
| HashiCorp Vault (`pkg/backend/vault/sealer.go`) | backend type or `KeyID` mismatch; empty ciphertext; Transit `400` whose messages are all `cipher: message authentication failed` or `invalid ciphertext…` | 5xx, 429, 403, `encryption key not found`, `invalid ciphertext: version is too new`, `…disallowed by policy (too old)`, `vault.ErrAssociatedDataIgnored` |
| PKCS#11 (`pkg/backend/pkcs11/sealer.go`) | backend type or `KeyID` mismatch; `ErrInvalidNonceLength` / `ErrInvalidTagLength`; `pkcs11.ErrCiphertextRejected` from `C_Decrypt` answering `CKR_ENCRYPTED_DATA_INVALID`, `CKR_ENCRYPTED_DATA_LEN_RANGE` or `CKR_AEAD_DECRYPT_FAILED` | uninitialized or closed backend, key not on the token, `C_DecryptInit` failures (`pkcs11.ErrDecryptInit`), `CKR_DEVICE_*`, `CKR_SESSION_*`, `CKR_*_MEMORY`, `CKR_USER_NOT_LOGGED_IN`, `CKR_PIN_*`, and `CKR_GENERAL_ERROR` -- the specification's unrecoverable token error. SoftHSM before 2.7.0 also returns `CKR_GENERAL_ERROR` for a GCM tag mismatch, indistinguishably from an OpenSSL engine fault, so on those versions a tampered ciphertext is reported with that native code and without the sentinel (SoftHSM 2.7.0 answers `CKR_ENCRYPTED_DATA_INVALID` and is classified; every image in this repository ships 2.7.0, built by `scripts/build-softhsm.sh` -- see [`../pkcs11-backend/engineering.md`](../pkcs11-backend/engineering.md) §"SoftHSM version") |
| TPM 2.0 (`pkg/tpm2/sealer.go`; `pkg/backend/tpm2/sealer.go` passes it through) | backend type mismatch; only one of `TPMPublic`/`TPMPrivate`; an area over 2048 bytes or the two over 3072, larger than any TPM creates and than one `TPM2_Load` command carries (`tpm2.ErrObjectAreaTooLarge`, checked before the TPM is asked); `TPM2_Load` refusing the object with a parameter-scoped code — `TPM_RC_INTEGRITY` (tampered private area, or one created under another parent or TPM), `TPM_RC_BINDING`, `TPM_RC_SIZE`, `TPM_RC_INSUFFICIENT` — or `TPM_RC_SENSITIVE`, inline or from storage (`tpm2.ErrSealedObjectRejected`); `TPM2_Unseal` refusing a loaded object that is not sealed data (`TPM_RC_TYPE` / `TPM_RC_ATTRIBUTES` on the item handle, e.g. an AES or HMAC key); an AAD binding that does not match | missing Platform SRK or stored object, transport errors, warnings (`TPM_RC_RETRY`, `TPM_RC_OBJECT_MEMORY`, `TPM_RC_LOCKOUT`), handle- and session-scoped codes: `TPM_RC_POLICY_FAIL` / PolicyPCR `TPM_RC_VALUE` (PCRs moved), `TPM_RC_AUTH_FAIL` / `TPM_RC_BAD_AUTH` (wrong UserAuth) |
| Software / PKCS#8 (`pkg/backend/software/software.go`, `pkg/keyprovider/pkcs8/sealer.go`) | backend type or `KeyID` mismatch; nonce not 12 or tag not 16 bytes; `gcm.Open` failure | closed backend, private key not loadable, sealing key not derivable |
| Secret sealer (`pkg/seal/secret_sealer.go`) | backend type not software; nonce not 12 bytes; payload shorter than the AEAD overhead (`PlaintextLen`); `gcm.Open` failure | sealer without a key |
| Platform sealer (`pkg/seal/platform_sealer.go`) | no strategy tag (also `ErrStrategyMismatch`); a strategy it does not hold (also `ErrStrategyNotFound`); the delegate's own classification | the delegate's environment failures |
| Composite key store (`pkg/xkms/composite_seal.go`) | `ErrSealBackendMismatch` (also `ErrBackendMismatch`); the provider's classification through `ErrSealOperation` | a cancelled or expired context (checked before the backend type); the provider's environment failures |
| Platform-store adapters (`pkg/server/platform_store.go`: `platformPolicySealer`, `fixedKeyAttrsSealer`) | the delegate's classification; they replace only the key identity they own and pass the caller's AAD through | the delegate's environment failures |

Two backends needed more than a mapping, because their AAD was not bound:

- **Vault Transit** binds AAD through `associated_data`. The backend sent it
  as `context`, which Transit uses only to derive keys and ignores for the
  non-derived keys this backend creates, so a wrong AAD decrypted. Encrypt and
  decrypt now send `associated_data`, and fail closed with
  `vault.ErrAssociatedDataIgnored` when the server warns it ignored the
  parameter (a Transit engine without AEAD associated data).
- **TPM 2.0** keyed-hash objects have no AAD input, and `Seal` ignored
  `opts.AAD`. The binding now travels inside the integrity-protected sealed
  secret: `magic(16) ‖ SHA-256(AAD) ‖ data`, compared in constant time on
  `Unseal`. A seal without AAD is byte-for-byte what earlier builds wrote; data
  that happens to start with the magic is wrapped, so the forms never collide.
  The binding costs 48 of the object's 128 bytes: at most 80 bytes of data
  seal with AAD (`tpm2.ErrSealAADTooLarge`). A nil-data seal binds the
  `SealData` preset on the key attributes, or with none a fresh 32-byte random
  secret; a preset is wrapped like any other data, so it cannot forge a
  binding.

`SecretSealer.Seal` / `Unseal` / `UnsealInto` now honour `opts.AAD` through the
GCM associated data the same way; a value sealed without AAD still unseals with
nil options.

## Configuration

Strategy is chosen at initialization and recorded with the sealed root key. The
CLI's `--barrier-strategy` defaults to `passphrase`
(`cmd/xkmsctl/barrier.go:1236`) — note that this is the *CLI's* default for an
interactive init, not an implicit library preference order.

Per-strategy credentials:

| Strategy | Credential |
|---|---|
| `tpm2` | platform/TPM authorization, plus PCR policy where configured |
| `pkcs11` | the token user PIN; for the node seal and xkey's barrier, the PIN sealed in the pre-barrier store (see below) |
| `awskms` / `gcpkms` / `azurekv` / `vault` | the provider's own ambient credential chain by default, from the **process's** environment — `xkmsd`'s or `xkey`'s, whichever builds the strategy (go-xkms#757); an explicit credential is a `*types.SecretValue` config reference, never a literal |
| `passphrase` | a passphrase |
| `shamir` | M-of-N shares |
| `none` | none — encryption disabled |

A TPM2 sealed object is bound to a named TPM policy (`pkg/tpm2/policy`, [`../tpm-policies/`](../tpm-policies/)) through `SealRequest.TPMPolicy`; the old PCR-selection seal fields were removed because they bound nothing.

**PKCS#11 node seal and the pre-barrier store (go-xkms#677).** With
`barrier.strategy: pkcs11`, `embeddednode.ResolveNodeSeal`
(`pkg/embeddednode/embedded_node.go`) calls `resolvePKCS11NodeSeal`
(`pkg/embeddednode/node_seal_pkcs11.go`) and returns a PKCS#11 node seal. It
never falls back to the "not yet wired" warning path. The steps are:

1. `embeddednode.OpenPreseal` opens the TPM that `backends.tpm2` configures,
   and the store in `<datastore.path>/preseal` (`PresealSubdir`).
2. `pkcs11strategy.BuildWithSealedPIN` (`pkg/pkcs11strategy/sealed_pin.go`)
   releases `seal.SecretPKCS11PIN` (`platform/pkcs11-pin`), holds it as a
   `types.SecretValue`, wipes the released bytes, and calls
   `pkcs11strategy.Build` against `backends.pkcs11.library`/`token` with the
   key CN `xkms-node-seal-pkcs11`.
3. The store and the TPM are closed. `ResolvedNodeSeal.Close` releases the
   PKCS#11 session.

xkey's barrier takes the same path through
`sdk/go.BuildPKCS11StrategyWithSealedPIN`, with key CN `xkey-barrier-pkcs11`.

`pkg/preseal` surface: `Open(tpm, dir, logger)`, `New(tpm, records, logger)`,
`(*Store).Put/Get/Close`, and `PKCS11PIN`. `TPM` is `types.Sealer` plus
`PlatformSRKAttributes()`. `New` refuses a TPM with no enrolled Platform SRK
(`*PlatformSRKError`), because go-xkms seals under no other parent.

| Error | When |
|---|---|
| `ErrTPMRequired`, `ErrRecordsRequired`, `ErrDirRequired` | a nil TPM, a nil record backend, or an empty directory |
| `*PlatformSRKError` | the Platform SRK is not enrolled |
| `*OpenError` | the record directory or the sealed store cannot be opened |
| `*EmptySecretError` | `Put` with an empty secret |
| `*SealError` | the TPM refuses to seal |
| `*NotFoundError` | `Get` of a name that was never sealed |
| `*RefusedError` | the TPM refuses to release: the platform PCRs, or the TPM, differ from the ones it was sealed under |
| `*UnsealError` | any other unseal failure |
| `pkcs11strategy.ErrPINSourceRequired` | `BuildWithSealedPIN` with a nil store |
| `*pkcs11strategy.BuildError` | the release, or the login with the released PIN, failed; the cause is kept |
| `*embeddednode.NodeSealError` | wraps every node-seal failure, including `backends.pkcs11` not being set |

Tests:
- `pkg/preseal/store_simulator_test.go` covers the round trip and refusal
  after a PCR change, on the simulator.
- `pkg/pkcs11strategy/sealed_pin_test.go` and `builder_softhsm_test.go`
  cover the release, the wipe and a SoftHSM login.
- `pkg/embeddednode/node_seal_pkcs11_*_test.go` covers the node seal.
- `test/integration/pkcs11/barrier/barrier_test.go` is the reboot-equivalent
  end-to-end test, run by `make integration-test-pkcs11-barrier` (part of
  `make integration-test`) in docker compose: a SoftHSM 2.7.0 token and one
  swtpm that outlives every xkmsd process, never the devcontainer's TPM. It
  seals the token PIN with `xkmsd seal-pkcs11-pin`, then starts xkmsd twice
  with `barrier.strategy: pkcs11` and no PIN in the configuration; both starts
  must report the barrier initialized and unsealed with no operator input.
  It then extends the platform PCR on the swtpm. The next start must exit
  non-zero at the node seal, and the same resolution in-process must return
  `*embeddednode.NodeSealError` wrapping `*pkcs11strategy.BuildError` and
  `*preseal.RefusedError` for `platform/pkcs11-pin`. The build tags are
  `integration pkcs11 pkcs11_barrier`.

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
- **gRPC / Unix** (`xkmsv1.KeystoreService.Seal*` methods)
- **QUIC** (same routes as REST)
- **MCP** (`xkms.seal`, `xkms.unseal`, `xkms.canSeal`)
- **USB** — documented structural exception; not a native transport.

RBAC is applied on every route: data sealing requires `keys:encrypt`/`keys:decrypt`.

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
- **M-of-N unseal with hardware-factor holders** —
  `pkg/init/mofn_unseal_hw_factor_test.go` (go-xkms#1355). It sets up a
  2-of-3 Shamir system barrier whose share holders are enrolled through
  go-qrdb's ceremony (`go-qrdb/sdk/go`) against the node's own factor registry
  (`factor.NewNodeRegistry`, `pkg/factor/registry.go:114`, which
  `server.NewNodeFactorRegistry`, `pkg/server/server.go:1778`, returns;
  `newMofnRig`, `pkg/init/mofn_unseal_hw_factor_test.go:84`). The three
  holders authenticate through the xkms PIV factor (software PIV key
  generator), through mTLS, and through the xkms PKCS#11 factor (its own P-256
  token key). Every holder claims its share, bound by
  `qrdbsdk.CertThumbprint`, before the barrier is sealed.
  `TestMofNUnseal_HardwareFactorHolderCompletesQuorum` (`:266`) unseals with
  the PIV and mTLS holders.
  `TestMofNUnseal_InvalidHardwareFactorAssertionIsRefused` (`:285`) shows
  that a PIV assertion signed by a key other than the enrolled one is refused
  and its share is not counted.
  `TestMofNUnseal_MismatchedMTLSCertificateIsRefused` (`:313`) shows the same
  for an mTLS holder that presents a certificate, and signs with a key, other
  than the enrolled one.
- **Node registry and mTLS share holders** — the node registry carries `piv`,
  `pkcs11` and `fido2`, but no `mtls`. The ceremony enrols an mTLS share holder
  by its certificate's public key. The holder answers the quorum challenge
  with `qrdbsdk.SignQuorumChallenge`, and go-qrdb's own `mtls` factor verifies
  that answer whenever the registry does not override it. The xkms `mtls`
  factor enrols a PEM certificate and verifies a signature over the bare
  nonce, so in the node registry it refused every ceremony mTLS holder.
  `factor.NewDefaultRegistry`, which keeps the xkms `mtls` factor, serves only
  administrator enrolment. `TestNewNodeRegistry_LeavesMTLSToQRDB`
  (`pkg/factor/registry_test.go:47`) pins the set.
- **Sealed-data authentication** — one `sealer_authentication_test.go` per
  backend (`pkg/backend/{awskms,gcpkms,azurekv,vault,pkcs11,software}`,
  `pkg/keyprovider/pkcs8`), `pkg/seal/sealed_data_authentication_test.go`,
  and `pkg/tpm2/sealed_data_authentication{,_simulator}_test.go`: bit-flipped,
  truncated, extended, foreign-key, wrong-backend, malformed and
  AAD-mismatched sealed data match the sentinel with the native cause
  reachable; injected KMS/Key Vault/Transit faults, a closed or
  uninitialized backend, a missing key, a cancelled context, and (TPM, on the
  reference simulator) a moved PCR and a wrong UserAuth do not. AWS, GCP and
  Vault run against in-process doubles doing real AES-GCM with the services'
  own error answers; TPM on the simulator; PKCS#11 on SoftHSM, where the
  token's refusal codes are exercised through a decrypt seam that answers a
  real tampered ciphertext with each specification code
  (`TestDecryptGCM_Classification`), and end to end the sentinel is pinned
  to follow the token's own code -- never for SoftHSM 2.6's ambiguous
  `CKR_GENERAL_ERROR` (`TestUnseal_TokenRefusalClassifiedByItsOwnCode`). The
  classifiers have table tests of their own (`TestRejectsCiphertext`,
  `TestRejectsSealedData`, `TestLoadRejectsSealedObject`), and
  `test/integration/vault` asserts the AAD binding against a real Vault.
- **go-enclave provider bridge** — `pkg/enclaveprovider` unit tests cover the
  envelope parser, the error mapping, the attribute copies and the wipe on
  every path. `enclaveprovidertest.Run` runs go-enclave's `providertest`
  suite in both modes, a go-enclave `Sealer` round trip in both modes and the
  cross-seam refusal, over one backend; it runs for the software backend
  (`pkg/enclaveprovider`) and from each backend's own package beside its
  sealed-data authentication fixture: `pkg/backend/{awskms,gcpkms,azurekv}`
  on their mock clients, `pkg/backend/vault` on the Transit double,
  `pkg/backend/pkcs11` on SoftHSM and `pkg/tpm2` on the simulator
  (`enclave_provider*_test.go`). The process-memory residue sweep runs and
  passes for the software and cloud KMS backends; it is skipped, with the
  reason recorded, for Vault (the plaintext crosses an HTTP JSON body), the
  in-process TPM simulator, and SoftHSM (an async-preemption signal can save
  its decrypt registers on the Go-allocated signal stack; no copy is found
  under `GODEBUG=asyncpreemptoff=1`). The PKCS#11 tampered-blob property
  needs SoftHSM 2.7.0.
- **Integration** — `test/integration/tpm2`, `awskms`, `gcpkms`, `azurekv`,
  `vault`, `pkcs11`, `storage`.

## Observability

`pkg/seal/audit.go` records seal and unseal events — the ones that matter most
in an incident. The chosen strategy should be visible at startup; a deployment
that believes it is on `tpm2` and is actually on `passphrase` has a materially
different security posture, and the audit trail is where that becomes visible.
