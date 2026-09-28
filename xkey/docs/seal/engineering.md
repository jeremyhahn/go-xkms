# Seal & Auto-Unseal — Engineering

> **Status: NORMATIVE** · Feature: `seal` · Module: `go-xkms/xkey` · Last verified: 2026-09-28

See [architecture.md](architecture.md) for the two-layer shape (Barrier vs.
the legacy sealed-blob store) and the auto-unseal decision order before
reading this document.

## Exported surface: Barrier

`xkms.Barrier` (`sdk/go`, wrapping `pkg/seal` in the root module) and
`xkms.BarrierConfig{RootKeyPath, PreferenceOrder}` are the root-module
primitives; xkey never imports `go-xkms/pkg` directly (per
`xkey/CLAUDE.md`'s SDK-boundary rule).

`pkg/gui/services.BarrierService` (used directly by both the GUI and the
CLI — see architecture.md's "Rejected alternatives") wraps it:

```go
func NewBarrierService(configDir string, log *slog.Logger) *BarrierService
func (s *BarrierService) SetDataDir(dir string)
func (s *BarrierService) SetTPMSealerFunc(fn func() xkms.Sealer)
func (s *BarrierService) SetCloudKMSStrategyFunc(fn func(strategyID string) (xkms.SealingStrategy, error))
func (s *BarrierService) Initialize(password, strategyID string) error
func (s *BarrierService) Unseal(password, strategyID string) error
func (s *BarrierService) Seal() error
func (s *BarrierService) IsUnsealed() bool
func (s *BarrierService) GetSealInfo() *BarrierSealInfo
func (s *BarrierService) GetBackend() xkms.StorageBackend
func (s *BarrierService) GetBarrier() *xkms.Barrier
```

`SetTPMSealerFunc` must be called before `Initialize`/`Unseal` with
`strategyID == "tpm2"` — `assembleStrategy` returns
`ErrBarrierStrategyUnavailable` otherwise. Likewise `SetCloudKMSStrategyFunc`
must be called before `Initialize`/`Unseal` with `strategyID` one of
`"awskms"`/`"gcpkms"`/`"azurekv"`/`"vault"` (`sdk/go.StrategyAWSKMS` etc.);
the injected function's own error return is propagated unchanged (e.g. a
`*BarrierError` from `cmd/xkey/cmd/barrier_cloudkms_<provider>.go` naming
what failed building the backend).

## Exported surface: cloud KMS barrier strategies (go-xkms#757)

`xkey/pkg/config` (`barrier_cloud.go`):

```go
type BarrierCloudKMSConfig struct {
	AWSKMS  *BarrierAWSKMSConfig
	GCPKMS  *BarrierGCPKMSConfig
	AzureKV *BarrierAzureKVConfig
	Vault   *BarrierVaultConfig
}
type BarrierAWSKMSConfig struct {
	Region, AccessKeyID, Endpoint, KeyID string
	SecretAccessKey, SessionToken        *xkms.SecretValue
}
type BarrierGCPKMSConfig struct {
	ProjectID, LocationID, KeyRingID, CredentialsFile string
}
type BarrierAzureKVConfig struct {
	VaultURL, TenantID, ClientID string
	ClientSecret                 *xkms.SecretValue
	AllowLocalVaultURL           bool
}
type BarrierVaultConfig struct {
	Address, Namespace, MountPath string
	Token                         *xkms.SecretValue
}

func (c *BarrierAWSKMSConfig) Validate() error
func (c *BarrierGCPKMSConfig) Validate() error
func (c *BarrierAzureKVConfig) Validate() error
func (c *BarrierVaultConfig) Validate() error
```

`Validate` checks only the non-secret connection fields (region required,
project/location/key-ring required, vault URL required, address required)
plus credential-field pairing (`access_key_id`/`secret_access_key` and
`tenant_id`/`client_id`/`client_secret` must each be all-or-nothing); it
never inspects whether a `*SecretValue` resolves. Every error is
`*config.DetailError` wrapping the sentinel
`config.ErrBarrierCloudKMSConfigInvalid` (`errors.go`), naming the specific
field. `Config.Barrier.CloudKMS` (`BarrierSection`, `config.go`) is the
persisted location `xkey barrier init` writes to and `xkey barrier
unseal`/`extension serve` read from.

`BarrierAWSKMSConfig.KeyID` (go-xkms#842) is the one field `Validate` does
NOT format-check: an existing CMK's key ID, key ARN, alias, or alias ARN to
seal under instead of letting the barrier provision one. Deliberately so —
`awskms.Config.Validate` (`pkg/backend/awskms`, the root module) is the one
place that check lives, reached when `buildAWSKMSBarrierStrategy` constructs
the backend via `sdk/go.NewAWSKMSBackend`; duplicating the AWS ID/ARN/alias
regex here would be a second copy that drifts. Left empty (the default), the
barrier creates and persists a new CMK under `sdk/go.SealKeyCN` the same way
it always has.

`cmd/xkey/cmd` (production code, gated as noted):

```go
// barrier_cloudkms.go (no build tag)
type cloudKMSStrategyBuilder func(ctx context.Context, dataDir string) (xkms.SealingStrategy, io.Closer, error)
func registerCloudKMSStrategyBuilder(id xkms.StrategyID, fn cloudKMSStrategyBuilder)
func buildCloudKMSBarrierStrategy(ctx context.Context, id xkms.StrategyID, dataDir string) (xkms.SealingStrategy, io.Closer, error)
func resolveBarrierCloudSecrets(ctx context.Context, cfg any) error

// barrier_cloudkms_awskms.go (//go:build awskms), and one file per provider
// (barrier_cloudkms_gcpkms.go, barrier_cloudkms_azurekv.go,
// barrier_cloudkms_vault.go) with the matching tag:
func init() { registerCloudKMSStrategyBuilder(xkms.StrategyAWSKMS, buildAWSKMSBarrierStrategy) }
func buildAWSKMSBarrierStrategy(ctx context.Context, dataDir string) (xkms.SealingStrategy, io.Closer, error)
```

Each `build<Provider>BarrierStrategy` reads `GetConfig().Barrier.CloudKMS.<Provider>`,
calls `.Validate()`, resolves any `*SecretValue` fields via
`resolveBarrierCloudSecrets`, constructs the backend (`sdk/go.NewAWSKMSBackend`
et al.) with local file storage for the backend's own key metadata under
`<data dir>/barrier/cloudkms/<provider>/`, and calls
`sdk/go.BuildCloudKMSStrategy` — see architecture.md for why that one call is
shared with `xkmsd`. A provider whose build tag is absent has no entry in
`cloudKMSStrategyBuilders`, and `buildCloudKMSBarrierStrategy` returns a
`*BarrierError` naming the tag.

`sdk/go` re-exports (new in this feature): `BuildCloudKMSStrategy`,
`IsCloudSealStrategy`, `SealKeyAttributes`, `SealKeyCN`,
`ErrSealBackendUnavailable`, `ErrNotCloudSealStrategy` (from `pkg/seal`);
`SecretValueBytes`, `NewSecretResolverRegistry`, `NewSecretConfigProcessor`,
`ErrUnresolvedSecretURI` (from go-qrdb's secret-reference SPI, `secret_config.go`).

### `*SecretValue` config fields need `pkg/config/load.go`'s own decode hook

This is the first `*xkms.SecretValue` field anywhere in xkey's `Config`, and
it exposed two properties of xkey's existing config loader
(`registerConfigKeys`/`walkConfigKeys`/`unmarshalAndValidate`, all in
`load.go`) that matter to every `*SecretValue` field added after this one:

1. **Every direct struct-pointer field is walked and materialized on
   `Load()`, whether or not anything under it was ever configured.**
   `walkConfigKeys` descends through a nil struct pointer (via
   `reflect.New`) purely to register its leaf keys for `XKEY_`-prefixed
   env-var binding; `v.Unmarshal` then allocates the same pointer as a side
   effect of decoding those registered keys, so the pointer is never nil
   after a real `Load()`/`LoadFromPath()`/`LoadFromHome()` call regardless
   of what `DefaultConfig()` returns. `DefaultConfig()`'s `Barrier.CloudKMS`
   literal (`config.go`) matches that shape on purpose — every provider
   pointer, and every `*SecretValue` field nested inside one, is
   initialized empty rather than left nil — so it is an honest picture of
   what a load actually produces (see `TestLoad_PartialPolicyKeepsDefaults`,
   which compares the two directly). A provider or credential being
   *present-but-empty* is not "configured": `Validate()` rejects an empty
   required field the same way it would reject a nil pointer, and
   `build<Provider>BarrierStrategy` normalizes an empty-`Raw` `*SecretValue`
   to nil (`normalizeAmbientSecret`, `barrier_cloudkms.go`) before deciding
   ambient vs. explicit credentials, so this materialization costs nothing
   functionally.
2. **viper's mapstructure decode never sees `SecretValue`'s own
   `UnmarshalYAML`/`UnmarshalJSON`.** Those exist for a plain `yaml.v3`/
   `encoding/json` decode; viper instead parses YAML into a generic
   `map[string]any` tree first and hands that tree to `mapstructure`
   second, which knows nothing about either interface. Without a decode
   hook, `Unmarshal` fails outright — `"expected a map or struct, got
   string"` — for a `Config` with ANY `*SecretValue` field, whether or not
   it is ever set, the moment `DefaultConfig()` puts one in the tree
   `mapstructure` walks. `secretValueDecodeHookFunc` (`load.go`) fixes
   this: composed into `unmarshalAndValidate`'s `viper.DecodeHook`, it
   converts a decoded string into `xkms.SecretValue{Raw: <string>}` — the
   same transform `SecretValue.setReference` performs — whenever the
   target type is `SecretValue`. Passing `viper.DecodeHook` at all
   *replaces* viper's own default hook chain rather than extending it, so
   `unmarshalAndValidate` also reproduces viper's unexported
   `stringToWeakSliceHookFunc` locally (`stringToWeakSliceHookFunc` in
   `load.go`) alongside `mapstructure.StringToTimeDurationHookFunc()` —
   dropping it in favour of the general-purpose
   `mapstructure.StringToSliceHookFunc` broke every non-`[]string` slice
   env-var override (`XKEY_GUI_AUTO_UNSEAL_PCRS=0,7` into `[]int`), because
   that hook only fires when the target type is exactly `[]string`.

A future `*SecretValue` (or any other direct struct-pointer) field added to
`Config` gets both of these for free; nothing further to wire.

## Exported surface: barrier auto-unseal

`pkg/gui/services.BarrierAutoUnsealService`
(`xkey/pkg/gui/services/barrier_auto_unseal.go`):

```go
func NewBarrierAutoUnsealService(policyStore pcrpolicy.PolicyStore, opts ...BarrierAutoUnsealOption) *BarrierAutoUnsealService
func WithBarrierAutoUnsealTPMAccessor(a *TPMAccessor) BarrierAutoUnsealOption
func WithBarrierAutoUnsealBarrier(b *BarrierService) BarrierAutoUnsealOption
func WithBarrierAutoUnsealLogger(l *slog.Logger) BarrierAutoUnsealOption
func WithBarrierAutoUnsealStrategyID(id string) BarrierAutoUnsealOption // default "tpm2"

func (s *BarrierAutoUnsealService) TryAutoUnseal(ctx context.Context) (bool, error)
func (s *BarrierAutoUnsealService) CaptureCurrentPCRs(ctx context.Context, bank string, pcrIndices []uint) (map[uint][]byte, error)
func (s *BarrierAutoUnsealService) GetAutoUnsealStatus() (*BarrierAutoUnsealStatus, error) // GUI-bound
func (s *BarrierAutoUnsealService) SetAutoUnsealPolicy(policyName string) error            // GUI-bound
func (s *BarrierAutoUnsealService) ClearAutoUnsealPolicy() error                           // GUI-bound
```

`TryAutoUnseal` returns `(true, nil)` on success, `(false, nil)` when no
auto-unseal policy is configured, `(false, err)` for every other failure
(PCR mismatch, TPM unavailable, the barrier's own `Unseal` failing).

The headless CLI counterpart lives in `xkey/cmd/xkey/cmd`, never
imported by anything outside the CLI:

```go
// barrier_auto_unseal.go
func tryBarrierPolicyAutoUnseal(ctx context.Context, logger *slog.Logger, barrierSvc *services.BarrierService, dataDir, tpmDevice string, tpmSimulator bool) (unsealed bool, closer io.Closer, err error)

// extension_serve.go
func probeTPMModule(logger *slog.Logger, dataDir, device string, useSimulator bool) (xkms.TrustedPlatformModule, io.Closer)
func probeTPMSealer(logger *slog.Logger, dataDir, device string, useSimulator bool) (xkms.Sealer, io.Closer) // narrows probeTPMModule to Sealer

// barrier_store.go
func openBarrierBackend(password, dataDir, tpmDevice string, tpmSimulator bool) (xkms.StorageBackend, error)
func unsealTPM2BarrierService(barrierSvc *services.BarrierService, dataDir, tpmDevice string, tpmSimulator bool) error

// policy.go
func openPolicyStore(storePath string) (pcrpolicy.PolicyStore, error) // storePath == "" resolves <data dir>/pcr_policies
```

`tryBarrierPolicyAutoUnseal` is the one function every headless caller
composes: open the policy store at `<data dir>/pcr_policies`, check for a
designated policy (no TPM touched at all if none exists), open the TPM only
once a policy exists, and drive `BarrierAutoUnsealService.TryAutoUnseal`.
It returns the TPM `io.Closer` it opened on success so the caller decides
the connection's lifetime (see "TPM connection lifetime" below).

## Exported surface: named PCR policies

`pkg/pcr_policy.PolicyStore` interface and `DAOStore` implementation:

```go
type PolicyStore interface {
	Create(ctx context.Context, name, bank string, pcrs map[uint][]byte) (*PCRPolicyEntity, error)
	Save(ctx context.Context, entity *PCRPolicyEntity) error
	Get(ctx context.Context, name string) (*PCRPolicyEntity, error)
	List(ctx context.Context) ([]*PCRPolicyEntity, error)
	Page(ctx context.Context, q qrdbsdk.PageQuery) (qrdbsdk.PageResult[*PCRPolicyEntity], error)
	Delete(ctx context.Context, name string) error
	SetAutoUnseal(ctx context.Context, name string) error
	ClearAutoUnseal(ctx context.Context) error
	GetAutoUnsealPolicy(ctx context.Context) (*PCRPolicyEntity, error)
	Close() error
}
```

`PCRPolicyEntity{Name, Bank, PCRs map[uint][]byte, AutoUnseal bool,
CreatedAt, UpdatedAt}`. Only one entity may have `AutoUnseal == true` at a
time; `SetAutoUnseal` clears any previous designation first. `Delete` on the
currently-designated policy returns `pcrpolicy.ErrDeleteAutoUnseal` — clear
the designation first.

## Invariants

- **A policy that exists but no longer matches the current PCR values is
  never a silent fallback.** `TryAutoUnseal` returns
  `ErrBarrierAutoUnsealPCRMismatch`, and every caller logs it at `Warn`
  before trying anything else.
- **No auto-unseal policy configured is the one case that produces no log
  line at all.** It is the expected state for a barrier that never had
  `xkey policy set-auto-unseal` run against it; `tryBarrierPolicyAutoUnseal`
  returns before ever opening the TPM.
- **`SetTPMSealerFunc` is always called before `Unseal`/`Initialize` for a
  tpm2-strategy barrier.** Every auto-unseal and direct-unseal call site
  sets it from the same TPM handle it just opened.
- **A one-shot CLI command's TPM connection is intentionally never
  explicitly closed**; `xkey extension serve` (long-running) threads its
  closer to a shutdown-time `defer` instead. See architecture.md's
  "Rejected alternatives" for why the closer is not threaded through the
  one-shot command chains.
- **The in-process TPM simulator (`-tags tpm_simulator`) allows only one
  simulator instance open per process at a time** (`simulator.Get`'s
  package-wide lock in `go-tpm-tools`) and starts every fresh instance
  unprovisioned. A test that needs two "separate" TPM opens to succeed at
  unsealing must close the first before opening the second, and must
  `Provision(nil)` each instance that seals or unseals — reading PCRs alone
  needs no provisioning. This is a simulator limitation
  (`xkey/test/integration/swtpm_test_helpers.go` documents the same thing
  for cross-process CLI integration tests, which use `swtpm` instead), not
  a behaviour a caller should route around.

## Errors

| Sentinel | Meaning |
|---|---|
| `services.ErrBarrierAutoUnsealPCRMismatch` | A policy is designated but the current PCR values don't match it |
| `services.ErrBarrierAutoUnsealTPMUnavailable` | No TPM could be opened |
| `services.ErrBarrierAutoUnsealNoPolicyStore` | `TryAutoUnseal` called with no policy store wired |
| `services.ErrBarrierAutoUnsealNoBarrier` | `TryAutoUnseal` called with no barrier wired |
| `services.ErrBarrierAutoUnsealFailed` | The barrier's own `Unseal` failed after PCRs matched |
| `services.ErrBarrierAutoUnsealInvalidBank` | The policy names an unsupported PCR bank |
| `services.ErrBarrierAutoUnsealReadPCRFailed` | The TPM PCR read itself failed |
| `cmd.ErrBarrierAutoUnsealPolicyStoreFailed` | The CLI could not open the policy store at the resolved path |
| `cmd.ErrBarrierStoreTPMUnavailable` | `openBarrierBackend`'s direct-unseal fallback found no TPM |
| `services.ErrBarrierStrategyUnavailable` | `SetTPMSealerFunc`/`SetCloudKMSStrategyFunc` was not called (or, for TPM2, returned nil/`!CanSeal()`) before an `Unseal`/`Initialize` needing it |
| `config.ErrBarrierCloudKMSConfigInvalid` | A cloud KMS barrier strategy's persisted config is missing a required field or pairs a credential field partially |
| `cmd.ErrBarrierConfigNotLoaded` | `xkey barrier init --strategy aws_kms\|gcp_kms\|azure_kv\|vault` ran before the unified config was loaded (defensive; not reachable through normal CLI startup) |
| `sdk/go.ErrUnresolvedSecretURI` | A cloud KMS strategy's explicit `*SecretValue` credential field names a reference xkey has no resolver for |
| `pkg/seal.ErrSealBackendUnavailable`, `ErrNotCloudSealStrategy` (`sdk/go`) | The backend handed to `BuildCloudKMSStrategy` doesn't implement `types.Sealer`/`types.SymmetricKeyProvider`, or `id` isn't one of the four cloud strategies |
| `pcrpolicy.ErrPolicyNotFound` | Named policy, or the auto-unseal designation, does not exist |
| `pcrpolicy.ErrDeleteAutoUnseal` | Attempted to delete the currently-designated auto-unseal policy |

Legacy sealed-blob store (`SealService`/`PlatformPolicyService`/
`AutoUnsealService`, GUI-only):

| Sentinel | Meaning |
|---|---|
| `ErrSealTPMNotAvailable`, `ErrSealBackendNotFound`, `ErrSealPolicyRequiresTPM` | Sealer/backend resolution failures |
| `ErrSealBlobNotFound`, `ErrSealBlobPolicyTypeMissing`, `ErrSealBlobBackendIDMissing` | A sealed blob record is missing, or predates required fields (rejected, never defaulted) |
| `ErrSealInvalidPolicyType`, `ErrSealPasswordRequired`, `ErrSealPolicyMismatch` | Seal/unseal request validation |
| `ErrPolicyNotConfigured`, `ErrPolicyInvalidPCRs`, `ErrPolicyInvalidBank`, `ErrPolicyVerifyFailed` | `PlatformPolicyService` (the single, unnamed GUI platform policy — distinct from the named `pcrpolicy` store above) |
| `ErrAutoUnsealNotConfigured`, `ErrAutoUnsealUnsealFailed`, `ErrAutoUnsealMountFailed`, `ErrAutoUnsealResealFailed` | LUKS-volume auto-unseal (`AutoUnsealService`) |

## Configuration

| Setting | Resolution | Notes |
|---|---|---|
| Data directory | `--data-dir` flag (where the command has one) → `XKEY_DATA_DIR` → `data_dir` config key → `~/.xkey/data` (`resolveDataDir`, `datadir.go`) | Roots the barrier, the PCR policy store, and PIN state |
| PCR policy store path | `xkey policy`'s `--store` flag; empty resolves to `<data dir>/pcr_policies` | Same location `pkg/gui/app.go`'s `initializeDataDir` opens |
| TPM device | `--tpm-device`/`--tpm-simulator` flags → `TPM_DEVICE_PATH` env → `/dev/tpmrm0` (`resolveTPMDevice`, `extension_serve.go`) | `--tpm-simulator` requires a `-tags tpm_simulator` build; never for production data |
| Barrier password | `--barrier-password-stdin` flag → `--barrier-password-file` → `XKEY_BARRIER_PASSWORD` env → interactive prompt (terminal only) (`resolveBarrierPassword`) | Not consulted at all for a tpm2-strategy or cloud-KMS-strategy barrier's unseal |
| Cloud KMS connection settings | `xkey barrier init --strategy <id> --<provider>-...` flags, persisted to `Config.Barrier.CloudKMS.<Provider>` | Read back by every later `unseal`/`extension serve`; never re-specified on the command line |

## Tests

| File | Tags | Covers |
|---|---|---|
| `xkey/pkg/gui/services/barrier_auto_unseal_test.go` | (none — mocked TPM/policy store) | `TryAutoUnseal`'s decision logic: success, no policy, PCR mismatch, TPM/store errors |
| `xkey/cmd/xkey/cmd/barrier_auto_unseal_test.go` | `tpm_simulator` | `tryBarrierPolicyAutoUnseal` against a real simulator TPM: `_Success` (real seal + unseal via `BarrierAutoUnsealService.TryAutoUnseal` on one already-open, provisioned TPM — see the simulator-limitation invariant above for why this doesn't drive a second, independent TPM open), `_NoPolicyConfigured` (silent fallback, no TPM touched), `_PCRMismatch` (typed error, exercised through the full CLI wrapper's own TPM open), `_PolicyStoreOpenFailedIsTyped` |
| `xkey/cmd/xkey/cmd/barrier_cli_test.go`, `policy_test.go`, `extension_serve_test.go`, `fido2_*_test.go` | `ble codec_json` | CLI flag parsing, non-TPM barrier/policy flows, extension-serve/fido2 wiring |
| `xkey/pkg/config/barrier_cloud_test.go` | `ble codec_json` | `BarrierAWSKMSConfig`/`BarrierGCPKMSConfig`/`BarrierAzureKVConfig`/`BarrierVaultConfig.Validate()` — required fields, credential-field pairing; `TestBarrierCloudKMSConfig_SecretValueRoundTrip` — a `*SecretValue` reference survives `Save`→`Load` intact |
| `xkey/pkg/config/load_test.go`, `load_partial_test.go`, `save_test.go` | `ble codec_json` | Pre-existing config-loader suite, re-run by this feature: `secretValueDecodeHookFunc`/`stringToWeakSliceHookFunc` (`load.go`) must not regress a `*SecretValue`-free `Load()`/`Save()` round trip or an env-var slice override (`TestLoadFromPath_EnvOverride`'s `XKEY_GUI_AUTO_UNSEAL_PCRS`) |
| `xkey/cmd/xkey/cmd/barrier_cloudkms_test.go` | `ble codec_json` | `resolveBarrierCloudSecrets` (nil field skipped, unclaimed reference fails), `buildCloudKMSBarrierStrategy`'s "not compiled in" error, `persistBarrierCloudKMSConfig` (no-op for non-cloud strategies, missing-config error, a full init→save→reload round trip including `KeyID`), `--aws-key-id` flag registration |
| `xkey/pkg/config/barrier_cloud_test.go` | `ble codec_json` | (also) `TestBarrierAWSKMSConfig_KeyIDRoundTrip` — `KeyID` survives `Save`→`Load` intact; `TestBarrierAWSKMSConfig_Validate_KeyIDNotCheckedHere` — `Validate` accepts any `KeyID` value, format checking is `awskms.Config.Validate`'s job |
| `xkey/pkg/gui/services/barrier_cloudkms_test.go` | `ble codec_json tpm_simulator` | `assembleStrategy`'s cloud KMS branch: unavailable without `SetCloudKMSStrategyFunc`, a full Initialize→Seal→Unseal round trip via `sdk/go.NewCloudKMSStrategy` over a mock sealer, injected-function error propagation |
| `pkg/seal/cloud_provision_test.go` (root module) | `awskms gcpkms azurekv vault` | `EnsureSealKey`/`BuildCloudKMSStrategy` against a generic mock `types.KeyProvider`, all four strategy IDs; `TestEnsureSealKey_AWSKMSOperatorKeyNotFoundFailsClosed` (go-xkms#842) — an operator-configured key that resolves not-found fails closed with `ErrOperatorSealKeyNotFound` instead of falling through to `GenerateSymmetricKey` |
| `pkg/seal/cloud_provision_awskms_test.go` (root module) | `awskms` | `BuildCloudKMSStrategy` against the real `*awskms.Backend` and its own `MockKMSClient`: init→seal→unseal round trip, a missing-credentials failure surfacing from `SealRootKey`, an operator-configured `Config.KeyID` reused without ever calling `CreateKey` (see that file's doc comment for why `EnsureSealKey`'s AWS KMS branch never reaches a real `CreateKey` call on this path — a pre-existing property of the shared provisioning recipe, not new here), and (go-xkms#842) `TestBuildCloudKMSStrategy_AWSKMSBackend_OperatorConfiguredKeyNotFound` — a configured `KeyID` `DescribeKey` reports as not found fails closed with `ErrOperatorSealKeyNotFound`, `CreateKey` never called |

Run the auto-unseal-specific tests:

```
cd xkey && GOWORK=off go test -tags 'ble codec_json tpm_simulator' \
  -run TestTryBarrierPolicyAutoUnseal -v ./cmd/xkey/cmd/...
```

Run the broader CLI suite (no simulator needed):

```
cd xkey && GOWORK=off go test -tags 'ble codec_json' ./cmd/xkey/cmd/...
```
