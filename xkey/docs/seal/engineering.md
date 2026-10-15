# Seal & Auto-Unseal — Engineering

> **Status: NORMATIVE** · Feature: `seal` · Module: `go-xkms/xkey` · Last verified: 2026-10-07

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
func (s *BarrierService) SetExternalStrategyFunc(fn func(strategyID string) (xkms.SealingStrategy, error))
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
`ErrBarrierStrategyUnavailable` otherwise. Likewise `SetExternalStrategyFunc`
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
   `mapstructure.StringToSliceHookFunc` would break any non-`[]string` slice
   env-var override, because that hook only fires when the target type is
   exactly `[]string`.

A future `*SecretValue` (or any other direct struct-pointer) field added to
`Config` gets both of these for free; nothing further to wire.

## Exported surface: barrier auto-unseal

`pkg/gui/services.BarrierAutoUnsealService`
(`xkey/pkg/gui/services/barrier_auto_unseal.go`):

```go
const BarrierAutoUnsealObject = "xkey-barrier-auto-unseal"

func NewBarrierAutoUnsealService(opts ...BarrierAutoUnsealOption) *BarrierAutoUnsealService
func WithBarrierAutoUnsealLocal(l *LocalTPMPolicies) BarrierAutoUnsealOption
func WithBarrierAutoUnsealBarrier(b *BarrierService) BarrierAutoUnsealOption
func WithBarrierAutoUnsealLogger(l *slog.Logger) BarrierAutoUnsealOption

func (s *BarrierAutoUnsealService) TryAutoUnseal(ctx context.Context, strategyID string) (bool, error)
func (s *BarrierAutoUnsealService) GetAutoUnsealStatus() (*BarrierAutoUnsealStatus, error) // GUI-bound
func (s *BarrierAutoUnsealService) EnableAutoUnseal(policyName, credential string) error   // GUI-bound
func (s *BarrierAutoUnsealService) DisableAutoUnseal() error                               // GUI-bound
```

`EnableAutoUnseal` seals `credential` (the barrier password) in the TPM as
`BarrierAutoUnsealObject`, bound to the named policy and nothing else, then
gives the policy the auto-unseal mark (clearing it from any other).
`TryAutoUnseal` returns `(true, nil)` on success, `(false, nil)` when no
policy carries the mark, and `(false, err)` for every other failure — the
TPM refusing the policy session, a mark with nothing sealed under it, or the
barrier's own `Unseal` rejecting the password.

The local TPM policy service it runs on is
`localtpm.Policies` (go-xkms `pkg/localtpm`, re-exported as
`sdk/go/localtpm`, shared with xkmsctl), opened with
`localtpm.Open(localtpm.Params{TPM, Keys, DataDir, OpenStore, Lock,
Logger})` -- the GUI passes its `TPMAccessor.Lock` -- or, by the CLI,
`localtpm.OpenHost`, over `BuildTPMPolicyService`; see
[docs/tpm-policies/](../../../docs/tpm-policies/) for the policy model and
the GUI's `TPMPolicyService`.

The headless CLI counterpart lives in `xkey/cmd/xkey/cmd`, never
imported by anything outside the CLI:

```go
// barrier_auto_unseal.go
func openLocalTPMPolicies(logger *slog.Logger, dataDir, device string, useSimulator bool) (*localTPMPolicies, error)
func tryBarrierPolicyAutoUnseal(ctx context.Context, logger *slog.Logger, barrierSvc *services.BarrierService, dataDir string, strategy xkms.StrategyID, tpmDevice string, tpmSimulator bool) (bool, io.Closer, error)

// extension_serve.go
func probeTPMModule(logger *slog.Logger, dataDir, device string, useSimulator bool) (xkms.TrustedPlatformModule, io.Closer)
func probeTPMSealer(logger *slog.Logger, dataDir, device string, useSimulator bool) (xkms.Sealer, io.Closer) // narrows probeTPMModule to Sealer

// barrier_store.go
func openBarrierBackend(password, dataDir, tpmDevice string, tpmSimulator bool) (xkms.StorageBackend, error)
func unsealTPM2BarrierService(barrierSvc *services.BarrierService, dataDir, tpmDevice string, tpmSimulator bool) error
```

`tryBarrierPolicyAutoUnseal` is the one function every headless caller
composes: open the local TPM policy service over this host's TPM (registry
at `<data dir>/tpm-policies`), and drive
`BarrierAutoUnsealService.TryAutoUnseal`. It returns the `io.Closer` of the
TPM it opened on success so the caller decides the connection's lifetime
(see the one-shot-command invariant below).

## Invariants

- **The TPM decides.** Auto-unseal never compares PCRs itself: the barrier
  password is released only by a TPM policy session over the auto-unseal
  policy's NV index. A PCR change or a revoke makes the TPM refuse
  (`ErrBarrierAutoUnsealRefused`), and every caller logs it at `Warn`
  before trying anything else.
- **The auto-unseal password object is assigned to its policy**, so the
  policy cannot be deleted while auto-unseal uses it; `DisableAutoUnseal`
  removes the object and its assignment without unsealing it, so it works
  after the PCRs changed.
- **The mark and the sealed password move together.** A mark set without
  sealing (on the server API, or moved to another policy) fails closed with
  `ErrBarrierAutoUnsealNotEnrolled`/`ErrBarrierAutoUnsealPolicyMoved`.
- **No policy carrying the mark is the one case that produces no log line
  at all.**
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
  unprovisioned, so a test keeps one provisioned instance open for the
  whole test. This is a simulator limitation
  (`xkey/test/integration/swtpm_test_helpers.go` documents the same thing
  for cross-process CLI integration tests, which use `swtpm` instead), not
  a behaviour a caller should route around.

## Errors

| Sentinel | Meaning |
|---|---|
| `services.ErrBarrierAutoUnsealRefused` | The TPM refused to release the password under the policy: the PCRs changed, or the policy was revoked |
| `services.ErrBarrierAutoUnsealNotEnrolled` | A policy carries the mark but no password is sealed under it |
| `services.ErrBarrierAutoUnsealPolicyMoved` | The password is sealed under another policy than the one carrying the mark |
| `services.ErrBarrierAutoUnsealNoPolicyService` | No local TPM policy service (no TPM, or no data directory yet) |
| `services.ErrBarrierAutoUnsealNoBarrier` | `TryAutoUnseal` called with no barrier wired |
| `services.ErrBarrierAutoUnsealFailed` | The TPM released the password but the barrier's own `Unseal` rejected it |
| `services.ErrBarrierAutoUnsealEmptyPolicyName`, `ErrBarrierAutoUnsealBuiltinPolicy`, `ErrBarrierAutoUnsealCredentialRequired` | `EnableAutoUnseal` validation: a named (not the built-in) policy and a non-empty password are required |
| `cmd.ErrLocalTPMPoliciesOpenFailed` | The CLI could not open the local TPM policy service (no TPM, an unprovisioned one, or its registry) |
| `cmd.ErrBarrierStoreTPMUnavailable` | `openBarrierBackend`'s direct-unseal fallback found no TPM |
| `services.ErrBarrierStrategyUnavailable` | `SetTPMSealerFunc`/`SetExternalStrategyFunc` was not called (or, for TPM2, returned nil/`!CanSeal()`) before an `Unseal`/`Initialize` needing it |
| `config.ErrBarrierCloudKMSConfigInvalid` | A cloud KMS barrier strategy's persisted config is missing a required field or pairs a credential field partially |
| `cmd.ErrBarrierConfigNotLoaded` | `xkey barrier init --strategy aws_kms\|gcp_kms\|azure_kv\|vault` ran before the unified config was loaded (defensive; not reachable through normal CLI startup) |
| `sdk/go.ErrUnresolvedSecretURI` | A cloud KMS strategy's explicit `*SecretValue` credential field names a reference xkey has no resolver for |
| `pkg/seal.ErrSealBackendUnavailable`, `ErrNotCloudSealStrategy` (`sdk/go`) | The backend handed to `BuildCloudKMSStrategy` doesn't implement `types.Sealer`/`types.SymmetricKeyProvider`, or `id` isn't one of the four cloud strategies |

Sealed-blob store (`SealService`/`AutoUnsealService`, GUI-only):

| Sentinel | Meaning |
|---|---|
| `ErrSealTPMNotAvailable`, `ErrSealBackendNotFound`, `ErrSealPolicyRequiresTPM` | Sealer/backend resolution failures; a TPM policy on a non-TPM backend |
| `ErrSealBlobNotFound`, `ErrSealBlobBackendIDMissing` | A sealed blob record is missing, or predates the required `backend_id` (rejected, never defaulted) |
| `ErrSealPasswordRequired`, `ErrSealPolicyMismatch` | A non-TPM blob's password is missing or wrong (the TPM checks a tpm2 blob's password itself) |
| `ErrAutoUnsealNotConfigured`, `ErrAutoUnsealUnsealFailed`, `ErrAutoUnsealMountFailed`, `ErrAutoUnsealResealFailed` | LUKS-volume auto-unseal (`AutoUnsealService`) |

## Configuration

| Setting | Resolution | Notes |
|---|---|---|
| Data directory | `--data-dir` flag (where the command has one) → `XKEY_DATA_DIR` → `data_dir` config key → `~/.xkey/data` (`resolveDataDir`, `datadir.go`) | Roots the barrier, the TPM policy registry (`tpm-policies`, `tpm-keys`), the TPM key store (`tpm`), and PIN state |
| TPM policy registry | `<data dir>/tpm-policies`, opened with `state.storage_engine` (default `file`) | Outside the barrier, so boot-time auto-unseal can read it; the GUI and CLI open the same stores |
| TPM device | `--tpm-device`/`--tpm-simulator` flags → `TPM_DEVICE_PATH` env → `/dev/tpmrm0` (`resolveTPMDevice`, `extension_serve.go`) | `--tpm-simulator` requires a `-tags tpm_simulator` build; never for production data |
| Barrier password | `--barrier-password-stdin` flag → `--barrier-password-file` → `XKEY_BARRIER_PASSWORD` env → interactive prompt (terminal only) (`resolveBarrierPassword`) | Not consulted when auto-unseal succeeds, or for a cloud-KMS-strategy barrier |
| Cloud KMS connection settings | `xkey barrier init --strategy <id> --<provider>-...` flags, persisted to `Config.Barrier.CloudKMS.<Provider>` | Read back by every later `unseal`/`extension serve`; never re-specified on the command line |

## Tests

| File | Tags | Covers |
|---|---|---|
| `xkey/pkg/gui/services/barrier_auto_unseal_test.go` | (none) | `BarrierAutoUnsealService` without a TPM: unavailable service, argument validation, missing barrier |
| `xkey/pkg/gui/services/tpm_policy_simulator_test.go` | `tpm_simulator` | Against a real simulator TPM: the TPM releases the barrier password under the policy, refuses it after a PCR change (`ErrBarrierAutoUnsealRefused`), releases it again after `UpdatePolicy`; a moved mark fails closed; a wrong password surfaces as `ErrBarrierAutoUnsealFailed`; the local policy lifecycle with keys (see docs/tpm-policies) |
| `xkey/cmd/xkey/cmd/tpm_policy_test.go`, `tpm_policy_simulator_test.go` | (none) / `tpm_simulator` | `xkey tpm policy` in server mode over a fake server and in local mode over the simulator, including `auto-unseal` sealing the barrier password; `tryBarrierPolicyAutoUnseal` failing with `ErrLocalTPMPoliciesOpenFailed` without a (provisioned) TPM |
| `xkey/cmd/xkey/cmd/barrier_cli_test.go`, `extension_serve_test.go`, `fido2_*_test.go` | `ble codec_json` | CLI flag parsing, non-TPM barrier flows, extension-serve/fido2 wiring |
| `xkey/pkg/config/barrier_cloud_test.go` | `ble codec_json` | `BarrierAWSKMSConfig`/`BarrierGCPKMSConfig`/`BarrierAzureKVConfig`/`BarrierVaultConfig.Validate()` — required fields, credential-field pairing; `TestBarrierCloudKMSConfig_SecretValueRoundTrip` — a `*SecretValue` reference survives `Save`→`Load` intact |
| `xkey/pkg/config/load_test.go`, `load_partial_test.go`, `save_test.go` | `ble codec_json` | Pre-existing config-loader suite, re-run by this feature: `secretValueDecodeHookFunc`/`stringToWeakSliceHookFunc` (`load.go`) must not regress a `*SecretValue`-free `Load()`/`Save()` round trip or an env-var override (`TestLoadFromPath_EnvOverride`) |
| `xkey/cmd/xkey/cmd/barrier_cloudkms_test.go` | `ble codec_json` | `resolveBarrierCloudSecrets` (nil field skipped, unclaimed reference fails), `buildCloudKMSBarrierStrategy`'s "not compiled in" error, `persistBarrierCloudKMSConfig` (no-op for non-cloud strategies, missing-config error, a full init→save→reload round trip including `KeyID`), `--aws-key-id` flag registration |
| `xkey/pkg/config/barrier_cloud_test.go` | `ble codec_json` | (also) `TestBarrierAWSKMSConfig_KeyIDRoundTrip` — `KeyID` survives `Save`→`Load` intact; `TestBarrierAWSKMSConfig_Validate_KeyIDNotCheckedHere` — `Validate` accepts any `KeyID` value, format checking is `awskms.Config.Validate`'s job |
| `xkey/pkg/gui/services/barrier_cloudkms_test.go` | `ble codec_json tpm_simulator` | `assembleStrategy`'s cloud KMS branch: unavailable without `SetExternalStrategyFunc`, a full Initialize→Seal→Unseal round trip via `sdk/go.NewCloudKMSStrategy` over a mock sealer, injected-function error propagation |
| `pkg/seal/cloud_provision_test.go` (root module) | `awskms gcpkms azurekv vault` | `EnsureSealKey`/`BuildCloudKMSStrategy` against a generic mock `types.KeyProvider`, all four strategy IDs; `TestEnsureSealKey_AWSKMSOperatorKeyNotFoundFailsClosed` (go-xkms#842) — an operator-configured key that resolves not-found fails closed with `ErrOperatorSealKeyNotFound` instead of falling through to `GenerateSymmetricKey` |
| `pkg/seal/cloud_provision_awskms_test.go` (root module) | `awskms` | `BuildCloudKMSStrategy` against the real `*awskms.Backend` and its own `MockKMSClient`: init→seal→unseal round trip, a missing-credentials failure surfacing from `SealRootKey`, an operator-configured `Config.KeyID` reused without ever calling `CreateKey` (see that file's doc comment for why `EnsureSealKey`'s AWS KMS branch never reaches a real `CreateKey` call on this path — a pre-existing property of the shared provisioning recipe, not new here), and (go-xkms#842) `TestBuildCloudKMSStrategy_AWSKMSBackend_OperatorConfiguredKeyNotFound` — a configured `KeyID` `DescribeKey` reports as not found fails closed with `ErrOperatorSealKeyNotFound`, `CreateKey` never called |

Run the auto-unseal-specific tests:

```
cd xkey && GOWORK=off go test -tags 'codec_json tpm_simulator' \
  -run 'TestBarrierAutoUnseal|TestTryBarrierPolicyAutoUnseal|TestTPMPolicyAutoUnseal' \
  ./pkg/gui/services/ ./cmd/xkey/cmd/
```

Run the broader CLI suite (no simulator needed):

```
cd xkey && GOWORK=off go test -tags 'ble codec_json' ./cmd/xkey/cmd/...
```
