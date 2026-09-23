# Seal & Auto-Unseal — Engineering

> **Status: NORMATIVE** · Feature: `seal` · Module: `go-xkms/xkey` · Last verified: 2026-09-23

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
`ErrBarrierStrategyUnavailable` otherwise.

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
| `services.ErrBarrierStrategyUnavailable` | `SetTPMSealerFunc` was not called (or returned nil/`!CanSeal()`) before a tpm2-strategy `Unseal`/`Initialize` |
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
| Barrier password | `--barrier-password` flag → `--barrier-password-file` → `XKEY_BARRIER_PASSWORD` env → interactive prompt (terminal only) (`resolveBarrierPassword`) | Not consulted at all for a tpm2-strategy barrier's auto/direct unseal |

## Tests

| File | Tags | Covers |
|---|---|---|
| `xkey/pkg/gui/services/barrier_auto_unseal_test.go` | (none — mocked TPM/policy store) | `TryAutoUnseal`'s decision logic: success, no policy, PCR mismatch, TPM/store errors |
| `xkey/cmd/xkey/cmd/barrier_auto_unseal_test.go` | `tpm_simulator` | `tryBarrierPolicyAutoUnseal` against a real simulator TPM: `_Success` (real seal + unseal via `BarrierAutoUnsealService.TryAutoUnseal` on one already-open, provisioned TPM — see the simulator-limitation invariant above for why this doesn't drive a second, independent TPM open), `_NoPolicyConfigured` (silent fallback, no TPM touched), `_PCRMismatch` (typed error, exercised through the full CLI wrapper's own TPM open), `_PolicyStoreOpenFailedIsTyped` |
| `xkey/cmd/xkey/cmd/barrier_cli_test.go`, `policy_test.go`, `extension_serve_test.go`, `fido2_*_test.go` | `ble codec_json` | CLI flag parsing, non-TPM barrier/policy flows, extension-serve/fido2 wiring |

Run the auto-unseal-specific tests:

```
cd xkey && GOWORK=off go test -tags 'ble codec_json tpm_simulator' \
  -run TestTryBarrierPolicyAutoUnseal -v ./cmd/xkey/cmd/...
```

Run the broader CLI suite (no simulator needed):

```
cd xkey && GOWORK=off go test -tags 'ble codec_json' ./cmd/xkey/cmd/...
```
