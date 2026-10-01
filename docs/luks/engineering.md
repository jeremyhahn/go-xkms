# LUKS (root module) — Engineering Contract

> **Status: NORMATIVE** · Feature: `luks` · Repo: `go-xkms` · Last verified: 2026-09-30

Design rationale: [`architecture.md`](architecture.md). This document is the
exported surface, config keys, errors, and test inventory for `pkg/luks`.

## Package

`pkg/luks` (`pkg/luks/errors.go`, package doc): "Package luks provides
FIPS-aware LUKS volume configuration and lifecycle management. It wraps LUKS
volume operations with automatic KDF selection based on the runtime FIPS
policy and exposes an Executor interface so callers can supply
platform-specific implementations (or test mocks)."

Re-exported as type/value aliases (no added logic) by `sdk/go/luks`
(`sdk/go/luks/luks.go`); this is the only sanctioned import path from
outside the root module, including `xkey`.

## Volume lifecycle

### `Executor` — `pkg/luks/manager.go`

```go
type Executor interface {
	Create(ctx context.Context, config *VolumeConfig, sizeBytes int64, passphrase string) error
	Unlock(ctx context.Context, config *VolumeConfig, passphrase string) error
	Lock(ctx context.Context, config *VolumeConfig) error
	Mount(ctx context.Context, config *VolumeConfig) error
	Unmount(ctx context.Context, config *VolumeConfig) error
	IsMounted(config *VolumeConfig) bool
	IsUnlocked(config *VolumeConfig) bool
}
```

### `LibExecutor` — `pkg/luks/executor.go`

```go
type LibExecutor struct {
	Filesystem string // defaults to "ext4" when empty
}

func NewLibExecutor() *LibExecutor
```

The production `Executor`, on `github.com/jeremyhahn/go-luks2`. Method
behavior:

| Method | Behavior |
|---|---|
| `Create` | Refuses `ErrVolumeAlreadyExists` if the container file already exists. Runs `EnsureKeyringAvailable`. Creates the parent directory, then the sparse container file with `O_EXCL`. Attaches a loop device, formats (`KDFType`/`PBKDFIterTime` from `VolumeConfig`), unlocks, creates the filesystem, locks, detaches. Every step's failure is a typed `*ExecutorError` and unwinds everything created so far (loop device detached, container file removed) except a format that already succeeded (a detach failure after a successful format leaves the container on disk, not removed). |
| `Unlock` | Refuses `ErrVolumeNotFound` if the container file does not exist. Runs `EnsureKeyringAvailable`. Attaches a loop device and opens the LUKS mapping. A failed `go-luks2.Unlock` detaches the loop device it just attached before returning. |
| `Lock` | Closes the LUKS mapping, then resolves and detaches the loop device via `go-luks2.FindLoopDevice` (not a cached handle) — a no-op, not an error, when no loop device is found. |
| `Mount` | Creates the mount point directory, mounts, then `chmod 0700`s the mount point (undoing whatever mode a freshly formatted filesystem's root inode left behind); a failed `chmod` unmounts before returning. |
| `Unmount` | Unmounts the mount point. |
| `IsMounted` | `go-luks2.IsMounted` on the mount point; an error from the kernel check reports `false`, not an error — `Executor.IsMounted` has no error return (see package-level `IsMounted` below for the error-returning form). |
| `IsUnlocked` | `go-luks2.IsUnlocked` on the mapper name. |

### Package-level free functions — `pkg/luks/executor.go`

```go
func IsLUKSVolume(path string) bool
func IsMounted(mountPoint string) (bool, error)
func IsUnlocked(mapperName string) bool
```

`IsLUKSVolume` reads the first 6 bytes of a file and compares against the
LUKS2 magic (`LUKS` + `0xba 0xbe`); any read failure or short file reports
`false`. `IsMounted` is the error-returning form of the mount check (used by
`xkey.Volume.IsMounted` and anywhere else that must distinguish "not
mounted" from "could not determine").

### `Manager` — `pkg/luks/manager.go`

| Symbol | Signature | Behavior |
|---|---|---|
| `NewManager` | `func NewManager(config *VolumeConfig, executor Executor) (*Manager, error)` | Applies `config.SetDefaults()`, then `config.Validate()`. Returns `ErrNilExecutor` for a nil executor. |
| `NewFIPSAwareManager` | `func NewFIPSAwareManager(luksPath, mountPoint, mapperName string, executor Executor) (*Manager, error)` | Builds a `VolumeConfig{LUKSPath, MountPoint, MapperName}` and delegates to `NewManager`. |
| `(*Manager) Create` | `func (m *Manager) Create(ctx context.Context, sizeBytes int64, passphrase string) error` | `ErrInvalidSize` if `sizeBytes <= 0`, `ErrEmptyPassphrase` if empty, else `Executor.Create`, errors wrapped as `&errs.Joined{Lead: ErrOperationFailed, Cause: err}`. |
| `(*Manager) Unlock` | `func (m *Manager) Unlock(ctx context.Context, passphrase string) error` | `ErrEmptyPassphrase` if empty, `ErrAlreadyUnlocked` if already unlocked, else `Executor.Unlock`; sets `unlocked = true` on success. |
| `(*Manager) Lock` | `func (m *Manager) Lock(ctx context.Context) error` | `ErrNotUnlocked` if not unlocked, else `Executor.Lock`; sets `unlocked = false` and `mounted = false` on success. |
| `(*Manager) Mount` | `func (m *Manager) Mount(ctx context.Context) error` | `ErrNotUnlocked` if not unlocked, `ErrAlreadyMounted` if already mounted, else `Executor.Mount`; sets `mounted = true` on success. |
| `(*Manager) Unmount` | `func (m *Manager) Unmount(ctx context.Context) error` | `ErrNotMounted` if not mounted, else `Executor.Unmount`; sets `mounted = false` on success. |
| `(*Manager) IsMounted` | `func (m *Manager) IsMounted() bool` | Reads the atomic `mounted` field. |
| `(*Manager) IsUnlocked` | `func (m *Manager) IsUnlocked() bool` | Reads the atomic `unlocked` field. |
| `(*Manager) Config` | `func (m *Manager) Config() VolumeConfig` | Value copy of the internal config. |

### `VolumeConfig` — `pkg/luks/config.go`

| Field | Type | Meaning | Required | Default |
|---|---|---|---|---|
| `LUKSPath` | `string` | Path to the LUKS container file | yes — empty fails `Validate` with `ErrInvalidConfig` | none |
| `MountPoint` | `string` | Directory the unlocked volume is mounted at | yes — same | none |
| `MapperName` | `string` | Device-mapper name under `/dev/mapper/` | yes — same | none |
| `KDF` | `KDFType` (`"argon2id"` \| `"pbkdf2"`) | Key-derivation function for LUKS keyslot processing | no | `DefaultKDF()` via `SetDefaults` |
| `PBKDFIterTime` | `int` | PBKDF2 iteration time in milliseconds | no | `2000` |

`Validate()`: `ErrInvalidConfig` for any empty required field; `ErrInvalidKDF`
if `KDF` is non-empty and not one of `validKDFs`.

`SetDefaults()`: fills `KDF` via `DefaultKDF()` and `PBKDFIterTime` via
`defaultPBKDFIterTime` (`2000`) when zero-valued. Idempotent.

### `KDFType` and `DefaultKDF` — `pkg/luks/config.go`

```go
type KDFType string

const (
	KDFArgon2id KDFType = "argon2id" // non-FIPS default
	KDFPBKDF2   KDFType = "pbkdf2"   // required in FIPS 140 mode
)

func DefaultKDF() KDFType
```

`fips140.Enabled()` is the stdlib `crypto/fips140` signal — no locally
maintained approved-algorithm list (go-xkms#21).

## TPM 2.0 passphrase sealing

### `SealParent` and `TPMSealerConfig` — `pkg/luks/config.go`

```go
type SealParent uint8

const (
	SealParentPSRK SealParent = iota // default: go-xkms's Platform SRK
	SealParentSSRK                   // TCG Shared SRK, systemd-tpm2 compatible
)

func (p SealParent) String() string
func (p SealParent) Validate() error
func ParseSealParent(s string) (SealParent, error) // "", "psrk" -> PSRK; "ssrk" -> SSRK

type TPMSealerConfig struct {
	Parent  SealParent // zero value: SealParentPSRK
	PCRBank string     // "sha1"|"sha256"|"sha384"|"sha512"; empty -> "sha256"; ignored for SealParentPSRK
}

func (c *TPMSealerConfig) SetDefaults()
func (c *TPMSealerConfig) Validate() error // SealParentInvalidError | ErrInvalidPCRBank
```

### `TPMSealUnsealer` — `pkg/luks/tpm.go`

```go
type TPMSealUnsealer interface {
	Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error)
	Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error)
	PlatformSRKAttributes() (*types.KeyAttributes, error)
	SSRKAttributes() (*types.KeyAttributes, error)
	Transport() transport.TPM
}
```

Satisfied by `*pkg/tpm2.TPM2` without any adapter. `Transport()` is used only
by the `SealParentSSRK` path, to compute a PolicyPCR digest via a trial
session (`computePCRPolicyDigest`) — the one piece of raw TPM session code
this package still owns, because `pkg/tpm2.Seal` requires a pre-computed
digest for a non-platform policy (`types.SealOptions.AuthPolicy`) and has
no public helper to compute one.

### `TPMSealer` — `pkg/luks/tpm.go`

```go
type TPMSealer struct { /* unexported: tpm, parent, pcrBank */ }

func NewTPMSealer(tpm TPMSealUnsealer, cfg TPMSealerConfig) (*TPMSealer, error)
func (s *TPMSealer) Parent() SealParent
func (s *TPMSealer) SealPassphrase(ctx context.Context, pcrs []int32) (*TPMSealResult, error)
func (s *TPMSealer) UnsealPassphrase(ctx context.Context, token *luks2.Token) ([]byte, error)
```

- `NewTPMSealer(nil, _)` → `ErrTPMNoTransport`. An invalid `cfg.Parent` →
  `*SealParentInvalidError`; an invalid `cfg.PCRBank` → `ErrInvalidPCRBank`.
  `cfg.SetDefaults()` is applied before validation, so an empty `PCRBank` is
  never rejected.
- `SealPassphrase(ctx, pcrs)`:
  - `SealParentPSRK`: `pcrs` must be empty — a non-empty selection returns
    `ErrTPMPCRSelectionNotSupported` (the platform policy's PCR set is fixed
    by `pkg/tpm2` configuration, not chosen per call). Resolves
    `PlatformSRKAttributes()`, builds `KeyAttributes{CN, Parent,
    TPMPolicy: types.TPMPolicyPlatform}` (no password), calls
    `tpm.Seal`. Token: `XKMSTPMTokenType`, `TPM2Blob`, `TPM2KeyHandle`.
  - `SealParentSSRK`: resolves `SSRKAttributes()`, computes a PolicyPCR
    digest over `pcrs` (bank from construction), builds
    `KeyAttributes{CN, Parent}` (no `TPMPolicy`, no password), calls
    `tpm.Seal` with `types.SealOptions.AuthPolicy` set to the computed
    digest.
    Token: `TPMTokenType`, `TPM2Blob`, `TPM2PCRBank`, `TPM2PCRs`,
    `TPM2KeyHandle`, `TPM2PolicyHash`.
  - Both paths generate the 32-byte passphrase with `crypto/rand`. The
    sealed object carries no password: `pkg/tpm2` clears its
    `UserWithAuth`, so only a policy session unseals it — see
    architecture.md §"No empty-auth bypass".
- `UnsealPassphrase(ctx, token)`:
  - Dispatches on `s.Parent()`, not `token.Type`.
  - `SealParentPSRK`: decodes `token.TPM2Blob`, resolves
    `PlatformSRKAttributes()`, builds `KeyAttributes{CN, Parent, TPMPolicy:
    types.TPMPolicyPlatform}` (no password — the PCR branch of the platform
    policy is what's expected to satisfy it), calls `tpm.Unseal`.
  - `SealParentSSRK`: always `ErrTPMSSRKUnsealUnsupported`, without
    decoding the token or touching `tpm`.
  - `nil` token → `ErrTPMInvalidToken`.

### Token — `*luks2.Token` (`github.com/jeremyhahn/go-luks2/pkg/luks2`)

No longer a `pkg/luks`-local type. Fields this package populates:
`Type`, `TPM2Blob`, `TPM2PCRBank`, `TPM2PCRs`, `TPM2KeyHandle`,
`TPM2PolicyHash`. `Keyslots` is left for the caller to fill in once it knows
which LUKS2 keyslot the sealed passphrase was added to
(`go-luks2.AddKey`/`ImportToken`).

### `TPMSealResult` — `pkg/luks/tpm.go`

```go
type TPMSealResult struct {
	Passphrase  *secure.Buffer // sdk/go/secure; caller MUST call Destroy()
	Token       *luks2.Token
	PublicBlob  []byte
	PrivateBlob []byte
}
```

### Blob packing — `pkg/luks/tpm.go`

```go
func EncodeTPMSealBlobs(public, private []byte) string
func DecodeTPMSealBlobs(s string) ([]byte, []byte, error)
```

Unchanged wire format: `base64(uint32BE(len(public)) | public | private)`.
`DecodeTPMSealBlobs` returns `ErrTPMInvalidToken` for invalid base64, a
too-short payload, or a length prefix that overruns the buffer.

## Errors — `pkg/luks/errors.go`

| Sentinel / type | Raised by |
|---|---|
| `ErrNotMounted`, `ErrAlreadyMounted`, `ErrNotUnlocked`, `ErrAlreadyUnlocked` | `Manager`'s state guards |
| `ErrInvalidConfig`, `ErrEmptyPassphrase`, `ErrInvalidSize`, `ErrInvalidKDF` | `VolumeConfig.Validate`, `Manager.Create`/`Unlock` |
| `ErrOperationFailed` | `Manager`, as the `Lead` of an `errs.Joined` wrapping the `Executor`'s error |
| `ErrNilExecutor` | `NewManager` |
| `ErrVolumeAlreadyExists`, `ErrVolumeNotFound` | `LibExecutor.Create`/`Unlock` |
| `*ExecutorError{Operation, Path, Err}` | Every other `LibExecutor` failure |
| `ErrKeyringUnavailable` / `*KeyringError{Err}` | `EnsureKeyringAvailable`, when the kernel keyring preflight fails |
| `ErrTPMNoTransport` | `NewTPMSealer(nil, _)` |
| `ErrInvalidSealParent` / `*SealParentInvalidError{Raw, Value}` | `SealParent.Validate`, `ParseSealParent`, `TPMSealerConfig.Validate` |
| `ErrInvalidPCRBank` | `TPMSealerConfig.Validate`, `resolvePCRBank` |
| `ErrTPMPCRSelectionNotSupported` | `SealPassphrase` under `SealParentPSRK` with a non-empty `pcrs` |
| `ErrTPMPolicyFailed` | `SealPassphrase` under `SealParentSSRK`, when `computePCRPolicyDigest` fails |
| `ErrTPMSealFailed` | `SealPassphrase`, on `rand.Read`, secure-buffer construction, or `tpm.Seal` failure |
| `ErrTPMUnsealFailed` | `UnsealPassphrase` under `SealParentPSRK`, on `tpm.Unseal` failure |
| `ErrTPMSSRKUnsealUnsupported` | `UnsealPassphrase` under `SealParentSSRK`, always |
| `ErrTPMInvalidToken` | `UnsealPassphrase` (nil token, bad blob), `DecodeTPMSealBlobs` |

`errs.Joined{Lead, Detail, Cause}`, `errs.Detail{Err, Detail}` and
`errs.Wrapped{Msg, Err}` (`pkg/errs`) all implement `Unwrap`, so
`errors.Is`/`errors.As` see through them to the sentinel.

## Config surface

There is **no** `pkg/config` (xkmsd YAML/env/flag) binding for any
`VolumeConfig`/`TPMSealerConfig` field. Both carry `yaml`/`json`/
`mapstructure` struct tags for future config-file wiring, following this
codebase's convention for config structs, but nothing currently loads them
from a file — they are plain Go struct fields set by the embedding caller.

## Tests

`pkg/luks` test files, by concern (all in-package, `package luks`):

- `config_test.go` — `VolumeConfig`/`TPMSealerConfig` `Validate`/
  `SetDefaults`, `DefaultKDF` under standard and FIPS builds, `SealParent`
  `String`/`Validate`/`ParseSealParent`.
- `manager_test.go` — `Manager` construction and every method's success,
  guard-error and executor-error paths.
- `executor_test.go` — `LibExecutor`'s full fault-injection matrix against
  faked `go-luks2` package vars (no real loop device, dm-crypt or mount),
  plus the package-level `IsLUKSVolume`/`IsMounted`/`IsUnlocked` functions.
- `keyring_test.go` — `EnsureKeyringAvailable`'s typed-error and
  probe-every-call behavior.
- `tpm_test.go` — `TPMSealer` construction, dispatch and error propagation
  against a fake `TPMSealUnsealer`; token blob encode/decode; PCR-selection
  building. No TPM, real or simulated.
- `tpm_simulator_test.go` — full PSRK and SSRK seal/unseal round trips, PCR
  state-change failure, and the empty-auth bypass proof, against a real
  `*pkg/tpm2.TPM2` wired to the go-tpm-tools simulator. Gated behind
  `-tags tpm_simulator`.

Run `GOWORK=off go test ./pkg/luks/...` for the non-simulator suite; add
`-tags "codec_cbor codec_json codec_msgpack tpm_simulator frost"` for the
full CI matrix including the TPM round trips.
