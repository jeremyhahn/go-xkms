# LUKS (root module) — Engineering Contract

> **Status: NORMATIVE** · Feature: `luks` · Repo: `go-xkms` · Last verified: 2026-09-24

Design rationale: [`architecture.md`](architecture.md). This document is the
exported surface, config keys, errors, and test inventory, each cited to
`path/file.go:Symbol` or a line range in `pkg/luks`.

## Package

`pkg/luks` (`pkg/luks/errors.go:14-18`, package doc): "Package luks provides
FIPS-aware LUKS volume configuration and lifecycle management. It wraps LUKS
volume operations with automatic KDF selection based on the runtime FIPS
policy and exposes an Executor interface so callers can supply
platform-specific implementations (or test mocks)."

Re-exported verbatim (types, consts, vars, no added logic) by
`sdk/go/luks` (`sdk/go/luks/luks.go`).

## Volume lifecycle

### `Executor` — `pkg/luks/manager.go:26-44`

```go
type Executor interface {
	Create(ctx context.Context, config *VolumeConfig, sizeBytes int64, passphrase string) error
	Unlock(ctx context.Context, config *VolumeConfig, passphrase string) error
	Lock(ctx context.Context, config *VolumeConfig) error
	IsMounted(config *VolumeConfig) bool
	IsUnlocked(config *VolumeConfig) bool
}
```

The seam a `cryptsetup`/`dmsetup`/mount-backed implementation fills in. **No
implementation of this interface exists anywhere in this repository or in
the `xkey` module** — verified by grep for the method set against
`*VolumeConfig`; the only implementations are `mockExecutor`
(`pkg/luks/manager_test.go`) and equivalents in the other `_test.go` files in
this package.

### `Manager` — `pkg/luks/manager.go:48-137`

| Symbol | Signature | Behavior |
|---|---|---|
| `NewManager` | `func NewManager(config *VolumeConfig, executor Executor) (*Manager, error)` | Applies `config.SetDefaults()`, then `config.Validate()`. Returns `ErrNilExecutor` for a nil executor. `pkg/luks/manager.go:58-70` |
| `NewFIPSAwareManager` | `func NewFIPSAwareManager(luksPath, mountPoint, mapperName string, executor Executor) (*Manager, error)` | Convenience constructor: builds a `VolumeConfig{LUKSPath, MountPoint, MapperName}` and delegates to `NewManager`. `pkg/luks/manager.go:75-82` |
| `(*Manager) Create` | `func (m *Manager) Create(ctx context.Context, sizeBytes int64, passphrase string) error` | Returns `ErrInvalidSize` if `sizeBytes <= 0`, `ErrEmptyPassphrase` if empty, else calls `Executor.Create` and wraps any error as `&errs.Joined{Lead: ErrOperationFailed, Cause: err}`. `pkg/luks/manager.go:86-97` |
| `(*Manager) Unlock` | `func (m *Manager) Unlock(ctx context.Context, passphrase string) error` | Returns `ErrEmptyPassphrase` if empty, else calls `Executor.Unlock`, wraps errors the same way, and sets `unlocked = true` on success. `pkg/luks/manager.go:101-110` |
| `(*Manager) Lock` | `func (m *Manager) Lock(ctx context.Context) error` | Calls `Executor.Lock`, wraps errors, and on success sets `unlocked = false` and `mounted = false`. `pkg/luks/manager.go:113-120` |
| `(*Manager) IsMounted` | `func (m *Manager) IsMounted() bool` | Reads the atomic `mounted` field. **Never set to `true` anywhere in this package** — see architecture.md "What Manager does not do". `pkg/luks/manager.go:124-126` |
| `(*Manager) IsUnlocked` | `func (m *Manager) IsUnlocked() bool` | Reads the atomic `unlocked` field, set by `Unlock`/`Lock`. `pkg/luks/manager.go:129-131` |
| `(*Manager) Config` | `func (m *Manager) Config() VolumeConfig` | Returns a value copy of the internal config. `pkg/luks/manager.go:135-137` |

### `VolumeConfig` — `pkg/luks/config.go:42-62`

Struct fields (there is no YAML/env/flag binding for any of these — see
"Config surface" below):

| Field | Type | Meaning | Required | Default |
|---|---|---|---|---|
| `LUKSPath` | `string` | Path to the LUKS container file | yes — empty fails `Validate` with `ErrInvalidConfig` | none |
| `MountPoint` | `string` | Directory the unlocked volume is mounted at | yes — same | none |
| `MapperName` | `string` | Device-mapper name under `/dev/mapper/` | yes — same | none |
| `KDF` | `KDFType` (`"argon2id"` \| `"pbkdf2"`) | Key-derivation function for LUKS keyslot processing | no | `DefaultKDF()` via `SetDefaults` |
| `PBKDFIterTime` | `int` | PBKDF2 iteration time in milliseconds | no | `2000` (matches the `cryptsetup` default, per the field's doc comment) |

`Validate()` (`pkg/luks/config.go:77-93`): returns `ErrInvalidConfig` for any
empty required field; returns `ErrInvalidKDF` if `KDF` is non-empty and not
one of `validKDFs` (`pkg/luks/config.go:37-40`, a map literal — O(1)
membership check, not a switch).

`SetDefaults()` (`pkg/luks/config.go:98-105`): fills `KDF` via `DefaultKDF()`
and `PBKDFIterTime` via the `defaultPBKDFIterTime` constant (`2000`,
`pkg/luks/config.go:31-33`) when zero-valued. Idempotent — a config that
already sets these fields is left unchanged (`TestVolumeConfig_SetDefaults_PreservesExistingKDF`,
`TestVolumeConfig_SetDefaults_PreservesExistingIterTime`,
`pkg/luks/config_test.go:184-206`).

### `KDFType` and `DefaultKDF` — `pkg/luks/config.go:18-33, 64-72`

```go
type KDFType string

const (
	KDFArgon2id KDFType = "argon2id" // non-FIPS default
	KDFPBKDF2   KDFType = "pbkdf2"   // required in FIPS 140 mode
)

func DefaultKDF() KDFType {
	if fips140.Enabled() {
		return KDFPBKDF2
	}
	return KDFArgon2id
}
```

`fips140.Enabled()` is the stdlib `crypto/fips140` signal (`GODEBUG=fips140=on|only`
or a `GOFIPS140` build) — no locally maintained approved-algorithm list.
`DefaultKDF`'s doc comment cites go-xkms#21 as the issue that wired this up.

## TPM 2.0 passphrase sealing

### `TPMOpener` / `TPMOpenerFunc` / `DefaultTPMOpener` — `pkg/luks/tpm.go:45-69`

```go
type TPMOpener interface {
	Open(ctx context.Context) (transport.TPMCloser, error)
}
type TPMOpenerFunc func(ctx context.Context) (transport.TPMCloser, error)
func DefaultTPMOpener() TPMOpener
```

`DefaultTPMOpener()` opens `/dev/tpmrm0` via `linuxtpm.Open`; on failure it
returns `&errs.Detail{Err: ErrTPMNoTransport, Detail: <os error>}`
(`pkg/luks/tpm.go:61-69`).

### `TPMSealer` — `pkg/luks/tpm.go:101-142`

```go
type TPMSealer struct { /* unexported: logger, opener, parentHandle, pcrBank */ }

func NewTPMSealer(logger *slog.Logger, opener TPMOpener) (*TPMSealer, error)
func (h *TPMSealer) WithParentHandle(handle uint32) *TPMSealer
```

- `NewTPMSealer(nil, nil)` → `ErrTPMNoTransport` (nil opener is rejected
  outright, `pkg/luks/tpm.go:119-122`). A nil `logger` is replaced with
  `slog.Default()`, not an error.
- `parentHandle` defaults to `DefaultTPMParentHandle = 0x81000001`
  (`pkg/luks/tpm.go:40-43`); `pcrBank` defaults to `TPMAlgSHA256`.
- `WithParentHandle(0)` resets to the default rather than persisting a zero
  handle (`pkg/luks/tpm.go:136-142`).

### `Seal` / `SealPassphrase` / `UnsealPassphrase`

| Method | Signature | Notes |
|---|---|---|
| `Seal` | `func (h *TPMSealer) Seal(ctx context.Context, handle string, pcrs []int32) ([]byte, []byte, error)` | Narrow handler-shaped API: calls `SealPassphrase`, copies the passphrase out of the `secure.Buffer`, calls `Destroy()` itself, and returns `(passphrase, tokenJSON, error)`. `pkg/luks/tpm.go:149-164` |
| `SealPassphrase` | `func (h *TPMSealer) SealPassphrase(ctx context.Context, handle string, pcrs []int32) (*TPMSealResult, error)` | Generates 32 random bytes (`crypto/rand`), seals them as a `TPMAlgKeyedHash` object under the resolved parent with an `AdminWithPolicy` PCR policy, and returns the full result including raw blobs. `pkg/luks/tpm.go:168-271` |
| `UnsealPassphrase` | `func (h *TPMSealer) UnsealPassphrase(ctx context.Context, tokenJSON []byte) ([]byte, error)` | Parses the token, loads the object under its recorded parent, replays the recorded PCR selection in a policy session, and unseals. `pkg/luks/tpm.go:276-345` |

`handle` in `Seal`/`SealPassphrase` is a decimal-or-`0x`-hex string resolved
by `resolveParentHandle` (`pkg/luks/tpm.go:354-370`); empty uses the sealer's
configured `parentHandle`. An unparseable value returns
`&errs.Detail{Err: ErrTPMInvalidHandle, ...}`.

### `TPMToken` — `pkg/luks/tpm.go:71-82`

```go
type TPMToken struct {
	Type         string   `json:"type"`
	Keyslots     []string `json:"keyslots"`
	TPM2Blob     string   `json:"tpm2-blob"`
	TPM2PCRBank  string   `json:"tpm2-pcr-bank"`
	TPM2PCRs     []int    `json:"tpm2-pcrs"`
	TPM2Handle   uint64   `json:"tpm2-key-handle"`
	TPM2PolicyHA string   `json:"tpm2-policy-hash,omitempty"`
}
```

`Type` is always `TPMTokenType = "systemd-tpm2"` (`pkg/luks/tpm.go:36-38`) —
chosen to match `systemd-cryptsetup`'s own token type name so third-party
tooling can still recognize the slot. `Keyslots` is present in the struct
(for the LUKS2 token schema) but is never populated by `SealPassphrase` —
populating it is the caller's responsibility when it adds the sealed
passphrase to an actual LUKS2 keyslot.

### `TPMSealResult` — `pkg/luks/tpm.go:84-99`

```go
type TPMSealResult struct {
	Passphrase   *secure.Buffer // sdk/go/secure, an mlocked/canary-guarded buffer
	TokenJSON    []byte
	PublicBlob   []byte
	PrivateBlob  []byte
	PolicyDigest []byte
}
```

Invariant stated in the doc comment: "Callers MUST call `Passphrase.Destroy()`
once the passphrase has been persisted... or otherwise consumed." `secure.Buffer`
is a type alias onto go-qrdb's `secure.Buffer`
(`sdk/go/secure/secure.go:36`) — `pkg/luks` reaches it only through the SDK
boundary, not a `pkg/*` import of go-qrdb, matching the SDK-boundary rule.

### Blob packing — `pkg/luks/tpm.go:474-509`

```go
func EncodeTPMSealBlobs(public, private []byte) string
func DecodeTPMSealBlobs(s string) ([]byte, []byte, error)
```

Wire format: `base64(uint32BE(len(public)) | public | private)`.
`DecodeTPMSealBlobs` returns `ErrTPMInvalidToken` for invalid base64, a
too-short payload (`< 4` bytes), or a length prefix that overruns the
buffer.

## Errors — `pkg/luks/errors.go:22-85`

All are package-level sentinel `error` values built with `errors.New`, meant
to be matched with `errors.Is`. Operational failures are surfaced wrapped in
`*errs.Detail` or `*errs.Joined` (`pkg/errs`), never as bare
`fmt.Errorf`-formatted strings, so the sentinel below is always reachable
via `errors.Is`/`errors.As` even when detail text is appended.

| Sentinel | Message | Raised by |
|---|---|---|
| `ErrNotMounted` | `luks: volume is not mounted` | Declared for callers; not returned by any function in this package today (`IsMounted` never becomes `true`, so nothing currently branches on it) |
| `ErrAlreadyMounted` | `luks: volume is already mounted` | Declared; not returned by any function in this package today |
| `ErrNotUnlocked` | `luks: volume is not unlocked` | Declared; not returned by any function in this package today |
| `ErrAlreadyUnlocked` | `luks: volume is already unlocked` | Declared; not returned by any function in this package today |
| `ErrInvalidConfig` | `luks: invalid configuration` | `VolumeConfig.Validate()` — missing `LUKSPath`/`MountPoint`/`MapperName` |
| `ErrEmptyPassphrase` | `luks: passphrase must not be empty` | `Manager.Create`, `Manager.Unlock` |
| `ErrInvalidSize` | `luks: size must be positive` | `Manager.Create` |
| `ErrInvalidKDF` | `luks: unsupported KDF type` | `VolumeConfig.Validate()` |
| `ErrOperationFailed` | `luks: operation failed` | `Manager.Create`/`Unlock`/`Lock`, as the `Lead` of an `errs.Joined` wrapping the `Executor`'s error |
| `ErrNilExecutor` | `luks: executor must not be nil` | `NewManager` |
| `ErrTPMNoTransport` | `luks: no tpm transport available` | `DefaultTPMOpener` (no `/dev/tpmrm0`), `NewTPMSealer` (nil opener) |
| `ErrTPMPolicyFailed` | `luks: tpm pcr policy digest failed` | `SealPassphrase`, when `computePCRPolicyDigest` fails |
| `ErrTPMSealFailed` | `luks: tpm seal failed` | `SealPassphrase`, on `rand.Read`, `TPM2_Create`, secure-buffer construction, or token marshal failure |
| `ErrTPMUnsealFailed` | `luks: tpm unseal failed` | `UnsealPassphrase`, on `TPM2_Load`, policy-session, `PolicyPCR`, or `TPM2_Unseal` failure |
| `ErrTPMInvalidHandle` | `luks: invalid tpm handle` | `resolveParentHandle`, on an unparseable handle string |
| `ErrTPMInvalidToken` | `luks: invalid tpm token payload` | `UnsealPassphrase` (bad JSON), `DecodeTPMSealBlobs` (bad base64 or length) |

`errs.Joined{Lead, Detail, Cause}` and `errs.Detail{Err, Detail}` are defined
in `pkg/errs/errs.go:49-61, 89-110` and both implement `Unwrap` so
`errors.Is`/`errors.As` see through them to the sentinel.

## Config surface

There is **no** `pkg/config` (xkmsd YAML/env/flag) binding for any
`VolumeConfig` or `TPMSealer` field — verified: no match for `luks` (any
case) in `pkg/config/*.go`, and the only `VolumeConfig{...}` literal outside
`pkg/luks` itself is inside `NewFIPSAwareManager`. `VolumeConfig` fields are
plain Go struct fields set by the embedding Go caller (the SDK, or a future
`xkmsd` wiring), not deployment configuration. If `xkmsd` grows a LUKS
volume of its own, that wiring does not exist yet and should be documented
here when it does.

## Tests

`pkg/luks` test files, by concern (all in-package, `package luks`):

- `config_test.go` — `VolumeConfig.Validate`/`SetDefaults`, `DefaultKDF`
  under standard and FIPS builds.
- `manager_test.go` — `NewManager`/`NewFIPSAwareManager` construction,
  `Create`/`Unlock`/`Lock` success and executor-error paths, state tracking.
- `tpm_test.go` — sealer construction, `resolveParentHandle`,
  `EncodeTPMSealBlobs`/`DecodeTPMSealBlobs`, PCR-selection building — the
  non-TPM-hardware-dependent surface.
- `tpm_gaps_test.go` — additional edge cases for the same non-hardware
  surface.
- `tpm_simulator_test.go`, `tpm_simulator_fault_test.go` — full seal/unseal
  round trips and induced-fault paths against a software TPM, gated behind
  the `tpm_simulator` build tag (`//go:build tpm_simulator`).

Run with `GOWORK=off go test ./pkg/luks/...` for the non-simulator suite;
add `-tags tpm_simulator` for the hardware-shaped round-trip tests.
