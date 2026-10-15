# PIN Management — Engineering Contract

> **Status: NORMATIVE** · Feature: `pin-management` · Repo: `go-xkms` · Last verified: 2026-10-12

## Exported surface

### `pkg/pinselect`

```go
var DefaultPreference = []qrdbsdk.PINStrategyID{
	qrdbsdk.PINStrategyTPM2,
	qrdbsdk.PINStrategyPKCS11,
	qrdbsdk.PINStrategySoftware,
}

type TPMProvider interface      { PlatformAuth() (pintpm2.PlatformAuthProvider, bool) }
type PKCS11Provider interface   { /* token presence + backend */ }
type SoftwareProvider interface { /* mandatory fallback */ }

type Config struct {
	TPM        TPMProvider                // nil = no TPM in this environment
	PKCS11     PKCS11Provider             // nil = no token in this environment
	Software   SoftwareProvider           // REQUIRED
	Preference []qrdbsdk.PINStrategyID    // empty = DefaultPreference
	Logger     *slog.Logger               // nil = slog.Default()
}

func Select(cfg Config) (qrdbsdk.PINBackend, error)
```

`Select` returns `ErrNoSoftwareProvider` when `Config.Software` is nil. Unknown
strategy IDs in `Preference` are skipped; software should always appear last so
`Select` can resolve. It emits exactly one decision line:
`"PIN backend selected" strategy=<id>`.

#### Governing strategy: `Resolve`

`Select` makes a choice; `Resolve` makes it once and records it. xkmsd, the
xKey GUI, `xkey pin` and `xkey extension serve` all call `Resolve`, so a PIN
set through one authenticates through the others (go-xkms#307). xKey reaches it
as `xkmssdk.ResolvePINBackend`.

```go
const StrategyAuto qrdbsdk.PINStrategyID = "auto"

type ResolveConfig struct {
	Config                            // providers, as for Select
	PINDir   string                   // <PINDir>/strategy holds the record
	Strategy qrdbsdk.PINStrategyID    // StrategyAuto/"" or an explicit ID
}

func Resolve(cfg ResolveConfig) (qrdbsdk.PINBackend, qrdbsdk.PINStrategyID, error)
func StrategyPath(pinDir string) string
func LoadStrategy(pinDir string) (qrdbsdk.PINStrategyID, error) // ErrStrategyNotPersisted
func SaveStrategy(pinDir string, strategy qrdbsdk.PINStrategyID) error
func NewTPMProvider(acquire TPMAcquireFunc, persistedTPM2 bool, log *slog.Logger) TPMProvider
```

| Record | Configured | Result |
|---|---|---|
| none | auto | `Select`, then record the choice |
| none | explicit | build exactly that backend, then record it |
| X | auto or X | build exactly X |
| X | Y ≠ X | `*StrategyMismatchError`: switching would orphan every PIN set under X |

A governing provider that cannot answer is `*ProviderUnavailableError`, never a
fallback to software. An unknown ID is `*UnknownStrategyError`. A refused build
records nothing.

`NewTPMProvider` offers the TPM only when its `PlatformKeyStore` exists, and
only when the Platform SRK's auth is confirmed or TPM2 already governs (recorded
or explicitly configured). An inherited SRK with an unknown auth value is never
silently adopted.

`pkg/tpm2.AttachPlatformKeyStore(logger, tpm, backend)` is how xkmsd and xKey
give a TPM its one `PlatformKeyStore`. It returns the existing store if there
is one.

#### xkmsd

`pin.strategy` is `auto` (the default), `software` or `tpm2`; any other value
is `*ErrUnknownPINStrategy`. PIN state lives in `<datastore.path>/pin`. `tpm2`
needs `backends.tpm2.enabled`; the PIN is the auth value of that TPM's Platform
SRK. Without the backend, startup fails with `*ProviderUnavailableError`.

### `pkg/pintpm2`

```go
type PlatformAuthProvider interface {
	VerifyAuth(pin string) error
	ChangeAuth(currentPIN, newPIN string) error
	GetLockoutInfo() (failedAttempts, maxFail, interval, recovery int, err error)
	DictionaryAttackLockoutReset(lockoutAuth []byte) error
	IsProvisioned() bool
	IsAuthReady() bool
}

type TPM2Backend struct{ /* implements qrdbsdk.PINBackend */ }
func NewTPM2Backend(platformStore PlatformAuthProvider) *TPM2Backend

func (b *TPM2Backend) Strategy() qrdbsdk.PINStrategyID
func (b *TPM2Backend) SetSOPIN(_, _ string) error                 // ErrPINNotSet
func (b *TPM2Backend) ChangeSOPIN(_, _ string) error              // ErrPINNotSet
func (b *TPM2Backend) VerifySOPIN(_ string) error                 // ErrPINNotSet
func (b *TPM2Backend) SOPINSet() bool                             // false
func (b *TPM2Backend) SetUserPIN(_ string, newUserPIN string) error
func (b *TPM2Backend) ChangeUserPIN(currentUserPIN, newUserPIN string) error
func (b *TPM2Backend) VerifyUserPIN(p string) error
func (b *TPM2Backend) UserPINSet() bool
func (b *TPM2Backend) IsInitialized() bool                        // platformStore.IsProvisioned()
func (b *TPM2Backend) GetLockoutStatus() *qrdbsdk.PINLockoutStatus
func (b *TPM2Backend) ResetLockout(lockoutAuth string) error
func (b *TPM2Backend) VerifyFIDO2Hash(hash []byte) bool
func (b *TPM2Backend) Close() error                               // ErrFIDO2HashDestroyFailed
```

The interface, `PINStrategyID`, `PINLockoutStatus` and `ErrPINNotSet` are
**go-qrdb's**, reached through `go-qrdb/sdk/go` only.

The FIDO2 hash `VerifyFIDO2Hash` checks is the CTAP2 one, `SHA-256(PIN)[:16]`
(`pkg/pintpm2/backend.go:267`).

`PlatformAuthProvider` is declared at `pkg/pintpm2/providers.go:22`;
`*tpm2.PlatformKeyStore` implements it. `IsProvisioned` and `IsAuthReady` answer
different questions: an SRK left by a prior TPM owner is provisioned, but its
auth value is unknown. `TPM2Backend` asserts both qrdb contracts at compile time,
`qrdbsdk.PINBackend` and `qrdbsdk.FIDO2HashVerifier` (`backend.go:36-39`).

How the TPM2 backend behaves:

- **Construction.** `NewTPM2Backend` reports `UserPINSet()` true only when the
  provider is provisioned **and** auth-ready (`backend.go:75-81`).
  Verification still runs whenever the SRK is provisioned.
- **PIN length.** `SetUserPIN` and `ChangeUserPIN` refuse a new PIN shorter
  than 6 characters with `qrdbsdk.ErrPINTooShort` (`backend.go:43`, `:314-317`).
  This is the same minimum as qrdb's software backend.
- **`SetUserPIN`** does not set anything on the TPM. It verifies the PIN
  against the SRK's existing auth value, and a mismatch is
  `qrdbsdk.ErrPINInvalid` (`backend.go:98-110`).
- **`VerifyUserPIN`** returns `qrdbsdk.ErrPINNotSet` on an unprovisioned
  platform (`backend.go:162-181`). On success, if no live hash enclave exists
  (for example after a restart), it caches the FIDO2 hash then.
- **`ChangeUserPIN`** goes through `ChangeAuth` (`backend.go:119-151`). When
  the change fails, the backend re-reads `IsAuthReady`. If the provider is no
  longer ready, it drops the cached FIDO2 hash.
- **Auth-failure detection** is string matching on the provider's error
  (`bad_auth`, `auth_fail`, `auth verification failed`). This keeps the
  package free of go-tpm types (`providers.go:53-61`).
- **An auth failure carries the lockout counters** (`backend.go:249-264`):
  - `*qrdbsdk.PINTPMLockedError` once `failedAttempts >= maxFail`;
  - `*qrdbsdk.PINInvalidWithStatusError` before that;
  - plain `qrdbsdk.ErrPINInvalid` when the counters cannot be read.
- **`GetLockoutStatus`** returns `nil` when the counters cannot be read
  (`backend.go:198-209`).

`PlatformKeyStore.SetAuthReady(bool)` is for a caller that has confirmed the SRK
auth by other means (`pkg/tpm2/platform_keystore.go:621-626`). A persisted
`pin.strategy` does not count as such a means: it records which backend was
chosen, not that this process checked the auth value.

### Platform SRK — `pkg/tpm2.PlatformKeyStore`

The user PIN of the TPM2 backend is the auth value of the Platform SRK.
`PlatformKeyStore` holds it.

- `EnrollPlatformSRK(soPIN, userPIN string)` is the first-boot enrollment
  (`pkg/tpm2/platform_keystore.go:323`). `soPIN` is the owner-hierarchy auth,
  and is needed only when that hierarchy has one. The call:
  - refuses an empty `userPIN` with `ErrPlatformSRKEnrollEmptyPIN`;
  - refuses a store whose auth is already known-good with
    `ErrPlatformSRKAlreadyEnrolled`;
  - otherwise runs `Initialize`.
- When the owner hierarchy has an auth value that was not supplied, the
  TPM answers `TPM_RC_BAD_AUTH`. Enrollment then returns
  `ErrPlatformSRKHierarchyAuth` joined with that TPM error
  (`platform_keystore.go:278`).
- `VerifyAuth(userPIN)` (`platform_keystore.go:502`):
  - on success, marks the auth ready (`IsAuthReady`);
  - maps a TPM auth failure to `ErrAuthFailed`;
  - returns any other TPM fault as is.
- `ChangeAuth(currentPIN, newPIN)` verifies `currentPIN` first
  (`platform_keystore.go:526`). The change evicts and re-persists the SRK. If
  it fails part-way, the auth is marked not-ready and the store re-probes
  whether an SRK still exists at the handle, so a retry through `Initialize`
  takes the right branch.
- The PIN SRK is created with `NoDA` cleared (`rsaSRKTemplateWithDA`,
  `enableDAOnSRK`, `platform_keystore.go:710`, `:718`). Wrong PINs therefore
  count against the TPM dictionary-attack lockout that `GetLockoutStatus`
  reports.

## Invariants

- **The TPM2 backend has no SO PIN, permanently.** All four SO methods return
  `qrdbsdk.ErrPINNotSet` and `SOPINSet()` returns `false`. This is not a stub to
  fill in later — TPM administrative authorization is hierarchy passwords held
  by the platform, not a KMS-managed PIN. Implementing them would be modelling
  something the TPM does not have.
- **`Select` skips unavailable, it does not swallow failures.** A nil provider,
  or a TPM whose `PlatformAuth()` reports not-ok, is skipped. A device that is
  present and erroring surfaces the error.
- **`Select` logs its choice exactly once.** Do not make it silent; the chosen
  strategy is the deployment's actual PIN security level.
- **`IsInitialized()` gates everything on the TPM2 backend.** Before the
  platform is provisioned, there is nothing to hold a PIN.
- **Lockout state is device state, not process state.** It survives restart, and
  on a PKCS#11 token exhausting the retry counter is terminal.
- **`ResetLockout` takes the lockout authorization**, which is distinct from and
  stronger than the user PIN.
- **`VerifyFIDO2Hash` grants PIN-equivalent authority.** Treat the hash as
  PIN-strength material.
- **The cached FIDO2 hash lives in protected memory.** `TPM2Backend` caches
  it in a go-enclave `MemoryEnclave` (mlock'd, guard-paged, wiped on
  release), never a plain `[]byte`, per the stack-wide protected-memory
  mandate. The enclave is admitted through `enclave.ProcessAllocator()`, the
  one locked-memory budget the process shares. `VerifyFIDO2Hash` compares via
  `MemoryEnclave.EqualTo` (constant-time, and fail-closed: a nil or destroyed
  enclave reports no match). `Close` destroys the enclave; safe to call more
  than once.
- **A hash that cannot be cached is an error, never a silent skip.** When the
  budget refuses the allocation, or the kernel refuses to lock the pages,
  `SetUserPIN`, `ChangeUserPIN` and `VerifyUserPIN` return
  `ErrFIDO2HashCacheFailed`. The TPM's decision still stands — the PIN is
  reported set — but any previously cached hash is destroyed, so
  `VerifyFIDO2Hash` never accepts the hash of a PIN the TPM no longer holds.
- **Concurrency.** `UserPINSet()` is backed by an atomic; the backend is safe for
  concurrent verification. Device access is serialised where the device demands
  it.
- **The PIN surface is platform-scoped and reached only through the service**
  (go-xkms#1227). Every `XKMSService` PIN method refuses a tenant-scoped
  caller with `*xkms.TenantBindingError` before the backend is touched
  (`pkg/xkms/servicer_pin.go:43,54,65,76,87,98,109,136`). REST
  (`pkg/api/rest/handlers_pin.go`), gRPC/Unix
  (`pkg/api/grpc/service_pin.go`) and MCP (`pkg/api/mcp/handlers_pin.go`)
  call those methods; none holds the `PINBackend`, and `rest.Config` no longer
  has a `PINManager` field. The password store's own user-PIN check
  (`pkg/xkms/servicer_password.go`) calls the backend directly and is not
  affected: a tenant unlocking its own vault still verifies the PIN.
- **A backend without lockout tracking reports none.** `GetLockoutStatus`
  answers a zero-valued status when the backend returns `nil` (the software
  backend does) (`pkg/xkms/servicer_pin.go:116`); before go-xkms#1227 the REST
  and MCP paths dereferenced the `nil` and panicked.

## Error semantics

`pkg/pinselect/errors.go`, `pkg/pintpm2/errors.go` and the qrdb PIN vocabulary.

| Error | Meaning |
|---|---|
| `ErrNoSoftwareProvider` | `Config.Software` was nil — a construction bug |
| `qrdbsdk.ErrPINNotSet` | this backend has no such PIN (every SO method on TPM2) |
| `qrdbsdk.ErrPINTooShort` | new user PIN under 6 characters |
| `qrdbsdk.ErrPINInvalid` | wrong PIN on `SetUserPIN`, or on verify/change when lockout counters are unreadable |
| `*qrdbsdk.PINInvalidWithStatusError` | wrong PIN, with the TPM DA counters |
| `*qrdbsdk.PINTPMLockedError` | the TPM DA counter is exhausted; the device refuses further attempts |
| `tpm2.ErrAuthProbeRejected` | the TPM refused the auth probe for a reason other than auth (`pkg/tpm2/auth.go:45`); passed through, never reported as a wrong PIN |
| `pintpm2.ErrFIDO2HashDestroyFailed` | `Close` could not wipe the hash enclave |
| `pintpm2.ErrFIDO2HashCacheFailed` | the TPM accepted the PIN but its FIDO2 hash could not be placed in locked memory; wraps `enclave.ErrBudgetExhausted`, `enclave.ErrLockedMemoryUnavailable` or `enclave.ErrLimitDiscoveryFailed` |

**Fail closed:** an unprovisioned platform, a locked-out device, a wrong PIN, an
absent device. None of them fall through to a weaker backend at operation time —
selection happens once, at composition.

## Configuration

Composed in-process, not by config file. What a composer supplies:

- **`Software` is mandatory.** Omitting it is the only way `Select` fails.
- **`TPM` / `PKCS11` nil** is the correct way to say "not in this environment" —
  do not supply a provider that always reports unavailable.
- **`Preference`** overrides the order. Software should stay last; putting it
  first silently disables hardware protection everywhere.
- **`Logger`** — leave it to `slog.Default()` or supply one, but do not discard
  it. That single line is the audit record of which PIN store is live.

## Persistence

Per backend: the TPM holds its own state (and its lockout counter); a PKCS#11
token holds its own; the software provider stores through go-qrdb. go-xkms
persists no PIN material of its own.

The virtual authenticator keeps a separate PIN state (`state.PINHash` in
`pkg/fido2/authenticator`) for the virtual FIDO2 authenticator. It is a distinct
subsystem, not a view of this one — see the note in
[`architecture.md`](architecture.md).

## Test strategy

- **Unit** — `pkg/pinselect/pinselect_test.go` (preference order, skipping,
  `ErrNoSoftwareProvider`), `pkg/pinselect/errors_test.go`,
  `pkg/pintpm2/backend_test.go`, and
  `pkg/pintpm2/backend_budget_test.go`, which re-executes the test under a
  one-page process allocator (`pkg/testing/enclavetest`) to pin the
  `ErrFIDO2HashCacheFailed` paths and the stale-hash discard.
- **Transport** — `pkg/api/rest/handlers_barrier_pin_test.go`,
  `pkg/api/grpc/service_barrier_pin_test.go`.
- **CLI** — `cmd/xkmsctl/pin.go` paths.
- **Integration** — `test/integration/tpm2`, `test/integration/pkcs11`.
- **Fault injection** — the TPM simulator suites cover auth failure and lockout;
  a lockout test must assert that the operation fails rather than falling back.

## Observability

One line at selection: `"PIN backend selected" strategy=<id>`. PIN operations
are audited through go-qrdb's PIN service. Lockout state is exposed through
`GET /api/v1/pin/lockout` so an operator can see a device approaching its limit
before it crosses it — which, on a PKCS#11 token, is the difference between a
reset and a replacement.
