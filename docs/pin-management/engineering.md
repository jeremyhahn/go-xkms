# PIN Management — Engineering Contract

> **Status: NORMATIVE** · Feature: `pin-management` · Repo: `go-xkms` · Last verified: 2026-08-19

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

### `pkg/pintpm2`

```go
type PlatformAuthProvider interface { /* supplies TPM platform authorization */ }

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
func (b *TPM2Backend) Close()
```

The interface, `PINStrategyID`, `PINLockoutStatus` and `ErrPINNotSet` are
**go-qrdb's**, reached through `go-qrdb/sdk/go` only.

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
- **Concurrency.** `UserPINSet()` is backed by an atomic; the backend is safe for
  concurrent verification. Device access is serialised where the device demands
  it.

## Error semantics

`pkg/pinselect/errors.go` and the qrdb PIN vocabulary.

| Error | Meaning |
|---|---|
| `ErrNoSoftwareProvider` | `Config.Software` was nil — a construction bug |
| `qrdbsdk.ErrPINNotSet` | this backend has no such PIN (every SO method on TPM2) |
| auth failure | wrong PIN; `buildAuthFailureError` distinguishes it from a device error |
| lockout | the device is refusing further attempts |

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

xkey's authenticator keeps a separate PIN state (`state.PINHash` in
`xkey/pkg/authenticator`) for the virtual FIDO2 authenticator. It is a distinct
subsystem, not a view of this one — see the note in
[`architecture.md`](architecture.md).

## Test strategy

- **Unit** — `pkg/pinselect/pinselect_test.go` (preference order, skipping,
  `ErrNoSoftwareProvider`), `pkg/pinselect/errors_test.go`,
  `pkg/pintpm2/backend_test.go`.
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
