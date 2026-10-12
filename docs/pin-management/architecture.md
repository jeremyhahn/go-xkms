# PIN Management — Architecture

> **Status: NORMATIVE** · Feature: `pin-management` · Repo: `go-xkms` · Last verified: 2026-10-12

## The problem

Hardware credentials are gated by PINs, and every kind of hardware gates them
differently. A TPM has hierarchy passwords and a dictionary-attack lockout with
its own recovery rules. A PKCS#11 token has a security-officer PIN and a user
PIN and a retry counter that ends in a permanently bricked token. Software has
neither.

go-qrdb defines the `PINBackend` interface — one vocabulary for "set, change,
verify, lockout" — and has zero hardware coupling. This feature is go-xkms
supplying the hardware implementations behind it, plus the logic that picks one.

## Shape chosen: selection by availability, in a declared preference order

`pkg/pinselect.Select(cfg) (qrdbsdk.PINBackend, error)` walks a preference list
and returns the first backend whose device is actually present:

```go
var DefaultPreference = []qrdbsdk.PINStrategyID{
	qrdbsdk.PINStrategyTPM2,
	qrdbsdk.PINStrategyPKCS11,
	qrdbsdk.PINStrategySoftware,
}
```

TPM first, then a PKCS#11 token, then software. `Config.TPM` and
`Config.PKCS11` are optional — nil means "this environment has no such device"
— and `Config.Software` is **required**, so `Select` always resolves unless the
software provider's storage cannot be opened. It logs exactly one line naming
the strategy it chose, which is the difference between a deployment you can
audit and one where nobody knows what protected the PIN.

Rejected alternatives:

- **Configuring the backend explicitly per deployment.** Rejected: the same
  image ships to a node with a TPM and a laptop without one, and a hard-coded
  choice fails on one of them.
- **Probing at every operation.** Rejected: a TPM or token probe costs a session
  and can advance a lockout counter.
- **Silently falling back on error.** Not what happens — `Select` skips a
  provider that reports itself *unavailable*, which is different from one that
  is present and failing. A present-but-failing device produces an error, not a
  downgrade to software.

## Component boundaries

| Piece | Package | Owner |
|---|---|---|
| `PINBackend` interface, `PINStrategyID`, `PINLockoutStatus`, `ErrPINNotSet` | `go-qrdb/sdk/go` | **go-qrdb** |
| `WithPINBackend` composition option | `go-qrdb/sdk/go` | **go-qrdb** |
| Backend selection | `pkg/pinselect` | go-xkms |
| TPM2 PIN backend | `pkg/pintpm2` | go-xkms |
| PKCS#11 PIN backend | `pkg/pkcs11` | go-xkms |
| Wire surface | `pkg/api/rest/handlers_pin.go`, `pkg/api/grpc/service_pin.go` | go-xkms |

This is capability row **"TPM2 / PKCS#11 PIN backends" (tier 2)** —
composition-plane, registered into go-qrdb via `WithPINBackend`.

## The TPM2 backend is deliberately asymmetric

`pkg/pintpm2.TPM2Backend` is not a generic PIN store. Reading its methods tells
you the model:

```go
func (b *TPM2Backend) Strategy() qrdbsdk.PINStrategyID { return qrdbsdk.PINStrategyTPM2 }
func (b *TPM2Backend) SetSOPIN(_, _ string) error      { return qrdbsdk.ErrPINNotSet }
func (b *TPM2Backend) ChangeSOPIN(_, _ string) error   { return qrdbsdk.ErrPINNotSet }
func (b *TPM2Backend) VerifySOPIN(_ string) error      { return qrdbsdk.ErrPINNotSet }
func (b *TPM2Backend) SOPINSet() bool                  { return false }
```

**There is no SO PIN on the TPM2 backend.** The TPM's administrative
authorization is its hierarchy passwords — endorsement, lockout, owner — held by
the platform, not by a PIN the KMS sets. Returning `ErrPINNotSet` says exactly
that, rather than pretending an SO PIN exists and silently doing nothing.

The user PIN is real: `SetUserPIN`, `ChangeUserPIN`, `VerifyUserPIN`,
`UserPINSet()`, and a `PlatformAuthProvider` seam
(`pkg/pintpm2/providers.go`) that supplies the platform authorization.
`IsInitialized()` reports `platformStore.IsProvisioned()` — the backend is only
usable once the platform is provisioned.

Two further capabilities are TPM-specific: `GetLockoutStatus()` reflects the
TPM's dictionary-attack state, `ResetLockout(lockoutAuth)` clears it using the
TPM's lockout authorization, and `VerifyFIDO2Hash(hash []byte)` supports the
FIDO2-derived unlock path.

## Data flow

```
composition:
  pinselect.Select(Config{TPM: …, PKCS11: …, Software: …})
    → first available in Preference order
    → logs "PIN backend selected  strategy=<id>"
    → qrdb's WithPINBackend(backend)

operation:
  xkmsctl pin user-set --new-pin -   →  POST /api/v1/pin/user/set
    → qrdb's PIN service → PINBackend.SetUserPIN
      → TPM2: platform auth; PKCS#11: token; software: local store
```

## Trust boundaries

- **A PIN is never logged, echoed, or put on a command line by design.** Every
  `xkmsctl pin` flag accepts `-` to read stdin, and prompts when omitted. The
  literal-value form exists for automation and puts the PIN in shell history.
- **Lockout is a real, sometimes terminal, state.** A PKCS#11 token that
  exhausts its retry counter is permanently unusable. `GetLockoutStatus` is not
  informational decoration.
- **`ResetLockout` requires the lockout authorization**, which is a different
  and higher credential than the user PIN.
- **The selected strategy is a security property.** A deployment that expected
  TPM2 and silently got software has a much weaker PIN store; the single
  selection log line is how you find out.
- **`VerifyFIDO2Hash` accepts a hash, not a PIN.** It exists so a FIDO2-derived
  secret can stand in for the PIN; whatever produces that hash inherits the
  PIN's authority.

## What this feature deliberately does not do

- **It does not define the `PINBackend` interface** or the PIN service. Those
  are go-qrdb's; go-xkms implements and registers.
- **It does not unify PINs across subsystems.** See the note below.
- **It does not store PINs itself.** Each backend delegates to its device or to
  qrdb's software store.

## Note on the "unified PIN architecture" design

The legacy `docs/architecture/pin-architecture.md` and
`docs/fido2/authenticator/architecture.md`, both absorbed and deleted
(go-xkms#1433), described a **`PINCoordinator`** that fans a PIN change out
across FIDO2, PKCS#11 and file-based subsystems, backed by a `pkg/pin` package.

**Neither exists in this repository.** There is no `PINCoordinator` type and no
`pkg/pin` directory, so the coordinator design was dropped, not carried over.
What does exist is `pkg/pinselect`, `pkg/pintpm2`, the PKCS#11 backend, and
xkey's own authenticator PIN state. Its one cross-subsystem link is xkey's
`UnifiedPIN` setting (`xkey/pkg/authenticator/config.go:468-476`). It mirrors
the host user PIN into the FIDO2 authenticator's CTAP2 PIN hash and does not
touch PKCS#11 or file PINs. Within the authenticator, a FIDO2 PIN set before the
SO PIN is configured sets `PINSyncPending`
(`xkey/pkg/authenticator/types.go:166-168`), and the next SO unlock wires it to
the CMK (`xkey/pkg/authenticator/key_manager.go:467-478`). Both are documented in
[`../../xkey/docs/virtual-authenticator/`](../../xkey/docs/virtual-authenticator/architecture.md).
