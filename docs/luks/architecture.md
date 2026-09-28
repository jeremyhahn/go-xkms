# LUKS (root module) — Architecture

> **Status: NORMATIVE** · Feature: `luks` · Repo: `go-xkms` · Last verified: 2026-09-28

## Scope

`pkg/luks` is the root go-xkms module's LUKS support. It has two halves that
are packaged together but not wired to each other:

1. **Volume lifecycle** — `Manager`, `VolumeConfig`, `Executor`
   (`pkg/luks/manager.go`, `pkg/luks/config.go`): a FIPS-aware state machine
   for creating, unlocking, and locking one LUKS container, delegating the
   actual disk operations to a caller-supplied `Executor`.
2. **TPM 2.0 passphrase sealing** — `TPMSealer`
   (`pkg/luks/tpm.go`): seals and unseals a random LUKS passphrase against a
   TPM 2.0, producing a `systemd-tpm2`-compatible LUKS2 token.

Both halves are exported together as `pkg/luks` and re-exported verbatim by
`sdk/go/luks` (`sdk/go/luks/luks.go`).

This document is about `pkg/luks` only. Two other things in this repository
are also named "luks" and are **out of scope** here — see "Neighboring
packages named luks" below.

## Why the package exists

LUKS volume software needs two things a plain `cryptsetup` wrapper doesn't
give you: a KDF choice that respects the process's FIPS 140 policy, and (for
unattended systems) a way to protect the passphrase itself without a human
typing it in — hence the TPM sealer. `pkg/luks` provides both as small,
independently testable pieces, and leaves the actual `cryptsetup`/`dmsetup`
invocation to an injected seam rather than owning a subprocess dependency in
the root module.

## Volume lifecycle: `Manager` + `Executor`

`Manager` (`pkg/luks/manager.go:52-183`) tracks mount/unlock state with
`sync/atomic` (`mounted`, `unlocked` fields, lock-free reads via `IsMounted`/
`IsUnlocked`) and validates every request against that state before it
reaches disk (go-xkms#917):

- `Create` rejects `sizeBytes <= 0` (`ErrInvalidSize`) and an empty
  passphrase (`ErrEmptyPassphrase`) before calling the executor
  (`pkg/luks/manager.go:92-103`).
- `Unlock` rejects an empty passphrase, and `ErrAlreadyUnlocked` if the
  volume is already unlocked, before calling the executor
  (`pkg/luks/manager.go:108-120`).
- `Lock` rejects with `ErrNotUnlocked` if the volume is not currently
  unlocked, then clears both `unlocked` and `mounted` state on success
  (`pkg/luks/manager.go:124-134`).
- `Mount` rejects with `ErrNotUnlocked` if the volume is not unlocked and
  `ErrAlreadyMounted` if it is already mounted, then sets `mounted` on
  success (`pkg/luks/manager.go:139-151`).
- `Unmount` rejects with `ErrNotMounted` if the volume is not currently
  mounted, then clears `mounted` on success
  (`pkg/luks/manager.go:156-165`).

`Executor` (`pkg/luks/manager.go:26-50`) is the seam: "Production
implementations call cryptsetup, dmsetup, and mount; test code supplies
lightweight mocks." It declares `Create`, `Unlock`, `Lock`, `Mount`,
`Unmount`, `IsMounted`, `IsUnlocked`. Every `Executor` method receives the
full `*VolumeConfig`, which is how a `cryptsetup`-backed implementation is
expected to translate `VolumeConfig.KDF` into `cryptsetup luksFormat --pbkdf`
and `VolumeConfig.PBKDFIterTime` into `--iter-time` — `pkg/luks` defines the
contract but performs none of that translation itself. `Executor.IsMounted`/
`IsUnlocked` are live queries an implementation can use to reconcile state;
`Manager` does not call them itself — see "What `Manager` does not do" below.

**No concrete `Executor` implementation exists in this repository.** This was
verified by searching both the root module and the `xkey` module for anything
implementing the full method set against `*luks.VolumeConfig`; the only types
satisfying the interface are the mocks in `pkg/luks/manager_test.go`. `xkey`'s
own LUKS2 volume code (`xkey/pkg/luks`, driving `xkey luks2 *`) is a separate,
self-contained implementation built on `github.com/jeremyhahn/go-luks2` (see
`xkey/go.mod`, pinned at `v0.2.0-alpha`) — it does not implement
`luks.Executor` and does not construct a `luks.Manager`. See "Neighboring
packages named luks" below.

`github.com/jeremyhahn/go-luks2` is a pure-Go LUKS2 implementation — no
`cryptsetup` subprocess — already vetted and in production use by `xkey`
in this same repository, and is the library go-xkms#917's triage identified
for a `pkg/luks` production `Executor`. It is not yet a dependency of the
root `go-xkms` module (only of the `xkey` nested module), so adding it here
is an explicit, separate decision pending owner approval; wiring an
`Executor` implementation on top of it is tracked under go-xkms#917 rather
than done in the same change that wired the state machine below.

### What `Manager` does not do

`Manager.IsMounted` and `Manager.IsUnlocked` report internal `atomic.Bool`
state only, driven exclusively by `Mount`/`Unmount`/`Unlock`/`Lock`
succeeding — never by asking the executor or the OS. `Manager` never calls
`Executor.IsMounted`/`Executor.IsUnlocked`; those two `Executor` methods
exist for an implementation's own reconciliation use, not for `Manager`'s
state machine. A caller relying on `Manager.IsMounted()`/`IsUnlocked()` is
relying on this package's own bookkeeping, which is only as accurate as the
sequence of `Mount`/`Unmount`/`Unlock`/`Lock` calls that produced it — there
is still no concrete `Executor`, so nothing in this repository exercises
that bookkeeping against a real LUKS volume today.

### FIPS-aware KDF selection

`VolumeConfig.SetDefaults` (`pkg/luks/config.go:98-105`) fills an empty `KDF`
via `DefaultKDF()` (`pkg/luks/config.go:64-72`), which checks the Go
standard library's own FIPS state:

```go
func DefaultKDF() KDFType {
	if fips140.Enabled() {
		return KDFPBKDF2
	}
	return KDFArgon2id
}
```

`crypto/fips140.Enabled()` is the same stdlib signal used across go-xkms (see
`docs/fips/README.md`) — this package keeps no separate approved-algorithm
list of its own. Argon2id is the non-FIPS default (memory-hard, stronger
brute-force resistance); PBKDF2-HMAC-SHA256 is substituted in FIPS mode
because Argon2 is not FIPS-approved. The code comment on `DefaultKDF`
cites go-xkms#21 as the origin of this FIPS-policy hookup.

## TPM 2.0 passphrase sealing: `TPMSealer`

`TPMSealer` (`pkg/luks/tpm.go:114-123`) seals a freshly generated 32-byte
passphrase as a TPM keyed-hash object and returns a token payload shaped like
`systemd-cryptsetup`'s `"systemd-tpm2"` LUKS2 token
(`TPMTokenType = "systemd-tpm2"`, `pkg/luks/tpm.go:40`), so a volume sealed
this way is inspectable with the same tooling used to read `systemd-tpm2`
tokens. Every `Seal`/`Unseal` call opens a fresh TPM transport via the
injected `TPMOpener` and closes it before returning
(`pkg/luks/tpm.go:103-106`) — the sealer keeps no TPM session state between
calls, so it is safe to share across goroutines.

The passphrase crosses the TPM bus only encrypted, in both directions. The
sealer drives go-tpm on its own transport rather than through a
`pkg/tpm2.TPM2`, so it hands that transport to `pkg/tpm2`'s transport-level
session layer (`pkg/luks/tpm.go:107-113`): `CommandEncryptionSession` on
`TPM2_Create` and `ResponseEncryptionSession` on `TPM2_Unseal`, each a salted
session that authorizes nothing and exists only to encrypt the one parameter
carrying the passphrase. Salting is against an ephemeral NULL-hierarchy key,
so the SSRK parent and the EK are never touched. The session code exists once,
in `pkg/tpm2`; the rejected alternative — a second copy of the salt and
parameter-encryption logic inside `pkg/luks`, to keep its dependency set
small — would have been a parallel implementation of the TPM session layer.

### Parent key: the TCG Storage Root Key, not the go-xkms Platform SRK

`DefaultTPMParentHandle = 0x81000001` (`pkg/luks/tpm.go:42-45`). Cross-checked
against `pkg/tpm2/config.go:272-275`, handle `0x81000001` is documented there
as **the SSRK — the Shared Storage Root Key, the TCG-standard storage parent**
that "carries NO platform policy" and is provisioned once, untouched
thereafter. It is a *different* key from go-xkms's own Platform SRK (PSRK,
`PlatformSRKConfig` in the same file), which is bound to a platform PCR
measurement and lives at a different handle.

`pkg/luks.TPMSealer` seals under the SSRK, using `libtpm2.PasswordAuth(nil)`
— empty authorization — for the parent handle in both `Create`
(`pkg/luks/tpm.go:247-255`) and `Load` (`pkg/luks/tpm.go:323-331`). This is
the standard TCG pattern for a storage parent: the SRK's own authorization is
never a PIN in this codebase (`pkg/tpm2/config.go` confirms the SSRK is
"untouched" and carries no auth policy of its own); a TPM2_Create or
TPM2_Load under it needs no secret because the *child* object's own
authorization is what actually gates its use. `TPMSealer.WithParentHandle`
(`pkg/luks/tpm.go:143-151`) lets a caller point at a different persistent
handle, including a PSRK, but `pkg/luks` itself never does so by default, and
nothing in this package resolves or requires a USER PIN.

**This diverges from the project TPM rule** that go-xkms seals only under the
Platform SRK (PSRK), with USER PIN plus platform PCR policy authorization
(go-xkms#681). `pkg/luks` seals under the SSRK with empty parent auth. The
reason is systemd compatibility: `TPMTokenType` is `systemd-tpm2`, and
systemd-cryptsetup resolves the SRK at 0x81000001 when it unlocks at boot.
Whether to move to the PSRK (and give up systemd-cryptsetup unlock) or to
record an explicit exception is an open decision, tracked in go-xkms#917.
This document records what the code does today.

### Child object: PCR policy, not a password

The sealed keyed-hash object's own authorization is a PCR policy digest, built
by `computePCRPolicyDigest` (`pkg/luks/tpm.go:440-469`) via a trial
`PolicySession` + `PolicyPCR`, and bound into the object template as
`AdminWithPolicy: true` with no `UserAuth` (`pkg/luks/tpm.go:205-223`). Even
an empty PCR selection still produces a (trivial) policy
(`buildPCRSelection`, `pkg/luks/tpm.go:399-424`) — the comment at
`pkg/luks/tpm.go:195-199` explains this is deliberate: a keyed-hash object
with no policy at all would require `userAuth` instead, which this design
does not want. `UnsealPassphrase` (`pkg/luks/tpm.go:291-372`) replays the same
PCR selection recorded in the token and fails closed
(`ErrTPMUnsealFailed`) if the live PCR state does not satisfy it — there is
no fallback path that returns the passphrase without a policy match.

### Token format and blob packing

`TPMToken` (`pkg/luks/tpm.go:73-84`) carries the sealed object as a single
base64 field, `TPM2Blob`, packed by `EncodeTPMSealBlobs`
(`pkg/luks/tpm.go:505-522`) as `base64(uint32BE(len(public)) | public |
private)` and unpacked by `DecodeTPMSealBlobs`
(`pkg/luks/tpm.go:524-540`), which returns `ErrTPMInvalidToken` on a length
mismatch or bad base64 rather than panicking or silently truncating.

### Passphrase handling

`TPMSealResult.Passphrase` is a `*secure.Buffer`
(`sdk/go/secure` → go-qrdb's `secure` package, per the SDK-boundary rule),
not a plain `[]byte` — the doc comment on `TPMSealResult`
(`pkg/luks/tpm.go:86-101`) states the passphrase "lives in an mlocked,
canary-guarded `*secure.Buffer`... between `SealPassphrase` and the caller
consuming it," and requires the caller to call `Passphrase.Destroy()` once
consumed. The narrower `Seal` method (`pkg/luks/tpm.go:153-173`) copies the
bytes out of the buffer, destroys it itself via `defer`, and returns a plain
`[]byte` — used by "the narrow handler interfaces used by downstream LUKS
backends" per its own doc comment; callers of `Seal` do not manage the
secure buffer, callers of `SealPassphrase` do.

## Fail-closed behavior (verified)

- `NewManager` returns `ErrNilExecutor` for a nil executor and propagates
  `VolumeConfig.Validate()` errors before constructing anything
  (`pkg/luks/manager.go:58-70`).
- `Manager.Create`/`Unlock` refuse an empty passphrase or non-positive size
  before the executor is ever called (`pkg/luks/manager.go:86-110`).
- Every executor error is wrapped as `&errs.Joined{Lead: ErrOperationFailed,
  Cause: err}` (`pkg/luks/manager.go:93-96, 105-107, 114-116`) — a caller can
  `errors.Is(err, ErrOperationFailed)` without losing the underlying cause.
- `DefaultTPMOpener` returns `ErrTPMNoTransport` (wrapped with the OS error
  via `errs.Detail`) when `/dev/tpmrm0` cannot be opened, instead of silently
  proceeding without a TPM (`pkg/luks/tpm.go:60-71`).
- `NewTPMSealer(_, nil)` returns `ErrTPMNoTransport` rather than constructing
  a sealer that would fail later (`pkg/luks/tpm.go:125-141`).
- A PCR-policy mismatch, a load failure, or a malformed token all return a
  typed error (`ErrTPMUnsealFailed`, `ErrTPMInvalidToken`) — there is no code
  path in `UnsealPassphrase` that returns a zero-value or best-effort
  passphrase on failure.

## Neighboring packages named luks (out of scope here)

- **`pkg/storage/luks`** (root module) — a `storage.Backend` that wraps a
  `VolumeOperator` interface and fails closed (`ErrVolumeLocked`) until a
  volume is unlocked. It does **not** import `pkg/luks` — its
  `VolumeOperator` interface exists specifically "to prevent import cycles
  between the main module and the xkey module whose `luks.Volume` satisfies
  this contract" (`pkg/storage/luks/backend.go:20-23`). This is the
  fail-closed storage gate described in detail in
  [`../../xkey/docs/luks/architecture.md`](../../xkey/docs/luks/architecture.md)
  §"The gate: `pkg/storage/luks.Backend`" — read that document for its
  design, not this one.
- **`xkey/pkg/luks`** — xKey's own LUKS2 container implementation
  (`xkey luks2 create|unseal|lock|migrate|wipe`, `pkg/gui/services.StorageService`),
  built on `github.com/jeremyhahn/go-luks2`. This is the actual
  `cryptsetup`-equivalent code that runs in production today; it is
  documented in full in [`../../xkey/docs/luks/`](../../xkey/docs/luks/) and
  is not re-documented here.

## Consumers

Grepping the root module (and `xkey`, which is a separate Go module in the
same repository) for `"github.com/jeremyhahn/go-xkms/pkg/luks"` finds exactly
one importer: `sdk/go/luks/luks.go`, a type-and-value re-export with no
additional logic. Its own package comment states the intent: "Downstream
consumers (go-quicbaas SDK shims, go-trusted-platform's LUKS backend) reach
LUKS + TPM sealing through this package instead of importing
`go-xkms/pkg/luks` directly." Those downstream consumers live in other
repositories and are out of scope for this document under the cross-project
boundary; nothing in this repository currently calls the SDK re-export
either — `pkg/luks` is fully implemented and tested but has no in-tree
caller yet.
