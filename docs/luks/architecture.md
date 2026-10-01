# LUKS (root module) — Architecture

> **Status: NORMATIVE** · Feature: `luks` · Repo: `go-xkms` · Last verified: 2026-09-30

## Scope

`pkg/luks` is the root go-xkms module's LUKS support, and — as of
go-xkms#917 — the **single** LUKS implementation in this repository. It has
three parts:

1. **Volume lifecycle** — `Manager`, `VolumeConfig`, `Executor`
   (`pkg/luks/manager.go`, `pkg/luks/config.go`): a FIPS-aware state machine
   for creating, unlocking, mounting, unmounting and locking one LUKS
   container, delegating the actual disk operations to an `Executor`.
2. **Production `Executor`** — `LibExecutor` (`pkg/luks/executor.go`): the
   `go-luks2`-backed implementation of that seam. There is now exactly one
   production `Executor` in the stack; nothing else drives `cryptsetup`,
   `dmsetup`, loop devices or mounts.
3. **TPM 2.0 passphrase sealing** — `TPMSealer` (`pkg/luks/tpm.go`): seals
   and unseals a random LUKS passphrase against a TPM 2.0, parented to
   either go-xkms's own Platform SRK or the TCG Shared SRK (`SealParent`,
   `pkg/luks/config.go`).

All three are exported together as `pkg/luks` and re-exported by
`sdk/go/luks` (`sdk/go/luks/luks.go`), the only way any other module —
including `xkey` — is allowed to reach this package.

## Why the package exists

LUKS volume software needs two things a plain `cryptsetup` wrapper doesn't
give you: a KDF choice that respects the process's FIPS 140 policy, and (for
unattended systems) a way to protect the passphrase itself without a human
typing it in — hence the TPM sealer. Before go-xkms#917, this logic existed
twice: once here as an untested state machine with no production `Executor`,
and once in `xkey/pkg/luks` as a complete, working implementation driving
`github.com/jeremyhahn/go-luks2` directly. go-xkms#917 collapsed that into
one implementation, here, built on `go-luks2`; `xkey` now consumes it
through `sdk/go/luks` and keeps only what is genuinely desktop-specific
(privilege-drop chown after mount, secure wipe of a retired container — see
"Neighboring packages named luks" below).

## Volume lifecycle: `Manager` + `Executor`

`Manager` (`pkg/luks/manager.go`) tracks mount/unlock state with
`sync/atomic` (`mounted`, `unlocked` fields, lock-free reads via `IsMounted`/
`IsUnlocked`) and validates every request against that state before it
reaches disk:

- `Create` rejects `sizeBytes <= 0` (`ErrInvalidSize`) and an empty
  passphrase (`ErrEmptyPassphrase`) before calling the executor.
- `Unlock` rejects an empty passphrase, and `ErrAlreadyUnlocked` if the
  volume is already unlocked, before calling the executor.
- `Lock` rejects with `ErrNotUnlocked` if the volume is not currently
  unlocked, then clears both `unlocked` and `mounted` state on success.
- `Mount` rejects with `ErrNotUnlocked` if the volume is not unlocked and
  `ErrAlreadyMounted` if it is already mounted, then sets `mounted` on
  success.
- `Unmount` rejects with `ErrNotMounted` if the volume is not currently
  mounted, then clears `mounted` on success.

`Executor` (`pkg/luks/manager.go`) is the seam: "Production implementations
call cryptsetup, dmsetup, and mount; test code supplies lightweight mocks."
It declares `Create`, `Unlock`, `Lock`, `Mount`, `Unmount`, `IsMounted`,
`IsUnlocked`. `Executor.IsMounted`/`IsUnlocked` are live kernel queries an
implementation can use to reconcile state; `Manager` does not call them
itself (its own `IsMounted`/`IsUnlocked` report only the atomic bookkeeping
— see "What `Manager` does not do" below). A caller that wants the kernel's
own ground truth without a `Manager` calls `Executor.IsMounted`/`IsUnlocked`
directly, or the package-level `IsMounted`/`IsUnlocked`/`IsLUKSVolume`
functions (`pkg/luks/executor.go`), which is exactly what `xkey.Volume` does
(see "Neighboring packages" below).

### `Manager` is per-process, not per-host

`Manager`'s atomic state starts at zero every time one is constructed. That
fits a long-lived daemon (one `Manager` built once at startup, held for the
process's life) but not a one-call-per-invocation CLI: a fresh `Manager`
constructed for a second command has no memory of the first command's
`Unlock`. Callers in that second shape — `xkey.Volume` is the only one today
— talk to an `Executor` directly and derive "already unlocked" / "already
mounted" from the kernel via `IsMounted`/`IsUnlocked`, not from a `Manager`.

### `LibExecutor` — the production `Executor`

`LibExecutor` (`pkg/luks/executor.go`) is built on
`github.com/jeremyhahn/go-luks2`, now a direct dependency of the root
`go-xkms` module (`go.mod`). It is the one implementation of the `Executor`
seam in this repository:

- `Create` formats a new LUKS2 container: creates the sparse container file
  (`O_EXCL`, so a concurrent `Create` cannot race past the existence check),
  attaches a loop device (`go-luks2.SetupLoopDevice`), formats
  (`go-luks2.Format`, with `VolumeConfig.KDF`/`PBKDFIterTime` passed through
  as `FormatOptions.KDFType`/`PBKDFIterTime`), unlocks long enough to create
  a filesystem (`go-luks2.MakeFilesystem`), then locks and detaches the loop
  device. The container is left locked.
- `Unlock` attaches a loop device to the container file and opens the LUKS
  mapping (`go-luks2.Unlock`). **`go-luks2.Unlock` needs a block device, and
  a file-backed container has none until one is attached — this loop-device
  attach/detach is the production behavior go-xkms#917 added**; the state
  machine in `Manager` has no opinion about it, and the old, untested
  `Executor` seam never implemented it.
- `Lock` closes the mapping (`go-luks2.Lock`) and detaches whatever loop
  device `go-luks2.FindLoopDevice` resolves for the container file — not a
  loop device cached from `Unlock`, so `Lock` works correctly even called
  from a different `LibExecutor` instance (or process) than the one that
  ran `Unlock`.
- `Mount`/`Unmount` wrap `go-luks2.Mount`/`Unmount`. `Mount` re-asserts
  `0700` on the mount point after mounting (a freshly formatted ext4 root
  inode defaults to `0755`), unmounting on a failed `chmod` rather than
  leaving a world-listable volume mounted.
- Every `Create`/`Unlock` runs `EnsureKeyringAvailable` (`pkg/luks/keyring.go`)
  first: `go-luks2.Unlock` hands dm-crypt the volume key by kernel-keyring
  reference, so a container that blocks `add_key`/`keyctl`/`request_key`
  (Docker's default seccomp profile does) must be refused before a loop
  device is attached or a container file is created, not after.

Errors from every step are a typed `*ExecutorError{Operation, Path, Err}`
(`pkg/luks/errors.go`), named by the step that failed (`"create_dir"`,
`"setup_loop"`, `"luks_format"`, `"luks_unlock"`, `"create_fs"`,
`"luks_lock"`, `"detach_loop"`, `"mount"`, `"chmod_mountpoint"`, `"unmount"`),
with cleanup failures joined in via `errors.Join` rather than discarded.

### What `Manager` does not do

`Manager.IsMounted` and `Manager.IsUnlocked` report internal `atomic.Bool`
state only, driven exclusively by `Mount`/`Unmount`/`Unlock`/`Lock`
succeeding — never by asking the executor or the OS. `Manager` never calls
`Executor.IsMounted`/`Executor.IsUnlocked`.

### FIPS-aware KDF selection

`VolumeConfig.SetDefaults` fills an empty `KDF` via `DefaultKDF()`, which
checks the Go standard library's own FIPS state:

```go
func DefaultKDF() KDFType {
	if fips140.Enabled() {
		return KDFPBKDF2
	}
	return KDFArgon2id
}
```

`crypto/fips140.Enabled()` is the same stdlib signal used across go-xkms —
this package keeps no separate approved-algorithm list of its own.
Argon2id is the non-FIPS default (memory-hard, stronger brute-force
resistance); PBKDF2-HMAC-SHA256 is substituted in FIPS mode because Argon2
is not FIPS-approved (go-xkms#21).

## TPM 2.0 passphrase sealing: `TPMSealer`

`TPMSealer` (`pkg/luks/tpm.go`) seals a freshly generated 32-byte passphrase
as a TPM keyed-hash object and returns a `*luks2.Token` (go-luks2's own
LUKS2 token type, which already carries native `tpm2-*` fields) to persist
in the volume's LUKS2 header. Unlike the pre-#917 sealer, `TPMSealer` drives
no TPM command of its own except the PolicyPCR trial session the SSRK path
needs (see below) — every actual seal/unseal is delegated to a
`TPMSealUnsealer` (satisfied by `*pkg/tpm2.TPM2`), the same `Seal`/`Unseal`
every other go-xkms TPM secret goes through. This closes go-xkms#917's
second finding: `pkg/luks` is no longer "a second TPM sealing implementation
beside `pkg/tpm2.(*TPM2).Seal`" — it has none.

### Configurable storage parent: `SealParent`

go-xkms#917's central decision: the TPM parent a LUKS passphrase seals under
is now an explicit config, `TPMSealerConfig{Parent SealParent, PCRBank
string}` (`pkg/luks/config.go`), not a hardcoded handle.

**`SealParentPSRK` (the default, `SealParent` zero value).** Seals under
go-xkms's own Platform SRK (PSRK), bound to go-xkms's platform PCR policy —
`pkg/tpm2`'s existing `types.TPMPolicyPlatform` mechanism, the same
PolicyOR(PolicyPCR, PolicyAuthValue) digest every other platform-policy-bound
secret in go-xkms uses. The token type is `XKMSTPMTokenType =
"xkms-tpm2"`. This is in line with go-xkms#681 (go-xkms seals only under the
PSRK, with USER PIN plus platform PCR policy authorization): the sealed
LUKS passphrase sits under the one storage parent every other go-xkms secret
sits under, and unattended boot-time unlock goes through go-xkms's own
auto-unseal path (go-xkms#677), not systemd-cryptsetup. `TPMSealer` does not
set a PIN on the sealed child object itself (only a random guard password —
see below); the platform PCR branch alone gates unattended unseal, exactly
as the barrier's own TPM2 auto-unseal strategy does.

**`SealParentSSRK`.** Seals under the TCG-standard Shared SRK (handle
`0x81000001`) with empty parent auth, matching the pre-#917 behavior but now
as an explicit, documented, opt-in choice rather than the only option. The
sealed object's policy is a **plain PolicyPCR digest** over the caller's PCR
selection — not go-xkms's platform policy, which systemd-cryptsetup cannot
build a session for — computed by `computePCRPolicyDigest`
(`pkg/luks/tpm.go`) via a trial `PolicySession` + `PolicyPCR`, the one piece
of TPM session code this package still owns (it is PCR-digest arithmetic,
not sealing: the actual `TPM2_Create` is still `pkg/tpm2.TPM2.Seal`, given
the digest as `types.TPMSealPolicy.AuthPolicy`). The token type is
`TPMTokenType = "systemd-tpm2"`, matching `systemd-cryptsetup`'s own token so
`systemd-cryptenroll`/crypttab can unlock the volume at boot without
go-xkms running at all. This is the documented, narrow exception to
go-xkms#681 the pre-#917 code took without recording it.

**`TPMSealer.UnsealPassphrase` refuses an SSRK token.** `SealPassphrase`
works for both parents; `UnsealPassphrase` dispatches on the *sealer's own
configured parent* (not the token's `Type` field) and returns
`ErrTPMSSRKUnsealUnsupported` for `SealParentSSRK` without touching the TPM.
This is not a missing feature: `pkg/tpm2`'s `Unseal` only knows how to build
a policy session for its platform policy or a named/authorized policy
(`pkg/tpm2/authorized_policy_session.go`) — neither is a plain, caller-chosen
PolicyPCR digest, so there is no existing, reusable session-construction
path for it. Building one would be exactly the "parallel sealer"
go-xkms#917 says not to add. `systemd-cryptsetup` builds that PolicyPCR
session itself at boot; go-xkms was never going to be the one unsealing an
SSRK-parented token.

### Guard password: closing the empty-auth bypass

Every object `pkg/tpm2` creates from `KeyedHashTemplate` (the only template
`sealKeyInternal` uses) carries `ObjectAttributes.UserWithAuth = true` and
is never cleared for either seal path here. TPM 2.0 semantics: an object
with `UserWithAuth` set answers its USER role to *either* a plain
password/HMAC session presenting the object's `authValue` (empty counts as
a match when `authValue` itself is empty) *or* a policy session satisfying
`AuthPolicy`. A sealed object with no `Password` set and `UserWithAuth`
still set is therefore unsealable by a trivial empty-password
`TPM2_Unseal` — bypassing the PCR gate entirely, for both `SealParentPSRK`
and `SealParentSSRK`.

`randomGuardPassword` (`pkg/luks/tpm.go`) closes this: both seal paths set
`KeyAttributes.Password` to 32 fresh random bytes, generated, used once as
the `TPM2_Create` sensitive area's `UserAuth`, and discarded (`Clear()`'d)
before `SealPassphrase` returns — nobody, including go-xkms itself, retains
it afterward. This forces the password branch of `UserWithAuth` to require a
secret nobody has, so the *only* practical way to satisfy the object's USER
role is the PolicyPCR branch — closing the bypass without touching
`pkg/tpm2`'s shared, widely-used `sealKeyInternal`.
`TestTPMSealer_SSRK_SealedObjectEnforcesPCRPolicy`
(`pkg/luks/tpm_simulator_test.go`) proves a bare `TPM2_Unseal` with
`PasswordAuth(nil)` against an SSRK-sealed object fails. This same gap
exists for any `pkg/tpm2` caller that seals under the platform policy
without setting a `Password` of its own; closing it generally, in
`pkg/tpm2` itself, is outside this package's scope and is called out
separately for owner triage (go-xkms#917's PR discussion).

### Token format

`*luks2.Token` (`github.com/jeremyhahn/go-luks2/pkg/luks2`) is go-luks2's
own LUKS2 token type, already shaped with native `tpm2-*` fields
(`TPM2Blob`, `TPM2PCRBank`, `TPM2PCRs`, `TPM2KeyHandle`, `TPM2PolicyHash`)
matching `systemd-tpm2`'s convention — this package no longer defines its
own parallel `TPMToken` struct. `TPM2Blob` packs the sealed object's public
and private areas as `base64(uint32BE(len(public)) | public | private)`
(`EncodeTPMSealBlobs`/`DecodeTPMSealBlobs`, unchanged wire format from the
pre-#917 sealer). Persisting the token into a volume's LUKS2 header (via
`go-luks2.ImportToken`) and adding the corresponding keyslot (via
`go-luks2.AddKey`) is the caller's responsibility — `TPMSealer` only seals
and unseals; it does not touch a LUKS2 header.

### Passphrase handling

`TPMSealResult.Passphrase` is a `*secure.Buffer` (`sdk/go/secure` → go-qrdb's
`secure` package, per the SDK-boundary rule), not a plain `[]byte` — the
caller MUST call `Passphrase.Destroy()` once the passphrase has been
persisted (e.g. handed to `go-luks2.AddKey`) or otherwise consumed.

## Fail-closed behavior (verified)

- `NewManager` returns `ErrNilExecutor` for a nil executor and propagates
  `VolumeConfig.Validate()` errors before constructing anything.
- `Manager.Create`/`Unlock` refuse an empty passphrase or non-positive size
  before the executor is ever called.
- Every executor error is wrapped as `&errs.Joined{Lead: ErrOperationFailed,
  Cause: err}` — a caller can `errors.Is(err, ErrOperationFailed)` without
  losing the underlying cause.
- `LibExecutor.Create` refuses with `ErrVolumeAlreadyExists` before touching
  the container file, and `LibExecutor.Unlock` refuses with
  `ErrVolumeNotFound` before attaching a loop device.
- `NewTPMSealer(nil, _)` returns `ErrTPMNoTransport` rather than
  constructing a sealer that would fail later; an invalid `SealParent` or
  `PCRBank` is refused at construction (`SealParentInvalidError`,
  `ErrInvalidPCRBank`), not at the first seal.
- A PCR-policy mismatch, a load failure, or a malformed token all return a
  typed error (`ErrTPMUnsealFailed`, `ErrTPMInvalidToken`) — there is no
  code path in `UnsealPassphrase` that returns a zero-value or best-effort
  passphrase on failure.

## Neighboring packages named luks (out of scope here)

- **`pkg/storage/luks`** (root module) — a `storage.Backend` that wraps a
  `VolumeOperator` interface and fails closed (`ErrVolumeLocked`) until a
  volume is unlocked. It does **not** import `pkg/luks` — its
  `VolumeOperator` interface exists specifically to prevent an import cycle
  between the root module and `xkey`, whose `luks.Volume` satisfies this
  contract. This is the fail-closed storage gate described in detail in
  [`../../xkey/docs/luks/architecture.md`](../../xkey/docs/luks/architecture.md)
  §"The gate: `pkg/storage/luks.Backend`" — read that document for its
  design, not this one.
- **`xkey/pkg/luks`** — xKey's desktop/CLI-facing LUKS glue
  (`xkey luks2 create|unseal|lock|migrate|wipe`,
  `pkg/gui/services.StorageService`). As of go-xkms#917 it no longer drives
  `go-luks2` itself: `xkey.Volume` is a thin wrapper around `sdk/go/luks`'s
  `Executor` (`sdkluks.NewLibExecutor()`), and only the genuinely
  xkey-specific behavior remains local — privilege-drop chown after mount
  (`resolveCallingUser`/`chownTreeToCallingUser`, driven by `SUDO_UID`/
  `PKEXEC_UID`) and secure container wipe (`Wipe`, DoD/NIST pattern
  sequences). Documented in full in
  [`../../xkey/docs/luks/`](../../xkey/docs/luks/).

## Consumers

`sdk/go/luks/luks.go` is the only importer of `pkg/luks` in this repository,
by design — its own package comment states the intent: downstream consumers
reach LUKS + TPM sealing through this package instead of importing
`go-xkms/pkg/luks` directly. As of go-xkms#917, `xkey/pkg/luks` is the first
in-tree consumer of that re-export (previously `pkg/luks` had no in-tree
caller at all). Consumers outside this repository (go-quicbaas SDK shims,
go-trusted-platform's LUKS backend) are out of scope here under the
cross-project boundary.
