# LUKS2 Encrypted Storage — Architecture

> **Status: NORMATIVE** · Feature: `luks` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

## Scope

LUKS2 is xKey's optional **base storage layer**: a dm-crypt encrypted
container file that the whole xKey home directory (`~/.xkey/` by default,
or `$XKEY_HOME`) is mounted onto when selected. It sits *underneath* the
Barrier (`xkey/docs/seal/`), which is always active regardless of whether
LUKS is in use:

```
Without LUKS:  App --> Barrier (AES-256-GCM) --> filestorage --> ~/.xkey/data/
With LUKS:     App --> Barrier (AES-256-GCM) --> filestorage --> ~/.xkey/ (LUKS mount) --> data/
```

This document covers the LUKS2 container lifecycle (`xkey/pkg/luks`, driven
by `xkey luks2 *` and `pkg/gui/services.StorageService`) and — the subject
of go-xkms#722 — the **lock gate** that makes it safe for either front end to
call into a home directory that might not actually be mounted yet:
`go-xkms/pkg/storage/luks.Backend`, re-exported through `sdk/go` as
`xkms.LUKSStorageBackend`, and `StorageService.RequireUnlocked`.

Out of scope: the Barrier itself and PCR-policy auto-unseal
(`xkey/docs/seal/`); the setup wizard's own step ordering, which decides
*whether* LUKS is offered and when its container is created
(`xkey/docs/setup-wizard/`).

## Why a lock gate

The LUKS mount point is the xKey home directory itself — not a dedicated
subdirectory. `xhome.Home.DataDir()` (`<home>/data`) and every other
well-known path xKey opens (`config.yaml`, `trust/`, `ca/`, `devices/`) sit
*beneath* that same mount point. Once the volume is mounted, every one of
those paths is transparently protected by dm-crypt at the kernel level —
whatever wrote to them (`os.WriteFile`, `pkg/storage/file`, a go-qrdb
storage engine) needs no LUKS-specific code, because it is simply writing
into a live encrypted block device through a normal mount.

The risk is entirely in the gap *before* that mount exists: if any code
path opens `<home>/data/...` while the container is configured but still
locked, the OS silently creates and writes to a plain directory on the
underlying (unencrypted) filesystem, and every store built on top of it —
credentials, passwords, trust anchors, OIDC tokens — persists in plaintext.
Before go-xkms#722 nothing enforced "the volume must be mounted before any
store opens": the CLI's `PersistentPreRunE` gate (`checkLUKSVolume`,
`cmd/xkey/cmd/root.go`) covered every ordinary command invocation, but nothing
symmetrical existed for the GUI's `App.initializeDataDir`, and neither front
end used the one piece of code built to answer "is it safe to write yet" as a
reusable, typed decision: `pkg/storage/luks.Backend` in the root go-xkms
module.

## The gate: `pkg/storage/luks.Backend`

`Backend` (re-exported as `xkms.LUKSStorageBackend`) is a `storage.Backend`
that wraps a `VolumeOperator` (`Exists`/`IsMounted`/`Create`/`Unlock`/`Lock`;
xKey's own `luks.Volume` satisfies it structurally — no import from
go-xkms back into xkey). It holds an atomic locked/unlocked state:

- **Locked** (the zero value): every `Get`/`Put`/`Delete`/`List`/`Scan`/
  `Exists` call returns `ErrVolumeLocked` (`xkms.ErrLUKSVolumeLocked`).
- **`Initialize(sizeBytes, passphrase)`**: creates the container, then
  unlocks it.
- **`Unlock(passphrase)`**: opens and mounts the container, then builds a
  `pkg/storage/file` delegate rooted at the mount point. All storage calls
  delegate to it from this point on.
- **`Attach()`**: a second, additive entry point (no passphrase) that builds
  the same delegate against a volume that is *already* mounted, without
  performing a LUKS open of its own. See "Two processes, one volume" below.
- **`Lock()`**: closes the delegate and locks the volume.

This package lived unwired in go-xkms until go-xkms#722: it existed, was
fully tested, and had no caller. Wiring it is exactly "use the mechanism
that already encodes fail-closed semantics" rather than re-deriving an
`IsMounted()` check at each of the dozen places a store gets opened.

## Two processes, one volume

xKey's CLI and GUI are independent OS processes that can legitimately share
one on-disk container: an elevated `xkey luks2 unseal` child process the GUI
itself spawned when not running as root, or a separate CLI session run
alongside a long-lived GUI session. A `Backend.Unlock` call always performs a
real `cryptsetup`-level open; calling it twice against an
already-mounted container fails (the container is busy) — so a second
process cannot simply retry `Unlock` to "catch up" to state another process
already established.

`Backend.Attach` exists for exactly that: it recognizes an existing mount
(`VolumeOperator.IsMounted() == true`) and builds the delegate without
touching the volume itself. It intentionally never accepts a passphrase —
attaching is authorization-free by design, because the authorization
already happened in whichever process actually unlocked the container.
`StorageService.RequireUnlocked` (`pkg/gui/services/storage_service.go`)
uses this to reconcile GUI-process state against reality on every call: if
its own `LUKSStorageBackend` hasn't been unlocked in-process but the volume
*is* mounted, it calls `Attach` rather than reporting a false locked state.

## Where the gate is wired

- **GUI** (`pkg/gui/app.go`, `App.initializeDataDir`): the first statement
  is `a.storageService.RequireUnlocked()`. A non-nil error — always
  `xkms.ErrLUKSVolumeLocked` when LUKS is the reason — aborts before any
  store is opened. `dataDirInit` stays `false`, so nothing downstream (the
  Barrier, FIDO2/OATH/PIV/SSH stores, the embedded key store, the extension
  pairing verifier) constructs anything. This is a defense-in-depth
  backstop: `App.startupReturningUser` already keeps `initializeDataDir`
  from being called at all while locked, by checking
  `StorageService.GetStatus().IsMounted` and emitting
  `events.EventStorageLUKSLocked` for the frontend's unlock dialog instead.
  The gate inside `initializeDataDir` itself covers every caller of that
  function, present and future — the setup wizard's completion callback,
  `PostUnlockInitialize`, `PostBarrierUnseal` — without each one needing its
  own copy of the check.
- **CLI** (`cmd/xkey/cmd/root.go`, `checkLUKSVolume` in `RootCmd`'s
  `PersistentPreRunE`): unchanged in structure (it still gates every
  non-exempt command before `RunE` runs), but the "not root, can't prompt"
  branch now reports `xkms.ErrLUKSVolumeLocked` as the matchable sentinel,
  with the existing `luks.ErrPermissionDenied` preserved as the wrapped
  cause (`SentinelCauseError`). A caller anywhere in the stack can now
  recognize a locked volume identically regardless of which front end hit
  it: `errors.Is(err, xkms.ErrLUKSVolumeLocked)`.
- **`StorageService.CreateVolume` / `UnlockVolume` / `LockVolume`** (the
  root-euid branches only — the elevated/pkexec branches shell out to
  `xkey luks2 *` as a separate process) now call `Backend.Initialize` /
  `Unlock` / `Lock` on the service's own `LUKSStorageBackend` instead of
  calling `luks.Volume` methods directly, so the same instance
  `RequireUnlocked` consults is the one that actually performed the
  operation.

## Rejected alternative: per-store prefix backend

An earlier design considered making `Backend` the actual storage backend for
every xKey store — replacing each store's dedicated subdirectory-rooted
engine (`a.openStore(filepath.Join(dir, "fido2"))`, etc.) with a namespaced
view (`xkms.NewStoragePrefixBackend(luksBackend, "fido2/xkey/")`) over one
shared `Backend`, mirroring how the Barrier is shared across stores today.

Rejected because the LUKS mount point is the xKey home directory itself: once
mounted, every subdirectory-rooted engine already sits on the encrypted
block device with zero extra plumbing. Routing everything through one KV
namespace would require rewriting ~10 already-correct call sites in
`App.initializeDataDir` and the SSH/PIV/FIDO2 stores' existing
prefix-vs-subdirectory conventions, for no additional protection —
the actual gap was never "the physical bytes travel through the wrong
object", it was "nothing stops the write from happening before the mount
exists." A single gate at the top of `initializeDataDir` (and the CLI's
existing `PersistentPreRunE`) closes that gap with a two-line change per
front end instead of a per-store rewrite, and is easier to prove complete:
every call site reachable from `initializeDataDir` is covered by
construction, not by an audit of each one.

## Migration and wipe are LUKS-exempt

`StorageService.MigrateToEncrypted` / `WipeVolume`, and the CLI's `luks2
migrate` / `luks2 wipe` / `luks2 seal` / `luks2 unseal` / `luks2 lock`
commands, manage the container's existence and mount state themselves —
they are exactly the code that must be able to run *before* a mount exists.
They are excluded from `checkLUKSVolume`'s gate via `luksExemptGroups`
(`cmd/xkey/cmd/root.go`) and were not changed by go-xkms#722; see
`cli.md` for their full reference.
