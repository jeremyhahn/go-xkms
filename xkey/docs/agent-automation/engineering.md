# Agent Automation — Engineering Contract

> **Status: NORMATIVE** · Feature: `agent-automation` · Module: `go-xkms/xkey` · Last verified: 2026-09-28

## Exported surface

Automation is configuration and IPC rather than a Go API, with one exception:
the presence handler an authenticator is constructed with.

### `xkey fido2` flags (`xkey/cmd/xkey/cmd/fido2.go`)

| Flag | Default | Effect |
|---|---|---|
| `--require-touch` | `true` | presence requirement after a verified PIN; false lets the PIN stand in for the touch |
| `--pin` | `true` | PIN support; the client sends the PIN with each ceremony |
| `--set-pin-stdin` | `false` | read the initial PIN to establish from standard input (needs `--pin`) |
| `--interactive` | `false` | terminal prompts instead of the socket handler |
| `--timeout` | `30s` | how long a presence request waits |
| `--notify` | `dialog` | `dialog`, `passive`, `log`, `none` |
| `--notify-command` | `""` | custom notification command |
| `--socket` | see resolution below | IPC socket path; the daemon listens where its clients resolve |
| `--cdp` | `false` | Chrome DevTools virtual-authenticator bridge |
| `--cdp-host` | `localhost` | DevTools host |
| `--cdp-port` | `9222` | DevTools port |
| `--default-password` | `""` | password typed on a bare touch |

### PIN input (`xkey/cmd/xkey/cmd/pin_input.go`)

`xkey auth register`, `xkey auth login` and `xkey unlock` share one resolver,
in precedence order: `--pin-stdin`, then `XKEY_PIN`.

| Flag | Default | Notes |
|---|---|---|
| `--pin-stdin` | `false` | read the PIN from standard input |

There is no `--pin` value flag (go-xkms#272 removed it, breaking any script
that passed `--pin <value>`): a value on the command line is visible to every
other process on the host via `ps`. `addPINFlags`/`addSOPINFlags` now declare
only the `-stdin` bool flag; `resolve` falls through to `os.Getenv` when it is
unset. `pinSource.valueFlag` no longer exists as a field.

For `auth register` / `auth login` this is the authenticator's CTAP2 PIN, sent
with the ceremony as a browser would send it. It is unrelated to `--spki-pin`,
which is the server's public-key pin and remains a value flag (it carries a
fingerprint, never a credential). An authenticator with no PIN configured
needs none.

### `xkey unlock` (`xkey/cmd/xkey/cmd/unlock.go`)

Takes the PIN flags above plus `--socket` (auto-detect). Errors:
`ErrUnlockDaemonNotRunning`, `ErrUnlockMissingPIN`, `ErrUnlockFailed`,
`ErrUnlockStillLocked`, `ErrUnlockIncomplete`. The last two are what a script
gates on: the daemon granted the unlock but still reports itself locked, or
released some subsystems and left others (the barrier) locked.

The PIN `unlock` verifies against is resolved by `pkg/pinselect` (reached through `xkmssdk.ResolvePINBackend`)
(go-xkms#307): the persisted strategy at `<dataDir>/pin/strategy`, read by
the GUI, `xkey extension serve` and `xkey pin` alike, so the same value
authenticates everywhere. `xkey extension serve` resolves it once at
startup; when the persisted strategy needs a provider unavailable on that
host (typically `tpm2` on a container with no TPM), the daemon refuses to
start at all — `ErrServePINManagerInitFailed` wrapping
`*pinselect.ProviderUnavailableError` — rather than starting against a
different backend than the one governing the device. `unlock` against such
a host then fails closed as `ErrUnlockDaemonNotRunning`, not
`ErrUnlockFailed`: there is no daemon to answer. An automation pipeline
driving a device it did not provision itself should check `xkey pin
status` for the governing strategy before relying on `unlock` there.

#### The unlock-attempt budget (go-xkms#272)

`AppLockService` (`xkey/pkg/gui/services/app_lock_service.go`) enforces its
own budget of `AppLockPINMaxAttempts` (8) unlock attempts, independent of
and in addition to whatever counter the PIN backend or hardware strategy
keeps. It exists because that other counter is not reachable on every
branch `Unlock` takes: the software PIN backend keeps none of its own, and
a sealed barrier's counter lives behind the very barrier the PIN is trying
to open. The budget is persisted at `<dataDir>/pin/unlock_attempts`
(`xkey/pkg/gui/services/app_lock_attempts.go`; JSON, atomic
temp-file-then-rename, `0600`), a sibling of the PIN state, NOT behind the
barrier — deliberately, so it is readable and writable while the barrier
stays sealed.

Every credential check `Unlock` performs — `PINService.VerifyUserPIN` or
`BarrierService.Unseal` — routes through `AppLockService.evaluateCredential`,
which checks the budget before evaluating anything and classifies the
result afterward: `ErrAppLockUnsealUnavailable`, `ErrAppLockStorageCorrupt`
and `qrdbsdk.ErrPINNotSet` (the #510 fault classifications) never spend an
attempt, because the credential itself was never evaluated; anything else
does. Once the budget reaches zero, `Unlock` returns the typed
`ErrAppLockPINBlocked` without calling either verifier again. Every
rejection or refusal is wrapped in `*AppLockAttemptsError{Cause,
Remaining}`, which implements `Unwrap` so `errors.Is` against the
underlying cause (`ErrAppLockPINInvalid`, `ErrAppLockPINBlocked`, a raw
`qrdbsdk` error) still matches. `ipc.UnlockResult` carries the same count in
`RemainingAttempts *int`, so `unlock`'s IPC caller does not have to parse
the error string to script on it.

A successful Security Officer PIN verification resets the budget:
`PINService.SetAppLockService` wires an `appLockAttemptsResetter`
(`ResetAttempts() error`), and `PINService.ResetLockout` /
`PINService.SetUserPIN` call it on success — both `App` (the GUI) and
`runExtensionServe` (the headless daemon) wire their own `AppLockService`
this way. `xkey pin reset-lockout` and `xkey pin set-user` run in a
separate process from the daemon whose `AppLockService` holds the live
counter, so they reach the same persisted file directly through
`services.ResetAppLockAttempts(dataDir)` instead.

### `xkey touch` (`xkey/cmd/xkey/cmd/touch.go`)

| Flag | Default | Notes |
|---|---|---|
| `--password` | `""` | name of the password to type |
| `--socket` | auto-detect | IPC socket path |

Approves the daemon's pending presence request. With no request pending it is
a no-op unless the daemon was started with `--default-password`, in which case
it types that password; a script that loops on `xkey touch` must run the
daemon without one.

### Presence handlers (`pkg/fido2/authenticator`, `xkey/pkg/presence`)

`NewAuthenticator` returns `ErrUserPresenceHandlerRequired` when
`Config.UserPresenceHandler` is nil. There is no default. The handlers:

| Handler | Constructor | Who installs it |
|---|---|---|
| `presence.SocketHandler` | `presence.NewSocketHandler(notifier, logger)` | `xkey fido2` (default) and the GUI; answered by a dialog or `xkey touch` |
| `InteractiveHandler` | `NewInteractiveHandler()` | `xkey fido2 --interactive`; terminal prompts |
| `AutoGrantHandler` | `NewAutoGrantHandler()` | programmatic devices only, named at their construction site |

Auto-grant grants **presence**. It does not assert verification: the UV flag
still comes only from a verified PIN or a backend that verifies a human
itself.

### Programmatic devices

`pkg/fido2/virtualdevice` (`native_virtual_device.go`) installs
`NewAutoGrantHandler()` when its caller supplies no handler, with the reason
stated at that line: a native virtual device is driven programmatically and
has no prompt channel. The CDP bridge (`xkey/pkg/cdp`) registers a Chrome
virtual authenticator with automatic presence simulation and user
verification simulated by Chrome. Both are test devices; neither is the
daemon a browser or `xkey auth` talks to.

### SDK integration

`go-xkms/sdk/go` reads `XKEY_IPC_SOCKET` (`sdk/go/options.go`,
`defaultXKeySocketEnvVar`) for its xkey-auth option; failures surface as
`ErrXKeyAuthFailed`. That is how an SDK consumer authenticates through a running
xkey instead of a key file.

### `xkey provision` (`xkey/cmd/xkey/cmd/provision.go`, #1033)

Sequences the same service-layer functions "barrier init", "pin
set-so"/"set-user", "fido2 init-token", "piv generate" and "ssh keys
generate" each already call, against one target home, from three separate
secrets. It is not a parallel implementation of any of those ceremonies.

| Flag | Default | Notes |
|---|---|---|
| `--home` | `""` | target xkey home; falls back to `XKEY_HOME`; one of the two is required |
| `--agent` | `""` | required; the agent's display name |
| `--force` | `false` | provision an already-initialized home |
| `--pin-stdin` | `false` | user PIN, via `addPINFlags`/`resolvePINInput`, same as everywhere else in this feature |
| `--so-pin-stdin` | `false` | SO PIN, via `addSOPINFlags`/`resolveSOPINInput`, same as `extension serve` |
| `--barrier-password` / `--barrier-password-file` | `""` | barrier password, via `addBarrierPasswordFlags`/`resolveBarrierPassword`, same as `extension serve` and fido2's `--storage barrier` mode |
| `--chrome-profile-dir` | `""` | also calls `nativemsg.InstallProfileManifest` |
| `--json` | `false` | machine-readable report |

**Three distinct secrets, never one standing in for another.** `runProvision`
resolves and validates all three before touching any state:
`resolvePINInput` (user PIN) → `resolveSOPINInput` (SO PIN) →
`resolveBarrierPassword` (barrier password), each returning its own typed
sentinel when missing (`ErrProvisionUserPINRequired`,
`ErrProvisionSOPINRequired`, `ErrProvisionBarrierPasswordRequired`). The user
PIN becomes the host PIN service's User PIN (`provisionPIN`'s `userPIN`
parameter). The SO PIN becomes *both* the host PIN service's SO PIN
(`svc.SetSOPIN`, authorizing `svc.SetUserPIN` too) *and* the FIDO2
authenticator's own, separate Security Officer PIN
(`provisionFIDO2`'s `soPIN` parameter, `auth.InitializeToken`) — the two
already share the name "SO PIN" without sharing a store (see `pin_set.go`
and `fido2_init_token.go`), so reusing one input for both is not the bug the
user/SO PIN collapse would be. The barrier password comes from
`resolveBarrierPassword` alone (`provisionBarrier`'s `barrierPassword`
parameter) and is used for nothing else. `addBarrierPasswordFlags` and
`resolveBarrierPassword` are the exact functions `barrier_store.go` and
`extension_serve.go` already share with `extension serve` and fido2's
`--storage barrier` mode — not a new flag pair invented for this command.
Collapsing the SO PIN into the user PIN (this command's behavior before
this fix) would erase the SO/user separation the host PIN service exists to
enforce: the SO can reset or unblock the user, but the user cannot reset the
SO. Because `--pin-stdin`, `--so-pin-stdin` and `resolveBarrierPassword`'s
interactive fallback all read the *same* standard input stream, only one of
the three may use its stdin form in a given invocation; the other two must
come from their file/environment-variable form.

`runProvisionPersistentPreRun` resolves `--home`/`XKEY_HOME` and exports it
as `XKEY_HOME` (`os.Setenv`) before calling `RootCmd.PersistentPreRunE`
directly. This is necessary, not decorative: Cobra invokes only the nearest
`PersistentPreRunE` in the command chain, so defining one on `provisionCmd`
replaces root's rather than running alongside it, and `resolvedHome` /
`loadedConfig` (`root.go`) — which `resolveXKeySSHDataDir` and `GetConfig()`
read directly, not re-resolved per call — must already reflect `--home`
by the time they run.

**Ordering is deliberate, not the order a plain reading of the issue
suggests.** SSH key generation runs *before* barrier initialization: once a
barrier root key exists, `xkeySSHBackend` (`ssh.go`) refuses every operation,
including reads, with `ErrSSHStoreBarrierEncrypted` — the CLI has no
barrier-unlock flow of its own. Generating the SSH key first is the only
order in which every step can complete non-interactively on a fresh home.
On a `--force` re-provision of an already-initialized home, SSH key
generation is not attempted at all — `AgentProvisionResult.SSHNote` reports
it as skipped, rather than failing the whole run over one step that cannot
succeed either way it is ordered.

FIDO2 token initialization normally waits on an interactive user-presence
prompt (`requestUserPresence`, `pkg/fido2/authenticator/token.go`).
`provisionFIDO2` substitutes `authenticator.NewAutoGrantHandler()` — the same
handler `extension_serve.go` installs for headless operation — for the
interactive handler `fido2 init-token` installs. It also forces
`fido2.storage` away from its process-wide default of `memory`
(`ensureFIDO2PersistentStorage`, restored via `defer` after the step): a
Security Officer PIN established in memory storage vanishes the moment this
process exits, which `fido2 init-token` already refuses outright
(`ErrTokenVolatileStorage`); provisioning makes the same choice an operator
configuring a persistent instance would make rather than surfacing that
refusal. PIV key generation needs no such substitution — `piv generate`
against the default software backend prompts for nothing.

The agent's display name is persisted to the *resolved home's own* config
file (`config.SaveToPath(cfg, home.ConfigPath())`, i.e.
`<home>/config.yaml`, `fido2.device_name`), not through the package-level
`config.Save` (which targets the operator's shared
`~/.config/xkey/xkey.yaml`): saving to the shared XDG path would leak one
agent's display name into every other agent's config on a host running one
xkey instance per agent.

`AgentProvisionResult` (JSON and human-readable) never carries a secret: it
names the `XKEY_HOME` export line, the resolved socket path, the barrier
strategy, the PIN status (`set` / `already set`), the FIDO2 AAGUID and token
state, the PIV slots set up, and the SSH key's public half and fingerprint.

## Invariants

- **Every automation switch is opt-in and defaults off.** `--require-touch`
  true, `--cdp` false, `--notify dialog`. Do not change a default to make a
  test pass.
- **A presence handler is named, never defaulted.** Construction without one
  fails with `ErrUserPresenceHandlerRequired`. A device that wants unattended
  approval passes `NewAutoGrantHandler()` explicitly, so the choice is visible
  at the call site and in review.
- **User verification is performed, never asserted.** UV is set when the
  ceremony carried a valid `pinUvAuthParam` or the key backend reports
  `HandlesUserVerification` because it verifies a human inside the key
  operation. No flag, setting or barrier state sets it. `getInfo` reports
  `uv=false` where a PIN is the verification method, so a browser collects
  the PIN.
- **`--require-touch=false` only narrows the presence request.** It skips the
  request after a verified PIN; a ceremony with no PIN auth still asks the
  handler, and with the socket handler that means `xkey touch` or a timeout.
- **The relying party is not involved.** No server-side flag participates; the
  ceremony it sees is ordinary, and what it says about UP and UV is true.
- **There is no `--pin` / `--so-pin` value flag anywhere in this feature.**
  Only `--pin-stdin` / `--so-pin-stdin` and the `XKEY_PIN` / `XKEY_SO_PIN`
  environment variables (go-xkms#272). Do not reintroduce a value flag to
  "make scripting easier" — that is the exact capability that was removed,
  and for the reason stated in its own former help text.
- **The app lock's own unlock-attempt budget is independent of the PIN
  backend's counter, and both apply.** A build against a backend that keeps
  its own lockout (TPM2 DA, a future hardware strategy) still enforces
  `AppLockPINMaxAttempts` on top of it; do not remove one on the assumption
  the other covers it — the whole reason the budget exists is that the
  backend counter is not reachable on every branch (see "The unlock-attempt
  budget" above).
- **A fault never spends a budget attempt; only an evaluated-and-rejected
  credential does.** `evaluateCredential`'s `isFault` classifier is the one
  place that decides which is which. Adding a new fault classification to
  `unsealBarrier` or `verifyUserPIN` means adding it there too, or the fault
  silently starts spending the budget it was carved out of (#510's own
  lesson, reapplied).
- **`unlock` reports only a state it has confirmed.** Success is taken from
  `ipc.UnlockResult.Success`, never from the transport status, and is then
  checked against the daemon's own `HandleStatus`. A daemon that reports
  `ipc.ActionLocked` after granting an unlock makes the command exit non-zero
  with `ErrUnlockStillLocked`; one that released the app lock but left the
  barrier sealed exits non-zero with `ErrUnlockIncomplete`; a daemon that owns
  no app lock reports neither state and the command says so rather than
  implying it checked. Reporting an unconfirmed unlock is a fail-open: the
  ceremony that follows fails with the authenticator's `operation denied`,
  naming the wrong subsystem.
- **A daemon that owns an app lock reports its lock state from `HandleStatus`.**
  `guiIPCHandler` and `headlessHandler` both do; `fido2Device`, which owns no
  lock, reports `ipc.ActionDaemonReady`. `unlock`'s confirmation depends on it.
- **IPC access control is filesystem permissions.** The socket has no
  authentication of its own; anything that can open it can use the unlocked
  authenticator.
- **`--require-touch=false` does not alter what the credential is bound to.**
  A TPM-backed credential stays TPM-backed.
- **`--notify none` with presence still required will time out.** Automation
  needs a PIN on the ceremony with `--require-touch=false`, or a scripted
  `xkey touch` — not just silence.
- **Concurrency.** One ceremony at a time per authenticator; the IPC socket
  serialises.
- **`xkey provision` never falls back to xkey's own default home
  resolution.** `--home` or an inherited `XKEY_HOME` is required, explicitly;
  the normal `~/.xkey` / binary-marker / `/etc/xkey` chain
  (`xhome.Resolve`) is not consulted. Provisioning into the operator's own
  default home by accident is exactly the failure this command exists to
  prevent on a host running one xkey instance per agent.
- **`xkey provision` never lets one secret stand in for another.** The user
  PIN, the SO PIN and the barrier password are three separate inputs
  (`resolvePINInput`, `resolveSOPINInput`, `resolveBarrierPassword`), each
  required and each refusing by its own typed error when missing. The SO PIN
  alone is shared across two credentials that already share its name without
  sharing a store (the host PIN service's SO PIN and the FIDO2
  authenticator's own); the user PIN and the barrier password are each used
  for exactly one thing. Do not collapse the SO PIN and the user PIN into one
  input again — that erases the SO/user separation the host PIN service
  exists to enforce (the SO can reset or unblock the user; the user cannot
  reset the SO), which is a security-policy change this command must never
  make implicitly.

## Error semantics

| Condition | Result |
|---|---|
| ceremony with a wrong PIN | refused; retries counted like real hardware; `auth register` / `auth login` exit non-zero |
| ceremony with no PIN, `--require-touch=false` | presence is still requested; `xkey touch` answers it or it times out |
| ceremony with no PIN against a policy requiring UV | refused by the authenticator or the relying party; nothing fabricates UV |
| unlock with a wrong PIN | refused; the app lock's own budget decrements and the attempts left are reported; `unlock` exits non-zero carrying the daemon's reason |
| unlock's attempt budget reaches zero | refused without evaluating the PIN; `ErrAppLockPINBlocked`; needs `xkey pin reset-lockout` / `xkey pin set-user` against the daemon's data directory |
| unlock granted but the daemon is still locked | `ErrUnlockStillLocked`, non-zero; no success line is printed |
| unlock released the app lock but not the barrier | `ErrUnlockIncomplete`, non-zero, naming what stayed locked |
| unlock against a daemon with no app lock | success, plus an explicit note that the state could not be confirmed |
| socket not found | `xkey fido2` is not running, or `--socket` disagrees |
| ceremony times out with `--require-touch` still on | a touch was required and nobody supplied it |
| authenticator constructed without a handler | `ErrUserPresenceHandlerRequired` |
| SDK cannot reach the socket | `ErrXKeyAuthFailed` |
| CDP port unreachable | the bridge is off, or bound elsewhere |
| `xkey provision` with no `--home`/`XKEY_HOME` | `ErrProvisionHomeRequired`, non-zero; nothing is written |
| `xkey provision` against an already-initialized home, no `--force` | `ErrProvisionAlreadyInitialized`, non-zero; nothing is written |
| `xkey provision` with no user PIN | `ErrProvisionUserPINRequired` (or the underlying `resolvePINInput` error), non-zero; nothing is written |
| `xkey provision` with no SO PIN | `ErrProvisionSOPINRequired` (or the underlying `resolveSOPINInput` error), non-zero; nothing is written |
| `xkey provision` with no barrier password | `ErrProvisionBarrierPasswordRequired` wrapping `resolveBarrierPassword`'s error, non-zero; nothing is written |
| `xkey provision --force` against an already-initialized home | PIN/FIDO2/PIV steps still run (or report "already set"/"already initialized"); SSH key generation is reported as skipped, not failed |

**Fail closed:** none of these degrade to an unauthenticated path, and none
report a gesture that did not happen.

## Configuration

The pattern that works, and why each part is there:

```
xkey fido2 \
    --storage file --storage-path "$XDG_DATA_HOME/xkey" \
    --backend tpm2 \
    --require-touch=false \
    --notify none \
    --socket "$XDG_RUNTIME_DIR/xkey/xkey.sock"
```

- `--storage file` — credentials survive a restart (`memory` is the default).
- `--backend tpm2` — the credential is bound to the machine, which is the whole
  justification for automating its use.
- `--require-touch=false` — no human to touch; the PIN on each ceremony is the
  deliberate act.
- `--notify none` — no human to prompt.

Then the PIN on every ceremony (`printf '%s' "$XKEY_PIN" | xkey auth login
--pin-stdin …`) and `XKEY_IPC_SOCKET` in the agent's environment so the SDK
finds it.

## Persistence

Nothing new. Credentials are the authenticator's; sessions are
`xkey/pkg/tokenstore`; the socket is ephemeral.

## Test strategy

- **End to end** — `go-xkms/test/integration/logins` builds `xkey`, runs the
  daemon headlessly and drives registration and login unattended, supplying
  presence with `xkey touch` in a loop. Automation is what makes that suite
  possible, so it is also the suite that covers it.
- **Presence and verification flags** — `pkg/fido2/authenticator` suites prove
  that a missing handler is refused, that auto-grant sets UP and not UV, and
  that UV follows a verified PIN or a verifying backend only.
- **Browser automation** — Playwright specs through the CDP bridge.
- **IPC** — `xkey/pkg/ipc` suites; `xkey/cmd/xkey/cmd/{unlock,touch}` paths.
- **Agent lifecycle** — `xkey/cmd/xkey/cmd/agent_lifecycle_test.go`.
- **Unlock-attempt budget** — `xkey/pkg/gui/services/app_lock_attempts_test.go`
  (the persisted counter directly: restarts, corruption, concurrent
  writers under `-race`) and `app_lock_service_test.go` /
  `app_lock_attempts_test.go` (through `Unlock`: decrements only on a real
  rejection, not on a fault; blocks at zero without evaluating the PIN;
  resets on success and on `ResetAttempts`). `pin_service_test.go` proves
  `ResetLockout` / `SetUserPIN` reach a wired `AppLockService`.
  `xkey/cmd/xkey/cmd/pin_test.go` proves `reset-lockout` / `set-user` reach
  the persisted file from a separate process; `unlock_test.go` proves the
  CLI surfaces the remaining-attempts count and that `--pin` no longer
  parses.
- **`xkey provision`** — `xkey/cmd/xkey/cmd/provision_test.go`, driven
  through `RootCmd.Execute()` end to end with three *distinct* secrets (a
  test that collapsed them back to one value would pass by coincidence, so
  the suite deliberately does not): a fresh temp home provisions completely
  (barrier initializes under the barrier password, FIDO2/PIV/SSH all report
  success, and the host PIN service's `VerifySOPIN`/`VerifyUserPIN` confirm
  the SO PIN verifies as SO and the user PIN as user, and that each is
  refused as the other); no `--home`/`XKEY_HOME` refuses; a second run
  against the same home refuses without `--force`; `--force` against an
  already-initialized home completes PIN/FIDO2/PIV and reports SSH as
  skipped; an empty `--pin-stdin` input and each of the three secrets
  omitted entirely each refuse by their own typed error before anything is
  written; `--json` round-trips through `AgentProvisionResult` with none of
  the three secrets anywhere in the output.

## Observability

`--notify log` is the setting for an automated context that still wants a
record: no dialog, but every presence event written. `--notify none` is silent
by design.

The relying party's audit trail records the login regardless — an automated
login is not distinguishable there, and deliberately so. If you need to tell
agent logins apart, do it by account, not by hoping the ceremony looks
different.

## Socket resolution and instances (#1033)

`--socket` is one persistent root flag, bound to `XKEY_IPC_SOCKET` through viper
(`xkey/cmd/xkey/cmd/root.go`). Every command resolves it through
`resolvedSocketPath` (`state_source.go`): first the flag, then the env var, then
`ipc.DefaultSocketPath()`. `DefaultSocketPath` (`xkey/pkg/ipc/socket.go`) checks,
in order:

1. `XKEY_IPC_SOCKET`.
2. `<XKEY_HOME>/run/xkey.sock` when `XKEY_HOME` is set. If that path would exceed
   90 bytes (under the 104/108-byte `sun_path` limits), it uses a runtime-dir path
   keyed by a 12-hex SHA-256 of the absolute home.
3. `<runtime dir>/xkey/xkey.sock`. `runtimeDirFor` (`socket.go:158`) picks
   `$XDG_RUNTIME_DIR`; then, under `sudo` (root with `SUDO_UID`), the invoking
   user's `/run/user/$SUDO_UID` (`socket.go:162-169`); on macOS `$TMPDIR`
   (launchd's per-user `0700` directory), then `~/Library/Caches`; elsewhere
   `~/.xkey/run`. sudo strips `XDG_RUNTIME_DIR`, but that user's clients in a
   desktop session still resolve `$XDG_RUNTIME_DIR/xkey/xkey.sock`, which is
   under `/run/user/$SUDO_UID`; the sudo branch makes `sudo xkey fido2` land on
   the same socket (#1138). It is taken only if it passes the socket-directory
   checks for `SUDO_UID` alone (`validateSocketDirWith`, `socketdir.go:58`: not a
   symlink, a directory, owned by `SUDO_UID` — not root — mode `0700`);
   otherwise resolution falls through. On the home fallbacks the home under
   `sudo` is the invoking user's (`effectiveHomeDir`, `socket.go:192`), so the
   server and that user's clients still agree when neither side has a runtime
   directory. `runtimeDirFor` is pure: the environment, home resolver, sudo uid
   (`sudoUID`, `socket.go:133`) and `lstat` are injected by `runtimeDir`
   (`socket.go:127`). With no home at all it returns
   `""`, which `NewServer` and `Dial` refuse with `ErrSocketPathUnresolved`. There
   is no `/tmp` fallback: a shared directory lets another local user create the
   directory first and receive the PIN (#1117).

The socket directory is checked on both ends (`xkey/pkg/ipc/socketdir.go`):

- `NewServer` (`server.go:495`) calls `ensureSocketDir` (`socketdir.go:100`),
  which creates each missing component with `Mkdir(0700)` and re-validates it
  immediately, so losing a creation race to another user is refused rather than
  trusted. An existing directory is validated, never chmoded or chowned. Only a
  component it created is handed to the `sudo` user.
- `validateSocketDir` (`socketdir.go:51`) `Lstat`s the directory: not a symlink,
  a directory, owned by a `trustedUIDs` member, `Perm() == 0700`. The checks
  live in `validateSocketDirWith` (`socketdir.go:58`), which takes the `lstat`
  as a parameter so `runtimeDirFor` can reuse them without touching the disk.
- A stale socket is unlinked only through `reclaimSocket` (`socketdir.go:147`):
  directory valid, file is a socket, owned by a trusted uid. A regular file at the
  socket path is never deleted. The GUI takes over a live socket
  (`xkey/pkg/gui/app.go:3330-3337`) only on `ErrSocketInUse` and only through
  `ipc.ReclaimSocket`.
- `ipc.Dial` (`client.go:273`) validates the directory, connects, then reads the
  listener's uid with `peerUID` — `peercred_linux.go` (`SO_PEERCRED`),
  `peercred_xucred.go` (`LOCAL_PEERCRED`, macOS and FreeBSD), and
  `peercred_other.go`, which returns `ErrPeerCredentialsUnsupported` everywhere
  else. The check itself is `verifyPeer` (`peercred.go:34`), which returns the
  peer's uid alongside the verdict.
- The server checks its clients the same way (#1137). Every accepted connection
  goes through `admitPeer` (`server.go:726`, called at `server.go:665` before
  anything is read) against `Server.trusted`, which `NewServer` fills from
  `trustedUIDs` (`server.go:544`). An untrusted client is closed unanswered with
  a `Warn` carrying `peer_uid`; one whose credentials cannot be read — including
  every connection on a platform without peer credentials — is closed with a
  `Warn` and no uid. The `0700` directory and `0600` socket remain a first gate,
  but access control no longer depends on nothing loosening them.

Tests simulate "another user" without chown by passing a trusted-uid set that
excludes the test's own uid (`socketdir_test.go` `foreignUIDs`, the
`Client.trusted` and `Server.trusted` fields). The server-side tests run a real
listener and a real client (`peercred_test.go:246-315`); the sudo resolution
tests feed `runtimeDirFor` a fake `lstat` whose entries carry a
`syscall.Stat_t` owner (`socket_test.go:246-304`). `t.TempDir()` is `0777 &^ umask`, so tests that bind a
socket in it chmod it to `0700` first (`privateDir` / `privateTempDir`).

`extension install chrome --profile-dir <dir>` writes the manifest into
`<dir>/NativeMessagingHosts/`. Its `path` points at a generated launcher,
`<XKEY_HOME>/run/extension-host-launcher.sh` (mode 0700), which exports
`XKEY_HOME` and execs `xkey extension host`. Chrome can't pass arguments to a
native host, so the launcher is what pins a profile to its instance
(`xkey/pkg/nativemsg/manifest.go` `GenerateLauncherScript`,
`InstallProfileManifest`). `--profile-dir` is Chrome-only
(`ErrExtensionProfileDirChromeOnly`).

The acceptance tests are `instance_isolation_test.go` (two daemons under one
UID, where a client naming B never sees A's credential),
`extension_profile_dir_test.go` and `xkey/pkg/nativemsg/profile_manifest_test.go`.

`xkey/pkg/pkcs11/ipc_transport.go`'s `NewIPCTransport` resolves its default
socket through `ipc.DefaultSocketPath()` as well (#1038), so the module and
the CLI always agree on which instance an unqualified caller talks to.
