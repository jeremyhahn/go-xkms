# Agent Automation — Engineering Contract

> **Status: NORMATIVE** · Feature: `agent-automation` · Module: `go-xkms/xkey` · Last verified: 2026-09-21

## Exported surface

Automation is configuration and IPC rather than a Go API, with one exception:
the presence handler an authenticator is constructed with.

### `xkey fido2` flags (`xkey/cmd/xkey/cmd/fido2.go`)

| Flag | Default | Effect |
|---|---|---|
| `--require-touch` | `true` | presence requirement after a verified PIN; false lets the PIN stand in for the touch |
| `--pin` | `true` | PIN support; the client sends the PIN with each ceremony |
| `--set-pin` | `""` | set the initial PIN (needs `--pin`) |
| `--interactive` | `false` | terminal prompts instead of the socket handler |
| `--timeout` | `30s` | how long a presence request waits |
| `--notify` | `dialog` | `dialog`, `passive`, `log`, `none` |
| `--notify-command` | `""` | custom notification command |
| `--socket` | `$XDG_RUNTIME_DIR/xkey/xkey.sock` | IPC socket path |
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

The PIN `unlock` verifies against is resolved by `xkey/pkg/pinstrategy`
(go-xkms#307): the persisted strategy at `<dataDir>/pin/strategy`, read by
the GUI, `xkey extension serve` and `xkey pin` alike, so the same value
authenticates everywhere. `xkey extension serve` resolves it once at
startup; when the persisted strategy needs a provider unavailable on that
host (typically `tpm2` on a container with no TPM), the daemon refuses to
start at all — `ErrServePINManagerInitFailed` wrapping
`*pinstrategy.ProviderUnavailableError` — rather than starting against a
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

### Presence handlers (`xkey/pkg/authenticator`)

`NewAuthenticator` returns `ErrUserPresenceHandlerRequired` when
`Config.UserPresenceHandler` is nil. There is no default. The handlers:

| Handler | Constructor | Who installs it |
|---|---|---|
| `SocketHandler` | `NewSocketHandler(notifier, logger)` | `xkey fido2` (default) and the GUI; answered by a dialog or `xkey touch` |
| `InteractiveHandler` | `NewInteractiveHandler()` | `xkey fido2 --interactive`; terminal prompts |
| `AutoGrantHandler` | `NewAutoGrantHandler()` | programmatic devices only, named at their construction site |

Auto-grant grants **presence**. It does not assert verification: the UV flag
still comes only from a verified PIN or a backend that verifies a human
itself.

### Programmatic devices

`xkey/pkg/virtualdevice` (`native_virtual_device.go`) installs
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
- **Presence and verification flags** — `xkey/pkg/authenticator` suites prove
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

## Observability

`--notify log` is the setting for an automated context that still wants a
record: no dialog, but every presence event written. `--notify none` is silent
by design.

The relying party's audit trail records the login regardless — an automated
login is not distinguishable there, and deliberately so. If you need to tell
agent logins apart, do it by account, not by hoping the ceremony looks
different.
