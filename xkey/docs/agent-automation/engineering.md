# Agent Automation — Engineering Contract

> **Status: NORMATIVE** · Feature: `agent-automation` · Module: `go-xkms/xkey` · Last verified: 2026-09-03

## Exported surface

Automation is configuration and IPC rather than a Go API.

### `xkey fido2` flags (`xkey/cmd/xkey/cmd/fido2.go`)

| Flag | Default | Effect |
|---|---|---|
| `--auto-uv` | `false` | satisfy user verification without a human |
| `--require-touch` | `true` | presence requirement; false removes it |
| `--notify` | `dialog` | `dialog`, `passive`, `log`, `none` |
| `--notify-command` | `""` | custom notification command |
| `--socket` | `$XDG_RUNTIME_DIR/xkey/xkey.sock` | IPC socket path |
| `--cdp` | `false` | Chrome DevTools virtual-authenticator bridge |
| `--cdp-host` | `localhost` | DevTools host |
| `--cdp-port` | `9222` | DevTools port |
| `--default-password` | `""` | password typed on a bare touch |

### `xkey unlock` (`xkey/cmd/xkey/cmd/unlock.go`)

| Flag | Default | Notes |
|---|---|---|
| `--pin` | `""` | **"visible in the process list; prefer --pin-stdin"** — the help text says this |
| `--pin-stdin` | `false` | read the PIN from standard input |
| `--socket` | auto-detect | IPC socket path |

Errors: `ErrUnlockDaemonNotRunning`, `ErrUnlockMissingPIN`, `ErrUnlockFailed`,
`ErrUnlockStillLocked`. The last is what a script gates on when the daemon
grants the unlock but does not end up unlocked.

### `xkey touch` (`xkey/cmd/xkey/cmd/touch.go`)

| Flag | Default | Notes |
|---|---|---|
| `--password` | `""` | name of the password to type |
| `--socket` | auto-detect | IPC socket path |

### SDK integration

`go-xkms/sdk/go` reads `XKEY_IPC_SOCKET` (`sdk/go/options.go`,
`defaultXKeySocketEnvVar`) for its xkey-auth option; failures surface as
`ErrXKeyAuthFailed`. That is how an SDK consumer authenticates through a running
xkey instead of a key file.

## Invariants

- **Every automation switch is opt-in and defaults off.** `--auto-uv` false,
  `--require-touch` true, `--cdp` false, `--notify dialog`. Do not change a
  default to make a test pass.
- **The relying party is not involved.** No server-side flag participates; the
  ceremony it sees is ordinary.
- **`--pin` is documented as unsafe in its own help text.** Keep it that way,
  and keep `--pin-stdin` working.
- **`unlock` reports only a state it has confirmed.** Success is taken from
  `ipc.UnlockResult.Success`, never from the transport status, and is then
  checked against the daemon's own `HandleStatus`. A daemon that reports
  `ipc.ActionLocked` after granting an unlock makes the command exit non-zero
  with `ErrUnlockStillLocked`; a daemon that owns no app lock reports neither
  state and the command says so rather than implying it checked. Reporting an
  unconfirmed unlock is a fail-open: the ceremony that follows fails with the
  authenticator's `operation denied`, naming the wrong subsystem (#250).
- **A daemon that owns an app lock reports its lock state from `HandleStatus`.**
  `guiIPCHandler` and `headlessHandler` both do; `fido2Device`, which owns no
  lock, reports `ipc.ActionDaemonReady`. `unlock`'s confirmation depends on it.
- **IPC access control is filesystem permissions.** The socket has no
  authentication of its own; anything that can open it can use the unlocked
  authenticator.
- **`--auto-uv` does not alter what the credential is bound to.** A TPM-backed
  credential stays TPM-backed.
- **`--notify none` with presence still required will time out.** Automation
  needs `--auto-uv` (or `--require-touch=false`), not just silence.
- **Concurrency.** One ceremony at a time per authenticator; the IPC socket
  serialises.

## Error semantics

| Condition | Result |
|---|---|
| unlock with a wrong PIN | refused; retries counted like real hardware; `unlock` exits non-zero carrying the daemon's reason |
| unlock granted but the daemon is still locked | `ErrUnlockStillLocked`, non-zero; no success line is printed |
| unlock against a daemon with no app lock | success, plus an explicit note that the state could not be confirmed |
| socket not found | `xkey fido2` is not running, or `--socket` disagrees |
| ceremony times out with `--auto-uv` unset | presence was required and nobody supplied it |
| SDK cannot reach the socket | `ErrXKeyAuthFailed` |
| CDP port unreachable | the bridge is off, or bound elsewhere |

**Fail closed:** none of these degrade to an unauthenticated path.

## Configuration

The pattern that works, and why each part is there:

```
xkey fido2 \
    --storage file --storage-path "$XDG_DATA_HOME/xkey" \
    --backend tpm2 \
    --auto-uv \
    --notify none \
    --socket "$XDG_RUNTIME_DIR/xkey/xkey.sock"
```

- `--storage file` — credentials survive a restart (`memory` is the default).
- `--backend tpm2` — the credential is bound to the machine, which is the whole
  justification for automating its use.
- `--auto-uv` — no human to verify.
- `--notify none` — no human to prompt.

Then `XKEY_IPC_SOCKET` in the agent's environment so the SDK finds it.

## Persistence

Nothing new. Credentials are the authenticator's; sessions are
`xkey/pkg/tokenstore`; the socket is ephemeral.

## Test strategy

- **End to end** — `go-xkms/test/integration/logins` builds `xkey` and drives
  registration and login unattended. Automation is what makes that suite
  possible, so it is also the suite that covers it.
- **Browser automation** — Playwright specs through the CDP bridge.
- **IPC** — `xkey/pkg/ipc` suites; `xkey/cmd/xkey/cmd/{unlock,touch}` paths.
- **Agent lifecycle** — `xkey/cmd/xkey/cmd/agent_lifecycle_test.go`.

## Observability

`--notify log` is the setting for an automated context that still wants a
record: no dialog, but every presence event written. `--notify none` is silent
by design.

The relying party's audit trail records the login regardless — an automated
login is not distinguishable there, and deliberately so. If you need to tell
agent logins apart, do it by account, not by hoping the ceremony looks
different.
