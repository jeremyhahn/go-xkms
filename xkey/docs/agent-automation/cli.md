# Agent Automation — CLI

> **Status: NORMATIVE** · Feature: `agent-automation` · Module: `go-xkms/xkey` · Last verified: 2026-09-21

Binary: `xkey`. This feature is a set of flags and two verbs rather than a
command group of its own.

## The daemon flags that make automation possible

On `xkey fido2` ([`../virtual-authenticator/cli.md`](../virtual-authenticator/cli.md)):

| Flag | Default | Use it when |
|---|---|---|
| `--require-touch=false` | `true` | nobody is there to touch; the PIN on the ceremony stands in |
| `--notify none` | `dialog` | nobody is there to see a prompt |
| `--notify log` | `dialog` | nobody is there, but you want a record |
| `--cdp` | `false` | driving a browser in tests |
| `--default-password` | `""` | a bare touch should type a specific password |

```
xkey fido2 --storage file --storage-path "$XDG_DATA_HOME/xkey" \
           --backend tpm2 --require-touch=false --notify none
```

There is no flag that satisfies user verification without a human. The PIN
sent with each ceremony is the verification, and the daemon reports it
because it checked it.

## The PIN on the ceremony

`xkey auth register` and `xkey auth login` take the authenticator's CTAP2 PIN
two ways, in precedence order:

| Source | Notes |
|---|---|
| `--pin-stdin` | read the PIN from standard input |
| `XKEY_PIN` | environment variable |

```
printf '%s' "$XKEY_PIN" | xkey auth login --pin-stdin \
    --server "$XKMS" --email agent-build@example.com
```

Use `--pin-stdin`. There is no `--pin` value flag (go-xkms#272 removed it): a
value on the command line is visible to every other process on the host via
`ps`, which is a wider audience than the IPC socket or the server connection
the PIN is usually headed for. `--spki-pin` is the server's public-key pin, an
unrelated, still-present value flag — it never carries a credential, only a
fingerprint.

## `xkey unlock`

For an xkey instance that owns an app lock — the GUI or the headless app.
`xkey fido2` owns none.

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--pin-stdin` | bool | `false` | read the PIN from standard input |
| `--socket` | string | auto-detect | IPC socket path |

```
printf '%s' "$XKEY_PIN" | xkey unlock --pin-stdin
```

### The unlock-attempt budget

A wrong PIN over `unlock` is counted against its own budget of 8 attempts
(`AppLockPINMaxAttempts`), independent of and in addition to whatever counter
the PIN backend or hardware strategy keeps (go-xkms#272). It exists because
that other counter is not always reachable: the software PIN backend keeps
none of its own, and a sealed barrier's counter lives behind the very barrier
the PIN is trying to open. The budget is persisted outside the barrier, at
`<dataDir>/pin/unlock_attempts`, so it survives a daemon restart and is
enforced even while the barrier stays sealed.

A rejection reports the attempts left, both in the printed error and in the
IPC response's `remaining_attempts` field, for a script to act on without
parsing prose:

```
$ printf '%s' "wrong" | xkey unlock --pin-stdin
Error: unlock: failed: app_lock: invalid PIN (5 attempt(s) remaining)
```

Once the budget reaches zero, `unlock` refuses outright — the PIN is not
evaluated at all — until a Security Officer resets it:

```
xkey pin reset-lockout          # or
xkey pin set-user               # setting the user PIN also proves the SO PIN
```

Both run against the daemon's own data directory, not through the socket:
the daemon and the CLI invocation are different processes, and the budget is
a file both reach independently, not daemon state the CLI can only poke over
IPC.

### `unlock` confirms the state it reports

`unlock` prints what it released, for example `Unlocked: app lock, barrier`,
and exits zero only when the daemon confirms it is unlocked afterwards.
Specifically:

| Daemon outcome | Exit | Output |
|---|---|---|
| unlock granted, daemon reports unlocked | `0` | `Unlocked: …` |
| unlock granted, daemon still reports locked | non-zero | `unlock: the daemon is still locked` |
| unlock released the app lock, barrier still sealed | non-zero | `unlock: incomplete`, naming what stayed locked |
| unlock refused | non-zero | `unlock: failed: <the daemon's reason>` |
| daemon owns no app lock (e.g. `xkey fido2`) | `0` | `Unlocked` plus `Lock state could not be confirmed: this daemon does not report one` |

So a script may gate on the exit code:

```
if ! printf '%s' "$XKEY_PIN" | xkey unlock --pin-stdin; then
    echo "still locked - do not start the ceremony" >&2
    exit 1
fi
```

`xkey fido2 status` reports the same state, and the two agree. A locked
authenticator refuses CTAP2 operations with `operation denied`, which reads as
a declined touch rather than a lock — which is why `unlock` must not report a
success it has not confirmed.

### The PIN `unlock` checks is the one `xkey pin status` names

`unlock`'s PIN goes to the same governing backend as `xkey pin verify --type
user` and the GUI's own unlock — software, TPM2 or PKCS#11, resolved once
per data directory and recorded at `<dataDir>/pin/strategy` (go-xkms#307).
A device provisioned through the desktop GUI's TPM2 wizard, then driven
headlessly from a container or CI runner with no TPM reachable, has a
governing strategy the automation host cannot serve. `xkey extension serve`
resolves it once at startup and refuses to come up at all rather than
starting against a different backend than the one that governs the device
— so `unlock` against such a host fails as "daemon not running", not a live
PIN rejection. `xkey pin verify` (no daemon involved) refuses per call with
a typed error naming the unreachable strategy, for the same reason. Run
`xkey pin status` first to see which backend governs before scripting
against a device you did not provision yourself; a `tpm2` answer on a host
with no TPM device means the automation cannot authenticate there, full
stop — there is no software fallback to reach for.

## `xkey touch`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--password` | string | `""` | name of the password to type |
| `--socket` | string | auto-detect | IPC socket path |

```
xkey touch
xkey touch --password upstream-portal
```

A synthetic touch: it approves the daemon's pending user-presence request. That
is how a ceremony that carries no PIN completes unattended — a script calls
`xkey touch` when the request is pending, or in a loop, since a touch with
nothing pending is a no-op as long as the daemon has no `--default-password`
(with one, a bare touch types it). With `--password` it types the named entry
from the vault through the keyboard layer — which is how a non-browser context
gets a stored password.

## `xkey agent`

Lifecycle management for a long-running xkey agent instance
(`xkey/cmd/xkey/cmd/agent*.go`), including its CA integration.

```
xkey agent --help
```

## A complete CI setup

```
# 1. the authenticator, unattended: a PIN-verified ceremony asks for no touch
xkey fido2 --storage file --storage-path "$XDG_DATA_HOME/xkey" \
           --backend tpm2 --require-touch=false --notify none &

# 2. trust the server's CA once, then enrol and sign in, sending the PIN each time
xkey trust add ca-chain.crt --purpose user-ca --source "file:ca-chain.crt"
printf '%s' "$XKEY_PIN" | xkey auth register --pin-stdin --server "$XKMS" \
                   --setup-token "$SETUP_TOKEN" --email agent-build@example.com
printf '%s' "$XKEY_PIN" | xkey auth login --pin-stdin --server "$XKMS" \
                   --email agent-build@example.com

# 3. use it
export XKEY_IPC_SOCKET="$XDG_RUNTIME_DIR/xkey/xkey.sock"
xkmsctl --server "$XKMS" --token "$(xkey auth token --server "$XKMS")" key list
```

Step 1's flags are the automation. Step 2 sends the authenticator PIN with each
ceremony; the daemon verifies it, sets UV because it did, and asks for no touch
because `--require-touch` is off. Step 2's `trust add` is what lets `auth`
verify the server by its CA; pass `--spki-pin` instead when you have no CA
bundle, or `--tls-ca ca-chain.crt` to trust the file without adding it to the
store. Step 3's environment variable is how the SDK finds the running xkey
instead of wanting a key file.

The variant with no PIN (`xkey fido2 --pin=false …`) needs presence supplied
instead: run `xkey touch --socket "$XDG_RUNTIME_DIR/xkey/xkey.sock"` in a loop
beside the ceremony. The credential it produces carries no user verification,
and a relying party that requires UV will refuse it.

## What you are trading

`--require-touch=false` turns "a person has this key and touched it" into "this
machine has this key and knows its PIN". With `--backend tpm2` that is a
machine-bound credential that can act on its own — which is what you want for
an agent, and is the reason not to run these flags on a workstation.

Anything that can open the IPC socket while the authenticator is unlocked can
use the credential. The socket's file permissions are the access control.

## Exit codes

`0` on success. Non-zero for a wrong or missing PIN, a socket that is not there
(the daemon is not running, or `--socket` disagrees), or a ceremony that timed
out because a touch was required and nobody supplied it.

## Parity coverage

The `go-xkms` parity runner covers `xkmsctl`. This feature is covered by
`go-xkms/test/integration/logins` — a suite that only runs at all because the
automation works — plus the xkey IPC and agent-lifecycle unit suites.
