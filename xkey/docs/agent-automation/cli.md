# Agent Automation — CLI

> **Status: NORMATIVE** · Feature: `agent-automation` · Module: `go-xkms/xkey` · Last verified: 2026-09-03

Binary: `xkey`. This feature is a set of flags and two verbs rather than a
command group of its own.

## The daemon flags that make automation possible

On `xkey fido2` ([`../virtual-authenticator/cli.md`](../virtual-authenticator/cli.md)):

| Flag | Default | Use it when |
|---|---|---|
| `--auto-uv` | `false` | nobody is there to verify |
| `--require-touch=false` | `true` | nobody is there to touch |
| `--notify none` | `dialog` | nobody is there to see a prompt |
| `--notify log` | `dialog` | nobody is there, but you want a record |
| `--cdp` | `false` | driving a browser in tests |
| `--default-password` | `""` | a bare touch should type a specific password |

```
xkey fido2 --storage file --storage-path "$XDG_DATA_HOME/xkey" \
           --backend tpm2 --auto-uv --notify none
```

## `xkey unlock`

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--pin-stdin` | bool | `false` | read the PIN from standard input |
| `--pin` | string | `""` | **visible in the process list** |
| `--socket` | string | auto-detect | IPC socket path |

```
printf '%s' "$XKEY_PIN" | xkey unlock --pin-stdin
```

Use `--pin-stdin`. The `--pin` flag exists and its own help text warns that the
value shows up in `ps`.

### `unlock` confirms the state it reports

`unlock` prints `Unlocked` and exits zero only when the daemon confirms it is
unlocked afterwards. Specifically:

| Daemon outcome | Exit | Output |
|---|---|---|
| unlock granted, daemon reports unlocked | `0` | `Unlocked` |
| unlock granted, daemon still reports locked | non-zero | `unlock: the daemon is still locked` |
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

## `xkey touch`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--password` | string | `""` | name of the password to type |
| `--socket` | string | auto-detect | IPC socket path |

```
xkey touch
xkey touch --password upstream-portal
```

A synthetic touch. With `--password` it types the named entry from the vault
through the keyboard layer — which is how a non-browser context gets a stored
password.

## `xkey agent`

Lifecycle management for a long-running xkey agent instance
(`xkey/cmd/xkey/cmd/agent*.go`), including its CA integration.

```
xkey agent --help
```

## A complete CI setup

```
# 1. the authenticator, unattended
xkey fido2 --storage file --storage-path "$XDG_DATA_HOME/xkey" \
           --backend tpm2 --auto-uv --notify none &

# 2. unlock without a terminal, and stop if it did not take
printf '%s' "$XKEY_PIN" | xkey unlock --pin-stdin

# 3. trust the server's CA once, then enrol and sign in
xkey trust add ca-chain.crt --purpose user-ca --source "file:ca-chain.crt"
xkey auth register --server "$XKMS" \
                   --setup-token "$SETUP_TOKEN" --email agent-build@example.com
xkey auth login --server "$XKMS" --email agent-build@example.com

# 4. use it
export XKEY_IPC_SOCKET="$XDG_RUNTIME_DIR/xkey/xkey.sock"
xkmsctl --server "$XKMS" --token "$(xkey auth token --server "$XKMS")" key list
```

Step 1's flags are the automation. Step 2 exits non-zero if the daemon is still
locked, so the ceremony never starts on a false premise. Step 3's `trust add` is
what lets `auth` verify the server by its CA; pass `--spki-pin` instead when you
have no CA bundle, or `--tls-ca ca-chain.crt` to trust the file without adding
it to the store. Step 4's environment variable is how the SDK finds the running
xkey instead of wanting a key file.

## What you are trading

`--auto-uv` turns "a person has this key and used it" into "this machine has
this key". With `--backend tpm2` that is a machine-bound credential that can act
on its own — which is what you want for an agent, and is the reason not to run
these flags on a workstation.

Anything that can open the IPC socket while the authenticator is unlocked can
use the credential. The socket's file permissions are the access control.

## Exit codes

`0` on success. Non-zero for a wrong PIN, a socket that is not there (the daemon
is not running, or `--socket` disagrees), or a ceremony that timed out because
presence was required and `--auto-uv` was not set.

## Parity coverage

The `go-xkms` parity runner covers `xkmsctl`. This feature is covered by
`go-xkms/test/integration/logins` — a suite that only runs at all because the
automation works — plus the xkey IPC and agent-lifecycle unit suites.
