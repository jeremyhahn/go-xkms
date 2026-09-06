# Agent Automation — User Guide

> **Status: NORMATIVE** · Feature: `agent-automation` · Module: `go-xkms/xkey` · Last verified: 2026-09-06

## The problem this solves

Security keys work because a person touches them. An agent or a CI job has no
person, so it normally falls back to a token in a file — which is copyable,
long-lived, and exactly what a hardware credential was supposed to replace.

This feature lets a machine use a real credential unattended, with the trade
made explicitly rather than by accident — and without the authenticator ever
claiming a human did something a human did not do.

## The flags

Start the authenticator with automation on:

```
xkey fido2 \
    --storage file --storage-path "$XDG_DATA_HOME/xkey" \
    --backend tpm2 \
    --require-touch=false \
    --notify none
```

- **`--require-touch=false`** — after a verified PIN, do not ask for a touch.
  The PIN is the deliberate act, and the job can send it.
- **`--notify none`** — stops it prompting for someone who is not there.
- **`--storage file`** — credentials survive a restart (`memory` is the default
  and does not).
- **`--backend tpm2`** — the credential is bound to this machine and cannot be
  copied off it. This is the part that makes automating its use reasonable.

There is no flag that satisfies user verification without a human. The PIN
you send with each ceremony is the verification; the authenticator reports it
because it checked it.

`--require-touch=false` with `--notify dialog` will pop a dialog nobody sees
whenever a ceremony arrives without a PIN. `--notify none` **without**
`--require-touch=false` will wait silently for a touch nobody was asked for,
then time out. Set both.

## Sending the PIN without a terminal

```
printf '%s' "$XKEY_PIN" | xkey auth login --pin-stdin \
    --server "$XKMS" --email agent-build@example.com
```

`auth register` and `auth login` take the authenticator's PIN from
`--pin-stdin`, then `XKEY_PIN`, then `--pin`. There is a `--pin` flag; its own
help text says the value is visible in the process list. Use `--pin-stdin`.

The same three sources drive `xkey unlock`, for an xkey instance that owns an
app lock (the GUI or headless app):

```
printf '%s' "$XKEY_PIN" | xkey unlock --pin-stdin
```

## Supplying a touch on demand

```
xkey touch
xkey touch --password upstream-portal
```

A synthetic touch: it approves the ceremony the daemon is waiting on. That is
how a ceremony with no PIN completes unattended — call it when the request is
pending, or in a loop, since a touch with nothing pending is a no-op unless the
daemon has a `--default-password` to type. With `--password` it types a named
vault entry — useful where the thing asking for a password is not a browser.

## A complete CI job

```
xkey fido2 --storage file --storage-path "$XDG_DATA_HOME/xkey" \
           --backend tpm2 --require-touch=false --notify none &

# $PIN is the server's SPKI pin; $XKEY_PIN is the authenticator's CTAP2 PIN.
printf '%s' "$XKEY_PIN" | xkey auth register --pin-stdin \
                   --server "$XKMS" --spki-pin "$PIN" \
                   --setup-token "$SETUP_TOKEN" --email agent-build@example.com
printf '%s' "$XKEY_PIN" | xkey auth login --pin-stdin \
                   --server "$XKMS" --email agent-build@example.com

export XKEY_IPC_SOCKET="$XDG_RUNTIME_DIR/xkey/xkey.sock"
xkmsctl --server "$XKMS" --token "$(xkey auth token --server "$XKMS")" key list
```

`XKEY_IPC_SOCKET` is how the SDK finds the running xkey rather than wanting a
key file.

## What you are actually trading

`--require-touch=false` changes the credential from "a person has this and
touched it" to "this machine has this and knows its PIN". For an agent that is
the correct statement — the machine *is* the identity. On your laptop it is
not, which is why these flags are opt-in and default off.

Three consequences worth being clear-eyed about:

- **Anything that can open the IPC socket, while the authenticator is unlocked,
  can use the credential.** File permissions on
  `$XDG_RUNTIME_DIR/xkey/xkey.sock` are the access control.
- **The server cannot tell.** An automated login looks exactly like a human one,
  by design. If you need to distinguish them, give agents their own accounts.
- **The server is told the truth.** A ceremony that carried a PIN reports user
  verification; one that did not, does not, and a policy that requires it will
  refuse that credential. Nothing here fakes the flag.

`--cdp` deserves its own line: it opens a Chrome debugging port (default `9222`)
that anything reachable can use to drive a Chrome virtual authenticator whose
presence and verification are simulated by Chrome. Loopback only, and off
outside tests.

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| the ceremony hangs, then times out | a touch was required and nobody supplied it: no PIN on the ceremony, or `--require-touch` still on | send the PIN with `--pin-stdin` and run with `--require-touch=false`; or answer with `xkey touch` |
| the relying party refuses the credential for lacking user verification | the ceremony carried no PIN, so no verification happened | set a PIN on the authenticator and send it with the ceremony |
| a dialog nobody sees | `--notify dialog` in an unattended context | `--notify none`, or `--notify log` to keep a record |
| "socket not found" | the daemon is not running, or `--socket` disagrees | start `xkey fido2`; check the path |
| the SDK will not authenticate | `XKEY_IPC_SOCKET` unset or wrong | export it |
| credentials gone after the job restarts | `--storage memory` | use `--storage file` |
| the PIN turned up in a CI log | `--pin` on a command line | `--pin-stdin` |
| it works locally, not in the container | `$XDG_RUNTIME_DIR` differs, or no TPM | set `--socket` explicitly; check the backend |

## Where to go next

- The authenticator itself: [`../virtual-authenticator/user.md`](../virtual-authenticator/user.md)
- Enrolling and signing in headlessly: [`../headless-webauthn/user.md`](../headless-webauthn/user.md)
- The password vault behind `xkey touch --password`: [`../../../docs/password-vault/user.md`](../../../docs/password-vault/user.md)
