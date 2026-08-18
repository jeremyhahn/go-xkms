# Agent Automation — User Guide

> **Status: NORMATIVE** · Feature: `agent-automation` · Module: `go-xkms/xkey` · Last verified: 2026-08-19

## The problem this solves

Security keys work because a person touches them. An agent or a CI job has no
person, so it normally falls back to a token in a file — which is copyable,
long-lived, and exactly what a hardware credential was supposed to replace.

This feature lets a machine use a real credential unattended, with the trade
made explicitly rather than by accident.

## The four flags

Start the authenticator with automation on:

```
xkey fido2 \
    --storage file --storage-path "$XDG_DATA_HOME/xkey" \
    --backend tpm2 \
    --auto-uv \
    --notify none
```

- **`--auto-uv`** — satisfies user verification with no human.
- **`--notify none`** — stops it prompting for someone who is not there.
- **`--storage file`** — credentials survive a restart (`memory` is the default
  and does not).
- **`--backend tpm2`** — the credential is bound to this machine and cannot be
  copied off it. This is the part that makes automating its use reasonable.

`--auto-uv` with `--notify dialog` will pop a dialog nobody sees.
`--notify none` **without** `--auto-uv` will wait silently for a touch nobody was
asked for, then time out. Set both.

## Supplying the PIN without a terminal

```
printf '%s' "$XKEY_PIN" | xkey unlock --pin-stdin
```

There is a `--pin` flag. Its own help text says the value is visible in the
process list. Use `--pin-stdin`.

## Typing a password on demand

```
xkey touch
xkey touch --password upstream-portal
```

A synthetic touch, optionally typing a named vault entry — useful where the
thing asking for a password is not a browser.

## A complete CI job

```
xkey fido2 --storage file --storage-path "$XDG_DATA_HOME/xkey" \
           --backend tpm2 --auto-uv --notify none &

printf '%s' "$XKEY_PIN" | xkey unlock --pin-stdin

xkey auth register --server "$XKMS" --spki-pin "$PIN" \
                   --setup-token "$SETUP_TOKEN" --username agent-build
xkey auth login --server "$XKMS" --username agent-build

export XKEY_IPC_SOCKET="$XDG_RUNTIME_DIR/xkey/xkey.sock"
xkmsctl --server "$XKMS" --token "$(xkey auth token --server "$XKMS")" key list
```

`XKEY_IPC_SOCKET` is how the SDK finds the running xkey rather than wanting a
key file.

## What you are actually trading

`--auto-uv` changes the credential from "a person has this and used it" to
"this machine has this". For an agent that is the correct statement — the
machine *is* the identity. On your laptop it is not, which is why these flags
are opt-in and default off.

Two consequences worth being clear-eyed about:

- **Anything that can open the IPC socket, while the authenticator is unlocked,
  can use the credential.** File permissions on
  `$XDG_RUNTIME_DIR/xkey/xkey.sock` are the access control.
- **The server cannot tell.** An automated login looks exactly like a human one,
  by design. If you need to distinguish them, give agents their own accounts.

`--cdp` deserves its own line: it opens a Chrome debugging port (default `9222`)
that anything reachable can use to drive the authenticator. Loopback only, and
off outside tests.

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| the ceremony hangs, then times out | presence was required and nobody supplied it | add `--auto-uv` |
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
