# Virtual FIDO2 Authenticator — User Guide

> **Status: NORMATIVE** · Feature: `virtual-authenticator` · Module: `go-xkms/xkey` · Last verified: 2026-09-06

## What this does

Turns your machine into a FIDO2 security key. Once it is running, your browser
sees an ordinary USB authenticator and "sign in with a security key" works — no
hardware to buy, none to lose.

Your credentials live wherever you tell them to: in software, in the machine's
TPM, or on a paired phone.

## Prerequisites

- Linux (the UHID path is Linux-only; the Chrome DevTools bridge is the
  cross-platform route for browser testing).
- Permission to create a UHID device. "Cannot create device" almost always means
  `/dev/uhid` permissions — a udev rule, not a broken build.

## First run

```
xkey fido2
```

That works, and it uses `--storage memory`, which means **your credentials
disappear when you stop it**. Fine for a look; not what you want next.

## The configuration to actually use

```
xkey fido2 \
    --storage file --storage-path "$XDG_DATA_HOME/xkey" \
    --backend tpm2 --attestation tpm \
    --pin --set-pin - --require-touch \
    --notify dialog
```

- **`--storage file`** — credentials survive restarts. `--storage barrier`
  encrypts them.
- **`--backend tpm2`** — the keys live in the machine's TPM rather than in a
  file. `--backend phone` puts them in a paired phone's secure element.
- **`--attestation tpm`** — the authenticator tells relying parties honestly
  what it is. `none` says nothing.
- **`--pin` / `--require-touch`** — a PIN and a deliberate act, the way a real
  key works. Both are already the defaults.

Then register with any site or service that supports security keys, and it will
find it.

## The flag that changes the security story

```
--require-touch=false
```

It tells the authenticator not to ask for a touch after a verified PIN. That is
what an agent or a CI job needs — there is nobody there to touch anything, but
the job can send the PIN with the ceremony — and it is what you do not want on
your laptop, where the touch is the deliberate act that proves you are there.

There is no flag that satisfies user verification without a human. The PIN is
the verification; the authenticator reports it because it checked it. A
ceremony that carries no PIN still waits for a touch, which a script can supply
with `xkey touch`.

Same for `--require-touch=false`, more narrowly.

## Choosing where the keys live

| `--backend` | Keys live in | Someone with your disk can… |
|---|---|---|
| `software` | xkey's own store | copy them, subject to storage protection |
| `tpm2` | the machine's TPM | not copy them |
| `phone` | a paired phone's secure element | not copy them |

**A relying party cannot tell these apart.** If you tell someone your
credentials are hardware-backed, `--backend` is the thing that makes it true.

## Per-site policy

```
xkey uhid setup
xkey uhid policy list
xkey uhid policy set …
xkey uhid profile show
```

## Testing in a browser without the device

```
xkey fido2 --cdp --cdp-port 9222
```

This exposes the authenticator over Chrome's DevTools protocol. Anything that
can reach that port can use it — keep it on loopback and off shared machines.

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| "cannot create device" | no permission for `/dev/uhid` | add a udev rule |
| credentials gone after a restart | `--storage memory`, the default | use `--storage file` or `barrier` |
| the browser hangs at "touch your key" | you were never prompted | `--notify none` with `--require-touch` — set `--notify dialog` |
| the site does not offer the key | the daemon is not running, or the device was not created | `xkey fido2 status` |
| "no credentials" on a site you registered with | credentials are per relying party, and were lost or are in another store | check `--storage` and `--storage-path` |
| PIN blocked | too many wrong attempts | the authenticator's PIN retry policy, same as real hardware |
| a `tpm2` backend refuses to start | the TPM is unreachable | it will not fall back to software — fix the TPM |
| it works for you but not for an agent | the agent cannot touch anything | send the PIN with the ceremony and run with `--require-touch=false`, or have the agent call `xkey touch` |
| "this device has no Security Officer PIN" | the token was never initialized, so administrative operations are refused | `xkey fido2 init-token` — see [`cli.md`](cli.md#the-token-lifecycle--init-token-and-change-so-pin) |
| "the FIDO2 daemon is running and owns the device state" | `init-token`, `change-so-pin` and `provision-attestation` write persisted state the running daemon would overwrite | stop the daemon, run the command, start it again |

## Where to go next

- Logging in headlessly: [`../headless-webauthn/user.md`](../headless-webauthn/user.md)
- Automating presence for agents and CI: [`../agent-automation/user.md`](../agent-automation/user.md)
- Using a phone as the secure element: [`../phone-hsm/user.md`](../phone-hsm/user.md)
- The server side that verifies all this: [`../../../docs/webauthn/user.md`](../../../docs/webauthn/user.md)
