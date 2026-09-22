# Virtual FIDO2 Authenticator — User Guide

> **Status: NORMATIVE** · Feature: `virtual-authenticator` · Module: `go-xkms/xkey` · Last verified: 2026-09-21

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

## At-rest encryption of the passkey store

`--storage barrier` and the GUI (once you run `xkey barrier init`) encrypt
the credential store with go-qrdb's seal barrier — the only at-rest
encryption xkey has. `--storage file` (and the GUI before the barrier is
initialized) is a plain file at `0600`: readable by anything running as you,
same as any other config file with no encryption of its own. That is a valid
choice — not everyone wants a barrier password in their startup — but you
should choose it knowingly. Every time the daemon or the GUI opens an
unencrypted store it logs one warning naming the exposure and the fix:

```
passkey store is unencrypted at rest: private keys are stored in plaintext
path=... remedy="run 'xkey barrier init' to encrypt the passkey store"
```

`--storage memory` never touches disk, so it never carries this warning.
`xkey fido2 status` also reports which store is live and whether it is
encrypted — see [`cli.md`](cli.md#xkey-fido2-start--status).

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

This drives xkey's own authenticator — real backend, real PIN, real `getInfo`
— through Chrome's virtual-authenticator slot instead of a physical device;
it does not change what UV means or how it is reported, so a native PIN
dialog is avoided but a genuine PIN is still needed for the ceremony to carry
UV. A test that only needs *a* working credential and has no reason to touch
xkey at all can use Chrome's virtual authenticator on its own instead — see
[`../agent-automation/user.md`](../agent-automation/user.md#headless-browsers-and-automation).

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
