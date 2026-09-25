# FIDO2 Daemon and GUI Device Host — User Guide

> **Status: NORMATIVE** · Feature: `fido2` · Module: `go-xkms/xkey` · Last verified: 2026-09-27

This page covers running `xkey fido2` day to day: approving touches from a
script, unlocking a locked instance, checking what it is doing, and turning
on real attestation. For setting the device up in the first place —
storage, backend, PIN, flags — see
[`virtual-authenticator/user.md`](../virtual-authenticator/user.md).

## Approving a touch without touching anything

Once the daemon is running with its default `--notify dialog` (or `--notify
none` for a headless host), a pending WebAuthn ceremony waits for something
to call the IPC socket:

```bash
xkey touch
```

A script driving CI can poll this after triggering a ceremony, or the
daemon can be run with `--require-touch=false` so a verified PIN stands in
for the touch entirely — see
[`virtual-authenticator/user.md`](../virtual-authenticator/user.md#the-flag-that-changes-the-security-story).

`xkey touch --password NAME` types a stored password through the virtual
keyboard instead, which is what a bare touch does by default if
`--default-password` is configured.

## Unlocking a locked instance

If an enrollment or a ceremony is refused with "operation denied" and you
did not expect that, the daemon is probably locked:

```bash
printf '%s' "$PIN" | xkey unlock --pin-stdin
```

The command tells you which subsystems it released — for example `Unlocked:
app lock, barrier` — and confirms the daemon actually reports itself
unlocked afterward, rather than trusting its own success message. Too many
wrong PINs here lock the verb out entirely (independent of the PIN
backend's own lockout); a Security Officer clears it with `xkey pin
reset-lockout`.

## Checking what is running

```bash
xkey fido2 status
```

Reports whether a daemon is listening, which storage it opened, and —
critically — whether that storage is encrypted at rest. `file` storage is
plaintext; `barrier` is encrypted; `memory` never touches disk. Script
against the exit code: non-zero means no daemon is listening.

## Turning on real attestation

A freshly set-up device reports `fmt: none` on every registration — it
works, but tells a relying party nothing about what created the credential.
If your organization runs its own CA and you want a WebAuthn Level 2 packed
attestation with a chain to that CA:

```bash
xkey fido2 provision-attestation
```

This is Security Officer work — it prompts for the SO PIN, because turning
on attestation is provisioning a new trust claim, not an everyday
operation. The private key is generated on the device and never leaves it;
only a certificate signing request travels to the CA. Stop the daemon
first — it owns the device state while running, and `xkey fido2 status`
tells you whether it is up.

After provisioning, make sure the daemon is actually configured to present
what you just installed:

```bash
xkey fido2 --attestation packed ...
```

`--attestation tpm` requires the TPM2 key backend; `provision-attestation`
works with any backend, since the attestation key is separate from the
credential keys it vouches for.

## The GUI runs its own authenticator

The desktop GUI bundles the same authenticator, credential store and RP
policy into its own process — it is not a client of `xkey fido2`. Do not
run both against the same data directory: you get two authenticators with
two independent PIN states, and whichever one currently holds `/dev/uhid`
is the one a browser actually uses.

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| "operation denied" on an otherwise-working daemon | the instance is locked | `xkey unlock --pin-stdin` |
| `xkey touch` says "No pending request" | nothing is waiting for presence right now | trigger the ceremony first, or check `--notify` reached you |
| `xkey unlock` reports "still locked" after a correct PIN | the PIN opened the app lock but a governed subsystem (e.g. the barrier) stayed sealed | the message names which one; address that subsystem directly |
| `xkey fido2 status` exits non-zero | no daemon is listening | start it with `xkey fido2` |
| `provision-attestation` refuses with a storage error | `--storage memory` was configured | switch to `file` or `barrier` before provisioning |
| `provision-attestation` says the daemon is running | the daemon owns the device state while it runs | stop it, run the command, start it again |
| registrations still show `fmt: none` after provisioning | `fido2.attestation` was not set to `packed` | restart the daemon with `--attestation packed` |
| the GUI and `xkey fido2` disagree about credentials | both are running against the same or different data directories | run only one against a given store at a time |

## Where to go next

- Setting up and configuring the authenticator:
  [`virtual-authenticator/user.md`](../virtual-authenticator/user.md)
- Logging in headlessly, no browser:
  [`headless-webauthn/user.md`](../headless-webauthn/user.md)
- Automating presence for agents and CI:
  [`agent-automation/user.md`](../agent-automation/user.md)
- Using a phone as the secure element:
  [`phone-hsm/user.md`](../phone-hsm/user.md)
