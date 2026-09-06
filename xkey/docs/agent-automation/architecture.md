# Agent Automation — Architecture

> **Status: NORMATIVE** · Feature: `agent-automation` · Module: `go-xkms/xkey` · Last verified: 2026-09-06

## The problem

Every strong credential in this stack is built on a human gesture: touch the
key, enter the PIN. That is the security property. It is also, for an agent or a
CI job, an absolute barrier — there is nobody there.

The wrong answers are well known: give the machine a bearer token in a file, or
turn the security property off globally. This feature is the third option —
**supply the gesture programmatically, in a place and with a scope that is
chosen deliberately, and never claim a gesture that did not happen.**

## Shape chosen: the gesture is supplied, not faked

Two gestures matter, and they are treated differently:

- **User presence** is a test that a human is there. An unattended daemon has
  no human, so presence is *supplied* by the machine: a scripted `xkey touch`
  answers the daemon's presence request, or the daemon is told that a verified
  PIN stands in for the touch (`--require-touch=false`).
- **User verification** is a claim to the relying party that a human proved
  who they were. It is *performed or absent*, never configured on. The
  authenticator sets the UV flag when a PIN was verified in the ceremony or
  the key backend verified a human itself (a paired phone's biometric). There
  is no flag that turns it on; the one that used to exist reported built-in
  verification so a browser would skip its PIN dialog, and was removed because
  the claim was false.

Automation is configured where the authenticator runs, not where credentials
are verified:

| Flag on `xkey fido2` | Default | What it does |
|---|---|---|
| `--require-touch` | `true` | when false, a verified PIN stands in for the touch |
| `--notify` | `dialog` | `none` stops prompting for a human who is not there |
| `--pin` | `true` | a PIN is enabled; the client sends it with each ceremony |
| `--cdp` | `false` | Chrome DevTools bridge, for browser automation |

Plus PIN and presence supply without a terminal:

| Verb | Flag | Notes |
|---|---|---|
| `xkey auth register` / `login` | `--pin-stdin` | the authenticator PIN, read from stdin, sent with the ceremony |
| `xkey unlock` | `--pin-stdin` | unlock an xkey instance that owns an app lock |
| `xkey unlock` | `--pin` | **visible in the process list** — the help says so |
| `xkey touch` | `--password` | approve a pending presence request; optionally type a named password |

The relying party is unchanged and unaware. That is the design decision: there
is no "agent mode" on the server, no weakened policy, and no second
authentication path to audit. The gesture happens; who performed it is a
property of where the authenticator runs — and what the ceremony reports is
what actually happened.

Rejected alternatives:

- **A bearer token for agents.** Rejected — copyable, long-lived, and the thing
  the dogfooding mandate moves away from: agent credentials belong on per-agent
  xkey instances using FIDO2/PIV/mTLS rather than raw key files.
- **A server-side "trusted client" exemption.** Rejected: it moves the decision
  to the wrong place and creates a second trust path.
- **A daemon flag that asserts user verification.** Existed, and was removed.
  It reported built-in verification whenever the daemon had its key material,
  which is exactly what user verification is defined not to mean; downstream,
  administrator enrolment and `credProtect` level 3 gate on that flag being
  true. Verification is now performed (a PIN, a biometric) or absent.
- **Auto-granting presence when no handler is configured.** Existed, and was
  removed. A caller that did not know the field existed got an authenticator
  that approved every ceremony silently. `NewAuthenticator` now refuses a
  missing handler; a device with no human names `NewAutoGrantHandler()` at its
  own construction site, so the decision is visible where it was made.
- **Making `--require-touch=false` the default.** Rejected. The default has to
  be the human one; automation is an explicit act.

## Component boundaries

| Piece | Where |
|---|---|
| Presence handlers (socket, terminal, auto-grant) | `xkey/pkg/authenticator` (`user_presence*.go`) |
| UP/UV flag decisions | `xkey/pkg/authenticator` (`cmd_makecredential.go`, `cmd_getassertion.go`) |
| Programmatic device (explicit auto-grant) | `xkey/pkg/virtualdevice` |
| Notification routing | `xkey/pkg/notify` |
| PIN input (`--pin-stdin`, `XKEY_PIN`, `--pin`) | `xkey/cmd/xkey/cmd/pin_input.go` |
| PIN/touch IPC | `xkey/pkg/ipc`, `xkey/cmd/xkey/cmd/{unlock,touch}.go` |
| Chrome DevTools bridge | `xkey/pkg/cdp` |
| Synthetic keyboard input | `xkey/pkg/keyboard` |
| Agent lifecycle | `xkey/pkg/agent`, `xkey/cmd/xkey/cmd/agent*.go` |
| SDK integration | `go-xkms/sdk/go` `XKEY_IPC_SOCKET` (`sdk/go/options.go`) |

Capability row: **"PIN/touch automation for agents and CI"** under the xkey
product surface — `xkey auth … --pin-stdin`, `xkey unlock --pin-stdin`,
`xkey touch`, `--require-touch=false`, `--cdp`.

## Data flow

```
agent / CI                      xkey fido2 (--require-touch=false --notify none)
   │                                     │
   ├─ xkey auth register --pin-stdin ───►│  PIN verified: UV set, no touch asked
   │                                     │
   ├─ xkey auth login --pin-stdin ──────►│  ceremony; presence satisfied locally
   │                                     │      │
   │                                     │      └─► relying party (unmodified)
   ├─ xkey touch ───────────────────────►│  presence for a ceremony that carried no PIN
   │                                     │
   └─ xkey auth token ──────────────────►│
        └─► xkmsctl --token …, or SDK via XKEY_IPC_SOCKET
```

`xkey touch` answers the daemon's pending presence request — optionally typing
a named password through `xkey/pkg/keyboard`, which is what makes the vault
usable from a non-browser context. `xkey unlock` is for an xkey instance that
owns an app lock (the GUI or headless app); `xkey fido2` owns none and says so.

A programmatic device — `xkey/pkg/virtualdevice`, or the Chrome virtual
authenticator behind `--cdp` — has no daemon and no socket. It states
auto-grant at construction and drives ceremonies in-process.

## Trust boundaries

- **`--require-touch=false` moves the credential from "something a person has
  and touched" to "something this machine has and knows the PIN to".** That
  is the trade, stated plainly. It is correct for an agent whose machine is the
  identity, and wrong on a workstation where the human is.
- **The relying party sees the truth.** UV is set because a PIN was verified
  in that ceremony; a ceremony with no PIN registers without UV and a policy
  that requires verification will refuse it, as it should.
- **The blast radius is the machine.** Anything that can reach the IPC socket
  while the authenticator is unlocked can use the credential. Filesystem
  permissions on `$XDG_RUNTIME_DIR/xkey/xkey.sock` are the access control.
- **`--pin` puts the PIN in the process list.** The flag's own help says so.
  `--pin-stdin` is the form to use.
- **`--cdp` opens a debugging port** (default `9222`). Anything that reaches it
  drives the authenticator. Loopback only. Chrome's virtual authenticator
  simulates presence and verification itself; it is a test device.
- **The credential's strength is still the backend's.** `--require-touch=false`
  with `--backend software` is a file plus a PIN that logs in by itself; with
  `--backend tpm2` it is a machine-bound credential that logs in by itself.
  Very different things.
- **`--notify none` is not cosmetic** in this context — with presence still
  required and nobody to prompt, the ceremony simply times out.

## What this feature deliberately does not do

- **It does not change the relying party.** No server-side agent mode.
- **It does not remove the credential's binding to its backend.**
- **It does not assert a verification that did not happen.** No flag, setting
  or default reports UV; a PIN or a verifying backend does.
- **It does not make automation safe by default.** Every switch here is opt-in,
  the defaults are the human ones, and a missing presence handler is a
  construction error rather than a silent yes.
- **It is not a secret-injection mechanism.** Credentials come from the
  authenticator and the vault, not from environment variables.
