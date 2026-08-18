# Agent Automation — Architecture

> **Status: NORMATIVE** · Feature: `agent-automation` · Module: `go-xkms/xkey` · Last verified: 2026-08-19

## The problem

Every strong credential in this stack is built on a human gesture: touch the
key, enter the PIN. That is the security property. It is also, for an agent or a
CI job, an absolute barrier — there is nobody there.

The wrong answers are well known: give the machine a bearer token in a file, or
turn the security property off globally. This feature is the third option —
**satisfy the gesture programmatically, in a place and with a scope that is
chosen deliberately.**

## Shape chosen: opt-in flags on the authenticator, not a mode on the server

Automation is configured where the authenticator runs, not where credentials are
verified:

| Flag on `xkey fido2` | Default | What it does |
|---|---|---|
| `--auto-uv` | `false` | satisfies user verification without a human |
| `--require-touch` | `true` | when false, drops the presence requirement |
| `--notify` | `dialog` | `none` stops prompting for a human who is not there |
| `--cdp` | `false` | Chrome DevTools bridge, for browser automation |

Plus PIN supply without a terminal:

| Verb | Flag | Notes |
|---|---|---|
| `xkey unlock` | `--pin-stdin` | read the PIN from stdin |
| `xkey unlock` | `--pin` | **visible in the process list** — the help says so |
| `xkey touch` | `--password` | name of the password to type on a synthetic touch |

The relying party is unchanged and unaware. That is the design decision: there
is no "agent mode" on the server, no weakened policy, and no second
authentication path to audit. The gesture happens; who performed it is a
property of where the authenticator runs.

Rejected alternatives:

- **A bearer token for agents.** Rejected — copyable, long-lived, and the thing
  the dogfooding mandate moves away from: agent credentials belong on per-agent
  xkey instances using FIDO2/PIV/mTLS rather than raw key files.
- **A server-side "trusted client" exemption.** Rejected: it moves the decision
  to the wrong place and creates a second trust path.
- **Making `--auto-uv` the default.** Rejected. The default has to be the safe
  one; automation is an explicit act.

## Component boundaries

| Piece | Where |
|---|---|
| Presence automation | `xkey/pkg/authenticator` (user-presence path) |
| Notification routing | `xkey/pkg/notify` |
| PIN/touch IPC | `xkey/pkg/ipc`, `xkey/cmd/xkey/cmd/{unlock,touch}.go` |
| Chrome DevTools bridge | `xkey/pkg/cdp` |
| Synthetic keyboard input | `xkey/pkg/keyboard` |
| Agent lifecycle | `xkey/pkg/agent`, `xkey/cmd/xkey/cmd/agent*.go` |
| SDK integration | `go-xkms/sdk/go` `XKEY_IPC_SOCKET` (`sdk/go/options.go`) |

Capability row: **"PIN/touch automation for agents and CI"** under the xkey
product surface — `xkey unlock --pin-stdin`, `xkey touch`, `--auto-uv`, `--cdp`.

## Data flow

```
agent / CI                      xkey fido2 (--auto-uv --notify none)
   │                                     │
   ├─ xkey unlock --pin-stdin ──────────►│  (PIN over the local IPC socket)
   │                                     │
   ├─ xkey auth login ──────────────────►│  ceremony; presence satisfied locally
   │                                     │      │
   │                                     │      └─► relying party (unmodified)
   └─ xkey auth token ──────────────────►│
        └─► xkmsctl --token …, or SDK via XKEY_IPC_SOCKET
```

`xkey touch` triggers a synthetic touch — optionally typing a named password
through `xkey/pkg/keyboard`, which is what makes the vault usable from a
non-browser context.

## Trust boundaries

- **`--auto-uv` moves the credential from "something a person has and used" to
  "something this machine has".** That is the trade, stated plainly. It is
  correct for an agent whose machine is the identity, and wrong on a workstation
  where the human is.
- **The blast radius is the machine.** Anything that can reach the IPC socket
  while the authenticator is unlocked can use the credential. Filesystem
  permissions on `$XDG_RUNTIME_DIR/xkey/xkey.sock` are the access control.
- **`--pin` puts the PIN in the process list.** The flag's own help says so.
  `--pin-stdin` is the form to use.
- **`--cdp` opens a debugging port** (default `9222`). Anything that reaches it
  drives the authenticator. Loopback only.
- **The credential's strength is still the backend's.** `--auto-uv` with
  `--backend software` is a file that logs in by itself; with `--backend tpm2`
  it is a machine-bound credential that logs in by itself. Very different
  things.
- **`--notify none` is not cosmetic** in this context — with presence still
  required and nobody to prompt, the ceremony simply times out.

## What this feature deliberately does not do

- **It does not change the relying party.** No server-side agent mode.
- **It does not remove the credential's binding to its backend.**
- **It does not make automation safe by default.** Every flag here is opt-in,
  and the defaults are the human ones.
- **It is not a secret-injection mechanism.** Credentials come from the
  authenticator and the vault, not from environment variables.
