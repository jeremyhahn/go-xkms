# SSH Agent Sessions — CLI

> **Status: NORMATIVE** · Feature: `ssh-agent-sessions` · Repo: `go-xkms` · Last verified: 2026-08-20

**No CLI surface: reachable only through the Go SDK (`xkmsssh.StartAgent`).**

This is deliberate, not an omission. An agent-only session exists to serve a
socket to a **child of the calling process** for as long as that caller lives,
and it dies with the caller's context. A CLI verb would have to either block a
terminal for the session's whole life, or daemonize and outlive its owner —
leaving a signing oracle running with nobody watching it, which is the failure
the lifetime contract is built to exclude.

The verb that would sit here is already provided by OpenSSH: `ssh-agent`. What
xkms adds is serving a key it holds *without exporting it*, and the consumer of
that is a program, not a shell.

Related CLI surface that does exist:

- `xkey ssh connect` — the connection-oriented path, which starts one of these
  sessions internally and adds host-key handling.
  See [`../ssh/README.md`](../ssh/README.md).
- `xkey ssh keys …` — generating and listing the keys a session serves.

Consumers wiring git commit signing do so in Go, not in shell; the worked
example is in [`user.md`](user.md).
