# Key Escrow — CLI

> **Status: NORMATIVE** · Feature: `escrow` · Repo: `go-xkms` · Last verified: 2026-09-15

**No CLI surface yet.** `xkmsctl` has no `escrow` command group.

This is not a design choice the way it is for
[`ssh-agent-sessions`](../ssh-agent-sessions/cli.md) — it is a blocked one.
`xkmsctl` verbs for key operations (`xkmsctl keys sign`, `xkmsctl certs
generate`, …) work by calling the REST API, which enforces RBAC on the
server side; the CLI itself carries no permission logic. Escrow's REST route
is not registered for the reason in
[`architecture.md`](architecture.md#what-is-not-wired-yet-and-why): every
existing key-material route is gated by an RBAC `resource:action` pair drawn
from go-qrdb's canonical permission registry, and that registry has no
`escrow` family. Adding CLI verbs ahead of that decision would either ship
them with no server-side authorization at all, or require guessing which
existing permission to reuse — both are choices [`architecture.md`](architecture.md)
explains this change does not make unilaterally.

## What works today

Escrow is reachable from the embedded Go SDK inside the xkmsd process (see
[`api.md`](api.md#embedded-go-sdk-works-today)) and is fully configured and
tested end-to-end through the service layer. Nothing between "an operator at
a terminal" and "an escrowed key" exists yet.

## Once the permission question is resolved

The expected shape, matching the existing `xkmsctl` command groups
(`xkmsctl key …`, `xkmsctl seal …`):

```
xkmsctl escrow submit   --key-id <id> --wrapped-key <path> --algorithm AES-KW [--purpose backup] [--tenant <id>]
xkmsctl escrow recover  --key-id <id> | --escrow-id <id>
xkmsctl escrow list
xkmsctl escrow revoke   --escrow-id <id>
```

`submit` and `recover` operate on already-wrapped key material — `xkmsctl`
does not wrap or unwrap on the operator's behalf, matching
[`architecture.md`](architecture.md)'s "key material never leaves in the
clear" invariant. This file will be updated with real flag definitions and
runnable examples in the same change that registers the CLI verbs.
