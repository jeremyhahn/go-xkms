# Key Escrow — User Guide

> **Status: NORMATIVE** · Feature: `escrow` · Repo: `go-xkms` · Last verified: 2026-09-15

## What this is for

If the machine running `xkmsd` — its disk, its backend, the whole node — is
destroyed, you need a copy of your durable keys somewhere else to recover
from. Key escrow replicates already-wrapped key material to an external
system you control: a disaster-recovery `xkmsd` instance, or a KMIP-speaking
appliance or third-party KMS.

**This is not a general secrets vault.** It is specifically for keys that
must survive the loss of the system that generated them.

## Before you turn it on

Escrow never sees a key in the clear. Whatever you send it must already be
wrapped with AES-KW or RSA-OAEP — wrapping happens in your own code or
tooling, before the key reaches escrow. Decide your wrapping key and how you
will get the corresponding unwrap key to wherever you will run recovery,
before you need it.

## Configuring an escrow agent

Add an `escrow:` section to your `xkmsd` configuration:

```yaml
escrow:
  enabled: true
  agents:
    - type: "xkms"                       # or "kmip"
      name: "dr-site"                    # optional; identifies this agent
      endpoint: "https://dr-xkms.example.com:8443"
      client_cert: "<install-dir>/certs/escrow-client.pem"
      client_key: "<install-dir>/certs/escrow-client-key.pem"
      ca_cert: "<install-dir>/certs/escrow-ca.pem"
```

You can configure more than one agent — every escrow submits to all of them
(belt-and-suspenders), and recovery tries each until one has the key. Two
agents of the same `type` need distinct `name` values.

Restart `xkmsd` after changing this section; escrow is configured at
startup.

## How to reach it right now

Escrow is not yet reachable from `xkmsctl` or over the network (REST, gRPC,
QUIC, MCP) — see [`cli.md`](cli.md) and [`api.md`](api.md) for exactly why
and what is blocking it. Today, the only way to escrow, recover, list, or
revoke a key is from Go code running in the same process as `xkmsd` (for
example, a program that embeds `pkg/xkms.XKMSService` directly, or composes
xkms via `sdk/go`'s embedded transport). If that is not how you consume
xkms, this feature is configured and audited, but not yet something you can
drive from a terminal or a remote client.

## What to expect once it is fully wired

- `xkmsctl escrow submit --key-id ... --wrapped-key ...` — escrow a
  pre-wrapped key.
- `xkmsctl escrow recover --key-id ...` — get the wrapped key material back.
  You unwrap it yourself; `xkmsctl` never holds the unwrap key.
- `xkmsctl escrow list` — see everything currently escrowed.
- `xkmsctl escrow revoke --escrow-id ...` — remove an escrowed key from every
  configured agent.

## Troubleshooting

- **"escrow: agent not configured" / not reachable from the CLI or REST** —
  expected today; see "How to reach it right now" above.
- **"escrow: no agents configured"** — `escrow.enabled: true` with an empty
  `agents` list. Add at least one agent or set `enabled: false`.
  `xkmsd` refuses to start with this configuration.
- **"escrow: agent already registered"** — two agents share a `type` and
  neither (or both) sets a distinct `name`. Give each a unique `name`.
- **A KMIP or xkms-federation agent is unreachable at startup** — `xkmsd`
  still starts; escrow calls to that agent fail until it is reachable. Check
  `client_cert` / `client_key` / `ca_cert` paths and that the remote endpoint
  accepts the configured mTLS client certificate.
