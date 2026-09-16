# Key Escrow — Architecture

> **Status: NORMATIVE** · Feature: `escrow` · Repo: `go-xkms` · Last verified: 2026-09-15

## The problem

NIST SP 800-57 expects a durable key to have an escrow path that lives outside
the system holding the working copy: if the working copy — its disk, its
backend, its whole node — is destroyed, the key must still be recoverable from
somewhere else. `pkg/escrow` is that "somewhere else" for go-xkms: it
replicates wrapped key material to an external service the primary system does
not control, and gets it back on request.

## Shape chosen: one interface, a pluggable agent per external system, a registry that fans out

```go
type EscrowAgent interface {
	Type() string
	Available(ctx context.Context) bool
	EscrowKey(ctx context.Context, req *EscrowRequest) (*EscrowReceipt, error)
	RecoverKey(ctx context.Context, req *RecoverRequest) (*RecoverResponse, error)
	ListEscrowed(ctx context.Context) ([]EscrowRecord, error)
	RevokeEscrow(ctx context.Context, escrowID string) error
	Close() error
}
```

Two implementations satisfy it today:

- **`pkg/escrow/xkms`** — replicates to a remote go-xkms instance over mTLS
  (xkms-to-xkms federation, e.g. a disaster-recovery site).
- **`pkg/escrow/kmip`** — replicates to any KMIP 1.4-compatible server (an
  HSM-backed KMIP appliance, a third-party KMS) via `github.com/ovh/kmip-go`,
  storing the wrapped key as a KMIP Opaque Object.

`Registry` (`pkg/escrow/registry.go`) holds every configured agent and applies
two dispatch strategies, not one, because escrow and recovery have opposite
failure tolerances:

- **`EscrowKeyAll` / `RevokeEscrowAll`** — belt-and-suspenders: send to every
  agent, succeed if at least one accepts. A key that only reached one of two
  configured escrow sites is a key escrow silently failed to fully replicate.
- **`RecoverKeyAny`** — failover: try each agent in turn, return the first
  success. Recovery only needs one surviving copy.

## Key material never leaves in the clear

`EscrowAgent` methods only ever see `WrappedKey []byte` plus a
`WrappingAlgorithm` string (`"AES-KW"` or `"RSA-OAEP-SHA256"`). Wrapping and
unwrapping happen in the caller — the code that already holds the plaintext
key and the wrapping key — never inside `pkg/escrow`. An escrow agent, and
anyone who compromises the external system it talks to, sees ciphertext.

## Why a factory instead of a direct constructor call

`pkg/escrow/xkms` and `pkg/escrow/kmip` both import `pkg/escrow` (for the
`EscrowAgent` interface and shared error types), so `pkg/escrow` cannot import
either of them back — that would cycle. `pkg/escrow/factory.go` resolves this
the same way `pkg/xkms/registry.go` resolves the equivalent problem for
crypto backends: each agent package registers a constructor function against
its `AgentConfig.Type` string from an `init()` function
(`escrow.RegisterAgentFactory`), and `escrow.NewAgent` / `NewRegistryFromConfig`
dispatch through that registry rather than a compiled-in switch. Wiring a
third agent type means adding a new leaf package that registers itself; it
never means editing `pkg/escrow`.

## Wired into the product

As of this change, `pkg/escrow` is reachable from configuration through to the
service layer:

```
config.Config.Escrow (pkg/config)
        │  escrow.Config { Enabled, Agents []AgentConfig }
        ▼
escrow.NewRegistryFromConfig            (pkg/escrow/factory.go)
        │  dispatches each AgentConfig.Type to its registered factory
        ▼
*escrow.Registry                        (one *FederationAgent / *KMIPAgent per configured agent)
        │
        ▼
server.Server.escrowRegistry            (pkg/server/server.go — initializeEscrow)
        │  svc.SetEscrowRegistry(s.escrowRegistry)
        ▼
xkms.XKMSService                        (pkg/xkms/servicer_escrow.go — EscrowServicer)
        │
        ▼
   (transport surface — see "What is not wired yet" below)
```

`xkmsd` loads `escrow:` from its YAML configuration exactly like every other
optional subsystem (see [`engineering.md`](engineering.md)); when the section
is absent or `enabled: false`, no agents are constructed and
`EscrowServicer` methods return `xkms.ErrNotConfigured`.

## What is not wired yet, and why

`pkg/api/rest`'s route table (`pkg/api/rest/routes.go`) gates every
key-material route — `keys:*`, `certs:*`, `barrier:*`, `frost:*` — behind an
RBAC `resource:action` permission pulled from `pkg/auth/permissions.go`. That
file is documented, in the codebase, as **the only authorization vocabulary in
the xkms process**, and every pair in it mirrors a permission already defined
in go-qrdb's canonical registry (`go-qrdb/pkg/permission/constants.go`) — xkms
is not permitted to invent its own resource or action string, because no
qrdb role could ever be granted a permission that does not exist in qrdb's
registry.

Escrow has no counterpart in that registry: `escrow`, or any per-operation
equivalent, does not exist in go-qrdb's `pkg/permission/constants.go` as of
`v0.16.3-alpha`. So gating a REST route, an SDK call, or a CLI verb the normal
way — `perm(method, pattern, auth.ResourceEscrow, auth.ActionX, handler)` —
is not currently possible without either:

1. Filing an issue against `go-qrdb` to add an `escrow:*` permission family to
   its canonical registry (the precedent every other resource in
   `permissions.go` follows), and wiring the xkms route table to it once that
   ships; or
2. Reusing an existing qrdb permission whose semantics already fit — the
   closest candidates being `keys:export` (escrowing = exporting wrapped key
   material to an external system) and `keys:import` (recovery = importing it
   back) — as an explicit, approved exception to "one route, one purpose-built
   permission."

Both are genuine security-policy decisions, not implementation details, so
this change stops short of registering the transport surface and leaves the
choice to the repository owner. See [`api.md`](api.md) and [`cli.md`](cli.md)
for what that leaves reachable today (the embedded Go SDK only, with no RBAC
gate beyond "the caller is running in-process") versus what ships once the
permission question is resolved.

## Rejected alternatives

- **Skip the factory, construct agents inline in `pkg/server`.** Rejected: it
  would duplicate the `AgentConfig` → concrete-config mapping that
  `pkg/escrow/xkms` and `pkg/escrow/kmip` already define next to their own
  `Validate()` methods, and it would make adding a third agent type a
  `pkg/server` change instead of a new leaf package.
- **Gate the transport surface behind `RouteAuthSession` (authenticated, no
  RBAC permission) to unblock reachability now.** Rejected for this change:
  escrow moves the same class of material as `keys:export` / `keys:import`,
  which are permission-gated; shipping it at a strictly weaker bar than its
  closest analogues is a security regression, not a neutral default, and the
  task's instructions are explicit that an ambiguous authorization model is a
  stop condition, not a judgment call to make silently.
