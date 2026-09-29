# Host Embedding — Architecture

> **Status: NORMATIVE** · Feature: `host-embedding` · Repo: `go-xkms` · Last verified: 2026-09-29

## The problem

go-xkms ships one qrdb `ServiceModule`, named `xkms` (`pkg/apimodule`). A host
that embeds a go-qrdb node — go-quicbaas, go-trusted-platform — mounts it with
`qrdbsdk.WithModule` and gets the xkms capability plane on the node's REST,
gRPC, unix, QUIC and MCP transports.

Before this feature, a mounted module was **host-inert** for every
store-backed feature: the self-built REST surface (`rest.NewHostServer`)
composed keys, certificates and the login plane, but no Password Manager, SSH,
Certificate Authority, platform sealed-secret store, credential service or PCR
policies. Those were built only by `xkmsd` (`pkg/server`), from its own
configuration file. A host therefore served routes that answered 404, 501 or
"not configured", and a client such as `xkey` could not use them against it.

## Shape chosen: the host supplies dependencies, the module builds the stores

```
 host (e.g. a qrdb-embedding daemon)             go-xkms
 ─────────────────────────────────────           ─────────────────────────────
 qrdb node client   ──WithQRDBClient────────┐
 tenant barrier registry ─WithBarrierRegistry┤    pkg/apimodule.Module
 PIN backend        ──WithPINBackend─────────┤      hostStores() — once
 sealer             ──WithPlatformSealer─────┼──►   │
 CA identity config ──WithCA─────────────────┤      ▼
 PCR reader (TPM)   ──WithPCRReader──────────┤    pkg/compose.Build(Deps)
 credential strategy ─WithCredentialStrategy─┤      │  BuildPasswordStore
 opt-in             ──WithBarrierRoutes──────┘      │  BuildTenantPasswordManager
                                                    │  BuildPlatformStore
 xkmsd (pkg/server) ──── calls the same ───────────►│  BuildCredentialService
                         Build* functions at        │  BuildSSHClient
                         its own start-up points    │  BuildCA
                                                    │  BuildPolicyManager
                                                    ▼
                                           Stores.Wire(XKMSService)
```

- **One construction path.** `pkg/compose` holds a `Build*` function per
  store. `xkmsd` calls them at the points of its start-up sequence where their
  inputs exist; a host reaches them through `compose.Build`, which
  `pkg/apimodule` runs on the module's first use. Both publish the result with
  `Stores.Wire`, so a store is never built two different ways.
- **Dependencies, not configuration.** The module does not read a
  configuration file. Each option supplies one thing only the host has: its
  qrdb client (storage), its tenant barrier registry, its PIN backend, a
  sealer, a CA identity hierarchy, a PCR reader.
- **Missing means off, and says so.** A feature whose dependency is absent
  stays off. `compose.Build` records a typed `*FeatureDisabledError` (or a
  `*FeatureBuildError` when construction failed) per feature, logs each one,
  and the module exposes them through `(*Module).HostStores().Disabled`.
- **Composed once, for every transport.** The first use of any transport (the
  REST self-build or the gRPC keystore) composes; the result is memoized under
  a mutex because building a CA initializes a root on first use and must not
  run twice.
- **Stores live in the host's KV.** Each store is a prefixed view of the
  host's qrdb KV under `xkms/<feature>/` (`apimodule.HostStoragePrefix`), so
  they replicate with the node and never collide with the host's own keys.

## The barrier stays the host's unless it opts in

The barrier route families — `/api/v1/barrier/*`, `/api/v1/custodian/*`,
`/api/v1/shares/*`, `/api/v1/init/*` (`rest.IsBarrierRoute`) — operate the
system barrier's lifecycle. A host that owns its barrier must keep those
paths, so on a self-built module they are **not registered** unless the host
passes `WithBarrierRoutes`. With it, the module serves them over the host's
own qrdb barrier (the system barrier of `WithBarrierRegistry`) and custody
clients (`WithQRDBClient`). A module bound to a host-supplied REST server
(`WithRESTServer`, which is how `xkmsd` mounts it) always registers them: that
server decides what it serves.

The tenant barrier registry is a data-plane dependency independent of that
choice: it always backs per-tenant Password Manager stores.

## Rejected alternatives

- **Have the host build the stores and hand them in.** Every host would repeat
  xkmsd's wiring, and the two would drift. The host supplies inputs; xkms owns
  construction.
- **Read an xkmsd configuration section in host mode.** Hosts already hold the
  live objects (node client, barrier registry, PIN backend); asking them to
  re-describe those as configuration duplicates state.
- **Always register the barrier routes and answer 501.** A host that serves
  its own barrier would then need a route-excluding wrapper to reclaim its own
  paths. Opt-in registration leaves the paths free by default; a wrapper still
  works for a host that has one.

## Not in this feature

- **Tenant management** (`/api/v1/tenants/*`) stays xkmsd-only on a self-built
  module: it needs xkms's composed tenant service, which a host owns itself.
- **The init ceremony** (`/api/v1/init/*`) registers with `WithBarrierRoutes`
  but answers 501: it needs an operator-configured ceremony service, which no
  running daemon composes today (xkmsd drives it offline through `xkmsd init`).
- **MCP tools** register only behind a host-supplied MCP server
  (`WithMCPServer`); a self-built module has no MCP surface.
- **PCR policies in xkmsd**: xkmsd has no PCR reader source, so its policy
  manager stays off. A host supplies one with `WithPCRReader`.
