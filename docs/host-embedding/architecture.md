# Host Embedding — Architecture

> **Status: NORMATIVE** · Feature: `host-embedding` · Repo: `go-xkms` · Last verified: 2026-10-09

## The problem

go-xkms ships one qrdb `ServiceModule`, named `xkms` (`pkg/apimodule`). A host
that embeds a go-qrdb node — go-quicbaas, go-trusted-platform — mounts it with
`qrdbserver.WithModule` and gets the xkms capability plane on the node's REST,
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
 tenant store resolver ──WithTenantStores────┤
 PIN backend        ──WithPINBackend─────────┤      hostStores() — once
 sealer             ──WithPlatformSealer─────┼──►   │
 CA identity config ──WithCA─────────────────┤      ▼
 vTPM supervisor    ──WithVTPM───────────────┤    pkg/compose.Build(Deps)
 credential strategy ─WithCredentialStrategy─┘      │  BuildPasswordStore
                                                    │  BuildTenantPasswordManager
                                                    │  BuildPlatformStore
 xkmsd (pkg/server) ──── calls the same ───────────►│  BuildCredentialService
                         Build* functions at        │  BuildSSHClient
                         its own start-up points    │  BuildCA
                                                    │  BuildTPMPolicyService (tpm2 backend)
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
  qrdb client (storage), its tenant barrier registry, its per-tenant store
  resolver, its PIN backend, a sealer, a CA identity hierarchy, a PCR reader.
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

## The barrier is the host's

xkms registers no barrier, custodian, share or init route family: the barrier
and its holder/quorum ceremony are go-qrdb's, served by the host's own node.
The per-tenant store resolver is the data-plane dependency that backs
per-tenant Password Manager stores: each tenant's entries live in that
tenant's go-qrdb system database, sealed by that tenant's barrier.

## Rejected alternatives

- **Have the host build the stores and hand them in.** Every host would repeat
  xkmsd's wiring, and the two would drift. The host supplies inputs; xkms owns
  construction.
- **Read an xkmsd configuration section in host mode.** Hosts already hold the
  live objects (node client, barrier registry, PIN backend); asking them to
  re-describe those as configuration duplicates state.


## Not in this feature

- **Tenant management** (`/api/v1/tenants/*`) stays xkmsd-only on a self-built
  module: it needs xkms's composed tenant service, which a host owns itself.
- **MCP tools** register only behind a host-supplied MCP server
  (`WithMCPServer`); a self-built module has no MCP surface.
