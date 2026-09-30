# Clustering — Architecture

> **Status: NORMATIVE** · Feature: `clustering` · Repo: `go-xkms` · Last verified: 2026-09-24

## The problem

A single `xkmsd` node is a single point of failure. High-availability
deployments need multiple nodes sharing one replicated datastore, so any
node's loss does not lose keys, and clients can keep writing once a new
leader is elected.

Per this repository's ownership boundary (`CLAUDE.md` "Layer Ownership"),
go-xkms ships **no Raft implementation, no consensus engine, and no
embedded state machine of its own** — clustering is go-qrdb's. What xkms
owns is: embedding go-qrdb's clustered node, translating xkms's own
`cluster:` configuration onto go-qrdb's Raft config, provisioning the
inter-node mTLS the Raft transport requires (composing the runtime CA and
TPM attestation xkms already owns), exposing read-only cluster status to
the web console, and giving operators a CLI to inspect and manage the
resulting cluster.

## Shape chosen: one embedded node, standalone by default, clustered behind a build tag

`xkmsd` always hosts exactly one embedded qrdb node when
`datastore.mode: "standalone"` (the default — see
[`../datastore/architecture.md`](../datastore/architecture.md)).
Whether that node is standalone or a Raft cluster member is a **build-time**
decision as well as a config one:

```
default build (no -tags raft):
  pkg/server/qrdb_node_standalone.go  →  always qrdb.NewStandaloneNode
  cluster.enabled=true here fails immediately: ErrClusterRequiresRaftBuild

-tags raft build:
  pkg/server/qrdb_node_cluster.go     →  cluster.enabled=false → still standalone
                                          cluster.enabled=true  → qrdb.NewClusteredNode
```

Neither build path implements two different servers: `-tags raft` only adds
the code that CAN cluster, and still runs single-node when `cluster.enabled`
is false. This is deliberate — a raft-tagged binary is not a heavier or
riskier default; it simply has more available.

**`-tags raft` is not part of any default `make` target.** `Makefile`'s
`SERVER_BUILD_TAGS` (used by `build-server`/`build-servers`, and therefore by
`make build`) does not include `raft`. It is used in exactly two places in
this repository: the CI job `build-raft` (`.github/workflows/ci.yml`), which
builds and tests the `raft`-tagged matrix specifically to keep it from
rotting, and `test/integration/cluster/Dockerfile.xkmsd`, which builds the
image the 3-node cluster integration test runs. An operator who wants a
clustered `xkmsd` binary must build it themselves with `-tags raft` (plus
whichever other tags their deployment needs); it does not ship pre-built by
the default targets.

The build tag mirrors down into `pkg/daemon`, the shared node-construction
package both `pkg/server` and other embedders use:
`pkg/daemon/node_standalone.go` (`//go:build !raft`) always builds a
standalone node and refuses `Cluster.Enabled`; `pkg/daemon/node_cluster.go`
(`//go:build raft`) builds a clustered node when enabled, standalone
otherwise.

## Two distinct surfaces over the same Raft shard

Cluster status and membership are reachable through **two independent
surfaces**, each built for a different caller, reading the *same* Raft shard
through the *same* underlying go-qrdb `ClusterClient` — there is no second
membership model:

1. **go-qrdb's own control plane**, registered directly onto xkmsd's gRPC
   server and Unix socket with zero xkms-authored handlers
   (`pkg/server/qrdb_control_plane.go:registerQRDBControlPlane`). `xkmsctl
   cluster status|members|add|remove` and `xkmsctl rebalance ...`
   (`cmd/xkmsctl/cluster.go`, `rebalance.go`) drive this surface as a qrdb
   SDK client over gRPC or the Unix socket — never through xkms's REST API.
   This is the operator/automation path, the only one that can mutate
   membership, and the one qrdb's own `AdminService`/`RebalanceService` RPCs
   answer.
2. **The xkms REST cluster surface**, `GET /api/v1/cluster/status` and `GET
   /api/v1/cluster/members` (`pkg/api/rest/handlers_cluster.go:ClusterHandlers`,
   registered in `pkg/api/rest/routes.go`), backed by the `XKMSService`
   servicer (`pkg/xkms/servicer_cluster.go`). This exists because a browser
   cannot speak gRPC or reach a Unix socket: the embedded web console's
   read-only Cluster page (`web/app/src/views/ClusterView.svelte`) and the
   TypeScript SDK's `ClusterClient` (`sdk/ts/src/clients/cluster.ts`) need an
   HTTP surface, authenticated and authorized exactly like every other xkms
   API route. The REST layer never calls qrdb directly for reads; it goes
   through the `XKMSService` servicer, following the same service-layer
   discipline as every other xkms subsystem (custodian groups, shares,
   tenants, …).

**Membership is mutated through surface #1 only — REST exposes no mutation
route at all.** There is no `POST`/`DELETE /api/v1/cluster/members`: a route
that could only ever answer "not implemented" would be a stub, and this
codebase does not register stubs
(`pkg/api/rest/handlers_cluster.go`'s package doc). This is not a gap to be
filled in later: an earlier xkms-authored cluster/auth-factor proxy plane was
already deleted once (`registerQRDBControlPlane`'s own comment records
replacing "the deleted xkms-authored cluster/auth-factor proxy planes"), and
adding a REST mutation path — working or not — would recreate exactly that
proxy. `docs/web/parity.md`'s "Cluster mutations" section and the web
console's Cluster page banner document the same decision independently. The
`XKMSService` servicer therefore exposes only the read half (`ClusterStatus`,
`ClusterMembers`); the lower-level `ClusterClient`/`ClusterMutator` Go
contract the qrdb SDK adapter satisfies still carries `AddReplica`/
`RemoveReplica` (`pkg/server/cluster_adapter.go`) — that plumbing exists only
to satisfy the qrdb SDK's shape, and no `XKMSService` method, and nothing in
REST/gRPC/QUIC, ever calls it.

### Standalone degradation, not capability gating, for reads

`XKMSService.Clustered()` (`pkg/xkms/service.go`) reports whether this
node's cluster client is wired (`SetClusterClient` with a non-nil
`ClusterClient`, set only when `config.Cluster.Enabled`). Read operations do
**not** gate on it:

- `ClusterStatus` returns `{clustered: false, has_leader: false, leader_id:
  0}` on a standalone node instead of failing — there is a well-defined
  "no cluster" status, not an absent one.
- `ClusterMembers` returns an empty list on a standalone node.

`ClusterStatus` and `ClusterMembers` are the only two servicer methods in
the codebase that intentionally *degrade* rather than fail closed on a
missing optional subsystem — every other subsystem servicer method
(custodian, shares, tenants, …) returns `xkms.ErrNotConfigured` when its
backing client is nil. This lets the web console's Cluster page render a
"standalone" badge correctly whether or not the deployment ever intends to
cluster, and lets `xkmsctl cluster status`/`members` work identically on
every node. The REST `/auth/me` `capabilities.cluster` flag
(`pkg/api/rest/handlers_auth.go:capabilityFlags`) still reports `false` on a
standalone node — it exists only to hide the web console nav entry by
default, not to gate the read routes; the routes themselves remain
reachable if navigated to directly.

## Component boundaries

| Piece | Where | Owner |
|---|---|---|
| Raft consensus, the clustered state machine, leader election | go-qrdb SDK (`qrdbnode.NewClusteredNode`) | **go-qrdb** |
| `cluster:` config → go-qrdb `Raft` config mapping | `Server.buildXKMSQRDBConfig` (`pkg/server/qrdb_node.go`) | go-xkms |
| Build-tag dispatch (standalone vs. clustered `newQRDBNode`) | `pkg/server/qrdb_node_standalone.go` (`!raft`), `qrdb_node_cluster.go` (`raft`); shared logic in `pkg/daemon` | go-xkms |
| Inter-node Raft mTLS provisioning (4-tier precedence) | `Server.resolveRaftMTLS` (`pkg/server/qrdb_node_cluster.go`) | go-xkms (composes the runtime CA / TPM attestation xkms owns) |
| Cluster CA key custody strategies (`barrier` / `hsm` / `tpm-kek`) | `pkg/trust/clusterca`, wired by `pkg/server/cluster_ca_strategy.go` | go-xkms (strategy toolkit re-exported via `sdk/go/clusterca` for the rest of the stack) |
| Leader wait, cluster advertisement | `Server.waitForClusterLeader`, `startClusterAdvertiser` (`pkg/server/qrdb_node.go`, `cluster_advertise.go`) | go-xkms |
| Not-leader → redirect translation per transport | `pkg/api/rest/errors.go`, `pkg/api/grpc/errors.go`, `pkg/xkms/errors.go` | go-xkms |
| Cluster admin / rebalance control plane (status, membership, shard stats) | go-qrdb's `AdminServicer`/`RebalanceServicer`, registered by `pkg/server/qrdb_control_plane.go` | **go-qrdb** implements; go-xkms registers it onto its own listeners |
| `xkmsctl cluster` / `xkmsctl rebalance` | `cmd/xkmsctl/cluster.go`, `rebalance.go` | go-xkms CLI, speaking the qrdb SDK client directly |
| REST cluster status/members (web console) | `pkg/api/rest/handlers_cluster.go:ClusterHandlers`, `pkg/xkms/servicer_cluster.go` | go-xkms, delegating reads to the embedded go-qrdb node's cluster client |

## Data flow

```
boot (raft build, cluster.enabled=true):
  config.Cluster → buildXKMSQRDBConfig → qcfg.Raft{ReplicaID, ShardID,
    DeploymentID, RaftAddress, ListenAddress, Peers, Join}
  → resolveRaftMTLS (only for >1 member): operator PEM files, else
    TPM-attested ACME enroll-01, else hardware node key, else
    software auto-provisioned cluster CA (clusterenroll)
  → qrdbnode.NewClusteredNode(...)
  → waitForClusterLeader (30s, 250ms poll) before the server reports ready
  → startClusterAdvertiser publishes this node's API endpoints

client write reaches a follower:
  qrdb rejects the write → xkms.AsNotLeader(err) → typed ErrNotLeader
  → REST/QUIC: HTTP 421 with leader coordinates in headers + JSON body
  → gRPC: FailedPrecondition status, ErrorInfo{Reason: "NOT_LEADER"}
  → SDK client: follows the redirect once, re-presenting the caller's
    OWN credentials to the leader (never a server-side forward)

web console / SDK reads cluster status or membership:
  GET /api/v1/cluster/status | /api/v1/cluster/members
  → ClusterHandlers → XKMSService.ClusterStatus / ClusterMembers
  → embedded go-qrdb node's ClusterClient (Members, Leader)
  → degrades to {clustered:false} / [] on a standalone node, never errors

xkmsctl cluster / rebalance:
  dials xkmsd's Unix socket (default) or --transport grpc / grpc://
  → speaks go-qrdb's OWN control-plane gRPC service directly
    (AdminServicer, RebalanceServicer) — no xkms-authored proxy,
    reachable only there, never through /api/v1/cluster/*
```

## Leader redirect (client request routing)

xkms client APIs (REST, gRPC, QUIC, Unix socket) route around Raft
leadership independently of the cluster status/membership surface above:

- Read operations succeed on any member.
- Write operations (`CreateKey`, `SignCSR`, `SetPin`, …) require the leader.
  A write sent to a follower is rejected with a typed not-leader error
  naming the current leader, surfaced per protocol (REST: HTTP `421
  Misdirected Request` with `X-XKMS-Leader-*` headers; gRPC/Unix:
  `FailedPrecondition` with an `ErrorInfo` detail; QUIC: the same `421`
  mapping as REST) — see `pkg/xkms/errors.go:ErrNotLeader`,
  `pkg/api/rest/errors.go:writeNotLeader`.

xkms **redirects the client** to the leader rather than forwarding
server-side. This is a security decision: xkms identities are bound to the
caller's own credentials (mTLS client certificate or session token). A
follower does not hold the caller's private key, so it cannot re-present the
caller's identity to the leader; forwarding server-side would require either
an impersonation channel or a full delegation protocol. With a redirect the
caller re-presents its own credentials to the leader, so the leader enforces
authentication and authorization exactly as it would for a directly-dialed
request.

Redirect behavior: exactly one hop (a second not-leader response is returned
to the caller rather than chased, so a leadership flap cannot loop); the
retry reuses the same TLS configuration and credentials; the client's
configured address is never permanently repointed; a not-leader response
carrying no API address is returned unchanged; the Unix socket transport
never follows redirects (a local socket client has no network credentials).

The cluster status/membership routes above are never subject to this
redirect — they answer from local Raft state on any member, standalone or
not.

### Advertised API endpoints

For a redirect to be actionable, a client must be able to turn "the leader is
replica N" into a dialable address. Each node publishes its own
client-facing API endpoints into the cluster registry, keyed by protocol
(`rest`, `grpc`, `quic`, `mcp` — never the Unix socket, which is meaningful
only on the node that owns it). Values come from the node's own
configuration (`cluster.advertise_host` plus each enabled protocol's
configured port), never derived from the Raft address by port arithmetic.
When no concrete host is available the node advertises nothing rather than
an address no client can dial, and membership listing never fails because
endpoint discovery did (`pkg/server/cluster_adapter.go:apiEndpointsToStrings`).
`xkmsctl cluster members` and the REST `/api/v1/cluster/members` route both
surface these endpoints per replica.

## Cluster CA key custody

Provisioning inter-node Raft mTLS and deciding which nodes may issue node
certificates is a separate design surface from Raft membership itself. See
[Cluster CA Key Custody Architecture](ca-key-custody.md) for the
`ClusterCAKeyStrategy` seam, the three custody models (`barrier`, `hsm`,
`tpm-kek`), and TPM-sealed seed delivery.

## Trust boundaries

- **Clustering redirects clients; it does not forward requests
  server-side.** A follower that received a write does not hold the
  caller's private key or session, so it cannot re-present the caller's
  identity to the leader without either impersonating them (one compromised
  node could then forge any identity cluster-wide) or building a full
  delegation protocol. Redirecting the *client* to retry against the leader
  with its own credentials avoids both.
- **The runtime xkms CA must never back Raft mTLS directly** — it is hosted
  by the very node the Raft transport replicates, so the two would be
  circular. Operator-supplied PEM files or the dedicated auto-provisioned
  cluster CA are used instead (`ClusterConfig.RaftTLS` doc comment,
  `pkg/config/config.go`).
- **The qrdb control plane's authorization posture is transitional; the REST
  cluster surface's is not.** `registerQRDBControlPlane`
  (`pkg/server/qrdb_control_plane.go`) states explicitly that its RPCs sit
  behind xkmsd's transport authentication (TLS + adaptive auth; the Unix
  socket adds filesystem-permission trust) and are **not yet** gated by
  xkms's own resource:action RBAC — membership mutation (`cluster
  add`/`remove`) requires only whatever the transport it is reached over
  already requires. The REST read routes are different: both `GET
  /api/v1/cluster/status` and `GET /api/v1/cluster/members` require the
  `admin:status`/`admin:peers` RBAC permission when RBAC is enabled
  (`pkg/auth/permissions.go`, enforced in `pkg/api/rest/routes.go`) — the
  same grant qrdb's own control-plane surface uses internally, so a caller's
  RBAC role never has to diverge between the two surfaces, even though only
  one of them currently enforces it at the xkms layer.
- **The KV data plane is deliberately unreachable through the qrdb control
  plane.** `registerQRDBControlPlane` registers the admin/rebalance/user
  surfaces with the KV servicer nil, so every data-plane RPC answers
  `Unimplemented` — "go-xkms is not a database server product" (comment,
  same file). Clustering replicates xkms's own data; it does not turn
  `xkmsd` into a general KV service.
- **A single-node cluster needs no Raft mTLS**; the in-process transport
  needs no peer certificates. Any cluster with more than one member always
  requires mTLS — it is mandatory in the Raft transport itself.

## What this feature deliberately does not do

- **It does not implement Raft, leader election, or log replication.**
  Entirely go-qrdb's.
- **It does not expose cluster *membership mutation* over xkms's own
  REST/gRPC/MCP API.** There is no `POST`/`DELETE /api/v1/cluster/members`
  and no `AddClusterReplica`/`RemoveClusterReplica` gRPC RPC on xkms's
  `XKMSService` — verified absent from `pkg/api/rest/routes.go` and
  `pkg/api/grpc`. Membership management goes through `xkmsctl
  cluster`/`rebalance` only, which dial go-qrdb's own control-plane service
  directly. Cluster *status and membership reads* are different: `GET
  /api/v1/cluster/status` and `GET /api/v1/cluster/members` do exist on the
  REST surface (`pkg/api/rest/handlers_cluster.go`, since go-xkms#847) for
  the web console; see "Two distinct surfaces over the same Raft shard" above. gRPC
  and MCP still carry no dedicated cluster status/membership RPC or tool —
  verified absent from `pkg/api/grpc` and `pkg/api/mcp`.
- **It does not migrate data between storage engines** or provide a way to
  convert a standalone deployment's data into a cluster's replicated state;
  starting a cluster starts a new replicated store.
