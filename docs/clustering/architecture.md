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
TPM attestation xkms already owns), and giving operators a CLI to inspect
and manage the resulting cluster.

## Shape chosen: one embedded node, standalone by default, clustered behind a build tag

`xkmsd` always hosts exactly one embedded qrdb node when
`storage.backend: "qrdb"` (see
[`../storage-engines/architecture.md`](../storage-engines/architecture.md)).
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

## Component boundaries

| Piece | Where | Owner |
|---|---|---|
| Raft consensus, the clustered state machine, leader election | go-qrdb SDK (`qrdbnode.NewClusteredNode`) | **go-qrdb** |
| `cluster:` config → go-qrdb `Raft` config mapping | `Server.buildXKMSQRDBConfig` (`pkg/server/qrdb_node.go`) | go-xkms |
| Build-tag dispatch (standalone vs. clustered `newQRDBNode`) | `pkg/server/qrdb_node_standalone.go` (`!raft`), `qrdb_node_cluster.go` (`raft`); shared logic in `pkg/daemon` | go-xkms |
| Inter-node Raft mTLS provisioning (4-tier precedence) | `Server.resolveRaftMTLS` (`pkg/server/qrdb_node_cluster.go`) | go-xkms (composes the runtime CA / TPM attestation xkms owns) |
| Cluster CA key custody strategies (`barrier` / `hsm` / `tpm-kek`) | `pkg/server/cluster_ca_strategy.go`, `sdk/go/clusterca` | go-xkms |
| Leader wait, cluster advertisement | `Server.waitForClusterLeader`, `startClusterAdvertiser` (`pkg/server/qrdb_node.go`, `cluster_advertise.go`) | go-xkms |
| Not-leader → redirect translation per transport | `pkg/api/rest/errors.go`, `pkg/api/grpc/errors.go`, `pkg/xkms/errors.go` | go-xkms |
| Cluster admin / rebalance control plane (status, membership, shard stats) | go-qrdb's `AdminServicer`/`RebalanceServicer`, registered by `pkg/server/qrdb_control_plane.go` | **go-qrdb** implements; go-xkms registers it onto its own listeners |
| `xkmsctl cluster` / `xkmsctl rebalance` | `cmd/xkmsctl/cluster.go`, `rebalance.go` | go-xkms CLI, speaking the qrdb SDK client directly |

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

xkmsctl cluster / rebalance:
  dials xkmsd's Unix socket (default) or --transport grpc / grpc://
  → speaks go-qrdb's OWN control-plane gRPC service directly
    (AdminServicer, RebalanceServicer) — no xkms-authored proxy,
    no /api/v1/cluster/* REST route
```

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
- **The cluster control plane's authorization posture is transitional.**
  `registerQRDBControlPlane` (`pkg/server/qrdb_control_plane.go`) states
  explicitly that these RPCs sit behind xkmsd's transport authentication
  (TLS + adaptive auth; the Unix socket adds filesystem-permission trust)
  and are **not yet** gated by xkms's own resource:action RBAC — fine-grained
  authorization on this surface is future work. Do not assume membership
  mutation (`cluster add`/`remove`) requires a specific RBAC permission
  today; it requires only whatever the transport it is reached over already
  requires.
- **The KV data plane is deliberately unreachable through this control
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
- **It does not expose cluster status or membership over xkms's own
  REST/gRPC/MCP API.** There is no `/api/v1/cluster/*` route and no
  `AddClusterReplica`/`RemoveClusterReplica` gRPC RPC on xkms's `XKMSService`
  — verified absent from `pkg/api/rest/routes.go` and `pkg/api/grpc`. Cluster
  inspection and membership management go through `xkmsctl cluster`
  /`rebalance`, which dial go-qrdb's own control-plane service directly. A
  prior documentation pass described `GET /api/v1/cluster/status` and
  `admin:add_member`/`admin:remove_member` xkms permissions; neither exists
  in this codebase, and `qrdb_control_plane.go`'s own comment records that
  the design it describes was a "deleted xkms-authored cluster ... proxy
  plane."
- **It does not migrate data between storage engines** or provide a way to
  convert a standalone deployment's data into a cluster's replicated state;
  starting a cluster starts a new replicated store.
