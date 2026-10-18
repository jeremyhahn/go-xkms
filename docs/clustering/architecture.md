# Clustering — Architecture

> **Status: NORMATIVE** · Feature: `clustering` · Repo: `go-xkms` · Last verified: 2026-10-12

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
TPM attestation xkms already owns), redirecting writes to the leader, and
giving operators a CLI to inspect and manage the resulting cluster.

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

The build tag mirrors down into `pkg/embeddednode`, the single node builder
that `pkg/server`, `pkg/datastore` and every SDK embedder (`NewDaemonNode`)
use: `pkg/embeddednode/node_standalone.go` (`//go:build !raft`) always builds
a standalone node and refuses `Cluster.Enabled`;
`pkg/embeddednode/node_cluster.go` (`//go:build raft`) builds a clustered
node when enabled, standalone otherwise. There is no second node builder.

## One cluster control plane: go-qrdb's

Cluster status, membership and membership changes have exactly one surface:
go-qrdb's own control plane, which the embedded node serves itself on its TLS
Unix socket with zero xkms-authored handlers (xkms only maps
`protocols.unix` and `unix.socket_path` onto the node,
`pkg/server/qrdb_node.go:85-89`), plus the embedded node's admin-plane
`GET /peers`. `xkmsctl cluster
status|members|add|remove` and `xkmsctl rebalance ...`
(`cmd/xkmsctl/cluster.go`, `rebalance.go`) drive it as a qrdb SDK client over
gRPC or the Unix socket. go-qrdb's `AdminService`/`RebalanceService` RPCs
answer.

xkms re-hosts none of it. The former `GET /api/v1/cluster/status` and
`GET /api/v1/cluster/members` REST routes, their servicer methods and the web
console's Cluster page proxied go-qrdb's reads through xkms and were removed:
go-xkms extends go-qrdb and never duplicates it.

The one cluster call xkms makes itself is leader-endpoint resolution for the
not-leader redirect. `xkms.ClusterClient`
(`pkg/xkms/servicer_cluster.go`) is a single-method contract,
`LeaderEndpoint`, satisfied by an adapter over the embedded node's
`*qrdbsdk.ClusterClient` (`pkg/server/cluster_adapter.go`).
`XKMSService.Clustered()` (`pkg/xkms/service.go`) reports whether that client
is wired (only when `config.Cluster.Enabled`); the REST `/auth/me`
`capabilities.cluster` flag (`pkg/api/rest/handlers_auth.go:capabilityFlags`)
reports it, and the web console's dashboard shows it as "clustered" or
"standalone".

## Component boundaries

| Piece | Where | Owner |
|---|---|---|
| Raft consensus, the clustered state machine, leader election | go-qrdb SDK (`qrdbnode.NewClusteredNode`) | **go-qrdb** |
| `cluster:` config → go-qrdb `Raft` config mapping | `Server.buildXKMSQRDBConfig` (`pkg/server/qrdb_node.go`) | go-xkms |
| Build-tag dispatch (standalone vs. clustered `newQRDBNode`) | `pkg/server/qrdb_node_standalone.go` (`!raft`), `qrdb_node_cluster.go` (`raft`); shared logic in `pkg/embeddednode` | go-xkms |
| Inter-node Raft mTLS provisioning (4-tier precedence) | `Server.resolveRaftMTLS` (`pkg/server/qrdb_node_cluster.go`) | go-xkms (composes the runtime CA / TPM attestation xkms owns) |
| Cluster CA key custody strategies (`barrier` / `hsm` / `tpm-kek`) | `pkg/trust/clusterca`, wired by `pkg/server/cluster_ca_strategy.go` | go-xkms (strategy toolkit re-exported via `sdk/go/clusterca` for the rest of the stack) |
| Leader wait, cluster advertisement | `Server.waitForClusterLeader`, `startClusterAdvertiser` (`pkg/server/qrdb_node.go`, `cluster_advertise.go`) | go-xkms |
| Not-leader → redirect translation per transport | `pkg/api/rest/errors.go`, `pkg/api/grpc/errors.go`, `pkg/xkms/errors.go` | go-xkms |
| Cluster admin / rebalance control plane (status, membership, shard stats) | go-qrdb's `AdminServicer`/`RebalanceServicer`, registered by `pkg/server/qrdb_control_plane.go` | **go-qrdb** implements; go-xkms registers it onto its own listeners |
| `xkmsctl cluster` / `xkmsctl rebalance` | `cmd/xkmsctl/cluster.go`, `rebalance.go` | go-xkms CLI, speaking the qrdb SDK client directly |
| Leader API endpoint lookup for the redirect | `XKMSService.ClusterLeaderEndpoint` (`pkg/xkms/servicer_cluster.go`), `pkg/server/cluster_adapter.go` | go-xkms, delegating to the embedded go-qrdb node's cluster client |

## Data flow

```
boot (raft build, cluster.enabled=true):
  config.Cluster → buildXKMSQRDBConfig → qcfg.Raft{ReplicaID, ShardID,
    DeploymentID, RaftAddress, ListenAddress, Peers, Join}
  → resolveRaftMTLS (only for >1 member): operator PEM files, else
    TrustedCA-issued (TPM-attested ACME enroll-01, or local-CA mode on
    any key backend, software included); no mode writes ca-key.pem
  → qrdbnode.NewClusteredNode(..., WithClusterCAKeyProvider(TrustedCA)
    unless operator PEM files are configured; bound in initializeCA)
  → waitForClusterLeader (30s, 250ms poll) before the server reports ready
  → startClusterAdvertiser publishes this node's API endpoints

joiner enrolls over ACME enroll-01 (raft_enrollment.acme.enabled):
  joiner fetches the anchor (raft_enrollment.bootstrap)
  → new-order permanent-identifier = its full raft_address (host:port)
  → serving node dials enroll-01 at that host, challenge port (8080)
  → finalize: NewClusterNodeURISANHook stamps
    spiffe://<td>/node/<raft_address> only if enroll-01 was the sole
    validated challenge AND raft_address is in cluster.peers
  → joiner accepts the leaf only if it carries its own node URI,
    else ErrSPIFFEMismatch

client write reaches a follower:
  qrdb rejects the write → xkms.AsNotLeader(err) → typed ErrNotLeader
  → REST/QUIC: HTTP 421 with leader coordinates in headers + JSON body
  → gRPC: FailedPrecondition status, ErrorInfo{Reason: "NOT_LEADER"}
  → SDK client: follows the redirect once, re-presenting the caller's
    OWN credentials to the leader (never a server-side forward)

xkmsctl cluster / rebalance:
  dials xkmsd's Unix socket (default) or --transport grpc / grpc://
  → speaks go-qrdb's OWN control-plane gRPC service directly
    (AdminServicer, RebalanceServicer) — no xkms-authored proxy
```

## Leader redirect (client request routing)

xkms client APIs (REST, gRPC, QUIC, Unix socket) route around Raft
leadership:

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

### Advertised API endpoints

For a redirect to be actionable, a client must be able to turn "the leader is
replica N" into a dialable address. Each node publishes its own
client-facing API endpoints into the cluster registry, keyed by protocol
(`rest`, `grpc`, `quic`, `mcp` — never the Unix socket, which is meaningful
only on the node that owns it). Values come from the node's own
configuration (`cluster.advertise_host` plus each enabled protocol's
configured port), never derived from the Raft address by port arithmetic.
When no concrete host is available the node advertises nothing rather than
an address no client can dial. `xkmsctl cluster members` surfaces these
endpoints per replica.

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
- **Raft mTLS chains to a dedicated cluster intermediate**, not to the
  runtime CA's issuing certificate. The TrustedCA signs it through its
  `crypto.Signer`, so no CA private key is written to disk; operator-supplied
  PEM files replace it entirely (`ClusterConfig.RaftTLS` /
  `RaftEnrollment` doc comments, `pkg/config/config.go`).
- **The qrdb control plane authenticates every caller.** Its RPCs are
  served by the embedded node behind go-qrdb's authentication chain, which
  carries xkms's session-JWT authenticator; an anonymous call answers
  `Unauthenticated` on every transport (`pkg/server/unified_api_e2e_test.go`).
  The former plaintext Unix control plane, which trusted filesystem
  permissions alone, was removed.
- **A joiner's claimed address is not its cluster identity.** The ACME
  `permanent-identifier` is client-declared. enroll-01 proves a TPM holds
  the key, not that the TPM belongs at that address. So the node URI is
  stamped only for addresses the serving node's own `cluster.peers` lists,
  and only after enroll-01 is the order's sole validated challenge. Stamping
  every enroll-01 identifier was rejected: any TPM the CA trusts could have
  named itself a peer. A device-to-address registry was also rejected,
  because `peers` is already the operator's statement of membership.
- **A single-node cluster needs no Raft mTLS**; the in-process transport
  needs no peer certificates. Any cluster with more than one member always
  requires mTLS — it is mandatory in the Raft transport itself.

## What this feature deliberately does not do

- **It does not implement Raft, leader election, or log replication.**
  Entirely go-qrdb's.
- **It does not expose cluster status, membership or membership mutation
  over xkms's own REST/gRPC/MCP API.** No `/api/v1/cluster/*` read or
  mutation route and no cluster RPC or tool exist on xkms's `XKMSService`
  (`pkg/api/rest/routes.go`, `pkg/api/grpc`, `pkg/api/mcp`). All of it goes
  through `xkmsctl cluster`/`rebalance`, which dial go-qrdb's own
  control-plane service directly.
- **It does not migrate data between storage engines** or provide a way to
  convert a standalone deployment's data into a cluster's replicated state;
  starting a cluster starts a new replicated store.
