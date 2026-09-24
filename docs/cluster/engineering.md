---
status: current
last_verified: 2026-09-24
---

# Clustering — Engineering

## Build tag

Clustering is compiled in only with `-tags raft`:

```bash
go build -tags raft -o xkmsd ./cmd/xkmsd
```

A default build is standalone-only; starting it with `cluster.enabled: true`
fails immediately with `error: clustering requires building xkms with -tags
raft`. Both builds run identically in single-node mode (the default).

## Node construction

`pkg/daemon/node_cluster.go:NewNode` (raft-tagged) hosts a standalone
go-qrdb node (`qrdbnode.NewStandaloneNode`) when `Cluster.Enabled` is false,
or a clustered node (`qrdbnode.NewClusteredNode`) when true. Raft mTLS is
consulted only for a multi-node cluster (`len(members) > 1`); a single-node
cluster uses an in-process transport.

## Servicer surface (`pkg/xkms/servicer_cluster.go`)

`XKMSService` wires an optional `cluster ClusterClient` (nil on a standalone
node) plus `clusterShardID`/`clusterNodeID`, set once at composition time by
`SetClusterClient(c ClusterClient, shardID, nodeID uint64)`
(`pkg/xkms/service.go`). `pkg/server/server.go` calls it with a live
`*clusterClientAdapter` (`pkg/server/cluster_adapter.go`, bridging the
embedded go-qrdb node's `*qrdbsdk.ClusterClient`) only when
`s.qrdbClient != nil && s.config.Cluster.Enabled`; otherwise it passes `nil`.

```go
type ClusterClient interface {
    ClusterReader          // Members, Leader
    ClusterEndpointResolver // LeaderEndpoint
    ClusterMutator          // AddReplica, RemoveReplica
}
```

Exported methods, all on `*XKMSService` — read-only by design; see
`docs/cluster/architecture.md` for why there is deliberately no
`ClusterAddReplica`/`ClusterRemoveReplica`:

| Method | Standalone behavior | Clustered behavior |
|---|---|---|
| `Clustered() bool` | `false` | `true` |
| `ClusterStatus(ctx) (*ClusterStatus, error)` | returns `{ShardID, NodeID}` with `Clustered: false`, `HasLeader: false`, no error | queries `Leader`; returns `*ClusterStatusError` on failure |
| `ClusterMembers(ctx) ([]ClusterMember, error)` | returns `nil, nil` (empty) | queries `Members`; returns `*ClusterMembersError` on failure |
| `ClusterLeaderEndpoint(ctx, protocol) (string, error)` | returns `"", nil` | resolves the leader's advertised address for `protocol`; returns `*ClusterLeaderEndpointError` on failure |

`ClusterStatus` and `ClusterMembers` are the only two servicer methods in the
codebase that intentionally *degrade* rather than fail closed on a missing
optional subsystem — every other subsystem servicer method (custodian,
shares, tenants, …) returns `xkms.ErrNotConfigured` when its backing client
is nil. This asymmetry is deliberate (see
`docs/cluster/architecture.md#standalone-degradation-not-capability-gating-for-reads`)
and is exercised directly by `pkg/xkms/servicer_cluster_test.go`
(`TestClusterStatus_Standalone`, `TestClusterMembers_Standalone`).

The `ClusterMutator` half of the `ClusterClient` interface (`AddReplica`,
`RemoveReplica`) still exists and `pkg/server/cluster_adapter.go` still
implements it — that plumbing is what lets `clusterClientAdapter` satisfy the
qrdb SDK's `*qrdbsdk.ClusterClient` shape — but no `XKMSService` method ever
calls it. Nothing in the REST, gRPC, or QUIC transports reaches it either.

### Types

```go
type ClusterMember struct {
    ReplicaID    uint64
    Address      string
    APIEndpoints map[string]string // nil when the replica advertises nothing
    IsLeader     bool
}

type ClusterStatus struct {
    ShardID   uint64
    NodeID    uint64
    LeaderID  uint64
    HasLeader bool
    Clustered bool
}
```

### Typed errors (`pkg/xkms/errors.go`)

`ClusterStatusError` and `ClusterMembersError` each carry `ShardID` plus the
wrapped underlying cause, and implement `Unwrap() error` for
`errors.Is`/`errors.As`.

## REST handler surface (`pkg/api/rest/handlers_cluster.go`)

`ClusterHandlers` is constructed unconditionally in `NewServer`
(`pkg/api/rest/server.go`), unlike the other optional handler groups
(`custodianHandlers`, `tenantHandlers`, …), because `StatusHandler` and
`MembersHandler` must work on a standalone node. There is no
`AddMemberHandler`/`RemoveMemberHandler` and no POST/DELETE route: a handler
that could only ever answer "not implemented" would be a stub, so none is
registered — see `docs/cluster/api.md` for the wire contract and
`docs/cluster/architecture.md` for why.

`handleClusterError` maps `errors.Is(err, xkms.ErrNotConfigured)` to a typed
`rest.ErrClusterNotConfigured` (503 — the construction-order case where no
`XKMSService` was wired at all, not the standalone-node case, which never
errors) and logs anything else before returning a generic 500
(`slog.Default().Error`) — the same pattern `handleCustodianError` uses.

## RBAC vocabulary

Permissions mirror go-qrdb's own `AdminService` vocabulary exactly
(`pkg/permission/constants.go` in go-qrdb: `AdminStatus`, `AdminPeers`),
declared in `pkg/auth/permissions.go` as `auth.ResourceAdmin` ("admin")
combined with `auth.ActionStatus` ("status") and `auth.ActionPeers`
("peers"):

| Route | Method | Permission |
|---|---|---|
| `/api/v1/cluster/status` | GET | `admin:status` |
| `/api/v1/cluster/members` | GET | `admin:peers` |

This is the same grant qrdb's own control-plane gRPC surface enforces
(`pkg/server/qrdb_control_plane.go`), so a caller's RBAC role never has to
diverge between the two surfaces. `pkg/auth/permissions.go` deliberately
carries no `ActionAddMember`/`ActionRemoveMember`: go-qrdb's
`AdminAddMember`/`AdminRemoveMember` permissions are enforced only by the
qrdb control plane itself (`xkmsctl cluster add`/`remove`), never by xkms's
REST layer, so xkms defines no xkms-side vocabulary for a route that does
not exist.

## Configuration (`pkg/config/config.go:ClusterConfig`)

| Field | YAML Key | Env Var | Type | Description |
|-------|----------|---------|------|-------------|
| Enabled | `enabled` | `XKMS_CLUSTER_ENABLED` | bool | Turns on Raft clustering. Requires `Storage.Backend == "qrdb"`. |
| NodeID | `node_id` | `XKMS_CLUSTER_NODE_ID` | uint64 | This node's unique Raft replica ID within the shard. Must be non-zero and unique across the cluster. |
| ShardID | `shard_id` | `XKMS_CLUSTER_SHARD_ID` | uint64 | The Raft shard (group) identifier. Defaults to 1. |
| DeploymentID | `deployment_id` | (config only) | uint64 | Isolates clusters that share a network. Optional; defaults to 0. |
| RaftAddress | `raft_address` | `XKMS_CLUSTER_RAFT_ADDRESS` | string | This node's advertised address for Raft peer communication. |
| ListenAddress | `listen_address` | `XKMS_CLUSTER_LISTEN_ADDRESS` | string | The address to bind for Raft communication. Defaults to `RaftAddress`. |
| AdvertiseHost | `advertise_host` | (config only) | string | Host/IP clients use to reach this node's xkms APIs. Defaults to the host portion of `raft_address`. |
| Peers | `peers` | `XKMS_CLUSTER_PEERS` | string | Comma-separated `nodeID=address` list of initial members. |
| Join | `join` | `XKMS_CLUSTER_JOIN` | bool | `false` bootstraps a new cluster; `true` joins an existing one. |
| RaftTLS.{CACertFile,CertFile,KeyFile} | `raft_tls.*` | `XKMS_CLUSTER_RAFT_TLS_*` | string | Raft peer mTLS material; all three or none (`ErrClusterRaftTLSIncomplete` on a partial set). |
| RaftEnrollment.* | `raft_enrollment.*` | (config only, mostly) | — | Auto-provisioned Raft mTLS — see `docs/cluster/user.md`. |

### Validation (`pkg/config`)

- `Enabled=true` requires `NodeID > 0`, `RaftAddress` non-empty, `Peers`
  non-empty, and `Storage.Backend == "qrdb"`.
- `Peers` entries must parse as `nodeID=address`; malformed entries fail
  startup.
- `ShardID` defaults to 1 when omitted; `DeploymentID` defaults to 0.
- A `raft_tls` block with one or two of the three paths set (not all three)
  fails startup with `ErrClusterRaftTLSIncomplete`.

## Tests

- `pkg/xkms/servicer_cluster_test.go` — `ClusterStatus`/`ClusterMembers`,
  both the standalone-degradation and clustered paths, plus underlying-error
  mapping to the typed errors (table above).
- `pkg/api/rest/handlers_cluster_test.go` — handler success/error per route,
  standalone vs. clustered; RBAC denial (`TestClusterRoutes_RBACDenied`) and
  the positive RBAC control (`TestClusterRoutes_RBACRequiredPermission`)
  over the two GET routes only; and the `/auth/me` `capabilities.cluster`
  flag (`TestCapabilityFlags_Cluster`).
- `test/integration/cluster/cluster_rest_api_test.go` — the 3-node cluster
  and standalone harnesses, proving the REST surface's status/members agree
  with go-qrdb's own `/peers` admin-plane view.
- `cmd/xkmsctl/cluster_test.go` — the qrdb-control-plane CLI path (unrelated
  wire surface; see `docs/cluster/cli.md`).
