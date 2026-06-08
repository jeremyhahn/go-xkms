# Clustering

Clustering enables high availability by replicating all datastore state across multiple xkms nodes via Raft. When enabled, xkms hosts an in-process go-qrdb clustered node so that keys, users, RBAC, custodian, shares, CA serials, revocations, audit events, and all other persistent state are replicated and available if any single node fails.

## What Clustering Does

A clustered xkms deployment runs a Raft consensus group where:

- All datastore mutations are replicated to every member.
- Reads can be served from any member.
- Write operations (key creation, CA signing, RBAC changes, etc.) must be sent to the Raft leader; followers will refuse writes with a "not leader" error.
- The cluster automatically elects a new leader if the current leader becomes unavailable.

Clustering is **not** required to use xkms; a single-node deployment works identically but has no redundancy.

## Build Requirement

Clustering is compiled in only with the `-tags raft` build tag:

```bash
go build -tags raft -o xkmsd ./cmd/xkmsd
```

A default build (without `-tags raft`) is **standalone-only**. If you attempt to start a standalone-built binary with `cluster.enabled: true`, it will immediately fail with:

```
error: clustering requires building xkms with -tags raft
```

Both builds run identically in single-node mode (the default). The raft tag adds clustering support but does not require it.

## Configuration

Cluster settings are configured via the `cluster:` block in `xkmsd.yaml` and overridden by `XKMS_CLUSTER_*` environment variables. Each setting maps to a go-qrdb Raft configuration parameter.

### Config Fields

| Field | YAML Key | Env Var | Type | Description |
|-------|----------|---------|------|-------------|
| Enabled | `enabled` | `XKMS_CLUSTER_ENABLED` | bool | Turns on Raft clustering. Requires Storage.Backend == "qrdb". |
| NodeID | `node_id` | `XKMS_CLUSTER_NODE_ID` | uint64 | This node's unique Raft replica ID within the shard. Must be non-zero and unique across the cluster. |
| ShardID | `shard_id` | `XKMS_CLUSTER_SHARD_ID` | uint64 | The Raft shard (group) identifier. Defaults to 1. All members of the same cluster must have the same ShardID. |
| DeploymentID | `deployment_id` | (config only) | uint64 | Isolates clusters that share a network. Optional; omit or set to 0 if not needed. Two clusters with different DeploymentIDs will not interfere. |
| RaftAddress | `raft_address` | `XKMS_CLUSTER_RAFT_ADDRESS` | string | This node's advertised address for Raft peer communication (e.g., "10.0.0.1:63001"). Must be reachable by all other cluster members. |
| ListenAddress | `listen_address` | `XKMS_CLUSTER_LISTEN_ADDRESS` | string | The address to bind for Raft communication. Defaults to RaftAddress. Use when the advertised address differs from the bind address (e.g., behind a load balancer). |
| Peers | `peers` | `XKMS_CLUSTER_PEERS` | string | Comma-separated list of initial cluster members in `nodeID=address` format (e.g., `1=10.0.0.1:63001,2=10.0.0.2:63001,3=10.0.0.3:63001`). Must include this node's own NodeID and address when bootstrapping. |
| Join | `join` | `XKMS_CLUSTER_JOIN` | bool | If `true`, the node joins an existing cluster; if `false`, it bootstraps a new cluster. The first node to boot should have `join: false` and a complete Peers list; subsequent nodes should have `join: true`. |
| RaftTLS.CACertFile | `raft_tls.ca_cert_file` | `XKMS_CLUSTER_RAFT_CA_CERT` | string | Path to the PEM CA certificate used to verify Raft peer certificates. Enables mutual TLS on the inter-node Raft transport when all three `raft_tls.*` paths are set. |
| RaftTLS.CertFile | `raft_tls.cert_file` | `XKMS_CLUSTER_RAFT_CERT` | string | Path to this node's PEM Raft certificate. |
| RaftTLS.KeyFile | `raft_tls.key_file` | `XKMS_CLUSTER_RAFT_KEY` | string | Path to this node's PEM Raft private key. |

### Example: 3-Node Cluster via YAML

```yaml
cluster:
  enabled: true
  node_id: 1
  shard_id: 1
  raft_address: "10.0.0.1:63001"
  listen_address: "10.0.0.1:63001"
  peers: "1=10.0.0.1:63001,2=10.0.0.2:63001,3=10.0.0.3:63001"
  join: false  # First node bootstraps
```

The second and third nodes would use identical YAML except:

```yaml
cluster:
  node_id: 2  # or 3 for node3
  join: true
```

### Example: 3-Node Cluster via Environment Variables

Node 1 (bootstrapper):

```bash
export XKMS_CLUSTER_ENABLED=true
export XKMS_CLUSTER_NODE_ID=1
export XKMS_CLUSTER_SHARD_ID=1
export XKMS_CLUSTER_RAFT_ADDRESS=node1:63001
export XKMS_CLUSTER_LISTEN_ADDRESS=node1:63001
export XKMS_CLUSTER_PEERS=1=node1:63001,2=node2:63001,3=node3:63001
export XKMS_CLUSTER_JOIN=false
xkmsd
```

Node 2 (joiner):

```bash
export XKMS_CLUSTER_ENABLED=true
export XKMS_CLUSTER_NODE_ID=2
export XKMS_CLUSTER_SHARD_ID=1
export XKMS_CLUSTER_RAFT_ADDRESS=node2:63001
export XKMS_CLUSTER_LISTEN_ADDRESS=node2:63001
export XKMS_CLUSTER_PEERS=1=node1:63001,2=node2:63001,3=node3:63001
export XKMS_CLUSTER_JOIN=true
xkmsd
```

Node 3 (joiner):

```bash
export XKMS_CLUSTER_ENABLED=true
export XKMS_CLUSTER_NODE_ID=3
export XKMS_CLUSTER_SHARD_ID=1
export XKMS_CLUSTER_RAFT_ADDRESS=node3:63001
export XKMS_CLUSTER_LISTEN_ADDRESS=node3:63001
export XKMS_CLUSTER_PEERS=1=node1:63001,2=node2:63001,3=node3:63001
export XKMS_CLUSTER_JOIN=true
xkmsd
```

## Bootstrap vs. Join

When forming a cluster, exactly one node must bootstrap the shard:

- **Bootstrapper** (join=false): Boot first with a complete Peers list. It forms the initial Raft group.
- **Joiners** (join=true): Boot after the bootstrapper is healthy. They discover the shard and replicate state from the leader.

If multiple nodes try to bootstrap simultaneously (join=false), the cluster may not form correctly. If all nodes set join=true, they will block waiting for a leader that never appears.

For most deployments, start node1 with join=false, then bring up node2 and node3 with join=true.

## Raft Peer Communication

Raft uses a separate network channel for consensus messages, distinct from xkms's client APIs. The `raft_address` and `listen_address` settings control this channel:

- **raft_address**: The address advertised to other Raft members. It must be reachable from all cluster members.
- **listen_address**: The address the node binds to for Raft. Usually the same as raft_address, but may differ if behind a load balancer or running in a containerized environment.

### Raft mTLS

The inter-node Raft transport supports mutual TLS. Set all three `raft_tls.*`
paths (or the `XKMS_CLUSTER_RAFT_CA_CERT` / `_CERT` / `_KEY` environment
variables) to encrypt and mutually authenticate Raft peer traffic:

```yaml
cluster:
  enabled: true
  # ... node_id, peers, etc ...
  raft_tls:
    ca_cert_file: /etc/xkms/raft-ca.pem
    cert_file: /etc/xkms/raft-cert.pem
    key_file: /etc/xkms/raft-key.pem
```

mTLS is enabled only when all three paths are present; a partially configured
`raft_tls` block (one or two of the three paths) is a startup error
(`ErrClusterRaftTLSIncomplete`). The PEM material must be operator-supplied and
**must not** be the runtime xkms CA: that CA is hosted by the very node the Raft
transport replicates, so binding Raft mTLS to it would be circular.

When `raft_tls` is unset, Raft peers communicate without TLS. That is suitable
only for a trusted private network; for untrusted networks configure `raft_tls`
or restrict Raft traffic with firewall rules to authorized members.

## Client Request Routing

xkms client APIs (REST, gRPC, QUIC, Unix socket) operate independently of Raft:

- **Read operations** (Get, List, etc.) succeed on any member.
- **Write operations** (CreateKey, SignCSR, SetPin, etc.) require the leader. A
  write sent to a follower is rejected with a typed not-leader error that names
  the current leader so the client can retry against it.

The not-leader rejection is surfaced per protocol:

- **REST**: HTTP `421 Misdirected Request`. The leader is echoed in the
  `X-XKMS-Leader-ID` and `X-XKMS-Leader-Address` response headers and in the
  JSON body (`{"error": ..., "shard_id": ..., "leader_id": ..., "leader_address": ...}`).
- **gRPC / Unix**: `FailedPrecondition` with an `ErrorInfo` detail whose
  `Reason` is `NOT_LEADER`, `Domain` is `xkms.cluster`, and `Metadata` carries
  `shard_id`, `leader_id`, and `leader_address`.
- **QUIC**: same `421 Misdirected Request` mapping as REST (HTTP/3).

The leader address in the redirect is the Raft peer address. Until a Raft→API
address map exists, xkms surfaces the typed redirect to the client rather than
forwarding the request server-side, so clients reconnect to the leader's xkms
API endpoint to retry the write.

## Cluster Inspection (CLI)

The read-only cluster surface is exposed over REST and through `xkmsctl`:

```bash
# Raft leadership status for the server's configured shard
xkmsctl cluster status

# Raft replicas for the configured shard (NODE ID, ADDRESS, leader marker)
xkmsctl cluster members

# JSON output and an explicit shard
xkmsctl cluster status --shard 1 --output json
xkmsctl cluster members --shard 1 --output json
```

These map to `GET /api/v1/cluster/status` and `GET /api/v1/cluster/members`.
When RBAC is enabled, both require the `backends:read` permission. A standalone
(non-clustered) server answers both uniformly: `status` reports a single-node,
non-clustered result (the node is its own leader) and `members` returns an empty
set, so the commands work whether or not clustering is enabled.

Membership **mutation** (adding or removing a replica) is not yet exposed: it
requires a Raft replica-mutation API (qrdb `AddReplica` / `RemoveReplica`) that
is not yet surfaced through the xkms SDK.

## Storage Backend

Clustering requires the embedded "qrdb" storage backend. The configuration must include:

```yaml
storage:
  backend: qrdb
  path: /var/lib/xkms/data
```

The `path` field specifies the directory where the PebbleDB Raft log and data are stored. Each node must have its own isolated data directory.

## Validation

xkms validates the cluster configuration at startup:

- Enabled=true requires NodeID > 0, RaftAddress is not empty, Peers is not empty, and Storage.Backend=="qrdb".
- Peers must be parseable as `nodeID=address` entries. Malformed entries cause a startup failure.
- DeploymentID is optional and defaults to 0.
- ShardID defaults to 1 if omitted.

## Monitoring and Debugging

When clustering is enabled, xkms logs cluster startup and election events:

```
time=2026-06-08T10:15:30Z level=info msg="Hosting clustered qrdb engine via NewClusteredNode" node_id=1 shard_id=1 raft_address=node1:63001 members=3 join=false
```

Look for "raft" in logs to see leader elections, membership changes, and replication status.

The CLI and SDKs can be used to verify cluster health: a healthy cluster responds to read operations on all members and write operations on the leader.
