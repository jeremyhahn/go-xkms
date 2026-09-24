---
status: current
last_verified: 2026-09-24
---

# Clustering — CLI

`xkmsctl cluster` (`cmd/xkmsctl/cluster.go`) drives go-qrdb's own
control-plane service directly over gRPC or the Unix socket — it does **not**
call the xkms REST `/api/v1/cluster/*` surface (that surface is for the web
console; see `docs/cluster/api.md` and
`docs/cluster/architecture.md#two-distinct-surfaces-over-the-same-raft-shard`).
The target follows the standard `--server`/`--transport` conventions: the
local Unix socket by default, `unix:///path`, `grpc://host:port`, or
`grpcs://host:port` with `--tls-cert`/`--tls-key`/`--tls-ca`. Every other
transport/scheme is rejected with a typed
`QRDBControlUnsupportedTransportError`.

## `cluster status`

Shows shard leadership and membership status for the server's configured
shard (default shard 1).

```bash
xkmsctl cluster status
xkmsctl cluster status --shard 2
xkmsctl cluster status --shard 1 --output json
```

Table output:

```
Shard:   1
Leader:  replica 1 (10.0.0.1:63001)
Members: 3
```

JSON output:

```json
{
  "shard_id": 1,
  "leader_id": 1,
  "has_leader": true,
  "member_count": 3,
  "members": [ { "replica_id": 1, "address": "10.0.0.1:63001", "is_leader": true, "api_endpoints": {"rest": "10.0.0.1:8443"} } ]
}
```

On a standalone (non-clustered) node this reports a single-node result with
no elected leader — see `docs/cluster/architecture.md` for why status never
errors just because clustering is off.

## `cluster members`

Lists shard replicas with their Raft addresses and advertised API endpoints.

```bash
xkmsctl cluster members
xkmsctl cluster members --shard 1 --output json
```

Table output:

```
REPLICA ID   RAFT ADDRESS              LEADER   API ENDPOINTS
------------------------------------------------------------------------
1            10.0.0.1:63001            true     rest=10.0.0.1:8443
2            10.0.0.2:63001            false    rest=10.0.0.2:8443
```

## `cluster add`

Adds a replica to a shard's Raft group.

```bash
xkmsctl cluster add --replica-id 2 --raft-address 10.0.0.2:63001
xkmsctl cluster add --replica-id 2 --raft-address 10.0.0.2:63001 --shard 1 --output json
```

`--replica-id` and `--raft-address` are required. `--shard` defaults to 1.

## `cluster remove`

Removes a replica from a shard's Raft group.

```bash
xkmsctl cluster remove --replica-id 2
xkmsctl cluster remove --replica-id 2 --shard 1
```

`--replica-id` is required. Removing a replica does not stop the process
running it — shut that node down separately.

## Errors

| Condition | Error |
|---|---|
| Unsupported `--server`/`--transport` combination | `QRDBControlUnsupportedTransportError` |
| Transport construction/connect failure | `QRDBControlConnectError` |
| No control-plane client factory configured (test-only) | `QRDBControlClientMissingError` |
| `status`/`members` query failure | `ErrClusterLeaderFailed` / `ErrClusterMembersFailed` |
| `add`/`remove` failure | `ErrClusterAddReplicaFailed` / `ErrClusterRemoveReplicaFailed` |

Every failure wraps the underlying cause via `*WrappedError{Sentinel, Err}`,
so `errors.Is` against the sentinel above still matches.
