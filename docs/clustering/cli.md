# Clustering — CLI

> **Status: NORMATIVE** · Feature: `clustering` · Repo: `go-xkms` · Last verified: 2026-10-07

Binary: `xkmsctl`. Groups: `cluster` and `rebalance`
(`cmd/xkmsctl/cluster.go`, `rebalance.go`). **These verbs do not go through
`xkmsctl`'s usual `--server`-targeted xkms API client.** They dial go-qrdb's
own control-plane gRPC service directly — the same service
`pkg/server/qrdb_control_plane.go` registers onto xkmsd's Unix socket and
gRPC listener — over the Unix socket (default) or `--transport grpc` /
`grpc://host:port` / `grpcs://host:port` (with `--tls-cert`/`--tls-key`/
`--tls-ca`). There is no xkms REST form of any verb on this page: go-qrdb's
control plane is the only cluster surface — see architecture.md's "One
cluster control plane: go-qrdb's". The target follows the standard `--server`/`--transport`
conventions; every scheme other than the Unix socket or `grpc(s)://` is
rejected with a typed `QRDBControlUnsupportedTransportError`.

## `xkmsctl cluster status`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--shard` | uint64 | `1` | shard ID to query |

```
xkmsctl cluster status
xkmsctl cluster status --shard 1 --output json
```

Shows the shard's current leader (if any) and member count. A standalone
(non-clustered) server answers uniformly: it reports itself as its own
leader.

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

## `xkmsctl cluster members`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--shard` | uint64 | `1` | shard ID to query |

```
xkmsctl cluster members
xkmsctl cluster members --shard 1 --output json
```

Lists every replica with its Raft address, leader status, and advertised
client-facing API endpoints (the addresses a redirected client would dial,
per protocol). A standalone server returns an empty member list.

Table output:

```
REPLICA ID   RAFT ADDRESS              LEADER   API ENDPOINTS
------------------------------------------------------------------------
1            10.0.0.1:63001            true     rest=10.0.0.1:8443
2            10.0.0.2:63001            false    rest=10.0.0.2:8443
```

## `xkmsctl cluster add`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--shard` | uint64 | `1` | shard to modify |
| `--replica-id` | uint64 | `0` (**required**) | replica ID to add |
| `--raft-address` | string | `""` (**required**) | the new replica's Raft peer address (`host:port`) |

```
xkmsctl cluster add --replica-id 2 --raft-address 10.0.0.2:63001
```

Rejected on a standalone node — there is no Raft group to reconfigure.
Adding a replica that is already a member succeeds without changing
anything (idempotent).

## `xkmsctl cluster remove`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--shard` | uint64 | `1` | shard to modify |
| `--replica-id` | uint64 | `0` (**required**) | replica ID to remove |

```
xkmsctl cluster remove --replica-id 2
```

Removing a replica does **not** stop the process running it — shut that
node down separately. Removing an absent replica succeeds without changing
anything (idempotent).

## `xkmsctl rebalance stats`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--shard` | uint64 | `1` | shard to query |

```
xkmsctl rebalance stats --shard 1
```

Per-shard key count, byte count, leader, and replica count.

## `xkmsctl rebalance plan`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--max-moves` | int | `0` (no limit) | cap on planned shard moves |
| `--dry-run` | bool | `false` | compute without server-side execution |
| `--target-balance` | float64 | `0` (perfectly balanced) | tolerance percentage |
| `--out` | string | `""` | save the plan as JSON for later `rebalance execute --plan` |

```
xkmsctl rebalance plan --dry-run
xkmsctl rebalance plan --max-moves 5 --out plan.json
```

## `xkmsctl rebalance execute`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--plan` | string | `""` | run a previously saved plan verbatim |
| `--max-moves` | int | `0` | cap when planning server-side (ignored with `--plan`) |
| `--target-balance` | float64 | `0` | tolerance when planning server-side (ignored with `--plan`) |

```
xkmsctl rebalance execute --plan plan.json
xkmsctl rebalance execute --max-moves 5
```

Without `--plan`, a fresh plan is computed server-side and executed
immediately.

## `xkmsctl rebalance report`

No flags.

```
xkmsctl rebalance report
```

Cluster-wide load distribution: imbalance score, hotspots, and a per-node
breakdown of shard/key/byte/leader counts.

## Exit codes and errors

`0` on success. A failed connection to the control plane (wrong
`--transport`, no server running, or a transport the control plane does not
serve — anything other than the Unix socket or gRPC) fails with a typed
`*QRDBControlUnsupportedTransportError` or `*QRDBControlConnectError`
before any verb-specific logic runs.

| Condition | Error |
|---|---|
| Unsupported `--server`/`--transport` combination | `QRDBControlUnsupportedTransportError` |
| Transport construction/connect failure | `QRDBControlConnectError` |
| No control-plane client factory configured (test-only) | `QRDBControlClientMissingError` |
| `status`/`members` query failure | `ErrClusterLeaderFailed` / `ErrClusterMembersFailed` |
| `add`/`remove` failure | `ErrClusterAddReplicaFailed` / `ErrClusterRemoveReplicaFailed` |

Every failure wraps the underlying cause via `*WrappedError{Sentinel, Err}`,
so `errors.Is` against the sentinel above still matches.

## Parity coverage

None of `cluster`'s or `rebalance`'s verbs has a `CommandDefinition` entry in
`test/integration/api/commands/commands.go` — verified absent by the same
grep used for the sealing-and-barrier feature's parity note. This mirrors
that feature's own documented gap.
