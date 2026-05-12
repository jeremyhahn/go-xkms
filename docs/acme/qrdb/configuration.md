# QRDB Configuration Reference

## Config

| Field | Type | YAML Key | Description |
|-------|------|----------|-------------|
| `Mode` | `Mode` | `mode` | Operating mode: `standalone` or `raft` |
| `Protocol` | `Protocol` | `protocol` | Transport protocol (see below) |
| `Address` | `string` | `address` | Server address for remote protocols (e.g., `localhost:63002`) |
| `UnixSocketPath` | `string` | `unix_socket_path` | Socket path for `unix` protocol |
| `DataDir` | `string` | `data_dir` | Data directory for `embedded` protocol |
| `ClusterID` | `uint64` | `cluster_id` | Raft cluster identifier (required for `raft` mode) |
| `NodeID` | `uint64` | `node_id` | Raft node identifier (required for `raft` mode) |
| `Raft` | `*RaftConfig` | `raft` | Raft-specific settings (optional) |
| `ClientTLS` | `*TLSClientConfig` | `client_tls` | Client TLS settings (optional) |
| `Timeout` | `time.Duration` | `timeout` | Default request timeout |
| `Shutdown` | `*ShutdownConfig` | `shutdown` | Graceful shutdown settings (optional) |

## Protocol Values

| Value | Description |
|-------|-------------|
| `embedded` | In-process, requires `DataDir` |
| `grpc` | Remote gRPC, requires `Address` |
| `rest` | Remote HTTP/2 REST, requires `Address` |
| `quic` | Remote QUIC, requires `Address` |
| `unix` | Unix socket, requires `UnixSocketPath` |
| `mcp` | Remote MCP, requires `Address` |

## RaftConfig

| Field | Type | YAML Key | Description |
|-------|------|----------|-------------|
| `Members` | `map[uint64]string` | `members` | Replica ID to Raft address mapping |
| `ElectionRTT` | `uint64` | `election_rtt` | RTT multiplier for election timeout |
| `HeartbeatRTT` | `uint64` | `heartbeat_rtt` | RTT multiplier for heartbeat interval |
| `SnapshotEntries` | `uint64` | `snapshot_entries` | Log entries between snapshots |
| `CompactionOverhead` | `uint64` | `compaction_overhead` | Entries retained after compaction |

## TLSClientConfig

| Field | Type | YAML Key | Description |
|-------|------|----------|-------------|
| `CertFile` | `string` | `cert_file` | Path to client certificate |
| `KeyFile` | `string` | `key_file` | Path to client private key |
| `CAFile` | `string` | `ca_file` | Path to CA certificate for server verification |
| `ServerName` | `string` | `server_name` | Expected server name for TLS verification |

`CertFile` and `KeyFile` must be provided together.

## ShutdownConfig

| Field | Type | YAML Key | Default | Description |
|-------|------|----------|---------|-------------|
| `GracePeriod` | `time.Duration` | `grace_period` | `15s` | Max wait for in-flight requests |
| `DrainTimeout` | `time.Duration` | `drain_timeout` | `10s` | Max wait for drain completion |
| `TransferLeader` | `bool` | `transfer_leader` | `true` | Transfer Raft leadership on shutdown |

## Defaults

`DefaultConfig()` returns:

```yaml
mode: standalone
protocol: embedded
data_dir: data/qrdb
timeout: 30s
shutdown:
  grace_period: 15s
  drain_timeout: 10s
  transfer_leader: true
```

## Validation Rules

- `Mode` must be `standalone` or `raft`.
- `Protocol` must be one of the six supported values.
- Remote protocols (all except `embedded`) require `Address` or `UnixSocketPath`.
- `embedded` protocol requires `DataDir`.
- `raft` mode requires both `NodeID` and `ClusterID`.
- TLS cert/key must be specified as a pair.
