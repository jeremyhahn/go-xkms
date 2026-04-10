# Network Agent

The xKey network agent enables remote machines to use xKey services (PKCS#11, FIDO2, PIV, CCID, crypto, SSH) from a master machine where xKey runs. All key material stays on the master; remote agents never hold private keys.

## Architecture

The agent uses a master/agent model over gRPC with mTLS (TLS 1.3 minimum):

```
Remote Machine (Agent)              Master Machine (xKey)
+------------------+               +--------------------+
| SSH Client       |               | xKey Services      |
|   |              |    mTLS/gRPC  |  PKCS#11, FIDO2,   |
|   v              | <-----------> |  PIV, CCID, Crypto, |
| Agent Client     |               |  SSH Agent          |
|   |              |               |                    |
|   v              |               | Agent Server       |
| SSH Proxy Socket |               | Enrollment Service |
+------------------+               +--------------------+
```

**Key principles:**

- Private keys never leave the master
- All connections use mTLS with certificates issued during enrollment
- The server tracks connected agents via gRPC interceptors
- Exponential backoff reconnection on the client side

## Server

The `Server` accepts mTLS connections from enrolled agents on a configurable listen address (default `:9443`). It runs as a gRPC server with a unary interceptor that tracks agent connections and last-activity timestamps.

```go
server, err := agent.NewServer(cfg, enrollmentService, logger)
if err != nil { /* handle */ }

if err := server.Start(); err != nil { /* handle */ }
defer server.Stop()

// Query connected agents at any time.
connected := server.ConnectedAgents()
```

- `Start()` binds the listener and serves in a background goroutine
- `Stop()` calls `GracefulStop()`, waits for the serve goroutine, and clears the connection map
- `ConnectedAgents()` returns a snapshot of all active connections with timestamps
- `IsRunning()` and `Addr()` provide runtime introspection

## Client

The `Client` connects to a master server and optionally monitors the connection for automatic reconnection with exponential backoff.

```go
client, err := agent.NewClient(clientCfg, logger)
if err != nil { /* handle */ }

if err := client.Connect(ctx); err != nil { /* handle */ }
defer client.Disconnect()

if client.IsConnected() {
    conn := client.Connection() // *grpc.ClientConn
}
```

When `ReconnectBackoffMax` is configured (default 2 minutes), the client spawns a monitor goroutine that watches `connectivity.TransientFailure` and `connectivity.Shutdown` states, doubling the backoff interval (starting at 1 second) up to the configured maximum.

## SSH Agent Proxy

The `SSHProxy` creates a local Unix socket that SSH clients use via `SSH_AUTH_SOCK`. All cryptographic operations are forwarded to the master over the gRPC connection. No key material is stored on the remote machine.

```go
proxy, err := agent.NewSSHProxy("/run/user/1000/xkey/agent.sock", client, logger)
if err != nil { /* handle */ }

if err := proxy.Start(); err != nil { /* handle */ }
defer proxy.Stop()

// Set in the shell:
// export SSH_AUTH_SOCK=/run/user/1000/xkey/agent.sock
```

- Socket created with `0600` permissions (owner-only)
- Stale sockets are detected and cleaned up on start
- Bidirectional byte-level proxy between the local socket and master
- Each accepted connection is handled in its own goroutine with `WaitGroup` tracking

## Configuration

### Server Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `listen_address` | string | `:9443` | Bind address for the agent server |
| `tls_cert_file` | string | | Server TLS certificate path |
| `tls_key_file` | string | | Server TLS private key path |
| `tls_ca_file` | string | | CA certificate for client verification (enables mTLS) |
| `enrollment_methods` | []string | `[one_time_code]` | Allowed enrollment methods |
| `require_attestation` | bool | `false` | Require platform attestation during enrollment |
| `cert_validity_days` | int | `365` | Validity period for issued agent certificates |
| `max_agents` | int | `0` | Maximum enrolled agents (0 = unlimited) |
| `one_time_code_length` | int | `8` | Character length of generated enrollment codes |
| `one_time_code_validity` | duration | `15m` | Default validity for one-time codes |

### Client Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `master_address` | string | | Address of the master agent server |
| `tls_cert_file` | string | | Client certificate path (from enrollment) |
| `tls_key_file` | string | | Client private key path |
| `tls_ca_file` | string | | CA certificate for server verification |
| `local_address` | string | `localhost:19443` | Local reverse-proxy bind address |
| `reconnect_backoff_max` | duration | `2m` | Maximum reconnection backoff (0 = no reconnect) |

## GUI Service Integration

The `AgentService` (in `xkey/pkg/gui/services/agent_service.go`) exposes agent functionality to the Wails frontend. It wraps the `Server` and `EnrollmentService` and emits events for UI updates.

**Exported methods:**

| Method | Description |
|--------|-------------|
| `StartServer(address)` | Start the agent server on the given address |
| `StopServer()` | Stop the running agent server |
| `GetServerStatus()` | Returns running state, connected/enrolled counts, methods |
| `GenerateEnrollmentCode()` | Generate a one-time enrollment code |
| `ListPendingEnrollments()` | List pending admin-approval requests |
| `ApproveEnrollment(id)` | Approve a pending enrollment request |
| `RejectEnrollment(id, reason)` | Reject a pending enrollment request |
| `ListAgents()` | List enrolled agents with live connection state |
| `RemoveAgent(id)` | Remove an enrolled agent |

Events emitted: `agent:server_started`, `agent:server_stopped`, `agent:code_generated`, `agent:enrollment_approved`, `agent:enrollment_rejected`, `agent:removed`.

## See Also

- [Enrollment Methods](enrollment.md) -- enrollment flows and security
- [SSH Agent](../ssh.md) -- SSH key management and agent usage
