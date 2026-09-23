# Multi-Protocol API Support

go-xkms exposes all administrative operations over six server protocols,
ensuring maximum interoperability across different client types and deployment
scenarios.

## Supported Protocols

Defaults below are the shipped configuration (`pkg/config/config.go`,
`configs/xkmsd-dev.yaml`).

| Protocol | Transport | Default Address | Use Case |
|----------|-----------|-----------------|----------|
| Unix | gRPC over UDS | xkms-data/xkms.sock | Local IPC, CLI |
| REST | HTTP/HTTPS | localhost:8443 | Web clients, external systems |
| gRPC | TCP | localhost:9443 | High-performance service-to-service |
| QUIC | UDP (HTTP/3 on the REST listener) | localhost:8443/udp | Low-latency, mobile clients |
| MCP | HTTP (Streamable HTTP, served by the embedded qrdb node) | localhost:8445 | AI/LLM integration |
| Noise | TCP | localhost:8447 | Cluster bootstrap (Noise NK) |

QUIC has no server package or port of its own: it is HTTP/3 served on the
same listener and port as REST, advertised via the `Alt-Svc` response
header (`quic_port` in config is vestigial).

The socket path is relative to the working directory by default; deployment
configs use an absolute path (`configs/xkmsd-integration.yaml` uses
`/var/run/xkms/xkms.sock`). Only Unix is enabled in the development config —
the rest are opt-in under `protocols:`.

## Architecture

All protocols share a common service layer, ensuring feature parity and
consistent behavior regardless of transport. Each transport is served from the
same `Servicer` interface (`pkg/api/transport/servicer.go`), which is what keeps
them in step:

```
Client Request --> Protocol Handler --> Service Layer --> Business Logic
                   (REST/gRPC/etc)      (Common API)      (CA Operations)
```

## Selecting a Protocol with xkmsctl

`xkmsctl` selects its transport with `--transport` (default `unix`) and its
endpoint with `--server`/`-s`. The endpoint is a URL, not a bare host:port:

```bash
# Unix socket (default, fastest for local operations)
xkmsctl --transport unix cert list

# REST API
xkmsctl --transport rest --server https://localhost:8443 cert list

# gRPC
xkmsctl --transport grpc --server grpc://localhost:9443 cert list

# QUIC (dials the REST port -- there is no separate QUIC port)
xkmsctl --transport quic --server quic://localhost:8443 cert list

# MCP (for AI/LLM tooling)
xkmsctl --transport mcp --server https://localhost:8445 cert list
```

`--transport` also accepts `embedded`, which runs the service in-process with no
server at all.

## Protocol Characteristics

### Unix Socket
- gRPC over Unix domain socket
- Kernel-enforced SO_PEERCRED authentication
- No network overhead
- Preferred for CLI and local automation
- Requires filesystem access to socket

### REST
- Universal HTTP-based access
- OpenAPI/Swagger documentation
- Browser and curl compatible
- Best for external integrations and web clients

### gRPC
- Binary protocol with Protocol Buffers
- Bidirectional streaming support
- Strong typing and code generation
- Optimal for microservice communication

### QUIC
- UDP-based with built-in encryption
- Connection migration support
- Reduced connection establishment latency
- Ideal for mobile and unreliable networks
- Served as HTTP/3 on the same listener and port as REST (advertised via
  `Alt-Svc`), not a standalone server

### MCP (Model Context Protocol)
- Designed for AI/LLM integration
- Structured tool definitions, one per xkms method (`xkms_<method>`)
- Streamable HTTP, served by the embedded qrdb node at `/mcp`
- Enables AI agents to manage certificates

### Noise
- Noise NK handshake over TCP
- Carries cluster bootstrap for a joining node
- Enabled only where nodes join over an untrusted network

## Configuration

Ports live under `server:`, and each protocol is switched on under `protocols:`:

```yaml
server:
  host: "127.0.0.1"
  rest_port: 8443
  grpc_port: 9443
  quic_port: 8444  # vestigial -- QUIC is served as HTTP/3 on rest_port
  mcp_port: 8445
  noise_port: 8447

protocols:
  unix: true
  rest: false
  grpc: false
  quic: false
  mcp: false

unix:
  enabled: true
  socket_path: "xkms-data/xkms.sock"
  socket_mode: "0660"
  protocol: "grpc"
```

Each port also has an environment override — `XKMS_SERVER_REST_PORT`,
`XKMS_SERVER_GRPC_PORT`, `XKMS_SERVER_QUIC_PORT`, `XKMS_SERVER_MCP_PORT`,
`XKMS_SERVER_NOISE_PORT` — applied when the value parses as a valid port.

## See Also

- [REST API Reference](rest.md)
- [gRPC API Reference](grpc.md)
- [QUIC Protocol Details](quic.md)
- [MCP Tool Definitions](mcp.md)
- [Unix Socket Usage](unix-socket.md)
