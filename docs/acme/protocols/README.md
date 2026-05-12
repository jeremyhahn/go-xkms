# Multi-Protocol API Support

go-trusted-ca exposes all administrative operations through five protocols, ensuring maximum interoperability across different client types and deployment scenarios.

## Supported Protocols

| Protocol | Transport | Default Address | Use Case |
|----------|-----------|-----------------|----------|
| Unix | gRPC over UDS | /run/trusted-ca-grpc.sock | Local IPC, CLI |
| REST | HTTP/HTTPS | localhost:8443 | Web clients, external systems |
| gRPC | TCP | localhost:9443 | High-performance service-to-service |
| QUIC | UDP | localhost:9444 | Low-latency, mobile clients |
| MCP | stdio/HTTP | localhost:9445 | AI/LLM integration |

## Architecture

All protocols share a common service layer, ensuring feature parity and consistent behavior regardless of transport. The architecture follows a clean separation:

```
Client Request --> Protocol Handler --> Service Layer --> Business Logic
                   (REST/gRPC/etc)      (Common API)      (CA Operations)
```

## Selecting a Protocol with cactl

The `cactl` CLI supports protocol selection via the `--transport` flag:

```bash
# Unix socket (default, fastest for local operations)
cactl --transport unix cert list

# REST API
cactl --transport rest --address localhost:8443 cert list

# gRPC
cactl --transport grpc --address localhost:9443 cert list

# QUIC
cactl --transport quic --address localhost:9444 cert list

# MCP (for AI/LLM tooling)
cactl --transport mcp --address localhost:9445 cert list
```

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

### MCP (Model Context Protocol)
- Designed for AI/LLM integration
- Structured tool definitions
- Supports stdio and HTTP transports
- Enables AI agents to manage certificates

## Configuration

Protocol endpoints are configured in the server configuration:

```yaml
api:
  grpc:
    enabled: true
    address: :9443
    unix_path: /run/trusted-ca-grpc.sock
    unix_mode: 0660
  rest:
    enabled: true
    address: :8443
    tls: true
  quic:
    enabled: true
    address: :9444
  mcp:
    enabled: true
    address: :9445
```

## See Also

- [REST API Reference](rest.md)
- [gRPC API Reference](grpc.md)
- [QUIC Protocol Details](quic.md)
- [MCP Tool Definitions](mcp.md)
- [Unix Socket Usage](unix-socket.md)
