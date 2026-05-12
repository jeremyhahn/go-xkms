# Unix Socket Protocol

Unix domain socket IPC using gRPC for local administration.

## Overview

The Unix socket transport provides high-performance local IPC with kernel-enforced peer authentication. It uses the same gRPC service as TCP connections but over a Unix domain socket.

## Connection

| Property | Value |
|----------|-------|
| Protocol | gRPC over Unix Domain Socket |
| Default Path | /run/trusted-ca-grpc.sock |
| Permissions | 0660 (owner + group read/write) |
| Authentication | SO_PEERCRED (kernel-enforced) |

## Configuration

### Server Configuration

```yaml
api:
  grpc:
    enabled: true
    address: :9443              # TCP
    unix_path: /run/trusted-ca-grpc.sock
    unix_mode: 0660
```

### Command Line

```bash
trusted-acme-server \
  --grpc-addr :9443 \
  --grpc-unix-path /run/trusted-ca-grpc.sock
```

## Authentication

Peer credentials (PID, UID, GID) are automatically extracted via the SO_PEERCRED socket option. This is kernel-enforced and cannot be forged. Role-based authorization maps UIDs/GIDs to admin/operator/viewer roles.

### Default Role Mapping

| Credential | Role |
|------------|------|
| UID 0 (root) | admin |
| GID 0 (root) | admin |
| GID 10 (wheel) | operator |
| GID 80 (admin) | operator |
| All others | viewer |

## Usage

### grpcurl

```bash
# List services
grpcurl -plaintext -unix /run/trusted-ca-grpc.sock list

# Get status
grpcurl -plaintext -unix /run/trusted-ca-grpc.sock \
  trustedca.admin.v1.AdminService/GetStatus

# List certificates
grpcurl -plaintext -unix -d '{"limit": 10}' \
  /run/trusted-ca-grpc.sock \
  trustedca.admin.v1.AdminService/ListCertificates
```

### cactl CLI

```bash
# Default uses Unix socket
cactl status

# Explicit Unix socket
cactl --transport unix --address /run/trusted-ca-grpc.sock status
```

### Go Client

```go
import "github.com/jeremyhahn/go-trusted-ca/pkg/api/grpc"

adapter, err := grpc.NewAdapter(&api.AdapterConfig{
    GRPCAddr: "unix:///run/trusted-ca-grpc.sock",
})
defer adapter.Close()

status, err := adapter.GetStatus(ctx)
```

## Security

- **Kernel-enforced authentication**: SO_PEERCRED credentials cannot be forged
- **File permissions**: Socket file permissions control initial access (default 0660)
- **No network exposure**: Unix sockets are local-only, no remote attack surface
- **Role separation**: Sensitive operations require elevated privileges

## See Also

- [gRPC Protocol](grpc.md)
- [Protocol Overview](README.md)
- [cactl CLI](../cli/cactl.md)
