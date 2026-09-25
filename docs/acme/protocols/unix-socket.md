# Unix Socket Protocol

Unix domain socket IPC using gRPC for local administration.

> **Correction (go-xkms#942):** there is no `trusted-acme-server` binary,
> no `cactl` binary, and no `TRUSTEDCA_` environment prefix. More
> substantially: [`../../acme-issuance/cli.md`](../../acme-issuance/cli.md)
> (NORMATIVE) states the ACME admin plane's `xkmsctl acme
> --acme-transport` supports `rest`, `grpc`, `quic`, `mcp` — explicitly
> **"there is no `unix` adapter for the ACME admin plane."** This page's
> premise (a Unix-socket ACME admin transport) conflicts with that and is
> unverified; treat this whole page as unconfirmed rather than adapting
> its specific commands.

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

Unverified — see the correction above.

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

### CLI

There is no `cactl` binary and no Unix-socket adapter for the ACME admin
plane — see the correction above.

### Go Client

```go
import "github.com/jeremyhahn/go-xkms/pkg/api/grpc"

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
- [`xkmsctl acme` CLI](../../acme-issuance/cli.md)
