# gRPC Protocol

High-performance gRPC API for Admin operations.

> **Correction (go-xkms#942):** there is no `trusted-acme-server` binary,
> no `cactl` binary, and no `TRUSTEDCA_` environment prefix. The real CLI
> is `xkmsctl acme` (`docs/acme-issuance/cli.md`); the ACME admin surface
> is mounted on `xkmsd`'s own unified listener
> (`cmd/xkmsd/admin.go:finalizeAdminModule`). The server-side address this
> page's gRPC examples assume is otherwise unverified against the current
> wiring.

## Overview

The gRPC API provides binary-encoded, strongly-typed access to all Admin operations. It's optimized for service-to-service communication with features like bidirectional streaming and automatic code generation.

## Connection

| Property | Value |
|----------|-------|
| Protocol | HTTP/2 |
| Default Port | 9443 |
| Transport | TCP with TLS |
| Encoding | Protocol Buffers |

## Configuration

### Server

Unverified — see the correction above.

### Client (`xkmsctl acme`)

```bash
xkmsctl acme --acme-server grpc://localhost:9443 status
```

## Protocol Buffers

### Service Definition

```protobuf
syntax = "proto3";

package admin.v1;

service AdminService {
  // Status operations
  rpc GetStatus(GetStatusRequest) returns (GetStatusResponse);
  rpc GetStats(GetStatsRequest) returns (GetStatsResponse);

  // Certificate operations
  rpc ListCertificates(ListCertificatesRequest) returns (ListCertificatesResponse);
  rpc GetCertificate(GetCertificateRequest) returns (GetCertificateResponse);
  rpc RevokeCertificate(RevokeCertificateRequest) returns (RevokeCertificateResponse);

  // Account operations
  rpc ListAccounts(ListAccountsRequest) returns (ListAccountsResponse);
  rpc GetAccount(GetAccountRequest) returns (GetAccountResponse);
  rpc DisableAccount(DisableAccountRequest) returns (DisableAccountResponse);

  // Tenant operations
  rpc CreateTenant(CreateTenantRequest) returns (CreateTenantResponse);
  rpc GetTenant(GetTenantRequest) returns (GetTenantResponse);
  rpc UpdateTenant(UpdateTenantRequest) returns (UpdateTenantResponse);
  rpc DeleteTenant(DeleteTenantRequest) returns (DeleteTenantResponse);
  rpc ListTenants(ListTenantsRequest) returns (ListTenantsResponse);

  // EAB operations
  rpc CreateEAB(CreateEABRequest) returns (CreateEABResponse);
  rpc GetEAB(GetEABRequest) returns (GetEABResponse);
  rpc DeleteEAB(DeleteEABRequest) returns (DeleteEABResponse);
  rpc ListEABs(ListEABsRequest) returns (ListEABsResponse);

  // Policy operations
  rpc CreatePolicy(CreatePolicyRequest) returns (CreatePolicyResponse);
  rpc GetPolicy(GetPolicyRequest) returns (GetPolicyResponse);
  rpc UpdatePolicy(UpdatePolicyRequest) returns (UpdatePolicyResponse);
  rpc DeletePolicy(DeletePolicyRequest) returns (DeletePolicyResponse);
  rpc ListPolicies(ListPoliciesRequest) returns (ListPoliciesResponse);
}
```

### Message Types

```protobuf
message CAStatus {
  string status = 1;
  string version = 2;
  string uptime = 3;
  int64 certificates_issued = 4;
  int64 certificates_revoked = 5;
}

message Certificate {
  string serial = 1;
  string subject = 2;
  string issuer = 3;
  google.protobuf.Timestamp not_before = 4;
  google.protobuf.Timestamp not_after = 5;
  bool revoked = 6;
  int32 revocation_reason = 7;
}

message Tenant {
  string id = 1;
  string name = 2;
  string display_name = 3;
  string contact_email = 4;
  google.protobuf.Timestamp created_at = 5;
  google.protobuf.Timestamp updated_at = 6;
}

message Policy {
  string id = 1;
  string name = 2;
  string effect = 3;  // ALLOW or DENY
  repeated string actions = 4;
  repeated string resources = 5;
  map<string, string> conditions = 6;
}
```

## Authentication

### mTLS

gRPC uses mTLS for authentication. Configure client credentials:

```go
creds, err := credentials.NewClientTLSFromFile("ca.crt", "")
conn, err := grpc.Dial("localhost:9443",
    grpc.WithTransportCredentials(creds),
)
```

### With Client Certificate

```go
cert, err := tls.LoadX509KeyPair("client.crt", "client.key")
caCert, err := os.ReadFile("ca.crt")
certPool := x509.NewCertPool()
certPool.AppendCertsFromPEM(caCert)

creds := credentials.NewTLS(&tls.Config{
    Certificates: []tls.Certificate{cert},
    RootCAs:      certPool,
})

conn, err := grpc.Dial("localhost:9443",
    grpc.WithTransportCredentials(creds),
)
```

## Client Usage

### Go Client

```go
package main

import (
    "context"
    "log"

    pb "github.com/jeremyhahn/go-xkms/api/proto/admin/v1"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
)

func main() {
    // Load TLS credentials
    creds, err := credentials.NewClientTLSFromFile("ca.crt", "")
    if err != nil {
        log.Fatal(err)
    }

    // Connect
    conn, err := grpc.Dial("localhost:9443", grpc.WithTransportCredentials(creds))
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    // Create client
    client := pb.NewAdminServiceClient(conn)

    // Get status
    resp, err := client.GetStatus(context.Background(), &pb.GetStatusRequest{})
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Status: %s", resp.Status.Status)
}
```

### grpcurl

```bash
# List services
grpcurl -cacert ca.crt localhost:9443 list

# Get status
grpcurl -cacert ca.crt localhost:9443 admin.v1.AdminService/GetStatus

# List certificates
grpcurl -cacert ca.crt -d '{"limit": 10}' \
  localhost:9443 admin.v1.AdminService/ListCertificates

# Create tenant
grpcurl -cacert ca.crt -d '{
  "name": "example",
  "display_name": "Example Tenant",
  "contact_email": "admin@example.com"
}' localhost:9443 admin.v1.AdminService/CreateTenant
```

## Error Handling

gRPC uses standard status codes:

| Code | Description |
|------|-------------|
| `OK` | Success |
| `INVALID_ARGUMENT` | Bad request |
| `NOT_FOUND` | Resource not found |
| `ALREADY_EXISTS` | Duplicate resource |
| `PERMISSION_DENIED` | Authorization failure |
| `UNAUTHENTICATED` | Authentication required |
| `RESOURCE_EXHAUSTED` | Rate limited |
| `INTERNAL` | Server error |

### Error Response

```go
if err != nil {
    st, ok := status.FromError(err)
    if ok {
        log.Printf("Code: %s, Message: %s", st.Code(), st.Message())
        for _, detail := range st.Details() {
            // Handle error details
        }
    }
}
```

## Performance

gRPC provides significant performance advantages:

| Feature | Benefit |
|---------|---------|
| Binary encoding | Smaller payloads, faster serialization |
| HTTP/2 | Multiplexing, header compression |
| Streaming | Bidirectional real-time data |
| Code generation | Type-safe clients, no runtime parsing |

### Benchmarks

Typical performance compared to REST:

- **Latency**: 30-50% lower
- **Throughput**: 2-3x higher
- **Bandwidth**: 50-70% less

## Reflection

The server supports gRPC reflection for debugging:

```bash
# List all services
grpcurl -cacert ca.crt localhost:9443 list

# Describe service
grpcurl -cacert ca.crt localhost:9443 describe admin.v1.AdminService
```

## Code Generation

Generate Go client code from proto files:

```bash
make proto
```

This generates:
- `api/proto/admin/v1/admin.pb.go` - Message types
- `api/proto/admin/v1/admin_grpc.pb.go` - Service client/server

## Unix Socket Transport

gRPC can also be accessed via Unix domain socket for local IPC with kernel-enforced authentication.

### Connection

```bash
grpcurl -plaintext -unix /run/trusted-ca-grpc.sock list
```

### Configuration

```yaml
api:
  grpc:
    unix_path: /run/trusted-ca-grpc.sock
    unix_mode: 0660
```

### Authentication

Unix socket connections use SO_PEERCRED for authentication instead of mTLS. The kernel provides the peer's PID, UID, and GID which are mapped to roles (admin/operator/viewer).

See [Unix Socket Protocol](unix-socket.md) for details.

## See Also

- [Protocol Overview](README.md)
- [REST Protocol](rest.md)
- [QUIC Protocol](quic.md)
- [Unix Socket Protocol](unix-socket.md)
- [`xkmsctl acme` CLI](../../acme-issuance/cli.md)
