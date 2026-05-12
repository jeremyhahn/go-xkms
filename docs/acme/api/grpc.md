# gRPC API Documentation

go-trusted-ca exposes its services via gRPC for high-performance service-to-service communication. This document covers the gRPC API, including service definitions, authentication, and usage examples.

## Overview

The gRPC API provides the same functionality as the REST API with additional benefits:

- Binary protocol (Protocol Buffers) for efficient serialization
- HTTP/2 transport with multiplexing
- Bi-directional streaming support
- Strong typing with code generation
- Built-in deadline propagation

## Connection Details

| Environment | Address | TLS |
|-------------|---------|-----|
| Production | `ca.example.com:9443` | Required |
| Development | `localhost:9443` | Optional |

## Protocol Buffer Definitions

Proto files are located in `/api/proto/`.

### Service Definitions

```protobuf
// api/proto/trustedca/v1/acme.proto
syntax = "proto3";

package trustedca.v1;

option go_package = "github.com/jeremyhahn/go-trusted-ca/api/proto/trustedca/v1";

import "google/protobuf/timestamp.proto";
import "google/protobuf/empty.proto";

// ACMEService provides ACME protocol operations
service ACMEService {
  // GetDirectory returns ACME directory endpoints
  rpc GetDirectory(google.protobuf.Empty) returns (Directory);

  // GetNonce returns a fresh replay-protection nonce
  rpc GetNonce(google.protobuf.Empty) returns (NonceResponse);

  // CreateAccount registers a new ACME account
  rpc CreateAccount(CreateAccountRequest) returns (Account);

  // GetAccount retrieves account details
  rpc GetAccount(GetAccountRequest) returns (Account);

  // UpdateAccount modifies account settings
  rpc UpdateAccount(UpdateAccountRequest) returns (Account);

  // DeactivateAccount deactivates an account
  rpc DeactivateAccount(DeactivateAccountRequest) returns (Account);

  // CreateOrder submits a new certificate order
  rpc CreateOrder(CreateOrderRequest) returns (Order);

  // GetOrder retrieves order status
  rpc GetOrder(GetOrderRequest) returns (Order);

  // ListOrders lists orders for an account
  rpc ListOrders(ListOrdersRequest) returns (ListOrdersResponse);

  // GetAuthorization retrieves authorization details
  rpc GetAuthorization(GetAuthorizationRequest) returns (Authorization);

  // RespondChallenge initiates challenge validation
  rpc RespondChallenge(RespondChallengeRequest) returns (Challenge);

  // FinalizeOrder finalizes an order with CSR
  rpc FinalizeOrder(FinalizeOrderRequest) returns (Order);

  // DownloadCertificate retrieves issued certificate
  rpc DownloadCertificate(DownloadCertificateRequest) returns (CertificateResponse);

  // RevokeCertificate revokes a certificate
  rpc RevokeCertificate(RevokeCertificateRequest) returns (google.protobuf.Empty);

  // KeyChange performs account key rollover
  rpc KeyChange(KeyChangeRequest) returns (Account);

  // GetCABundle returns CA certificate chain
  rpc GetCABundle(google.protobuf.Empty) returns (CABundleResponse);
}

// Directory contains ACME server resource URLs
message Directory {
  string new_nonce = 1;
  string new_account = 2;
  string new_order = 3;
  string revoke_cert = 4;
  string key_change = 5;
  DirectoryMeta meta = 6;
}

message DirectoryMeta {
  string terms_of_service = 1;
  string website = 2;
  repeated string caa_identities = 3;
  bool external_account_required = 4;
}

message NonceResponse {
  string nonce = 1;
}

message CreateAccountRequest {
  repeated string contact = 1;
  bool terms_of_service_agreed = 2;
  bool only_return_existing = 3;
  ExternalAccountBinding external_account_binding = 4;
  string jws = 5;  // Signed JWS for authentication
}

message ExternalAccountBinding {
  string kid = 1;
  string hmac_key = 2;
}

message Account {
  uint64 id = 1;
  string status = 2;
  repeated string contact = 3;
  string orders_url = 4;
  google.protobuf.Timestamp created_at = 5;
  bool terms_of_service_agreed = 6;
}

message GetAccountRequest {
  uint64 id = 1;
  string jws = 2;
}

message UpdateAccountRequest {
  uint64 id = 1;
  repeated string contact = 2;
  string jws = 3;
}

message DeactivateAccountRequest {
  uint64 id = 1;
  string jws = 2;
}

message CreateOrderRequest {
  repeated Identifier identifiers = 1;
  google.protobuf.Timestamp not_before = 2;
  google.protobuf.Timestamp not_after = 3;
  string jws = 4;
}

message Identifier {
  string type = 1;  // dns, ip, permanent-identifier
  string value = 2;
}

message Order {
  uint64 id = 1;
  string status = 2;
  google.protobuf.Timestamp expires = 3;
  repeated Identifier identifiers = 4;
  google.protobuf.Timestamp not_before = 5;
  google.protobuf.Timestamp not_after = 6;
  repeated string authorization_urls = 7;
  string finalize_url = 8;
  string certificate_url = 9;
  Error error = 10;
}

message GetOrderRequest {
  uint64 id = 1;
  string jws = 2;
}

message ListOrdersRequest {
  uint64 account_id = 1;
  string jws = 2;
  int32 page = 3;
  int32 per_page = 4;
}

message ListOrdersResponse {
  repeated Order orders = 1;
  Pagination pagination = 2;
}

message Authorization {
  uint64 id = 1;
  Identifier identifier = 2;
  string status = 3;
  google.protobuf.Timestamp expires = 4;
  repeated Challenge challenges = 5;
  bool wildcard = 6;
}

message GetAuthorizationRequest {
  uint64 id = 1;
  string jws = 2;
}

message Challenge {
  uint64 id = 1;
  string type = 2;
  string url = 3;
  string status = 4;
  string token = 5;
  google.protobuf.Timestamp validated = 6;
  Error error = 7;
}

message RespondChallengeRequest {
  uint64 id = 1;
  string jws = 2;
  // Challenge-specific payload (attestation data, etc.)
  bytes payload = 3;
}

message FinalizeOrderRequest {
  uint64 order_id = 1;
  bytes csr = 2;  // DER-encoded CSR
  string jws = 3;
}

message DownloadCertificateRequest {
  uint64 serial = 1;
  string jws = 2;
}

message CertificateResponse {
  bytes certificate_chain = 1;  // PEM-encoded certificate chain
}

message RevokeCertificateRequest {
  bytes certificate = 1;  // DER-encoded certificate
  int32 reason = 2;       // RFC 5280 revocation reason
  string jws = 3;
}

message KeyChangeRequest {
  string old_key_jws = 1;
  string new_key_jws = 2;
}

message CABundleResponse {
  bytes ca_bundle = 1;  // PEM-encoded CA chain
}

message Error {
  string type = 1;
  string detail = 2;
  int32 status = 3;
  repeated Error subproblems = 4;
}

message Pagination {
  int32 page = 1;
  int32 per_page = 2;
  int64 total = 3;
}
```

### Admin Service

```protobuf
// api/proto/trustedca/v1/admin.proto
syntax = "proto3";

package trustedca.v1;

option go_package = "github.com/jeremyhahn/go-trusted-ca/api/proto/trustedca/v1";

import "google/protobuf/timestamp.proto";
import "google/protobuf/empty.proto";

// AdminService provides CA administration operations
service AdminService {
  // GetStatus returns CA operational status
  rpc GetStatus(google.protobuf.Empty) returns (CAStatus);

  // GetStats returns CA statistics
  rpc GetStats(google.protobuf.Empty) returns (CAStats);

  // Certificate operations
  rpc ListCertificates(ListCertificatesRequest) returns (ListCertificatesResponse);
  rpc GetCertificate(GetCertificateRequest) returns (CertificateInfo);
  rpc RevokeCertificate(AdminRevokeCertificateRequest) returns (google.protobuf.Empty);
  rpc ListExpiringCertificates(ListExpiringCertificatesRequest) returns (ListCertificatesResponse);

  // Account operations
  rpc ListAccounts(ListAccountsRequest) returns (ListAccountsResponse);
  rpc GetAccount(AdminGetAccountRequest) returns (AccountInfo);
  rpc DisableAccount(DisableAccountRequest) returns (google.protobuf.Empty);

  // Order operations
  rpc ListOrders(AdminListOrdersRequest) returns (AdminListOrdersResponse);
  rpc GetOrder(AdminGetOrderRequest) returns (OrderInfo);
}

message CAStatus {
  string identity = 1;
  bool initialized = 2;
  string version = 3;
  google.protobuf.Timestamp started_at = 4;
  string key_algorithm = 5;
  string signature_algorithm = 6;
  string root_ca = 7;
  string intermediate_ca = 8;
}

message CAStats {
  int64 total_certificates = 1;
  int64 valid_certificates = 2;
  int64 revoked_certificates = 3;
  int64 expired_certificates = 4;
  int64 total_accounts = 5;
  int64 active_accounts = 6;
  int64 total_orders = 7;
  int64 pending_orders = 8;
  int64 completed_orders = 9;
}

message ListCertificatesRequest {
  int32 page = 1;
  int32 per_page = 2;
  string status = 3;
  string subject = 4;
}

message ListCertificatesResponse {
  repeated CertificateInfo certificates = 1;
  Pagination pagination = 2;
}

message CertificateInfo {
  uint64 id = 1;
  string serial_number = 2;
  string subject = 3;
  string issuer = 4;
  google.protobuf.Timestamp not_before = 5;
  google.protobuf.Timestamp not_after = 6;
  string status = 7;
  google.protobuf.Timestamp issued_at = 8;
  string cert_url = 9;
}

message GetCertificateRequest {
  string serial = 1;
}

message AdminRevokeCertificateRequest {
  string serial = 1;
  string reason = 2;
}

message ListExpiringCertificatesRequest {
  int32 days = 1;
  int32 page = 2;
  int32 per_page = 3;
}

message ListAccountsRequest {
  int32 page = 1;
  int32 per_page = 2;
  string status = 3;
}

message ListAccountsResponse {
  repeated AccountInfo accounts = 1;
  Pagination pagination = 2;
}

message AccountInfo {
  uint64 id = 1;
  string status = 2;
  repeated string contact = 3;
  google.protobuf.Timestamp created_at = 4;
  bool terms_of_service_agreed = 5;
  string orders_url = 6;
  int64 order_count = 7;
  string tenant_id = 8;
}

message AdminGetAccountRequest {
  uint64 id = 1;
}

message DisableAccountRequest {
  uint64 id = 1;
}

message AdminListOrdersRequest {
  int32 page = 1;
  int32 per_page = 2;
  string status = 3;
  uint64 account_id = 4;
}

message AdminListOrdersResponse {
  repeated OrderInfo orders = 1;
  Pagination pagination = 2;
}

message OrderInfo {
  uint64 id = 1;
  uint64 account_id = 2;
  string status = 3;
  repeated string identifiers = 4;
  string not_before = 5;
  string not_after = 6;
  string expires = 7;
  string certificate = 8;
  google.protobuf.Timestamp created_at = 9;
}

message AdminGetOrderRequest {
  uint64 id = 1;
  uint64 account_id = 2;
}
```

### Tenant Service

```protobuf
// api/proto/trustedca/v1/tenant.proto
syntax = "proto3";

package trustedca.v1;

option go_package = "github.com/jeremyhahn/go-trusted-ca/api/proto/trustedca/v1";

import "google/protobuf/timestamp.proto";
import "google/protobuf/empty.proto";

// TenantService provides multi-tenant management
service TenantService {
  // Tenant CRUD
  rpc ListTenants(ListTenantsRequest) returns (ListTenantsResponse);
  rpc CreateTenant(CreateTenantRequest) returns (TenantInfo);
  rpc GetTenant(GetTenantRequest) returns (TenantInfo);
  rpc UpdateTenant(UpdateTenantRequest) returns (TenantInfo);
  rpc DeleteTenant(DeleteTenantRequest) returns (google.protobuf.Empty);
  rpc UpdateTenantStatus(UpdateTenantStatusRequest) returns (google.protobuf.Empty);

  // Tenant CA management
  rpc CreateTenantRootCA(CreateTenantRootCARequest) returns (TenantRootCAInfo);
  rpc ListTenantIntermediateCAs(ListTenantIntermediateCAsRequest) returns (ListTenantIntermediateCAsResponse);
  rpc CreateTenantIntermediateCA(CreateTenantIntermediateCARequest) returns (TenantIntCAInfo);
  rpc GetTenantIntermediateCA(GetTenantIntermediateCARequest) returns (TenantIntCAInfo);
  rpc UpdateIntermediateCAStatus(UpdateIntermediateCAStatusRequest) returns (google.protobuf.Empty);
  rpc SetDefaultIntermediateCA(SetDefaultIntermediateCARequest) returns (google.protobuf.Empty);
  rpc GetTenantCAStatus(GetTenantCAStatusRequest) returns (TenantCAStatusInfo);

  // EAB management
  rpc ListTenantEABs(ListTenantEABsRequest) returns (ListTenantEABsResponse);
  rpc CreateTenantEAB(CreateTenantEABRequest) returns (CreateTenantEABResponse);
  rpc GetTenantEAB(GetTenantEABRequest) returns (EABInfo);
  rpc DeleteTenantEAB(DeleteTenantEABRequest) returns (google.protobuf.Empty);

  // Policy management
  rpc ListTenantPolicies(ListTenantPoliciesRequest) returns (ListTenantPoliciesResponse);
  rpc CreateTenantPolicy(CreateTenantPolicyRequest) returns (IAMPolicy);
  rpc GetTenantPolicy(GetTenantPolicyRequest) returns (IAMPolicy);
  rpc UpdateTenantPolicy(UpdateTenantPolicyRequest) returns (IAMPolicy);
  rpc DeleteTenantPolicy(DeleteTenantPolicyRequest) returns (google.protobuf.Empty);
}

message ListTenantsRequest {
  int32 page = 1;
  int32 per_page = 2;
  string status = 3;
}

message ListTenantsResponse {
  repeated TenantInfo tenants = 1;
  Pagination pagination = 2;
}

message TenantInfo {
  string id = 1;
  string name = 2;
  string status = 3;
  TenantRootCAInfo root_ca = 4;
  repeated TenantIntCAInfo intermediate_cas = 5;
  string default_intermediate_ca_id = 6;
  TenantSettings settings = 7;
  google.protobuf.Timestamp created_at = 8;
  google.protobuf.Timestamp updated_at = 9;
  string created_by = 10;
}

message TenantRootCAInfo {
  string common_name = 1;
  string serial_number = 2;
  string key_algorithm = 3;
  google.protobuf.Timestamp not_before = 4;
  google.protobuf.Timestamp not_after = 5;
  string status = 6;
  google.protobuf.Timestamp created_at = 7;
}

message TenantIntCAInfo {
  string id = 1;
  string common_name = 2;
  string serial_number = 3;
  string parent_type = 4;
  string purpose = 5;
  string key_algorithm = 6;
  google.protobuf.Timestamp not_before = 7;
  google.protobuf.Timestamp not_after = 8;
  string status = 9;
  google.protobuf.Timestamp created_at = 10;
  google.protobuf.Timestamp updated_at = 11;
}

message TenantSettings {
  int64 max_certificates = 1;
  int64 max_accounts = 2;
  repeated string allowed_key_algorithms = 3;
  repeated string allowed_challenge_types = 4;
  int32 certificate_validity_days = 5;
  bool require_eab = 6;
  bool allow_endorse_01 = 7;
  bool allow_enroll_01 = 8;
}

message CreateTenantRequest {
  string id = 1;
  string name = 2;
  TenantSettings settings = 3;
}

message GetTenantRequest {
  string id = 1;
}

message UpdateTenantRequest {
  string id = 1;
  string name = 2;
  TenantSettings settings = 3;
}

message DeleteTenantRequest {
  string id = 1;
}

message UpdateTenantStatusRequest {
  string id = 1;
  string status = 2;
}

message CreateTenantRootCARequest {
  string tenant_id = 1;
  string common_name = 2;
  string key_algorithm = 3;
  int32 validity_years = 4;
}

message ListTenantIntermediateCAsRequest {
  string tenant_id = 1;
}

message ListTenantIntermediateCAsResponse {
  repeated TenantIntCAInfo intermediate_cas = 1;
}

message CreateTenantIntermediateCARequest {
  string tenant_id = 1;
  string common_name = 2;
  string parent_type = 3;
  string purpose = 4;
  string key_algorithm = 5;
  int32 validity_years = 6;
  bool set_as_default = 7;
}

message GetTenantIntermediateCARequest {
  string tenant_id = 1;
  string ca_id = 2;
}

message UpdateIntermediateCAStatusRequest {
  string tenant_id = 1;
  string ca_id = 2;
  string status = 3;
}

message SetDefaultIntermediateCARequest {
  string tenant_id = 1;
  string intermediate_ca_id = 2;
}

message GetTenantCAStatusRequest {
  string tenant_id = 1;
}

message TenantCAStatusInfo {
  string tenant_id = 1;
  TenantRootCAInfo root_ca = 2;
  repeated TenantIntCAInfo intermediate_cas = 3;
  string default_intermediate_ca_id = 4;
  int32 active_ca_count = 5;
  bool can_issue_certificates = 6;
}

message ListTenantEABsRequest {
  string tenant_id = 1;
  int32 page = 2;
  int32 per_page = 3;
  string status = 4;
  string purpose = 5;
}

message ListTenantEABsResponse {
  repeated EABInfo eabs = 1;
  Pagination pagination = 2;
}

message EABInfo {
  string id = 1;
  string tenant_id = 2;
  string status = 3;
  string purpose = 4;
  uint64 account_id = 5;
  string external_account_id = 6;
  EABDeviceInfo device_info = 7;
  repeated string contact = 8;
  google.protobuf.Timestamp created_at = 9;
  string created_by = 10;
  google.protobuf.Timestamp used_at = 11;
  google.protobuf.Timestamp expires_at = 12;
}

message EABDeviceInfo {
  string device_id = 1;
  string manufacturer = 2;
  string model = 3;
  string ek_public_key_hash = 4;
  string tpm_manufacturer = 5;
  string tpm_firmware_version = 6;
  map<string, string> metadata = 7;
}

message CreateTenantEABRequest {
  string tenant_id = 1;
  string purpose = 2;
  string external_account_id = 3;
  EABDeviceInfo device_info = 4;
  repeated string contact = 5;
  int32 expires_in_days = 6;
  map<string, string> metadata = 7;
}

message CreateTenantEABResponse {
  string id = 1;
  string mac_key = 2;
  string algorithm = 3;
  google.protobuf.Timestamp expires_at = 4;
}

message GetTenantEABRequest {
  string tenant_id = 1;
  string kid = 2;
}

message DeleteTenantEABRequest {
  string tenant_id = 1;
  string kid = 2;
}

message ListTenantPoliciesRequest {
  string tenant_id = 1;
  int32 page = 2;
  int32 per_page = 3;
  string purpose = 4;
}

message ListTenantPoliciesResponse {
  repeated IAMPolicy policies = 1;
  Pagination pagination = 2;
}

message IAMPolicy {
  string api_version = 1;
  string kind = 2;
  IAMPolicyMetadata metadata = 3;
  IAMPolicySpec spec = 4;
}

message IAMPolicyMetadata {
  string name = 1;
  string tenant = 2;
  map<string, string> labels = 3;
  map<string, string> annotations = 4;
  google.protobuf.Timestamp created = 5;
  google.protobuf.Timestamp updated = 6;
}

message IAMPolicySpec {
  string description = 1;
  string effect = 2;
  repeated IAMSubject subjects = 3;
  repeated IAMResource resources = 4;
  repeated string actions = 5;
  repeated IAMCondition conditions = 6;
}

message IAMSubject {
  string type = 1;
  string id = 2;
}

message IAMResource {
  string type = 1;
  string pattern = 2;
}

message IAMCondition {
  string field = 1;
  string operator = 2;
  string value = 3;
}

message CreateTenantPolicyRequest {
  string tenant_id = 1;
  IAMPolicy policy = 2;
}

message GetTenantPolicyRequest {
  string tenant_id = 1;
  string name = 2;
}

message UpdateTenantPolicyRequest {
  string tenant_id = 1;
  string name = 2;
  IAMPolicy policy = 3;
}

message DeleteTenantPolicyRequest {
  string tenant_id = 1;
  string name = 2;
}
```

## Authentication

gRPC requests use JWT tokens passed via metadata (equivalent to HTTP headers).

### Go Client Example

```go
package main

import (
    "context"
    "crypto/tls"
    "log"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    "google.golang.org/grpc/metadata"

    pb "github.com/jeremyhahn/go-trusted-ca/api/proto/trustedca/v1"
)

func main() {
    // Create TLS credentials
    creds := credentials.NewTLS(&tls.Config{
        // For production: use proper CA bundle
        InsecureSkipVerify: false,
    })

    // Create connection
    conn, err := grpc.Dial(
        "ca.example.com:9443",
        grpc.WithTransportCredentials(creds),
    )
    if err != nil {
        log.Fatalf("Failed to connect: %v", err)
    }
    defer conn.Close()

    // Create client
    client := pb.NewAdminServiceClient(conn)

    // Add JWT token to context
    ctx := metadata.AppendToOutgoingContext(
        context.Background(),
        "authorization", "Bearer "+jwtToken,
    )

    // Make request
    status, err := client.GetStatus(ctx, &pb.Empty{})
    if err != nil {
        log.Fatalf("GetStatus failed: %v", err)
    }

    log.Printf("CA Status: %+v", status)
}
```

### Python Client Example

```python
import grpc
from trustedca.v1 import admin_pb2, admin_pb2_grpc

# Create credentials
credentials = grpc.ssl_channel_credentials()

# Create channel
channel = grpc.secure_channel('ca.example.com:9443', credentials)

# Create stub
stub = admin_pb2_grpc.AdminServiceStub(channel)

# Create metadata with JWT
metadata = [('authorization', f'Bearer {jwt_token}')]

# Make request
response = stub.GetStatus(admin_pb2.Empty(), metadata=metadata)
print(f"CA Status: {response}")
```

## Error Handling

gRPC errors use standard status codes with additional details.

| Status Code | Meaning | ACME Equivalent |
|-------------|---------|-----------------|
| `OK` | Success | 200 |
| `INVALID_ARGUMENT` | Invalid request | 400 |
| `UNAUTHENTICATED` | Missing/invalid auth | 401 |
| `PERMISSION_DENIED` | Insufficient privileges | 403 |
| `NOT_FOUND` | Resource not found | 404 |
| `ALREADY_EXISTS` | Duplicate resource | 409 |
| `RESOURCE_EXHAUSTED` | Rate limited | 429 |
| `INTERNAL` | Server error | 500 |

### Error Details

Errors include structured details:

```go
import (
    "google.golang.org/grpc/status"
    "google.golang.org/genproto/googleapis/rpc/errdetails"
)

_, err := client.GetCertificate(ctx, req)
if err != nil {
    st, ok := status.FromError(err)
    if ok {
        // Get error code and message
        log.Printf("Code: %s, Message: %s", st.Code(), st.Message())

        // Get additional details
        for _, detail := range st.Details() {
            switch d := detail.(type) {
            case *errdetails.BadRequest:
                for _, v := range d.GetFieldViolations() {
                    log.Printf("Field: %s, Error: %s", v.GetField(), v.GetDescription())
                }
            case *errdetails.ErrorInfo:
                log.Printf("Reason: %s, Domain: %s", d.GetReason(), d.GetDomain())
            }
        }
    }
}
```

## Streaming Operations

### Certificate Events Stream

Subscribe to certificate lifecycle events:

```protobuf
service EventService {
  // Stream certificate events (issuance, revocation, expiry)
  rpc StreamCertificateEvents(StreamEventsRequest) returns (stream CertificateEvent);
}

message StreamEventsRequest {
  repeated string event_types = 1;  // issued, revoked, expiring
  string tenant_id = 2;
}

message CertificateEvent {
  string event_type = 1;
  CertificateInfo certificate = 2;
  google.protobuf.Timestamp timestamp = 3;
}
```

### Client Example

```go
stream, err := eventClient.StreamCertificateEvents(ctx, &pb.StreamEventsRequest{
    EventTypes: []string{"issued", "revoked"},
})
if err != nil {
    log.Fatalf("Failed to subscribe: %v", err)
}

for {
    event, err := stream.Recv()
    if err == io.EOF {
        break
    }
    if err != nil {
        log.Fatalf("Stream error: %v", err)
    }
    log.Printf("Event: %s, Certificate: %s", event.EventType, event.Certificate.SerialNumber)
}
```

## Health Checks

gRPC health checking follows the standard protocol:

```protobuf
service Health {
  rpc Check(HealthCheckRequest) returns (HealthCheckResponse);
  rpc Watch(HealthCheckRequest) returns (stream HealthCheckResponse);
}
```

### Check Health

```go
import "google.golang.org/grpc/health/grpc_health_v1"

healthClient := grpc_health_v1.NewHealthClient(conn)
resp, err := healthClient.Check(ctx, &grpc_health_v1.HealthCheckRequest{
    Service: "trustedca.v1.ACMEService",
})
if resp.Status == grpc_health_v1.HealthCheckResponse_SERVING {
    log.Println("Service is healthy")
}
```

## Reflection

The server supports gRPC reflection for dynamic clients:

```bash
# List services
grpcurl -plaintext localhost:9443 list

# Describe service
grpcurl -plaintext localhost:9443 describe trustedca.v1.ACMEService

# Call method
grpcurl -plaintext -d '{}' localhost:9443 trustedca.v1.ACMEService/GetDirectory
```

## Load Balancing

For HA deployments, use client-side load balancing:

```go
import "google.golang.org/grpc/resolver"

// Register DNS resolver for round-robin
conn, err := grpc.Dial(
    "dns:///ca-cluster.example.com:9443",
    grpc.WithDefaultServiceConfig(`{"loadBalancingPolicy":"round_robin"}`),
    grpc.WithTransportCredentials(creds),
)
```

## Interceptors

### Logging Interceptor

```go
func loggingInterceptor(
    ctx context.Context,
    method string,
    req, reply interface{},
    cc *grpc.ClientConn,
    invoker grpc.UnaryInvoker,
    opts ...grpc.CallOption,
) error {
    start := time.Now()
    err := invoker(ctx, method, req, reply, cc, opts...)
    log.Printf("Method: %s, Duration: %v, Error: %v", method, time.Since(start), err)
    return err
}

conn, err := grpc.Dial(
    address,
    grpc.WithUnaryInterceptor(loggingInterceptor),
)
```

### Retry Interceptor

```go
import "github.com/grpc-ecosystem/go-grpc-middleware/retry"

conn, err := grpc.Dial(
    address,
    grpc.WithUnaryInterceptor(
        grpc_retry.UnaryClientInterceptor(
            grpc_retry.WithMax(3),
            grpc_retry.WithBackoff(grpc_retry.BackoffExponential(100*time.Millisecond)),
            grpc_retry.WithCodes(codes.Unavailable, codes.ResourceExhausted),
        ),
    ),
)
```

## Code Generation

Generate client code from proto files:

```bash
# Go
protoc --go_out=. --go-grpc_out=. api/proto/trustedca/v1/*.proto

# Python
python -m grpc_tools.protoc \
    -I api/proto \
    --python_out=. \
    --grpc_python_out=. \
    api/proto/trustedca/v1/*.proto

# TypeScript
protoc \
    --plugin=protoc-gen-ts=./node_modules/.bin/protoc-gen-ts \
    --ts_out=. \
    --ts_opt=esModuleInterop=true \
    api/proto/trustedca/v1/*.proto
```

## Performance Tuning

### Connection Pooling

```go
conn, err := grpc.Dial(
    address,
    grpc.WithDefaultCallOptions(
        grpc.MaxCallRecvMsgSize(10*1024*1024),  // 10MB
        grpc.MaxCallSendMsgSize(10*1024*1024),
    ),
    grpc.WithKeepaliveParams(keepalive.ClientParameters{
        Time:                10 * time.Second,
        Timeout:             3 * time.Second,
        PermitWithoutStream: true,
    }),
)
```

### Compression

```go
import "google.golang.org/grpc/encoding/gzip"

conn, err := grpc.Dial(
    address,
    grpc.WithDefaultCallOptions(grpc.UseCompressor(gzip.Name)),
)
```
