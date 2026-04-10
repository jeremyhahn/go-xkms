# Shamir Barrier SDK Implementation Gap - Research Report (Feb 24, 2026)

## Summary
The go-xkms SDK has 13 unimplemented Barrier Shamir methods in both gRPC and Unix transports, while the REST transport is fully implemented. The gRPC proto definitions and message types exist, but the server-side gRPC handlers are completely missing. This is a wiring problem that requires server-side gRPC handlers.

## The 13 Unimplemented Methods

All are in:
- `sdk/go/transport/grpc/transport.go` (lines 1232-1333)
- `sdk/go/transport/unix/transport.go` (lines 1271-1368)

Methods (in order):
1. `BarrierInitializeShamir(ctx, req) (*BarrierInitializeShamirResponse, error)`
2. `BarrierUnsealWithShare(ctx, req) (*BarrierUnsealShareResponse, error)`
3. `BarrierUnsealWithShares(ctx, req) error`
4. `BarrierShamirListShares(ctx) (*BarrierShamirSharesResponse, error)`
5. `BarrierShamirDeleteShare(ctx, req) error`
6. `BarrierShamirDeleteAllShares(ctx) error`
7. `BarrierShamirVerify(ctx) error`
8. `BarrierRekey(ctx, req) (*BarrierRekeyResponse, error)`
9. `BarrierGenerateRecoveryKeys(ctx, req) (*BarrierRecoveryKeysResponse, error)`
10. `BarrierRecoverWithKeys(ctx, req) error`
11. `BarrierDeleteRecoveryKeys(ctx) error`
12. `BarrierHasRecoveryKeys(ctx) (*BarrierHasRecoveryKeysResponse, error)`
13. `BarrierGenerateRootToken(ctx, req) (*BarrierRootTokenResponse, error)`

All simply return `ErrNotImplemented` after the connection check.

## Proto Definitions (Complete)

**File**: `pkg/api/grpc/proto/xkmsv1/xkms.proto` (lines 263-302)

All 13 RPC definitions exist in the KeystoreService:
```protobuf
rpc BarrierInitializeShamir(BarrierInitializeShamirRequest) returns (BarrierShamirInitResponse);
rpc BarrierUnsealShare(BarrierUnsealShareRequest) returns (BarrierQuorumProgressResponse);
rpc BarrierUnsealShares(BarrierUnsealSharesRequest) returns (google.protobuf.Empty);
rpc BarrierShamirListShares(google.protobuf.Empty) returns (BarrierShamirSharesResponse);
rpc BarrierShamirDeleteShare(BarrierShamirDeleteShareRequest) returns (google.protobuf.Empty);
rpc BarrierShamirDeleteAllShares(google.protobuf.Empty) returns (google.protobuf.Empty);
rpc BarrierShamirVerify(google.protobuf.Empty) returns (google.protobuf.Empty);
rpc BarrierRekey(BarrierRekeyRequest) returns (BarrierShamirInitResponse);
rpc BarrierGenerateRecoveryKeys(BarrierGenerateRecoveryKeysRequest) returns (BarrierRecoveryKeysResponse);
rpc BarrierRecoverWithKeys(BarrierRecoverWithKeysRequest) returns (google.protobuf.Empty);
rpc BarrierDeleteRecoveryKeys(google.protobuf.Empty) returns (google.protobuf.Empty);
rpc BarrierGenerateRootToken(BarrierGenerateRootTokenRequest) returns (BarrierRootTokenResponse);
```

**Status**: Message types and RPC signatures are fully defined. Generated `xkms_grpc.pb.go` stubs exist.

## REST Transport (Complete)

**File**: `sdk/go/transport/rest/transport.go` (lines 2025-2190)

All 13 methods are fully implemented with proper HTTP endpoints:
- `BarrierInitializeShamir` → POST `/api/v1/barrier/shamir/initialize`
- `BarrierUnsealWithShare` → POST `/api/v1/barrier/shamir/unseal-share`
- `BarrierUnsealWithShares` → POST `/api/v1/barrier/shamir/unseal-shares`
- `BarrierShamirListShares` → GET `/api/v1/barrier/shamir/shares`
- `BarrierShamirDeleteShare` → DELETE `/api/v1/barrier/shamir/shares/{index}`
- `BarrierShamirDeleteAllShares` → DELETE `/api/v1/barrier/shamir/shares`
- `BarrierShamirVerify` → POST `/api/v1/barrier/shamir/verify`
- `BarrierRekey` → POST `/api/v1/barrier/rekey`
- `BarrierGenerateRecoveryKeys` → POST `/api/v1/barrier/recovery/generate`
- `BarrierRecoverWithKeys` → POST `/api/v1/barrier/recovery/recover`
- `BarrierDeleteRecoveryKeys` → DELETE `/api/v1/barrier/recovery/keys`
- `BarrierHasRecoveryKeys` → GET `/api/v1/barrier/recovery/keys`
- `BarrierGenerateRootToken` → POST `/api/v1/barrier/recovery/root-token`

All use `t.DoRawRequest()` to send JSON payloads and parse responses.

## REST Server Handlers (Complete)

**File**: `pkg/api/rest/handlers_barrier_shamir.go` (all 13 handlers, plus response types)

Handler functions exist with logic:
- Call `h.Barrier` methods directly (e.g., `h.Barrier.InitializeShamir()`, `h.Barrier.Rekey()`)
- Validate request parameters
- Return appropriate error responses via `handleBarrierError()`
- Serialize responses as JSON

**Routing**: `pkg/api/rest/server.go` (lines 585-602)
- All 13 routes are registered under `/api/v1/barrier`
- Routes are wired to the correct handlers

## gRPC Server Implementation (Missing)

**File**: `pkg/api/grpc/service.go`

**Status**: NO Barrier-related methods exist.
- File has 63 functions total, but ZERO Barrier methods
- gRPC service implements Health, key ops, cert ops, PIV, frost, but NOT Barrier Shamir
- The proto defines the RPC stubs (in `xkms_grpc.pb.go`), but service methods are absent

### What's Missing in gRPC Server
The gRPC service needs these 13 methods with signatures like:
```go
func (s *Service) BarrierInitializeShamir(ctx context.Context, 
  req *pb.BarrierInitializeShamirRequest) (*pb.BarrierShamirInitResponse, error) {
  // Implementation delegating to s.Barrier (like REST does)
}
```

## SDK Request/Response Types

**File**: `sdk/go/xkms.go` (lines 376-384)

The SDK re-exports request/response types:
```go
BarrierInitializeShamirRequest     = transport.BarrierInitializeShamirRequest
BarrierInitializeShamirResponse    = transport.BarrierInitializeShamirResponse
BarrierRekeyRequest                = transport.BarrierRekeyRequest
BarrierRekeyResponse               = transport.BarrierRekeyResponse
// ... and others
```

These are transport-level types, not proto-specific.

## gRPC Proto Messages (Complete)

**File**: `pkg/api/grpc/proto/xkmsv1/xkms.proto` (lines 1712-1830)

All message types are defined:
- `BarrierInitializeShamirRequest`, `BarrierShamirInitResponse`
- `BarrierUnsealShareRequest`, `BarrierQuorumProgressResponse`
- `BarrierUnsealSharesRequest`
- `BarrierShamirSharesResponse`, `BarrierShamirDeleteShareRequest`
- `BarrierRekeyRequest`
- `BarrierGenerateRecoveryKeysRequest`, `BarrierRecoveryKeysResponse`
- `BarrierRecoverWithKeysRequest`
- `BarrierRootTokenRequest`, `BarrierRootTokenResponse`
- `BarrierHasRecoveryKeysResponse`

## Transport Interface

**File**: `sdk/go/transport/transport.go`

The Transport interface itself does NOT define Barrier methods. The interface is protocol-agnostic. Each transport implementation (gRPC, REST, Unix, MCP, QUIC, Embedded) adds Barrier methods as their own type methods.

## Key Findings

### What Exists
1. ✅ Proto definitions (all 13 RPC signatures)
2. ✅ Proto message types (all request/response types)
3. ✅ Generated gRPC stubs (`xkms_grpc.pb.go` client/server interfaces)
4. ✅ REST transport implementation (fully working)
5. ✅ REST server handlers (fully working)
6. ✅ REST routing (fully working)
7. ✅ SDK type aliases (`sdk/go/xkms.go`)

### What's Missing
1. ❌ gRPC server handler methods (13 methods needed in `pkg/api/grpc/service.go`)
2. ❌ Unix transport implementation (13 methods are all `ErrNotImplemented`)
3. ❌ gRPC transport implementation (13 methods are all `ErrNotImplemented`)
4. ❌ MCP transport implementation (likely also has `ErrNotImplemented`)
5. ❌ QUIC transport implementation (likely also has `ErrNotImplemented`)
6. ❌ Embedded transport implementation (likely also has `ErrNotImplemented`)

## Implementation Strategy

This is primarily a **server-side wiring problem**.

1. **High Priority**: Implement 13 gRPC server handler methods in `pkg/api/grpc/service.go`
   - Each handler should delegate to the underlying `h.Barrier` service
   - Copy the REST handler logic as a template
   - Use proto types instead of transport types

2. **Medium Priority**: Wire gRPC transport methods to call the gRPC server
   - Similar to how REST transport uses `t.DoRawRequest()`
   - Use the gRPC client stubs already generated in `xkms_grpc.pb.go`

3. **Follow-on**: Implement remaining transports (Unix, MCP, QUIC, Embedded)
   - These are SDK-side (no server work needed)
   - Can delegate to gRPC or embed the barrier service directly

## Example Implementation Pattern

REST handlers show the pattern. For gRPC, it would be:
```go
func (s *Service) BarrierInitializeShamir(ctx context.Context, 
  req *pb.BarrierInitializeShamirRequest) (*pb.BarrierShamirInitResponse, error) {
  // Authorization check
  // Validate request
  // Call s.Barrier.InitializeShamir()
  // Convert response type from transport to proto
  // Return proto response
}
```
