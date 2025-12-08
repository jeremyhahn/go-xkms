# Go-Keychain Server Architecture


## Table of Contents

1. [Overview](#overview)
2. [Design Principles](#design-principles)
3. [Directory Structure](#directory-structure)
4. [Core Components](#core-components)
5. [Protocol Implementations](#protocol-implementations)
6. [Configuration Management](#configuration-management)
7. [Error Handling Strategy](#error-handling-strategy)
8. [Security Considerations](#security-considerations)
9. [Testing Strategy](#testing-strategy)
10. [Implementation Guidelines](#implementation-guidelines)


## Overview

The go-keychain server exposes the KeyStore interface through multiple protocols:
- **REST API** (HTTP/1.1 + HTTP/2) - Standard JSON REST API
- **gRPC** - High-performance RPC with Protocol Buffers
- **MCP** (Model Context Protocol) - JSON-RPC 2.0 for AI agent integration
- **QUIC** (HTTP/3) - Modern UDP-based protocol for low-latency
- **CLI** - Command-line interface for local and remote operations

All protocols share a common service layer that interacts with the KeyStore interface, ensuring consistency across all endpoints.

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         Client Layer                             │
├──────────┬──────────┬──────────┬──────────┬─────────────────────┤
│   REST   │   gRPC   │   MCP    │   QUIC   │        CLI          │
│ (HTTP/2) │  (HTTP/2)│(JSON-RPC)│ (HTTP/3) │  (Cobra/Viper)      │
└─────┬────┴────┬─────┴────┬─────┴────┬─────┴─────────────────────┘
      │         │          │          │
      └─────────┴──────────┴──────────┘
                    │
        ┌───────────▼───────────┐
        │   Service Layer       │
        │  (internal/service)   │
        │  - KeyManager         │
        │  - BackendRegistry    │
        │  - Validators         │
        └───────────┬───────────┘
                    │
        ┌───────────▼───────────┐
        │   KeyStore Interface  │
        │  (pkg/keychain)       │
        └───────────┬───────────┘
                    │
        ┌───────────▼───────────┐
        │   Backend Layer       │
        │  - PKCS#8             │
        │  - PKCS#11            │
        │  - TPM2               │
        │  - Cloud KMS          │
        └───────────────────────┘
```


## Design Principles

### 1. Separation of Concerns
- **Protocol handlers** handle protocol-specific serialization/deserialization
- **Service layer** contains business logic and orchestration
- **KeyStore** manages cryptographic operations

### 2. DRY (Don't Repeat Yourself)
- Common logic resides in service layer
- Protocol handlers are thin adapters
- Shared validation, error handling, and logging

### 3. Thread Safety
- All components are thread-safe
- Use read-write locks for shared state
- Prefer immutable configurations

### 4. Error Handling
- Protocol-specific error mapping
- Structured error responses
- Comprehensive error logging

### 5. Testability
- Dependency injection throughout
- Mock-friendly interfaces
- Comprehensive integration tests

### 6. Performance
- Lock-free algorithms where possible
- Connection pooling
- Request context propagation
- Graceful shutdown


## Directory Structure

```
go-keychain/
├── cmd/
│   ├── server/                    # Multi-protocol server binary
│   │   ├── main.go               # Entry point, server initialization
│   │   └── config.go             # Configuration loading
│   └── cli/                       # CLI binary
│       ├── main.go               # CLI entry point
│       ├── root.go               # Root command (Cobra)
│       └── commands/             # Command implementations
│           ├── backends.go       # Backend management commands
│           ├── key.go            # Key operations commands
│           ├── sign.go           # Signing operations
│           ├── verify.go         # Verification operations
│           └── version.go        # Version command
│
├── internal/
│   ├── server/                    # Server orchestration
│   │   ├── server.go             # Main server struct, lifecycle
│   │   ├── shutdown.go           # Graceful shutdown logic
│   │   └── middleware/           # Cross-cutting concerns
│   │       ├── logging.go        # Request logging
│   │       ├── metrics.go        # Prometheus metrics
│   │       ├── auth.go           # Authentication middleware
│   │       ├── cors.go           # CORS handling
│   │       └── recovery.go       # Panic recovery
│   │
│   ├── config/                    # Configuration management
│   │   ├── config.go             # Configuration structs
│   │   ├── loader.go             # Config loading (file, env, flags)
│   │   ├── validator.go          # Config validation
│   │   └── defaults.go           # Default values
│   │
│   ├── service/                   # Business logic layer
│   │   ├── keymanager.go         # Key management service
│   │   ├── backend_registry.go   # Backend registration/selection
│   │   ├── validators.go         # Input validation
│   │   ├── errors.go             # Service-level errors
│   │   └── types.go              # Common types/DTOs
│   │
│   ├── rest/                      # REST API implementation
│   │   ├── server.go             # REST server setup
│   │   ├── router.go             # Route definitions
│   │   ├── handlers/             # HTTP handlers
│   │   │   ├── health.go         # Health check endpoint
│   │   │   ├── backends.go       # Backend endpoints
│   │   │   ├── keys.go           # Key CRUD endpoints
│   │   │   ├── sign.go           # Signing endpoint
│   │   │   └── verify.go         # Verification endpoint
│   │   ├── middleware.go         # REST-specific middleware
│   │   ├── errors.go             # HTTP error mapping
│   │   └── types.go              # REST request/response types
│   │
│   ├── grpc/                      # gRPC implementation
│   │   ├── server.go             # gRPC server setup
│   │   ├── service.go            # gRPC service implementation
│   │   ├── interceptors/         # gRPC interceptors
│   │   │   ├── logging.go        # Request logging
│   │   │   ├── auth.go           # Authentication
│   │   │   ├── recovery.go       # Panic recovery
│   │   │   └── metrics.go        # Metrics collection
│   │   ├── errors.go             # gRPC error mapping
│   │   └── helpers.go            # Protocol buffer helpers
│   │
│   ├── mcp/                       # Model Context Protocol
│   │   ├── server.go             # MCP server setup (JSON-RPC 2.0)
│   │   ├── handlers.go           # JSON-RPC method handlers
│   │   ├── transport.go          # TCP/WebSocket transport
│   │   ├── notifications.go      # Server-sent notifications
│   │   ├── batch.go              # Batch request handling
│   │   ├── errors.go             # JSON-RPC error codes
│   │   └── types.go              # JSON-RPC types
│   │
│   ├── quic/                      # QUIC/HTTP3 implementation
│   │   ├── server.go             # HTTP/3 server setup
│   │   ├── router.go             # HTTP/3 route definitions
│   │   ├── handlers/             # Shared with REST (thin wrapper)
│   │   ├── tls.go                # TLS certificate management
│   │   └── errors.go             # HTTP/3 error handling
│   │
│   └── cli/                       # CLI implementation
│       ├── client.go             # Client for remote server
│       ├── local.go              # Local KeyStore operations
│       ├── formatter.go          # Output formatting (JSON, table, YAML)
│       ├── config.go             # CLI configuration
│       └── helpers.go            # Common CLI utilities
│
├── api/                           # API definitions
│   ├── proto/                    # Protocol Buffer definitions
│   │   └── keychainv1/
│   │       ├── keychain.proto    # Main service definition
│   │       ├── types.proto       # Common types
│   │       └── errors.proto      # Error definitions
│   └── openapi/                  # OpenAPI/Swagger specs
│       └── keychain.yaml         # REST API specification
│
├── pkg/                           # Public packages
│   ├── keychain/                 # KeyStore interface (existing)
│   └── backend/                  # Backend interface (existing)
│
└── test/
    └── integration/
        └── api/                   # Integration tests (existing)
```


## Core Components

### 1. Server Orchestrator (`internal/server/server.go`)

The main server component that manages all protocol servers.

```go
type Server struct {
    config      *config.Config
    keyManager  *service.KeyManager
    restServer  *rest.Server
    grpcServer  *grpc.Server
    mcpServer   *mcp.Server
    quicServer  *quic.Server
    shutdown    chan os.Signal
}

// Key responsibilities:
// - Initialize all protocol servers
// - Coordinate startup sequence
// - Handle graceful shutdown
// - Manage shared resources
```

**Key Features:**
- Parallel server startup with error handling
- Coordinated graceful shutdown
- Health checking across all protocols
- Metrics collection and exposure

### 2. Configuration Management (`internal/config/`)

Hierarchical configuration system using Viper:

```go
type Config struct {
    Server ServerConfig
    REST   RESTConfig
    GRPC   GRPCConfig
    MCP    MCPConfig
    QUIC   QUICConfig
    Auth   AuthConfig
    TLS    TLSConfig
    Logging LoggingConfig
    Metrics MetricsConfig
    Backends []BackendConfig
}
```

**Configuration Sources (in order of precedence):**
1. Command-line flags
2. Environment variables
3. Configuration file (YAML)
4. Defaults

### 3. Service Layer (`internal/service/`)

Business logic shared across all protocols.

#### KeyManager Service

```go
type KeyManager struct {
    keystore keychain.KeyStore
    registry *BackendRegistry
    validator *Validator
}

// Operations:
// - GenerateKey(req GenerateKeyRequest) (*KeyInfo, error)
// - GetKey(backendName, keyID string) (*KeyInfo, error)
// - DeleteKey(backendName, keyID string) error
// - ListKeys(backendName string, opts ListOptions) ([]*KeyInfo, error)
// - Sign(backendName, keyID string, data []byte, opts SignOptions) ([]byte, error)
// - Verify(backendName, keyID string, data, sig []byte, opts VerifyOptions) (bool, error)
```

#### Backend Registry

```go
type BackendRegistry struct {
    backends map[string]keychain.KeyStore
    mu       sync.RWMutex
}

// Operations:
// - Register(name string, ks keychain.KeyStore) error
// - Get(name string) (keychain.KeyStore, error)
// - List() []BackendInfo
// - GetInfo(name string) (*BackendInfo, error)
```

#### Validators

```go
type Validator struct{}

// Validation functions:
// - ValidateKeyID(keyID string) error
// - ValidateKeyType(keyType string) error
// - ValidateKeySize(keyType string, size int) error
// - ValidateCurve(curve string) error
// - ValidateHashAlgorithm(hash string) error
```


## Protocol Implementations

### 1. REST API (`internal/rest/`)

**Framework:** Standard library `net/http` with custom router or `chi`

**Base Path:** `/api/v1`

**Endpoints:**

```
Health & Metadata:
GET    /health                    - Health check
GET    /version                   - Version information
GET    /api/v1/backends           - List available backends
GET    /api/v1/backends/{name}    - Get backend info

Key Management:
POST   /api/v1/keys               - Generate new key
GET    /api/v1/keys               - List keys (with backend query param)
GET    /api/v1/keys/{id}          - Get key details
DELETE /api/v1/keys/{id}          - Delete key

Cryptographic Operations:
POST   /api/v1/keys/{id}/sign     - Sign data
POST   /api/v1/keys/{id}/verify   - Verify signature
POST   /api/v1/keys/{id}/decrypt  - Decrypt data (if supported)
POST   /api/v1/keys/{id}/rotate   - Rotate key (if supported)
```

**Request/Response Format:**

```json
// Generate Key Request
POST /api/v1/keys
{
  "key_id": "my-key",
  "backend": "pkcs8",
  "key_type": "rsa",
  "key_size": 2048,
  "curve": ""  // For ECDSA
}

// Generate Key Response (201 Created)
{
  "key_id": "my-key",
  "backend": "pkcs8",
  "key_type": "rsa",
  "key_size": 2048,
  "public_key_pem": "-----BEGIN PUBLIC KEY-----...",
  "created_at": "2025-11-05T12:00:00Z"
}

// Error Response (4xx/5xx)
{
  "error": {
    "code": "INVALID_KEY_TYPE",
    "message": "Invalid key type: invalid",
    "details": {}
  }
}
```

**HTTP Status Codes:**
- 200 OK - Successful operation
- 201 Created - Resource created
- 400 Bad Request - Invalid input
- 404 Not Found - Resource not found
- 409 Conflict - Resource already exists
- 500 Internal Server Error - Server error
- 503 Service Unavailable - Backend unavailable

### 2. gRPC API (`internal/grpc/`)

**Protocol Buffer Definition:** `api/proto/keychainv1/keychain.proto`

```protobuf
service KeystoreService {
  // Health & Metadata
  rpc Health(HealthRequest) returns (HealthResponse);
  rpc ListBackends(ListBackendsRequest) returns (ListBackendsResponse);
  rpc GetBackendInfo(GetBackendInfoRequest) returns (GetBackendInfoResponse);

  // Key Management
  rpc GenerateKey(GenerateKeyRequest) returns (GenerateKeyResponse);
  rpc GetKey(GetKeyRequest) returns (GetKeyResponse);
  rpc ListKeys(ListKeysRequest) returns (ListKeysResponse);
  rpc DeleteKey(DeleteKeyRequest) returns (DeleteKeyResponse);

  // Cryptographic Operations
  rpc Sign(SignRequest) returns (SignResponse);
  rpc Verify(VerifyRequest) returns (VerifyResponse);
  rpc Decrypt(DecryptRequest) returns (DecryptResponse);
  rpc RotateKey(RotateKeyRequest) returns (RotateKeyResponse);
}
```

**Error Handling:**
- Use gRPC status codes (codes.InvalidArgument, codes.NotFound, etc.)
- Include structured error details using google.rpc.Status

**Interceptors:**
1. Logging - Request/response logging
2. Authentication - API key/JWT validation
3. Recovery - Panic recovery with stack traces
4. Metrics - Request duration, counts

### 3. MCP (Model Context Protocol) (`internal/mcp/`)

**Protocol:** JSON-RPC 2.0 over TCP or WebSocket

**Transport Layer:**
- TCP on port 9444 (default)
- WebSocket upgrade support
- Newline-delimited JSON

**Methods:**

```json
// Health Check
{"jsonrpc": "2.0", "method": "health", "id": 1}

// List Backends
{"jsonrpc": "2.0", "method": "keychain.listBackends", "id": 2}

// Generate Key
{
  "jsonrpc": "2.0",
  "method": "keychain.generateKey",
  "params": {
    "key_id": "my-key",
    "backend": "pkcs8",
    "key_type": "rsa",
    "key_size": 2048
  },
  "id": 3
}

// Subscribe to Events (notifications)
{
  "jsonrpc": "2.0",
  "method": "keychain.subscribe",
  "params": {
    "events": ["key.created", "key.deleted", "key.rotated"]
  },
  "id": 4
}
```

**Notifications (server-to-client):**

```json
{
  "jsonrpc": "2.0",
  "method": "key.created",
  "params": {
    "key_id": "my-key",
    "backend": "pkcs8",
    "timestamp": "2025-11-05T12:00:00Z"
  }
}
```

**Features:**
- Batch request support
- Server-sent notifications for key events
- Long-lived connections
- WebSocket fallback

### 4. QUIC/HTTP3 (`internal/quic/`)

**Framework:** `quic-go/quic-go` with HTTP/3 support

**Protocol:** HTTP/3 over QUIC (UDP-based)

**Implementation:**
- Shares REST API routes and handlers
- Requires TLS 1.3
- Benefits: Lower latency, better handling of packet loss
- Same endpoint structure as REST API

**Differences from REST:**
- Transport: UDP instead of TCP
- Protocol: HTTP/3 instead of HTTP/2
- Multiplexing: Native stream multiplexing without head-of-line blocking

### 5. CLI (`cmd/cli/`)

**Framework:** Cobra (commands) + Viper (config)

**Modes of Operation:**

1. **Local Mode:** Direct KeyStore access
   ```bash
   keychain key generate my-key --backend pkcs8 --key-type rsa --key-size 2048
   ```

2. **Remote Mode:** HTTP/gRPC client to server
   ```bash
   keychain --server http://localhost:8080 key generate my-key --backend pkcs8
   ```

**Command Structure:**

```
keychain
├── version                        # Show version
├── backends
│   ├── list                      # List backends
│   └── info <name>               # Backend details
├── key
│   ├── generate <id>             # Generate key
│   ├── get <id>                  # Get key details
│   ├── list                      # List keys
│   ├── delete <id>               # Delete key
│   ├── sign <id> <data>          # Sign data
│   └── verify <id> <data> <sig>  # Verify signature
└── server
    ├── start                     # Start server
    └── status                    # Check server status
```

**Output Formats:**
- `--output json` - JSON output
- `--output yaml` - YAML output
- `--output table` - Human-readable table (default)


## Configuration Management

### Configuration Structure

```yaml
# Server configuration
server:
  data_dir: /var/lib/keychain
  log_level: info
  log_format: json

# REST API
rest:
  enabled: true
  address: :8443
  tls:
    enabled: true
    cert_file: /etc/keychain/tls/server.crt
    key_file: /etc/keychain/tls/server.key

# gRPC
grpc:
  enabled: true
  address: :9443
  tls:
    enabled: true
    cert_file: /etc/keychain/tls/server.crt
    key_file: /etc/keychain/tls/server.key

# MCP (Model Context Protocol)
mcp:
  enabled: true
  address: :9444
  transport: tcp  # tcp or websocket

# QUIC/HTTP3
quic:
  enabled: true
  address: :8444
  tls:
    cert_file: /etc/keychain/tls/server.crt
    key_file: /etc/keychain/tls/server.key

# Authentication
auth:
  enabled: true
  type: api_key  # api_key, jwt, mtls
  api_keys:
    - key: "test-api-key"
      name: "test-client"

# TLS Configuration
tls:
  min_version: "1.2"
  ciphers:
    - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

# Metrics
metrics:
  enabled: true
  address: :9090
  path: /metrics

# Backends
backends:
  - name: pkcs8
    type: pkcs8
    config:
      key_dir: /var/lib/keychain/keys
      cert_dir: /var/lib/keychain/certs

  - name: pkcs11
    type: pkcs11
    config:
      library: /usr/lib/softhsm/libsofthsm2.so
      slot_id: 0
      pin: "1234"

  - name: tpm2
    type: tpm2
    config:
      device: /dev/tpmrm0
```

### Environment Variables

All configuration can be overridden via environment:

```bash
KEYCHAIN_SERVER_LOG_LEVEL=debug
KEYCHAIN_REST_ADDRESS=:8080
KEYCHAIN_GRPC_ADDRESS=:9090
KEYCHAIN_AUTH_ENABLED=true
KEYCHAIN_BACKENDS_0_NAME=pkcs8
KEYCHAIN_BACKENDS_0_TYPE=pkcs8
```


## Error Handling Strategy

### Error Hierarchy

```go
// Service-level errors
var (
    ErrInvalidKeyID      = errors.New("invalid key ID")
    ErrInvalidKeyType    = errors.New("invalid key type")
    ErrKeyNotFound       = errors.New("key not found")
    ErrKeyAlreadyExists  = errors.New("key already exists")
    ErrBackendNotFound   = errors.New("backend not found")
    ErrOperationNotSupported = errors.New("operation not supported")
)
```

### Error Mapping

| Service Error | REST | gRPC | MCP (JSON-RPC) |
|--------------|------|------|----------------|
| ErrInvalidKeyID | 400 Bad Request | InvalidArgument | -32602 Invalid params |
| ErrKeyNotFound | 404 Not Found | NotFound | -32001 Resource not found |
| ErrKeyAlreadyExists | 409 Conflict | AlreadyExists | -32002 Resource exists |
| ErrBackendNotFound | 404 Not Found | NotFound | -32001 Resource not found |
| ErrOperationNotSupported | 501 Not Implemented | Unimplemented | -32601 Method not found |

### Error Response Structures

**REST:**
```json
{
  "error": {
    "code": "KEY_NOT_FOUND",
    "message": "Key with ID 'my-key' not found in backend 'pkcs8'",
    "details": {
      "key_id": "my-key",
      "backend": "pkcs8"
    }
  }
}
```

**gRPC:**
```go
status.Errorf(codes.NotFound, "key not found: %s", keyID)
```

**MCP (JSON-RPC):**
```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32001,
    "message": "Key not found",
    "data": {
      "key_id": "my-key",
      "backend": "pkcs8"
    }
  },
  "id": 1
}
```


## Security Considerations

### 1. Authentication

**Supported Methods:**
- API Key (X-API-Key header)
- JWT (Bearer token)
- Mutual TLS (client certificates)

**Implementation:**
- Middleware validates credentials
- Context propagation for user identity
- Rate limiting per client

### 2. Authorization

**Future Enhancement:**
- Role-based access control (RBAC)
- Per-backend permissions
- Key-level access control

### 3. TLS/Encryption

**Requirements:**
- TLS 1.2+ for all network protocols
- Strong cipher suites only
- Certificate validation
- Perfect forward secrecy

### 4. Input Validation

**All inputs must be validated:**
- Key IDs: alphanumeric + hyphens, max 255 chars
- Key types: whitelist (rsa, ecdsa, ed25519)
- Key sizes: valid for algorithm
- Backend names: registered backends only

### 5. Rate Limiting

**Per-client limits:**
- Key generation: 10/minute
- Signing operations: 100/minute
- List operations: 50/minute

### 6. Audit Logging

**All operations logged:**
- Key generation, deletion
- Signing, verification
- Failed authentication attempts
- Configuration changes


## Testing Strategy

### Unit Tests

**Coverage:** 90%+ for all packages

**Focus:**
- Validation logic
- Error handling
- Configuration parsing
- Protocol helpers

### Integration Tests

**Location:** `test/integration/api/`

**Existing tests:**
- REST API tests
- gRPC tests
- MCP tests
- QUIC tests
- CLI tests
- E2E workflow tests

**Test environment:**
- Docker Compose orchestration
- Real backend services (SoftHSM, SWTPM)
- Health check dependencies

### Benchmark Tests

**Performance targets:**
- Key generation: < 100ms (RSA 2048)
- Signing: < 10ms (RSA 2048)
- REST request: < 5ms (excluding crypto)
- gRPC request: < 2ms (excluding crypto)


## Implementation Patterns

### Common Patterns

#### 1. Dependency Injection

```go
// Service layer constructor
func NewKeyManager(
    ks keychain.KeyStore,
    registry *BackendRegistry,
    validator *Validator,
) *KeyManager {
    return &KeyManager{
        keystore: ks,
        registry: registry,
        validator: validator,
    }
}

// Protocol handler constructor
func NewRESTServer(
    config RESTConfig,
    keyManager *service.KeyManager,
) *Server {
    return &Server{
        config: config,
        keyManager: keyManager,
    }
}
```

#### 2. Context Propagation

```go
// All operations accept context
func (km *KeyManager) GenerateKey(
    ctx context.Context,
    req GenerateKeyRequest,
) (*KeyInfo, error) {
    // Extract request ID, user, etc. from context
    // Pass context to backend operations
}
```

#### 3. Error Wrapping

```go
func (km *KeyManager) GetKey(ctx context.Context, backend, keyID string) (*KeyInfo, error) {
    ks, err := km.registry.Get(backend)
    if err != nil {
        return nil, fmt.Errorf("get backend %s: %w", backend, err)
    }

    // ... operation

    if err != nil {
        return nil, fmt.Errorf("get key %s from backend %s: %w", keyID, backend, err)
    }
}
```

#### 4. Graceful Shutdown

```go
func (s *Server) Shutdown(ctx context.Context) error {
    var wg sync.WaitGroup
    errors := make(chan error, 4)

    // Shutdown all servers in parallel
    wg.Add(4)
    go func() { defer wg.Done(); errors <- s.restServer.Shutdown(ctx) }()
    go func() { defer wg.Done(); errors <- s.grpcServer.GracefulStop(); nil }()
    go func() { defer wg.Done(); errors <- s.mcpServer.Shutdown(ctx) }()
    go func() { defer wg.Done(); errors <- s.quicServer.Shutdown(ctx) }()

    wg.Wait()
    close(errors)

    // Collect errors
    var errs []error
    for err := range errors {
        if err != nil {
            errs = append(errs, err)
        }
    }

    if len(errs) > 0 {
        return fmt.Errorf("shutdown errors: %v", errs)
    }
    return nil
}
```

#### 5. Request Validation

```go
type Validator struct{}

func (v *Validator) ValidateGenerateKeyRequest(req GenerateKeyRequest) error {
    if err := v.ValidateKeyID(req.KeyID); err != nil {
        return err
    }
    if err := v.ValidateKeyType(req.KeyType); err != nil {
        return err
    }
    // ... more validation
    return nil
}
```


## API Consistency

All protocols must provide equivalent functionality:

| Operation | REST | gRPC | MCP | QUIC | CLI |
|-----------|------|------|-----|------|-----|
| Health Check | ✓ | ✓ | ✓ | ✓ | ✓ |
| List Backends | ✓ | ✓ | ✓ | ✓ | ✓ |
| Generate Key | ✓ | ✓ | ✓ | ✓ | ✓ |
| Get Key | ✓ | ✓ | ✓ | ✓ | ✓ |
| List Keys | ✓ | ✓ | ✓ | ✓ | ✓ |
| Delete Key | ✓ | ✓ | ✓ | ✓ | ✓ |
| Sign | ✓ | ✓ | ✓ | ✓ | ✓ |
| Verify | ✓ | ✓ | ✓ | ✓ | ✓ |
| Notifications | - | Stream | ✓ | - | - |


## Monitoring & Observability

### Metrics (Prometheus)

```
# Key operations
keychain_key_generate_total{backend, key_type}
keychain_key_generate_duration_seconds{backend, key_type}
keychain_key_delete_total{backend}
keychain_sign_total{backend}
keychain_sign_duration_seconds{backend}

# API requests
keychain_http_requests_total{method, path, status}
keychain_http_request_duration_seconds{method, path}
keychain_grpc_requests_total{method, status}
keychain_grpc_request_duration_seconds{method}

# System metrics
keychain_backends_available{backend}
keychain_keys_total{backend}
```

### Logging

**Structured logging with fields:**
- `request_id` - Unique request identifier
- `protocol` - rest, grpc, mcp, quic, cli
- `backend` - Backend name
- `key_id` - Key identifier
- `operation` - generate, sign, verify, etc.
- `duration_ms` - Operation duration
- `error` - Error message (if any)

### Health Checks

```
/health - Overall health
/ready  - Readiness probe (backends available)
/live   - Liveness probe (server running)
```


## Deployment Considerations

### Docker

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /build
COPY . .
RUN go build -o keychaind ./cmd/server

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /build/keychaind /usr/local/bin/
EXPOSE 8443 9443 9444 9090
ENTRYPOINT ["keychaind"]
```

### Kubernetes

```yaml
apiVersion: v1
kind: Service
metadata:
  name: keychain-server
spec:
  ports:
    - name: rest
      port: 8443
    - name: grpc
      port: 9443
    - name: mcp
      port: 9444
    - name: metrics
      port: 9090
  selector:
    app: keychain-server
apiVersion: apps/v1
kind: Deployment
metadata:
  name: keychain-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: keychain-server
  template:
    metadata:
      labels:
        app: keychain-server
    spec:
      containers:
      - name: keychain-server
        image: go-keychain:latest
        ports:
        - containerPort: 8443
        - containerPort: 9443
        - containerPort: 9444
        - containerPort: 9090
        livenessProbe:
          httpGet:
            path: /health
            port: 8443
        readinessProbe:
          httpGet:
            path: /ready
            port: 8443
```


## References

### Related Documents
- [KeyStore Interface](../../pkg/keychain/keystore.go)
- [Backend Interface](../../pkg/backend/backend.go)
- [Integration Tests](../../test/integration/api/)

### External Standards
- [REST API Best Practices](https://restfulapi.net/)
- [gRPC Documentation](https://grpc.io/docs/)
- [JSON-RPC 2.0 Specification](https://www.jsonrpc.org/specification)
- [HTTP/3 (RFC 9114)](https://www.rfc-editor.org/rfc/rfc9114.html)
- [Model Context Protocol](https://github.com/anthropics/model-context-protocol)

### Dependencies
- `github.com/spf13/cobra` - CLI framework
- `github.com/spf13/viper` - Configuration management
- `google.golang.org/grpc` - gRPC framework
- `github.com/quic-go/quic-go` - QUIC/HTTP3 support
- `github.com/prometheus/client_golang` - Metrics
- Standard library `net/http` - HTTP servers


