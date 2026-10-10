# Go-xKMS Server Architecture


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

The go-xkms server exposes the KeyStore interface through multiple protocols:
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
        │  (pkg/server)         │
        │  - KeyManager         │
        │  - BackendRegistry    │
        │  - Validators         │
        └───────────┬───────────┘
                    │
        ┌───────────▼───────────┐
        │   KeyStore Interface  │
        │  (pkg/xkms)       │
        └───────────┬───────────┘
                    │
        ┌───────────▼───────────┐
        │   Backend Layer       │
        │  - Software            │
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
go-xkms/
├── cmd/
│   ├── xkmsd/                     # Multi-protocol server binary
│   │   └── main.go               # Entry point, server initialization
│   └── xkmsctl/                   # CLI binary
│       ├── main.go               # CLI entry point
│       ├── root.go               # Root command (Cobra)
│       └── commands/             # Command implementations
│
├── pkg/
│   ├── server/                    # Server orchestration & service layer
│   │   ├── server.go             # Main server struct, lifecycle
│   │   ├── reload.go             # Configuration reload
│   │   ├── backend_<backend>.go  # Per-backend construction (initXBackend), with _stub.go siblings
│   │   └── storage_factory.go    # Storage backend selection (memory, pebble, file, qrdb)
│   │
│   ├── config/                    # Configuration management
│   │   ├── config.go             # Configuration structs
│   │   ├── auth.go               # Auth configuration
│   │   └── tls.go                # TLS configuration
│   │
│   ├── api/
│   │   ├── rest/                  # REST API implementation
│   │   │   ├── server.go         # REST server setup
│   │   │   ├── handlers.go       # HTTP handlers
│   │   │   ├── middleware.go     # REST-specific middleware
│   │   │   ├── errors.go         # HTTP error mapping
│   │   │   ├── validation.go     # Input validation
│   │   │   └── types.go          # REST request/response types
│   │   │
│   │   ├── grpc/                  # gRPC implementation
│   │   │   ├── server.go         # gRPC server setup
│   │   │   └── service.go        # gRPC service implementation
│   │   │
│   │   ├── mcp/                   # Model Context Protocol
│   │   │   ├── server.go         # MCP server setup (JSON-RPC 2.0)
│   │   │   ├── handlers.go       # JSON-RPC method handlers
│   │   │   ├── utils.go          # Utilities
│   │   │   └── types.go          # JSON-RPC types
│   │   │
│   │   ├── quic/                  # QUIC/HTTP3 implementation
│   │   │   ├── server.go         # HTTP/3 server setup
│   │   │   ├── handlers.go       # HTTP/3 handlers
│   │   │   └── utils.go          # QUIC utilities
│   │   │
│   │   └── unix/                  # Unix socket gRPC
│   │       └── grpc_server.go    # Unix socket server
│   │
│   ├── backend/                   # Backend interface & implementations
│   ├── crypto/                    # Cryptographic primitives
│   ├── encoding/                  # Encoding (JWK, JWE, JWT, PEM)
│   ├── storage/                   # Storage layer
│   └── types/                     # Common types
│
└── test/
    └── integration/
        └── api/                   # Integration tests
```


## Core Components

### 1. Server Orchestrator (`pkg/server/server.go`)

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

### Subsystem Wiring

After `xkms.Initialize()` creates the `XKMSService` singleton with backends, the server wires additional subsystems via setter methods. This approach is necessary because subsystems (barrier, PIN, users, etc.) are initialized *after* `xkms.Initialize()`. The store-backed subsystems are built by `pkg/compose`'s `Build*` functions and published with `compose.Stores.Wire` — the same path an embedding host's module takes ([`../host-embedding/`](../host-embedding/)):

```go
// In server.go, once every subsystem is initialized:
svc, _ := xkms.Get()
stores := s.composedStores() // password store + tenant manager, PIN, platform store,
                             // credentials, CA, policies, barrier, custody clients
stores.Wire(svc)
// ... then the non-store wiring (WebAuthn, users, audit, cluster, ...).
```

Once all subsystems are wired, the `XKMSService` satisfies the full `XKMSServicer` interface and can be used with the embedded SDK transport (`sdk.NewEmbedded(svc)`) for in-process clients like the xkey GUI.

### Transport Dependency Injection

Protocol transports never call `xkms.Get()` themselves. The `*xkms.XKMSService`
is resolved once at a composition root and injected into every transport
constructor:

| Transport | Injection point |
|-----------|-----------------|
| REST      | `rest.Config.XKMSService` → `rest.NewServer(cfg)` |
| gRPC      | `grpc.NewService(authorizer, auditLogger, xkmsService)` |
| QUIC      | `quic.Config.XKMSService` → `quic.NewServer(cfg)` |
| MCP       | `mcp.Config.XKMSService` → `mcp.NewServer(cfg)` (returns `ErrXKMSServiceRequired` when nil) |
| Unix      | `unix.GRPCConfig.XKMSService` |

There are exactly two composition roots that call `xkms.Get()`:

1. `pkg/server/server.go` — `New()` resolves the service after
   `xkms.Initialize()` and threads it into every protocol server it starts.
2. `sdk/go/embedded.go` — the embedded transport resolves the service for
   in-process clients.

REST handler sub-groups receive the service the same way:
`NewCustodianHandlers(svc)`, `NewShareHandlers(svc)`, `NewClusterHandlers(svc)`,
`NewTenantHandlers(registry, svc)`.

Inside a transport, backend access goes through nil-guarding helpers
(`lookupBackend`, `backendNames`, `sealWithBackend`, ...) that return
`xkms.ErrNotInitialized` when the service was not wired, so a misconfigured
transport fails fast with a typed error instead of panicking.

Tests construct a service via `xkms.Initialize()` + `xkms.Get()` in their
setup helpers and inject it explicitly — the singleton accessor is a
composition-root convenience, not an API for business logic.

### Unified API Server: the xkms ServiceModule (Phase 3, additive)

Per the unified-API-server plan
(`plans/unified-api-server-2026-08-14.md`, Software Department), the parallel
transport stacks above are being superseded by go-qrdb's one multi-protocol
server, into which capabilities register as `qrdbsdk.ServiceModule`s. The
stack-wide convention is one module per provider project, named after the
project (registered names `xkms`, `quicbaas`, ...); each provider re-exports
its module through its own SDK so hosts embedding a qrdb node compose modules
without importing provider `pkg/*` (xkms's re-export is
`sdk/go/apimodule.go`, `xkms.NewServiceModule`).
`pkg/apimodule.Module` is xkms's module: it carries the wholesale
`KeystoreService` gRPC surface (the same `pb.KeystoreServiceServer` every
legacy transport drives) and is registered into xkmsd's embedded qrdb node via
`qrdbsdk.WithModule` in `pkg/server/qrdb_node.go`. On that server,
per-method authorization comes from the `option (qrdb.v1.permission)`
annotation each RPC now carries in `pkg/api/grpc/proto/xkmsv1/xkms.proto`
(enforced default-deny by qrdb's reflection interceptor;
`pkg/api/grpc/authz_proto_option_test.go` locks the annotations to the golden
gate table), so the module's in-handler authorizer is constructed
nil-with-local-trust exactly like the Unix listener's. Because the node is
built before the `XKMSService` is composed, the module binds the service
lazily on first RPC (answering `Unavailable` until composition completes).

The module now carries all three unified-server surfaces:

- **gRPC** — the wholesale `KeystoreService` (above).
- **HTTP** — `RegisterHTTP` registers the complete REST route table
  (`pkg/api/rest/routes.go`, the same `Routes()` the legacy chi router
  serves) through qrdb's permission-recording registrar: public routes via
  `HandlePublic`, authenticated-session routes under the `identity:gated`
  sentinel, permission routes under their `resource:action`. Handlers
  late-bind through `pkg/server.ModuleRESTServer()` (the running legacy
  REST server, or a lazily built non-listening instance from the identical
  `buildRESTConfig`); routes answer 503 until composition and 501 when the
  backing subsystem is absent. Group middleware (authentication, tenant
  enforcement, login rate limiting) is reapplied per route via
  `rest.BindRoute`, so handler context contracts hold until Phase 5
  unifies the authentication plane.
- **MCP** — `RegisterMCP` registers every xkms JSON-RPC method
  (`pkg/api/mcp.ModuleMethods()`, including the frost namespace) as a real
  mcp-go tool (`xkms_*`) whose single `params_json` argument carries the
  method's params verbatim; dispatch runs `mcp.Server.InvokeMethod` — the
  same tenant and authorization gates as the wire path — resolved lazily
  via `pkg/server.ModuleMCPServer()`. At go-qrdb v0.3.0-alpha module tools
  are fail-closed under qrdb's auth middleware until qrdb exports a module
  tool-permission registry hook.

**Host mode.** A host that embeds a qrdb node mounts the same module
without a REST resolver; the module then self-builds its surface and
composes the store-backed features (Password Manager, SSH, CA, platform
store, credentials, PCR policies) from host-supplied dependencies through
`pkg/compose` — the path xkmsd builds them through. See
[`../host-embedding/`](../host-embedding/).

**Network serving IS the unified server (Phase 4 complete)**: enabling any
network protocol (`rest`, `grpc`, `quic`, `mcp`) requires
`storage.backend: qrdb` and `tls.enabled: true` — the embedded qrdb node's
multi-protocol server takes xkmsd's ports and serves the capability plane
through the module; the legacy per-transport network listeners (and the
whole legacy QUIC server package) are deleted. QUIC is HTTP/3 on the REST
port (the unified REST server runs an HTTP/3 listener alongside TCP and
advertises it via `Alt-Svc`), so the xkms QUIC client works against the
REST port unchanged. TLS material: operator `cert_file`/`key_file` if
configured, otherwise a persisted node-local bootstrap certificate serves
from first boot and is replaced in-place by the CA-issued certificate once
the CA composes (`pkg/server/unified_tls.go`). The client-CA pool the
unified server verifies mTLS clients against upgrades the same way: once the
CA composes, `upgradeUnifiedTLSCert` (`pkg/server/unified_tls.go:157`)
installs the union of the operator-configured `tls.ca_file`/`tls.client_cas`
(resolved through `loadClientCAsUnion`, the same helper `buildTLSConfig`
uses at startup) and the CA's own bundle, via
`unifiedClientCAPool` (`pkg/server/unified_tls.go:196`) — an mTLS client
anchored by either stays accepted after the upgrade (go-xkms#794). Local IPC is exempt: the
Unix socket serves in-process for non-qrdb storage (with qrdb storage the
node's own UDS serves it), and the desktop loopback engine serves a
pre-bound injected listener. The embedded web UI registers on the unified
server as public prefix routes with lazy SPA binding.

### 2. Configuration Management (`pkg/config/`)

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

### 3. Service Layer (`pkg/server/`)

Business logic shared across all protocols.

#### KeyManager Service

```go
type KeyManager struct {
    keystore xkms.KeyStore
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
    backends map[string]xkms.KeyStore
    mu       sync.RWMutex
}

// Operations:
// - Register(name string, ks xkms.KeyStore) error
// - Get(name string) (xkms.KeyStore, error)
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

### 1. REST API (`pkg/api/rest/`)

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
  "backend": "software",
  "key_type": "rsa",
  "key_size": 2048,
  "curve": ""  // For ECDSA
}

// Generate Key Response (201 Created)
{
  "key_id": "my-key",
  "backend": "software",
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

### 2. gRPC API (`pkg/api/grpc/`)

**Protocol Buffer Definition:** `pkg/api/grpc/proto/xkmsv1/xkms.proto`

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
2. Authentication - JWT/mTLS/OIDC validation
3. Recovery - Panic recovery with stack traces
4. Metrics - Request duration, counts

### 3. MCP (Model Context Protocol) (`pkg/api/mcp/`)

**Protocol:** JSON-RPC 2.0 over TCP or WebSocket

**Transport Layer:**
- Real Model Context Protocol: Streamable HTTP at `https://host:<mcp_port>/mcp`
  (TLS-only, mTLS-peer authenticated), served by the unified API server
- Every xkms operation is an MCP tool named `xkms_` + the method with dots
  replaced by underscores; one optional string argument `params_json`
  carries the method's params object verbatim

**Tool calls (MCP `tools/call`):**

```json
// Health Check
{"name": "xkms_health"}

// List Backends
{"name": "xkms_listBackends"}

// Generate Key
{
  "name": "xkms_generateKey",
  "arguments": {
    "params_json": "{\"key_id\":\"my-key\",\"backend\":\"software\",\"key_type\":\"rsa\",\"key_size\":2048}"
  }
}
```

The tool result is a text content item containing the method's JSON result;
tool-level failures return an MCP tool error. Dispatch runs
`pkg/api/mcp.Server.InvokeMethod` — the same tenant and authorization gates
as every other transport. There is no subscription/notification plane yet
(the legacy `xkms.subscribe` stream was removed with the JSON-RPC listener;
real-MCP notifications are a future design).

### 4. QUIC/HTTP3

**Protocol:** HTTP/3 over QUIC (UDP-based), served by the unified API
server's REST listener — there is no separate QUIC server package. When TLS
is configured the unified REST server runs an HTTP/3 listener on the same
port as TCP and advertises it via the `Alt-Svc` header.

**Implementation:**
- Identical routes, handlers, and authorization to REST (it IS the REST
  surface over HTTP/3)
- Requires TLS 1.3
- Benefits: Lower latency, better handling of packet loss
- The QUIC client transport (`pkg/api/transport/quic`) dials the REST port

### 5. CLI (`cmd/xkmsctl/`)

**Framework:** Cobra (commands) + Viper (config)

**Modes of Operation:**

1. **Local Mode:** Direct KeyStore access
   ```bash
   xkmsctl key generate my-key --backend software --key-type rsa --key-size 2048
   ```

2. **Remote Mode:** HTTP/gRPC client to server
   ```bash
   xkmsctl --server http://localhost:8080 key generate my-key --backend software
   ```

**Command Structure:**

```
xkmsctl
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
  data_dir: /var/lib/xkms
  log_level: info
  log_format: json

# REST API
rest:
  enabled: true
  address: :8443
  tls:
    enabled: true
    cert_file: /etc/xkms/tls/server.crt
    key_file: /etc/xkms/tls/server.key

# gRPC
grpc:
  enabled: true
  address: :9443
  tls:
    enabled: true
    cert_file: /etc/xkms/tls/server.crt
    key_file: /etc/xkms/tls/server.key

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
    cert_file: /etc/xkms/tls/server.crt
    key_file: /etc/xkms/tls/server.key

# Authentication
auth:
  enabled: true
  type: composite  # jwt, mtls, oidc, composite (composite with no methods derives jwt+mtls)
  # Adaptive escalates to JWT once the first user exists, so a JWT
  # verification key is required; startup fails without it.
  jwt:
    public_key_file: /etc/xkms/jwt-public.pem
    issuer: "my-issuer"
    audience: ["xkms"]

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

# Backends: one fixed section per backend (config.BackendsConfig); a backend
# is registered under its section name, and default_backend names one of them.
default_backend: software

backends:
  software:
    enabled: true
    path: /var/lib/xkms/keys

  pkcs11:
    enabled: true
    library: /usr/lib/softhsm/libsofthsm2.so
    token: xkms
    pin: ""

  tpm2:
    enabled: true
    device_path: /dev/tpmrm0
```

### Environment Variables

All configuration can be overridden via environment:

```bash
XKMS_LOGGING_LEVEL=debug
XKMS_SERVER_HOST=0.0.0.0
XKMS_SERVER_REST_PORT=8080
XKMS_SERVER_GRPC_PORT=9090
XKMS_AUTH_ENABLED=true
XKMS_DEFAULT_BACKEND=software
XKMS_BACKENDS_SOFTWARE_ENABLED=true
XKMS_BACKENDS_SOFTWARE_PATH=/var/lib/xkms/keys
XKMS_BACKENDS_TPM2_ENABLED=true
XKMS_BACKENDS_TPM2_DEVICE_PATH=/dev/tpmrm0
```

`ServerConfig` has no combined host:port "address" field, only `rest_port`
and `grpc_port` (ints) plus a shared `host` — there is no
`XKMS_REST_ADDRESS`/`XKMS_GRPC_ADDRESS`, and the log level lives under
`logging.level`, not `server.log_level` (`pkg/config/config.go:329-341,382`).
See [`../xkmsd-configuration/architecture.md`](../xkmsd-configuration/architecture.md)
for the binding mechanism and [`../xkmsd-configuration/user.md`](../xkmsd-configuration/user.md)
for the verified key/variable table.

The variable name is `XKMS_<SECTION>_<KEY>` with nested keys joined by `_`;
there is no indexed form, because backends are fixed sections, not a list.


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
    "message": "Key with ID 'my-key' not found in backend 'software'",
    "details": {
      "key_id": "my-key",
      "backend": "software"
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
      "backend": "software"
    }
  },
  "id": 1
}
```


## Security Considerations

### 1. Authentication

**Supported Methods:**
- JWT (Bearer token with public key signature verification)
- Mutual TLS (client certificate authentication)
- OIDC (OpenID Connect with automatic provider discovery)
- Adaptive (auto-switches between bootstrap and secured mode)
- Composite (chains multiple authenticators)
- PKCS#11-backed TLS (hardware token client authentication)

**Implementation:**
- Middleware validates cryptographic credentials
- Context propagation for authenticated identity
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
    ks xkms.KeyStore,
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
xkms_key_generate_total{backend, key_type}
xkms_key_generate_duration_seconds{backend, key_type}
xkms_key_delete_total{backend}
xkms_sign_total{backend}
xkms_sign_duration_seconds{backend}

# API requests
xkms_http_requests_total{method, path, status}
xkms_http_request_duration_seconds{method, path}
xkms_grpc_requests_total{method, status}
xkms_grpc_request_duration_seconds{method}

# System metrics
xkms_backends_available{backend}
xkms_keys_total{backend}
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
FROM golang:1.27.2-alpine AS builder
WORKDIR /build
COPY . .
RUN go build -o xkmsd ./cmd/server

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /build/xkmsd /usr/local/bin/
EXPOSE 8443 9443 9444 9090
ENTRYPOINT ["xkmsd"]
```

### Kubernetes

```yaml
apiVersion: v1
kind: Service
metadata:
  name: xkms-server
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
    app: xkms-server
apiVersion: apps/v1
kind: Deployment
metadata:
  name: xkms-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: xkms-server
  template:
    metadata:
      labels:
        app: xkms-server
    spec:
      containers:
      - name: xkms-server
        image: go-xkms:latest
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
- [KeyStore Interface](../../pkg/xkms/keystore.go)
- [Backend Interface](../../pkg/xkms/keystore.go) (`pkg/xkms/keystore.go:36`)
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


