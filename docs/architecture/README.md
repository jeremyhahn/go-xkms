# Go-Keychain Architecture Documentation

Comprehensive architecture documentation for the go-keychain multi-protocol server.


## Documentation Overview

This directory contains the complete architecture and implementation guidance for building the go-keychain server that exposes the KeyStore interface via multiple protocols.

### Documents

1. **[server-architecture.md](./server-architecture.md)** (30KB)
   - **Purpose:** Complete technical architecture document
   - **Audience:** Architects, senior developers
   - **Contents:**
     - System architecture diagrams
     - Detailed directory structure with descriptions
     - Component design and responsibilities
     - Configuration management
     - Error handling strategy
     - Security considerations
     - Testing strategy
     - Common patterns and best practices
     - Deployment considerations

2. **[implementation-guide.md](./implementation-guide.md)** (15KB)
   - **Purpose:** Step-by-step implementation checklist
   - **Audience:** Developers implementing the server
   - **Contents:**
     - Phase-by-phase implementation plan (8 weeks)
     - Detailed checklists for each component
     - Testing commands and verification steps
     - Common issues and solutions
     - Development workflow
     - Debugging tips
     - Performance optimization guidance

3. **[api-specifications.md](./api-specifications.md)** (22KB)
   - **Purpose:** Complete API reference for all protocols
   - **Audience:** API users, integrators, frontend developers
   - **Contents:**
     - REST API endpoint specifications
     - gRPC service definitions
     - MCP (Model Context Protocol) methods
     - QUIC/HTTP3 API details
     - CLI command reference
     - Common data types
     - Error codes and handling
     - Rate limits
     - Complete usage examples

4. **[overview.md](./overview.md)** (14KB)
   - **Purpose:** High-level architecture overview
   - **Audience:** Project stakeholders, managers
   - **Contents:** Existing overview document


## Quick Start

### For Developers Starting Implementation

1. **Read first:** [server-architecture.md](./server-architecture.md)
   - Understand the overall design
   - Review the architecture diagrams
   - Familiarize yourself with design principles

2. **Follow:** [implementation-guide.md](./implementation-guide.md)
   - Understand the core infrastructure components
   - Use the development workflow guidelines
   - Follow the testing strategy

3. **Reference:** [api-specifications.md](./api-specifications.md)
   - Implement APIs according to specifications
   - Ensure consistency across all protocols
   - Validate against provided examples

### For API Users / Integrators

Start with [api-specifications.md](./api-specifications.md) to understand:
- Available endpoints and methods
- Request/response formats
- Authentication requirements
- Error handling
- Rate limits

### For Project Managers / Stakeholders

Read [overview.md](./overview.md) and the "Overview" section of [server-architecture.md](./server-architecture.md) for high-level understanding.


## Architecture Summary

### System Overview

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
        │  - KeyManager         │
        │  - BackendRegistry    │
        │  - Validators         │
        └───────────┬───────────┘
                    │
        ┌───────────▼───────────┐
        │   KeyStore Interface  │
        └───────────┬───────────┘
                    │
        ┌───────────▼───────────┐
        │   Backend Layer       │
        │  - PKCS#8  - TPM2     │
        │  - PKCS#11 - Cloud    │
        └───────────────────────┘
```

### Key Features

**Multi-Protocol Support:**
- REST API (HTTP/1.1 + HTTP/2) on port 8443
- gRPC (HTTP/2) on port 9443
- MCP (JSON-RPC 2.0) on port 9444
- QUIC (HTTP/3) on port 8444
- CLI for local and remote operations

**Security:**
- TLS 1.2+ for all network protocols
- API key, JWT, and mTLS authentication
- Rate limiting per client
- Comprehensive audit logging

**Operations:**
- Health checks and readiness probes
- Prometheus metrics on port 9090
- Graceful shutdown
- Configurable via file, environment, or flags

### Supported Operations

All protocols support:
- Health checking
- Backend management (list, info)
- Key generation (RSA, ECDSA, Ed25519)
- Key retrieval and listing
- Key deletion
- Cryptographic signing
- Signature verification
- Key rotation (backend-dependent)


## System Components

### Core Infrastructure
- Configuration management
- Service layer implementation
- Middleware framework
- Server orchestrator

### Protocol Implementations
- REST API
- gRPC API
- QUIC/HTTP3
- MCP (JSON-RPC)
- CLI (local and remote)

### Security & Operations
- Authentication/authorization
- TLS configuration
- Metrics & monitoring
- Audit logging

### Testing & Documentation
- Comprehensive integration tests
- Performance benchmarks
- API documentation
- Deployment guides


## Directory Structure

```
go-keychain/
├── cmd/
│   ├── server/          # Multi-protocol server binary
│   └── cli/             # CLI binary
├── internal/
│   ├── server/          # Server orchestration
│   ├── config/          # Configuration management
│   ├── service/         # Business logic layer
│   ├── rest/            # REST API implementation
│   ├── grpc/            # gRPC implementation
│   ├── mcp/             # MCP implementation
│   ├── quic/            # QUIC/HTTP3 implementation
│   └── cli/             # CLI implementation
├── api/
│   ├── proto/           # Protocol Buffer definitions
│   └── openapi/         # OpenAPI/Swagger specs
├── pkg/
│   ├── keychain/        # KeyStore interface
│   └── backend/         # Backend interface
├── test/
│   └── integration/
│       └── api/         # Integration tests
└── docs/
    └── architecture/    # This directory
```


## Testing Strategy

### Unit Tests
- **Target:** 90%+ coverage
- **Command:** `go test -v ./internal/...`
- **Focus:** Validation, error handling, configuration

### Integration Tests
- **Location:** `test/integration/api/`
- **Command:** `make integration-test`
- **Environment:** Docker Compose with real backends
- **Tests:**
  - REST API tests
  - gRPC tests
  - MCP tests
  - QUIC tests
  - CLI tests
  - E2E workflow tests

### Benchmark Tests
- **Command:** `go test -bench=. ./internal/...`
- **Targets:**
  - Key generation < 100ms (RSA 2048)
  - Signing < 10ms (RSA 2048)
  - REST request < 5ms (overhead)
  - gRPC request < 2ms (overhead)


## Dependencies

### Core Dependencies
- `github.com/spf13/cobra` - CLI framework
- `github.com/spf13/viper` - Configuration
- `google.golang.org/grpc` - gRPC
- `github.com/quic-go/quic-go` - QUIC/HTTP3
- `github.com/prometheus/client_golang` - Metrics

### Existing Packages
- `github.com/jeremyhahn/go-keychain/pkg/keychain` - KeyStore interface
- `github.com/jeremyhahn/go-keychain/pkg/backend` - Backend interface


## Configuration Example

```yaml
server:
  data_dir: /var/lib/keychain
  log_level: info

rest:
  enabled: true
  address: :8443

grpc:
  enabled: true
  address: :9443

mcp:
  enabled: true
  address: :9444

quic:
  enabled: true
  address: :8444

auth:
  enabled: true
  type: api_key

metrics:
  enabled: true
  address: :9090

backends:
  - name: pkcs8
    type: pkcs8
    config:
      key_dir: /var/lib/keychain/keys
```


## API Consistency

All protocols provide equivalent functionality:

| Operation | REST | gRPC | MCP | QUIC | CLI |
|-----------|:----:|:----:|:---:|:----:|:---:|
| Health Check | ✓ | ✓ | ✓ | ✓ | ✓ |
| List Backends | ✓ | ✓ | ✓ | ✓ | ✓ |
| Generate Key | ✓ | ✓ | ✓ | ✓ | ✓ |
| Get Key | ✓ | ✓ | ✓ | ✓ | ✓ |
| List Keys | ✓ | ✓ | ✓ | ✓ | ✓ |
| Delete Key | ✓ | ✓ | ✓ | ✓ | ✓ |
| Sign | ✓ | ✓ | ✓ | ✓ | ✓ |
| Verify | ✓ | ✓ | ✓ | ✓ | ✓ |
| Notifications | - | Stream | ✓ | - | - |


## Design Principles

1. **Separation of Concerns**
   - Protocol handlers handle protocol-specific details
   - Service layer contains business logic
   - KeyStore manages cryptographic operations

2. **DRY (Don't Repeat Yourself)**
   - Common logic in service layer
   - Protocol handlers are thin adapters
   - Shared validation and error handling

3. **Thread Safety**
   - All components thread-safe
   - Read-write locks for shared state
   - Immutable configurations

4. **Error Handling**
   - Protocol-specific error mapping
   - Structured error responses
   - Comprehensive logging

5. **Testability**
   - Dependency injection throughout
   - Mock-friendly interfaces
   - Comprehensive integration tests

6. **Performance**
   - Lock-free algorithms where possible
   - Connection pooling
   - Context propagation
   - Graceful shutdown


## Security Considerations

### Authentication
- API Key (X-API-Key header)
- JWT (Bearer token)
- Mutual TLS (client certificates)

### TLS Configuration
- TLS 1.2+ required
- Strong cipher suites
- Certificate validation
- Perfect forward secrecy

### Input Validation
- Key IDs: alphanumeric + hyphens, max 255 chars
- Key types: whitelist only
- Key sizes: algorithm-specific validation
- Backend names: registered backends only

### Rate Limiting
- Key generation: 10/minute
- Signing: 100/minute
- List operations: 50/minute

### Audit Logging
- All key operations logged
- Authentication events logged
- Failed operations logged
- Structured logging with context


## Monitoring & Observability

### Metrics (Prometheus)
```
keychain_key_generate_total{backend, key_type}
keychain_key_generate_duration_seconds{backend, key_type}
keychain_sign_total{backend}
keychain_http_requests_total{method, path, status}
keychain_grpc_requests_total{method, status}
```

### Health Checks
- `/health` - Overall health
- `/ready` - Readiness probe
- `/live` - Liveness probe

### Logging
Structured JSON logging with fields:
- `request_id` - Unique request ID
- `protocol` - rest, grpc, mcp, quic, cli
- `backend` - Backend name
- `operation` - generate, sign, verify
- `duration_ms` - Operation duration
- `error` - Error message (if any)


## Deployment

### Docker
```bash
docker build -t go-keychain-server .
docker run -p 8443:8443 -p 9443:9443 -p 9444:9444 go-keychain-server
```

### Kubernetes
```bash
kubectl apply -f deployments/kubernetes/
```

### Binary
```bash
# Build
make build

# Run
./bin/keychain-server --config /etc/keychain/config.yaml
```


## Development Commands

### Build
```bash
make build              # Build all binaries
make build-server       # Build server only
make build-cli          # Build CLI only
```

### Test
```bash
make test               # Unit tests
make integration-test   # Integration tests
make bench             # Benchmarks
make coverage          # Coverage report
```

### Generate
```bash
make proto-gen         # Generate protobuf code
make swagger-gen       # Generate OpenAPI docs
```

### Docker
```bash
make docker-build      # Build Docker image
make docker-run        # Run in Docker
make docker-test       # Run integration tests in Docker
```


## Next Steps

1. **Begin Development:** Start with Core Infrastructure components
2. **Follow Checklist:** Use implementation-guide.md
3. **Test Continuously:** Run tests after each component
4. **Document Changes:** Update docs as you implement
5. **Review Regularly:** Ensure consistency across protocols


## Support Resources

### Internal Documentation
- [Server Architecture](./server-architecture.md) - Complete technical design
- [Implementation Guide](./implementation-guide.md) - Step-by-step checklist
- [API Specifications](./api-specifications.md) - Complete API reference
- [KeyStore Interface](../../pkg/keychain/keystore.go) - Core interface
- [Backend Interface](../../pkg/backend/backend.go) - Backend contract
- [Existing Tests](../../test/integration/api/) - Integration test suite

### External Standards
- [REST API Best Practices](https://restfulapi.net/)
- [gRPC Documentation](https://grpc.io/docs/)
- [JSON-RPC 2.0 Specification](https://www.jsonrpc.org/specification)
- [HTTP/3 (RFC 9114)](https://www.rfc-editor.org/rfc/rfc9114.html)
- [Model Context Protocol](https://github.com/anthropics/model-context-protocol)
- [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- [Google Go Style Guide](https://google.github.io/styleguide/go/)

### Tools & Libraries
- [Protocol Buffers](https://protobuf.dev/)
- [Cobra CLI Framework](https://cobra.dev/)
- [Viper Configuration](https://github.com/spf13/viper)
- [QUIC-GO](https://github.com/quic-go/quic-go)
- [Prometheus Go Client](https://github.com/prometheus/client_golang)


## Contributing

When implementing components, ensure:

1. **Follow Design Patterns:** Use patterns from architecture document
2. **Maintain Consistency:** Keep APIs consistent across protocols
3. **Write Tests:** Unit tests + integration tests for all components
4. **Document Code:** Clear comments and godoc documentation
5. **Update Docs:** Keep architecture docs synchronized with code


## Document Maintenance

These architecture documents should be updated when:

- Adding new protocols or endpoints
- Changing error handling strategies
- Modifying configuration structure
- Updating security requirements
- Adding new features or capabilities

**Architecture Version:** 1.0
**Document Owner:** Architecture Team


**Ready to begin development? Start with [implementation-guide.md](./implementation-guide.md)!**
