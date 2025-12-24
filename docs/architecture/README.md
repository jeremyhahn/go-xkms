# Go-Keychain Architecture Documentation

Comprehensive architecture documentation for the go-keychain multi-protocol server.


## Documentation Overview

This directory contains the complete architecture and implementation guidance for building the go-keychain server that exposes the KeyStore interface via multiple protocols.

### Core Documents

1. **[quick-reference.md](./quick-reference.md)** (1-page)
   - **Purpose:** One-page developer cheat sheet
   - **Audience:** All developers
   - **Contents:** Quick API reference, common patterns, key commands

2. **[overview.md](./overview.md)** (14KB)
   - **Purpose:** High-level architecture overview
   - **Audience:** Project stakeholders, managers, new developers
   - **Contents:** System overview, key features, component relationships

3. **[server-architecture.md](./server-architecture.md)** (30KB)
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

4. **[api-specifications.md](./api-specifications.md)** (22KB)
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

### Feature & Component Documentation

5. **[storage.md](./storage.md)**
   - **Purpose:** Consolidated storage architecture
   - **Audience:** Backend developers, platform engineers
   - **Contents:**
     - Storage abstraction layer design
     - BlobStorer interface specifications
     - Backend implementations (filesystem, memory, cloud)
     - Integration patterns
     - Migration guides

6. **[adapter-framework.md](./adapter-framework.md)**
   - **Purpose:** Authentication, logging, and adapter patterns
   - **Audience:** Platform developers
   - **Contents:**
     - Adapter architecture
     - Auth adapters (API key, JWT, mTLS)
     - Logging adapters
     - Custom adapter development

7. **[rbac.md](./rbac.md)** (12KB)
   - **Purpose:** Role-based access control documentation
   - **Audience:** Developers implementing authorization
   - **Contents:**
     - Permission model (resource:action pairs)
     - Predefined roles (admin, operator, auditor, user, readonly, guest)
     - RBAC adapter interface
     - Integration with user management
     - HTTP middleware examples

8. **[unified-keyid-jwk-integration.md](./unified-keyid-jwk-integration.md)**
   - **Purpose:** Key ID format and JWK integration guide
   - **Audience:** Key management developers
   - **Contents:**
     - Key ID format specifications
     - JWK integration patterns
     - Quick reference for common operations
     - Best practices

9. **[hardware-certificate-storage.md](./hardware-certificate-storage.md)**
   - **Purpose:** Hardware-backed certificate storage
   - **Audience:** Security engineers, PKI developers
   - **Contents:**
     - HSM/TPM integration
     - Certificate chain storage
     - Hardware key attestation

10. **[correlation-ids.md](./correlation-ids.md)**
    - **Purpose:** Request tracing and correlation
    - **Audience:** Platform developers, SREs
    - **Contents:**
      - Correlation ID propagation
      - Distributed tracing patterns
      - Logging integration

11. **[objstore-integration.md](./objstore-integration.md)**
    - **Purpose:** Cloud object storage integration
    - **Audience:** Platform engineers
    - **Contents:**
      - go-objstore integration
      - Cloud provider backends
      - Migration strategies

12. **[post-quantum-cryptography.md](./post-quantum-cryptography.md)**
    - **Purpose:** Post-quantum cryptography support
    - **Audience:** Cryptography engineers
    - **Contents:**
      - PQC algorithm support
      - Hybrid key schemes
      - Migration planning

13. **[symmetric-encryption.md](./symmetric-encryption.md)**
    - **Purpose:** Symmetric encryption capabilities
    - **Audience:** Security developers
    - **Contents:**
      - AES-GCM support
      - ChaCha20-Poly1305 implementation
      - Key derivation patterns

## Quick Start

### For Developers (Quick Reference)

**Start here:** [quick-reference.md](./quick-reference.md) - One-page cheat sheet with:
- Common API patterns
- Key generation examples
- Configuration snippets
- Essential commands

### For Developers Starting Implementation

1. **Read first:** [overview.md](./overview.md)
   - Understand the system at a high level
   - Learn about key components and their relationships

2. **Deep dive:** [server-architecture.md](./server-architecture.md)
   - Understand the overall design
   - Review the architecture diagrams
   - Familiarize yourself with design principles
   - Use the development workflow guidelines
   - Follow the testing strategy

3. **Reference:** [api-specifications.md](./api-specifications.md)
   - Implement APIs according to specifications
   - Ensure consistency across all protocols
   - Validate against provided examples

4. **Component-specific:** Review relevant feature documents
   - [storage.md](./storage.md) - For storage layer work
   - [rbac.md](./rbac.md) - For authorization implementation
   - [unified-keyid-jwk-integration.md](./unified-keyid-jwk-integration.md) - For key management

### For API Users / Integrators

1. **Quick start:** [quick-reference.md](./quick-reference.md)
2. **Complete reference:** [api-specifications.md](./api-specifications.md)
   - Available endpoints and methods
   - Request/response formats
   - Authentication requirements
   - Error handling
   - Rate limits

### For Project Managers / Stakeholders

Read [overview.md](./overview.md) for high-level understanding of the system architecture and capabilities.


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
./bin/keychaind --config /etc/keychain/config.yaml
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
2. **Follow Architecture:** Review server-architecture.md for implementation details
3. **Test Continuously:** Run tests after each component
4. **Document Changes:** Update docs as you implement
5. **Review Regularly:** Ensure consistency across protocols


## Documentation History

### Consolidated Documents (2025-12)

The following documents have been consolidated to reduce duplication and improve maintainability:

**Merged into [storage.md](./storage.md):**
- `storage-abstraction.md` - Storage abstraction concepts
- `storage-interfaces.md` - BlobStorer interface details

**Merged into [unified-keyid-jwk-integration.md](./unified-keyid-jwk-integration.md):**
- `keyid-jwk-quick-reference.md` - Quick reference content

**Removed (outdated):**
- `backend-registry.md` - Superseded by server-architecture.md
- `blobstorer-refactoring.md` - Internal development notes

**Condensed:**
- `hardware-certificate-storage.md` - Streamlined for clarity


## Support Resources

### Internal Documentation
- [Quick Reference](./quick-reference.md) - One-page cheat sheet
- [Overview](./overview.md) - High-level architecture
- [Server Architecture](./server-architecture.md) - Complete technical design
- [API Specifications](./api-specifications.md) - Complete API reference
- [Storage Architecture](./storage.md) - Storage layer design
- [RBAC](./rbac.md) - Role-based access control
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

- Adding new protocols or endpoints → Update [api-specifications.md](./api-specifications.md) and [quick-reference.md](./quick-reference.md)
- Changing error handling strategies → Update [server-architecture.md](./server-architecture.md)
- Modifying configuration structure → Update [server-architecture.md](./server-architecture.md) and [quick-reference.md](./quick-reference.md)
- Updating security requirements → Update [rbac.md](./rbac.md) and [adapter-framework.md](./adapter-framework.md)
- Adding new features or capabilities → Update [overview.md](./overview.md) and relevant feature documents
- Changing storage implementation → Update [storage.md](./storage.md)
- Modifying key management → Update [unified-keyid-jwk-integration.md](./unified-keyid-jwk-integration.md)

### Documentation Structure Guidelines

- **Keep it DRY:** Avoid duplicating content across documents. Link to authoritative sources.
- **Single source of truth:** Each topic should have one primary document.
- **Progressive disclosure:** Start simple (quick-reference), then detailed (feature docs).
- **Consolidate when needed:** Merge documents that overlap significantly.

**Architecture Version:** 1.1 (2025-12-24)
**Document Owner:** Architecture Team
**Last Consolidated:** 2025-12-24


**Ready to begin development? Start with [quick-reference.md](./quick-reference.md) or [overview.md](./overview.md)!**
