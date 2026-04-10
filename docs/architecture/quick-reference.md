# Go-xKMS Server - Quick Reference Card

**One-page reference for developers**


## Architecture at a Glance

```
Client → Protocol Handler → Service Layer → KeyStore → Backend
```

## Ports

| Protocol | Port | TLS Required |
|----------|------|--------------|
| REST     | 8443 | Yes          |
| gRPC     | 9443 | Yes          |
| MCP      | 9444 | No (TCP)     |
| QUIC     | 8444 | Yes (1.3)    |
| Metrics  | 9090 | No           |

## Directory Structure

```
cmd/
├── xkmsd/         # Server binary
└── xkmsctl/       # CLI binary

pkg/
├── server/        # Orchestration & service layer
├── config/        # Configuration
├── api/
│   ├── rest/      # REST API
│   ├── grpc/      # gRPC
│   ├── mcp/       # MCP
│   ├── quic/      # QUIC
│   └── unix/      # Unix socket gRPC
├── backend/       # Backend implementations
├── crypto/        # Cryptographic primitives
├── encoding/      # Encoding (JWK, JWE, JWT, PEM)
├── storage/       # Storage layer
└── types/         # Common types
```

## Key Interfaces

### Service Layer
```go
type KeyManager interface {
    GenerateKey(ctx, req) (*KeyInfo, error)
    GetKey(ctx, backend, keyID) (*KeyInfo, error)
    ListKeys(ctx, backend, opts) ([]*KeyInfo, error)
    DeleteKey(ctx, backend, keyID) error
    Sign(ctx, backend, keyID, data, opts) ([]byte, error)
    Verify(ctx, backend, keyID, data, sig, opts) (bool, error)
}

type BackendRegistry interface {
    Register(name, ks) error
    Get(name) (xkms.KeyStore, error)
    List() []BackendInfo
}
```

## API Endpoints

### REST (JSON)
```
GET    /health
GET    /api/v1/backends
GET    /api/v1/backends/{name}
POST   /api/v1/keys
GET    /api/v1/keys?backend=software
GET    /api/v1/keys/{id}?backend=software
DELETE /api/v1/keys/{id}?backend=software
POST   /api/v1/keys/{id}/sign?backend=software
POST   /api/v1/keys/{id}/verify?backend=software
```

### gRPC
```protobuf
service KeystoreService {
  rpc Health(HealthRequest) returns (HealthResponse);
  rpc ListBackends(ListBackendsRequest) returns (ListBackendsResponse);
  rpc GenerateKey(GenerateKeyRequest) returns (GenerateKeyResponse);
  rpc GetKey(GetKeyRequest) returns (GetKeyResponse);
  rpc ListKeys(ListKeysRequest) returns (ListKeysResponse);
  rpc DeleteKey(DeleteKeyRequest) returns (DeleteKeyResponse);
  rpc Sign(SignRequest) returns (SignResponse);
  rpc Verify(VerifyRequest) returns (VerifyResponse);
}
```

### MCP (JSON-RPC)
```
health
xkms.listBackends
xkms.generateKey
xkms.getKey
xkms.listKeys
xkms.deleteKey
xkms.sign
xkms.verify
xkms.subscribe
```

### CLI
```bash
xkmsctl version
xkmsctl backends list
xkmsctl backends info <name>
xkmsctl key generate <id> --backend <name> --key-type <type>
xkmsctl key list --backend <name>
xkmsctl key get <id> --backend <name>
xkmsctl key delete <id> --backend <name>
xkmsctl key sign <id> <data> --backend <name> --hash <alg>
xkmsctl key verify <id> <data> --signature <sig> --backend <name>
```

## Configuration

```yaml
server:
  data_dir: /var/lib/xkms
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
  type: adaptive  # jwt, mtls, oidc, adaptive, composite

metrics:
  enabled: true
  address: :9090

backends:
  - name: software
    type: software
    config:
      key_dir: /var/lib/xkms/keys
```

## Error Handling

### Service Errors → Protocol Mapping

| Service Error | REST | gRPC | MCP |
|--------------|------|------|-----|
| ErrInvalidKeyID | 400 | InvalidArgument | -32602 |
| ErrKeyNotFound | 404 | NotFound | -32001 |
| ErrKeyAlreadyExists | 409 | AlreadyExists | -32002 |
| ErrBackendNotFound | 404 | NotFound | -32001 |
| ErrOperationNotSupported | 501 | Unimplemented | -32601 |

## Common Patterns

### Dependency Injection
```go
func NewKeyManager(
    ks xkms.KeyStore,
    registry *BackendRegistry,
    validator *Validator,
) *KeyManager
```

### Context Propagation
```go
func (km *KeyManager) GenerateKey(
    ctx context.Context,
    req GenerateKeyRequest,
) (*KeyInfo, error)
```

### Error Wrapping
```go
if err != nil {
    return nil, fmt.Errorf("operation failed: %w", err)
}
```

### Graceful Shutdown
```go
func (s *Server) Shutdown(ctx context.Context) error {
    var wg sync.WaitGroup
    // Shutdown all servers in parallel
    // Collect and return errors
}
```

## Testing

### Unit Tests
```bash
go test -v ./pkg/config/...
go test -v ./pkg/server/...
go test -cover ./pkg/...
```

### Integration Tests
```bash
make integration-test

# Individual protocols
go test -v -tags=integration ./test/integration/api/rest_test.go
go test -v -tags=integration,grpc ./test/integration/api/grpc_test.go
go test -v -tags=integration ./test/integration/api/mcp_test.go
go test -v -tags=integration ./test/integration/api/quic_test.go
go test -v -tags=integration ./test/integration/api/cli_test.go
```

### Benchmarks
```bash
go test -bench=. -benchmem ./pkg/...
```

## Build & Run

### Build
```bash
make build              # All binaries
make build-server       # Server only
make build-cli          # CLI only
```

### Run
```bash
# Server
./bin/xkmsd --config config.yaml

# CLI
./bin/xkmsctl key generate my-key --backend software --key-type rsa
```

### Docker
```bash
docker-compose up -d
docker-compose ps
docker-compose logs -f xkms-server
```

## Development Workflow

1. **Create feature branch**
   ```bash
   git checkout -b feature/rest-api
   ```

2. **Implement component**
   ```bash
   mkdir -p pkg/api/rest
   vim pkg/api/rest/server.go
   vim pkg/api/rest/handlers.go
   ```

3. **Write tests**
   ```bash
   vim pkg/api/rest/handlers_test.go
   go test -v ./pkg/api/rest/...
   ```

4. **Integration test**
   ```bash
   make integration-test
   ```

5. **Commit & push**
   ```bash
   git add .
   git commit -m "feat: implement REST API"
   git push origin feature/rest-api
   ```

## Debugging

### Enable Debug Logging
```bash
export XKMS_SERVER_LOG_LEVEL=debug
./bin/xkmsd
```

### Test Individual Endpoints

**REST:**
```bash
curl -X POST http://localhost:8443/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{"key_id":"test","backend":"software","key_type":"rsa","key_size":2048}'
```

**gRPC:**
```bash
grpcurl -plaintext -d '{"key_id":"test","backend":"software","key_type":"rsa","key_size":2048}' \
  localhost:9443 xkms.v1.KeystoreService/GenerateKey
```

**MCP:**
```bash
echo '{"jsonrpc":"2.0","method":"health","id":1}' | nc localhost 9444
```

### Check Docker Services
```bash
docker-compose ps
docker-compose logs xkms-server
```

### Check Ports
```bash
netstat -tuln | grep -E '8443|9443|9444|9090'
```

## Performance Targets

| Operation | Target |
|-----------|--------|
| Key Generation (RSA 2048) | < 100ms |
| Signing (RSA 2048) | < 10ms |
| REST Request Overhead | < 5ms |
| gRPC Request Overhead | < 2ms |

## Metrics

```
xkms_key_generate_total{backend, key_type}
xkms_key_generate_duration_seconds{backend, key_type}
xkms_sign_total{backend}
xkms_http_requests_total{method, path, status}
xkms_grpc_requests_total{method, status}
```

## System Components

1. **Core Infrastructure:**
   - Config, Service, Middleware, Server

2. **Protocol Implementations:**
   - REST, gRPC, QUIC, MCP, CLI

3. **Security & Operations:**
   - Auth, TLS, Metrics, Logging

4. **Testing & Documentation:**
   - Integration tests, Benchmarks, Docs

## Common Issues

**Issue:** gRPC compilation errors
```bash
make proto-gen
go mod tidy
```

**Issue:** Integration tests failing
```bash
docker-compose ps
docker-compose restart
netstat -tuln | grep -E '8443|9443|9444'
```

**Issue:** TLS certificate errors
```bash
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout server.key -out server.crt -days 365 \
  -subj "/CN=localhost"
```

## Resources

### Documentation
- [server-architecture.md](./server-architecture.md) - Complete design
- [IMPLEMENTATION_GUIDE.md](./IMPLEMENTATION_GUIDE.md) - Step-by-step
- [API_SPECIFICATIONS.md](./API_SPECIFICATIONS.md) - API reference
- [README.md](./README.md) - Overview

### External
- [gRPC Go Tutorial](https://grpc.io/docs/languages/go/quickstart/)
- [HTTP/3 in Go](https://github.com/quic-go/quic-go)
- [Cobra CLI](https://cobra.dev/)
- [Viper Config](https://github.com/spf13/viper)


**Quick Start:** Follow [IMPLEMENTATION_GUIDE.md](./IMPLEMENTATION_GUIDE.md) to begin!
