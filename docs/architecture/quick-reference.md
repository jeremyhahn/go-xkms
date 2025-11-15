# Go-Keychain Server - Quick Reference Card

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
├── server/        # Server binary
└── cli/           # CLI binary

internal/
├── server/        # Orchestration
├── config/        # Configuration
├── service/       # Business logic
├── rest/          # REST API
├── grpc/          # gRPC
├── mcp/           # MCP
├── quic/          # QUIC
└── cli/           # CLI

api/
├── proto/         # Protocol Buffers
└── openapi/       # OpenAPI specs
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
    Get(name) (keychain.KeyStore, error)
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
GET    /api/v1/keys?backend=pkcs8
GET    /api/v1/keys/{id}?backend=pkcs8
DELETE /api/v1/keys/{id}?backend=pkcs8
POST   /api/v1/keys/{id}/sign?backend=pkcs8
POST   /api/v1/keys/{id}/verify?backend=pkcs8
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
keychain.listBackends
keychain.generateKey
keychain.getKey
keychain.listKeys
keychain.deleteKey
keychain.sign
keychain.verify
keychain.subscribe
```

### CLI
```bash
keychain version
keychain backends list
keychain backends info <name>
keychain key generate <id> --backend <name> --key-type <type>
keychain key list --backend <name>
keychain key get <id> --backend <name>
keychain key delete <id> --backend <name>
keychain key sign <id> <data> --backend <name> --hash <alg>
keychain key verify <id> <data> --signature <sig> --backend <name>
```

## Configuration

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
    ks keychain.KeyStore,
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
go test -v ./internal/config/...
go test -v ./internal/service/...
go test -cover ./internal/...
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
go test -bench=. -benchmem ./internal/...
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
./bin/keychain-server --config config.yaml

# CLI
./bin/keychain key generate my-key --backend pkcs8 --key-type rsa
```

### Docker
```bash
docker-compose up -d
docker-compose ps
docker-compose logs -f keychain-server
```

## Development Workflow

1. **Create feature branch**
   ```bash
   git checkout -b feature/rest-api
   ```

2. **Implement component**
   ```bash
   mkdir -p internal/rest/handlers
   vim internal/rest/server.go
   vim internal/rest/handlers/keys.go
   ```

3. **Write tests**
   ```bash
   vim internal/rest/handlers/keys_test.go
   go test -v ./internal/rest/...
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
export KEYCHAIN_SERVER_LOG_LEVEL=debug
./bin/keychain-server
```

### Test Individual Endpoints

**REST:**
```bash
curl -X POST http://localhost:8443/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{"key_id":"test","backend":"pkcs8","key_type":"rsa","key_size":2048}'
```

**gRPC:**
```bash
grpcurl -plaintext -d '{"key_id":"test","backend":"pkcs8","key_type":"rsa","key_size":2048}' \
  localhost:9443 keychain.v1.KeystoreService/GenerateKey
```

**MCP:**
```bash
echo '{"jsonrpc":"2.0","method":"health","id":1}' | nc localhost 9444
```

### Check Docker Services
```bash
docker-compose ps
docker-compose logs keychain-server
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
keychain_key_generate_total{backend, key_type}
keychain_key_generate_duration_seconds{backend, key_type}
keychain_sign_total{backend}
keychain_http_requests_total{method, path, status}
keychain_grpc_requests_total{method, status}
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
