# Go-xKMS Server - Quick Reference Card

**One-page reference for developers**


## Architecture at a Glance

```
Client → Protocol Handler → Service Layer → KeyStore → Backend
```

## Ports

`xkmsd` has no port flags and no built-in port defaults -- it binds exactly what
the YAML names (`cmd/xkmsd/main.go:67-74`). The "shipped default" column is what
`configs/*.yaml` sets, which is what a stock daemon actually binds. The
"library fallback" column is what the API server packages substitute when they
are embedded with a zero port, and it is not the same number for MCP.

| Protocol | Shipped default (`configs/*.yaml`) | Library fallback | TLS Required |
|----------|------------------------------------|------------------|--------------|
| REST     | 8443 (`rest_port`)  | 8443 (`pkg/api/rest/server.go:311`) | Yes |
| gRPC     | 9443 (`grpc_port`)  | none | Yes |
| QUIC     | 8444 (`quic_port`)  | 8444 (`pkg/api/quic/server.go:119`) | Yes (1.3) |
| MCP      | 8445 (`mcp_port`)   | 9444 (`pkg/api/mcp/server.go:178`) | No (TCP) |
| Noise    | 8447 (`noise_port`, `configs/xkmsd-local.yaml:10`) | 8445 (`DefaultNoisePort`, `pkg/trust/bootstrap/bootstrap.go:98`) | Noise_NK |
| Metrics  | 9090 (`metrics.port`) | none | No |

MCP is the one to watch: the shipped configurations bind it on 8445, but the SDK
client dials `localhost:9444` by default (`sdk/go/options.go:33`). Point the
client at the configured port or change `mcp_port` to 9444.

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

Ports live under `server:` as `*_port` integers and protocols are switched on
under `protocols:` -- there are no top-level `rest:` / `grpc:` / `mcp:` / `quic:`
sections and no `address:` keys (`pkg/config/config.go:198-217`). Compare
`configs/xkmsd.yaml`.

```yaml
server:
  host: "0.0.0.0"
  rest_port: 8443
  grpc_port: 9443
  quic_port: 8444
  mcp_port: 8445

protocols:
  unix: true
  rest: true
  grpc: true
  quic: true
  mcp: true

auth:
  enabled: true
  type: adaptive  # noop|none, mtls, jwt, adaptive, composite -- there is no oidc type
  # Adaptive escalates to JWT once the first user exists, so a JWT
  # verification key is required; startup fails without it.
  jwt:
    public_key_file: /etc/xkms/jwt-public.pem

metrics:
  enabled: true
  path: /metrics
  port: 9090

# backends is a map keyed by backend name, not a list
backends:
  software:
    enabled: true
    path: "xkms-data/keys/software"
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
# mcp_port is 8445 in the shipped configs; the SDK client default is 9444
echo '{"jsonrpc":"2.0","method":"health","id":1}' | nc localhost 8445
```

### Check Docker Services
```bash
docker-compose ps
docker-compose logs xkms-server
```

### Check Ports
```bash
netstat -tuln | grep -E '8443|9443|8444|8445|9090'
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
netstat -tuln | grep -E '8443|9443|8444|8445'
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
- [overview.md](./overview.md) - System architecture and design philosophy
- [api-specifications.md](./api-specifications.md) - API reference
- [../configuration/build-system.md](../configuration/build-system.md) - Build tags and compilation options
- [README.md](./README.md) - Overview

### External
- [gRPC Go Tutorial](https://grpc.io/docs/languages/go/quickstart/)
- [HTTP/3 in Go](https://github.com/quic-go/quic-go)
- [Cobra CLI](https://cobra.dev/)
- [Viper Config](https://github.com/spf13/viper)


**Quick Start:** Follow the [Getting Started guide](../../xkey/docs/usage/getting-started.md) to begin.
