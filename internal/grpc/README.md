# gRPC Server for go-keychain

Production-ready gRPC server implementation for the go-keychain library.

## Features

- **Multiple Backend Support**: Works with PKCS#8, PKCS#11, TPM 2.0, AWS KMS, GCP KMS, Azure Key Vault, and HashiCorp Vault
- **Full Key Lifecycle**: Generation, retrieval, listing, signing, verification, and deletion
- **Multiple Algorithms**: RSA (2048, 3072, 4096), ECDSA (P-256, P-384, P-521), Ed25519
- **Proper Error Handling**: Uses standard gRPC error codes (InvalidArgument, NotFound, Internal, etc.)
- **Interceptors**: Request logging, panic recovery, and error normalization
- **Thread-Safe**: All operations are safe for concurrent access
- **Health Checks**: Built-in health endpoint for monitoring

## Architecture

```
┌─────────────────┐
│  gRPC Clients   │
└────────┬────────┘
         │
    ┌────▼────┐
    │ Server  │ (port 9090)
    └────┬────┘
         │
    ┌────▼────────┐
    │  Service    │ (RPC handlers)
    └────┬────────┘
         │
    ┌────▼──────────┐
    │ BackendRegistry │
    └────┬───────────┘
         │
    ┌────▼───────┬──────────┬──────────┐
    │  pkcs8     │  pkcs11  │   tpm2   │ ...
    │ KeyStore   │ KeyStore │ KeyStore │
    └────────────┴──────────┴──────────┘
```

## Files

- `keychain.proto` - Protocol Buffers service definition
- `server.go` - gRPC server with interceptors
- `service.go` - RPC method implementations
- `manager.go` - Backend registry and management
- `doc.go` - Package documentation

## Usage

### Starting the Server

```bash
# Using the provided command
go run ./cmd/grpc-server --port 9090 --data-dir /var/lib/keychain

# Or build and run
go build -o grpc-server ./cmd/grpc-server
./grpc-server --port 9090
```

### Programmatic Usage

```go
import (
    grpcserver "github.com/jeremyhahn/go-keychain/internal/grpc"
    "github.com/jeremyhahn/go-keychain/pkg/backend/pkcs8"
    "github.com/jeremyhahn/go-keychain/pkg/keychain"
    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
)

// Create backend manager
manager := grpcserver.NewBackendRegistry()

// Register backends
keyStorage, _ := file.NewKeyStorage("/var/lib/keys")
certStorage, _ := file.NewCertStorage("/var/lib/certs")
backend, _ := pkcs8.NewBackend(&pkcs8.Config{KeyStorage: keyStorage})
keystore, _ := keychain.New(&keychain.Config{
    Backend:     backend,
    CertStorage: certStorage,
})
manager.Register("pkcs8", keystore)

// Create and start server
server, _ := grpcserver.NewServer(&grpcserver.ServerConfig{
    Port:           9090,
    Manager:        manager,
    EnableLogging:  true,
    EnableRecovery: true,
})

server.Start() // Blocks until stopped
```

### Client Example

```go
import (
    pb "github.com/jeremyhahn/go-keychain/api/proto/keychainv1"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
)

conn, _ := grpc.NewClient("localhost:9090",
    grpc.WithTransportCredentials(insecure.NewCredentials()))
defer conn.Close()

client := pb.NewKeystoreServiceClient(conn)

// Health check
resp, _ := client.Health(ctx, &pb.HealthRequest{})
fmt.Printf("Status: %s, Version: %s\n", resp.Status, resp.Version)

// List backends
backends, _ := client.ListBackends(ctx, &pb.ListBackendsRequest{})
for _, b := range backends.Backends {
    fmt.Printf("Backend: %s (%s)\n", b.Name, b.Type)
}

// Generate RSA key
key, _ := client.GenerateKey(ctx, &pb.GenerateKeyRequest{
    KeyId:   "my-rsa-key",
    Backend: "pkcs8",
    KeyType: "rsa",
    KeySize: 2048,
})

// Sign data
signature, _ := client.Sign(ctx, &pb.SignRequest{
    KeyId:   "my-rsa-key",
    Backend: "pkcs8",
    Data:    []byte("hello world"),
    Hash:    "SHA256",
})

// Verify signature
valid, _ := client.Verify(ctx, &pb.VerifyRequest{
    KeyId:     "my-rsa-key",
    Backend:   "pkcs8",
    Data:      []byte("hello world"),
    Signature: signature.Signature,
    Hash:      "SHA256",
})
```

## RPC Methods

### Health
Returns service health status and version.

**Request:** `HealthRequest{}`
**Response:** `HealthResponse{status, version}`

### ListBackends
Lists all registered backend providers.

**Request:** `ListBackendsRequest{}`
**Response:** `ListBackendsResponse{backends[], count}`

### GetBackendInfo
Gets detailed information about a specific backend.

**Request:** `GetBackendInfoRequest{name}`
**Response:** `GetBackendInfoResponse{backend}`

### GenerateKey
Generates a new cryptographic key.

**Request:** `GenerateKeyRequest{key_id, backend, key_type, key_size, curve, hash, partition}`
**Response:** `GenerateKeyResponse{key_id, backend, key_type, public_key_pem, created_at}`
**Errors:** `InvalidArgument`, `NotFound`, `Internal`

### ListKeys
Lists all keys in a backend with pagination.

**Request:** `ListKeysRequest{backend, partition, limit, offset}`
**Response:** `ListKeysResponse{keys[], total}`
**Errors:** `InvalidArgument`, `NotFound`, `Internal`

### GetKey
Retrieves information about a specific key.

**Request:** `GetKeyRequest{key_id, backend}`
**Response:** `GetKeyResponse{key}`
**Errors:** `InvalidArgument`, `NotFound`, `Internal`

### Sign
Signs data with a key.

**Request:** `SignRequest{key_id, backend, data, hash}`
**Response:** `SignResponse{signature}`
**Errors:** `InvalidArgument`, `NotFound`, `Internal`

### Verify
Verifies a signature.

**Request:** `VerifyRequest{key_id, backend, data, signature, hash}`
**Response:** `VerifyResponse{valid, message}`
**Errors:** `InvalidArgument`, `NotFound`, `Internal`

### DeleteKey
Deletes a key from the backend.

**Request:** `DeleteKeyRequest{key_id, backend}`
**Response:** `DeleteKeyResponse{success, message}`
**Errors:** `InvalidArgument`, `NotFound`, `Internal`

## Error Codes

The server uses standard gRPC status codes:

- `OK` (0) - Success
- `InvalidArgument` (3) - Invalid request parameters
- `NotFound` (5) - Backend or key not found
- `Internal` (13) - Internal server error

## Interceptors

### Logging Interceptor
Logs all RPC calls with method name, duration, status code, and errors.

```
gRPC: method=/keychain.v1.KeystoreService/GenerateKey duration=45ms code=OK error=<nil>
```

### Recovery Interceptor
Catches panics in RPC handlers and returns proper error responses.

### Error Handling Interceptor
Normalizes all errors to proper gRPC status errors.

## Testing

The server is tested via integration tests in `test/integration/api/grpc_test.go`:

```bash
# Run integration tests (requires Docker)
make integration-test
```

Tests cover:
- Health checks
- Backend listing and info
- Key generation (RSA, ECDSA, Ed25519)
- Key listing and retrieval
- Sign/verify operations
- Key deletion
- Error handling

## Port Configuration

Default port: **9090**

Change via:
- Command-line: `--port 9443`
- Config: `ServerConfig{Port: 9443}`
- Environment: Set in test config via `GRPC_ADDR`

## Security Notes

- This implementation uses insecure credentials for simplicity
- For production, use TLS with mutual authentication
- Implement proper authorization and authentication
- Consider rate limiting for public-facing deployments
- Audit log all key operations

## Performance

- Thread-safe concurrent request handling
- Read-write locks for backend access
- Efficient pagination for list operations
- Minimal allocations in hot paths

## Future Enhancements

- TLS/mTLS support
- Authentication and authorization
- Rate limiting
- Metrics and tracing
- Streaming operations for large keys
- Key import/export
- Batch operations
