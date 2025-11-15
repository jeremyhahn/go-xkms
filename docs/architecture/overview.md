# Architecture Overview

High-level system architecture and design patterns for go-keychain.

## System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Client Layer                          │
│  ┌──────┬──────┬──────┬──────┬──────────┐             │
│  │ CLI  │ REST │ gRPC │ QUIC │   MCP    │             │
│  └──────┴──────┴──────┴──────┴──────────┘             │
└─────────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│              Backend Registry                           │
│   Runtime Discovery & Factory Registration              │
└─────────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│                Keystore Layer                           │
│  ┌─────────┬─────────┬─────────┬─────────┐            │
│  │ PKCS#8  │  TPM2   │ PKCS#11 │  Cloud  │            │
│  └─────────┴─────────┴─────────┴─────────┘            │
└─────────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│             Storage Abstraction                         │
│  ┌─────────┬─────────┬──────────┬─────────┐           │
│  │  File   │ Memory  │ Database │ Custom  │           │
│  └─────────┴─────────┴──────────┴─────────┘           │
└─────────────────────────────────────────────────────────┘
```

## Component Relationships

### Backend Registry
- Thread-safe registration system
- Build tag-based conditional compilation
- Factory pattern for backend instantiation
- Runtime backend discovery

### Keystore Backends
- PKCS#8: Software keys (always available)
- TPM2: Hardware TPM (conditional)
- PKCS#11: HSM support (conditional)
- Cloud: AWS KMS, GCP KMS, Azure KV (conditional)

### Storage Abstraction
- Pluggable persistence layer
- File storage (production)
- Memory storage (testing)
- Custom implementations (database, cloud, etc.)

### Client Interfaces
- CLI: Command-line tool
- REST: HTTP/REST API
- gRPC: High-performance RPC
- QUIC: UDP-based multiplexed protocol
- MCP: Model Context Protocol

## Data Flow

```
Request: Generate Key
──────────────────────

1. Client Request
   CLI: keychain generate --key-id test
   │
   ▼
2. Backend Selection
   Registry → GetBackendInfo("pkcs8")
   │
   ▼
3. Backend Factory
   Factory creates PKCS#8 backend instance
   │
   ▼
4. Key Generation
   Backend generates cryptographic key
   │
   ▼
5. Storage Persistence
   Storage layer saves key material
   │
   ▼
6. Response
   Returns success + public key
```

## Directory Structure

```
go-keychain/
├── cmd/
│   ├── cgo/              # CGO shared library entry point
│   └── cli/              # CLI application (future)
├── pkg/
│   ├── backend/          # Backend interface definitions
│   ├── pkcs8/            # PKCS#8 backend (build tag: pkcs8)
│   ├── aes/              # AES backend (software symmetric)
│   ├── tpm2/             # TPM2 backend (build tag: tpm2)
│   ├── pkcs11/           # PKCS#11 backend (build tag: pkcs11)
│   ├── smartcardhsm/     # SmartCard-HSM backend (build tag: pkcs11)
│   ├── yubikey/          # YubiKey backend (build tag: pkcs11)
│   ├── awskms/           # AWS KMS (build tag: awskms)
│   ├── gcpkms/           # GCP KMS (build tag: gcpkms)
│   ├── azurekv/          # Azure KV (build tag: azurekv)
│   ├── vault/            # HashiCorp Vault (build tag: vault)
│   ├── keychain/         # Core keychain implementation
│   ├── storage/          # Storage abstraction
│   │   ├── file/         # File storage
│   │   └── memory/       # Memory storage
│   ├── signing/          # Signing utilities
│   ├── verification/     # Verification utilities
│   ├── certstore/        # Certificate store
│   └── encoding/         # Encoding utilities
├── test/
│   └── integration/      # Integration tests by backend
│       ├── pkcs8/        # PKCS#8 integration tests
│       ├── pkcs11/       # PKCS#11 integration tests
│       ├── tpm2/         # TPM2 integration tests
│       ├── awskms/       # AWS KMS integration tests
│       ├── gcpkms/       # GCP KMS integration tests
│       ├── azurekv/      # Azure KV integration tests
│       └── vault/        # Vault integration tests
├── docs/                 # Documentation
│   ├── architecture/     # Architecture docs
│   └── testing/          # Testing documentation
├── Makefile             # Build automation
├── VERSION              # Version file
└── README.md
```

## Design Patterns

### Registry Pattern

Factory-based backend registration:

```go
func init() {
    keychain.RegisterBackend(BackendInfo{
        Name:        "pkcs8",
        Type:        "software",
        Description: "PKCS#8 file-based keychain",
        Features:    []string{"rsa", "ecdsa", "ed25519"},
        Available:   true,
    })
}
```

### Strategy Pattern

Pluggable storage strategies:

```go
type Backend interface {
    Get(key string) ([]byte, error)
    Put(key string, data []byte) error
    Delete(key string) error
    List(prefix string) ([]string, error)
    Exists(key string) (bool, error)
    Close() error
}
```

### Adapter Pattern

PKCS#8 storage adapter:

```go
type StorageAdapter struct {
    storage storage.Backend
}

func (a *StorageAdapter) Get(attrs *KeyAttributes) ([]byte, error) {
    key := buildStorageKey(attrs)
    return a.storage.Get(key)
}
```

### Builder Pattern

Server configuration:

```go
config := server.NewConfig().
    WithHost("localhost").
    WithRESTPort(8443).
    WithGRPCPort(9443).
    Build()
```

## Build System

### Build Tags

```bash
# Backend tags
pkcs8     # PKCS#8 backend (default: included)
tpm2      # TPM2 backend
pkcs11    # PKCS#11 backend
awskms    # AWS KMS backend
gcpkms    # GCP KMS backend
azurekv   # Azure Key Vault backend

# Protocol tags
cli       # CLI interface
rest      # REST API
grpc      # gRPC API
quic      # QUIC protocol
mcp       # Model Context Protocol
```

### Makefile Targets

```bash
make build                  # Build shared library (default)
make lib                    # Build shared library
make test                   # Run unit tests (excludes hardware/cloud backends)
make integration-test       # Run all integration tests
make integration-test-pkcs8    # Run PKCS#8 integration tests
make integration-test-pkcs11   # Run PKCS#11/SoftHSM integration tests
make integration-test-tpm2     # Run TPM2 simulator integration tests
make integration-test-awskms   # Run AWS KMS/LocalStack integration tests
make integration-test-gcpkms   # Run GCP KMS integration tests
make integration-test-azurekv  # Run Azure Key Vault integration tests
make integration-test-vault    # Run HashiCorp Vault integration tests
make coverage               # Generate coverage report
make release                # Create GitHub release
```

## Concurrency Model

### Thread Safety

- **Backend Registry**: `sync.RWMutex` for registration map
- **Storage Backends**: Each implements own locking
- **PKCS#8**: `sync.RWMutex` for file operations
- **Memory Storage**: `sync.RWMutex` for map access

### Lock-Free Operations

Prefer atomic operations where possible:

```go
atomic.AddInt64(&metrics.RequestCount, 1)
atomic.LoadPointer(&config)
```

## Performance Characteristics

### Backend Performance
- **PKCS#8 Generation**: ~10ms (RSA-2048), ~1ms (ECDSA-P256)
- **PKCS#8 Signing**: ~0.5ms (RSA-2048), ~0.1ms (ECDSA-P256)
- **TPM2**: Hardware-dependent (~5-50ms)
- **Cloud**: Network latency-dependent (50-500ms)

### Storage Performance
- **File Storage**: ~1ms write, ~0.5ms read
- **Memory Storage**: ~10µs write, ~5µs read

## Security Architecture

### Defense in Depth

```
┌────────────────────────────────┐
│  Network Layer (TLS)           │  ← Transport encryption
├────────────────────────────────┤
│  Authentication Layer          │  ← Client verification
├────────────────────────────────┤
│  Authorization Layer           │  ← Access control
├────────────────────────────────┤
│  Keystore Layer                │  ← Key operations
├────────────────────────────────┤
│  Storage Layer (Encryption)    │  ← At-rest encryption
└────────────────────────────────┘
```

### Key Protection

- **PKCS#8**: Password-protected PKCS#8 encoding
- **TPM2**: Hardware-backed keys in TPM
- **PKCS#11**: Keys protected by HSM
- **Cloud**: Keys never leave cloud infrastructure

## Extensibility Points

### Custom Backends

Implement `KeyStore` interface:

```go
type CustomBackend struct{}

func (b *CustomBackend) GenerateKey(...) error { }
func (b *CustomBackend) Sign(...) ([]byte, error) { }
// ... implement all interface methods

func init() {
    keychain.RegisterBackend(BackendInfo{
        Name:        "custom",
        Type:        "custom",
        Description: "Custom backend",
        Features:    []string{"rsa"},
        Available:   true,
    })
}
```

### Custom Storage

Implement `storage.Backend` interface:

```go
type CustomStorage struct{}

func (s *CustomStorage) Get(key string) ([]byte, error) { }
func (s *CustomStorage) Put(key string, data []byte) error { }
// ... implement all interface methods
```

### Custom Protocols

Register protocol handler:

```go
//go:build custom

func init() {
    server.RegisterProtocol("custom", NewCustomProtocol)
}
```

## Configuration Precedence

1. Command-line flags (highest priority)
2. Environment variables
3. Configuration file
4. Default values (lowest priority)

## Testing Strategy

### Unit Tests
- Fast, in-memory execution
- Mock external dependencies
- 90%+ code coverage target
- No system modifications
- Run with: `make test`
- Current coverage: 74.9%

### Integration Tests
- Docker-based environment (per backend)
- Real service dependencies (LocalStack, SoftHSM, SWTPM)
- End-to-end workflows
- Organized in `test/integration/{backend}/`
- Run with: `make integration-test` or `make integration-test-{backend}`
- Total: 151 tests passing across 10 backends

## Deployment Architectures

### Standalone

```
┌──────────┐
│  Client  │
└────┬─────┘
     │
     ▼
┌──────────────────┐
│ Keystore Server  │
└──────────────────┘
```

### Distributed

```
┌──────┐  ┌──────┐  ┌──────┐
│Client│  │Client│  │Client│
└───┬──┘  └───┬──┘  └───┬──┘
    │         │         │
    └─────────┼─────────┘
              │
         ┌────▼────┐
         │Load Bal │
         └────┬────┘
              │
    ┌─────────┼─────────┐
    │         │         │
┌───▼───┐ ┌───▼───┐ ┌───▼───┐
│Server1│ │Server2│ │Server3│
└───┬───┘ └───┬───┘ └───┬───┘
    │         │         │
    └─────────┼─────────┘
              │
       ┌──────▼──────┐
       │   Storage   │
       └─────────────┘
```

## See Also

- [Backend Registry](../backend-registry.md)
- [Storage Abstraction](../storage-abstraction.md)
- [Build System](../build-system.md)
- [Getting Started](../getting-started.md)
