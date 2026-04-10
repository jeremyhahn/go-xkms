# Architecture Overview

High-level system architecture and design patterns for go-xkms.

## Three-Layer Dependency Architecture

go-xkms is part of a three-project stack with dependency inversion:

```
go-quicraft/pkg/seal/    Interfaces + memguard + minimal barrier (AES-GCM, epochs)
        ^
go-qrdb/pkg/seal/        ExtendedBarrier: Shamir, multi-tenant, storage wrapping, recovery
        ^
go-xkms/pkg/seal/        Hardware strategies: TPM2, PKCS#11, AWS/GCP/Azure KMS, Vault
```

- **Barrier**: go-xkms imports `ExtendedBarrier` from go-qrdb (which embeds go-quicraft's minimal barrier). go-xkms adds hardware `SealingStrategy` implementations.
- **Storage**: Canonical storage engines (file, memory, pebble, namespace) live in go-qrdb. go-xkms imports them directly and provides a thin QRDB networked adapter for distributed mode.

See [barrier-integration.md](barrier-integration.md) for details.

## System Architecture

```
+-----------------------------------------------------------+
|                   Client Layer                              |
|  +------+------+------+------+----------+                  |
|  | CLI  | REST | gRPC | QUIC |   MCP    |                  |
|  +------+------+------+------+----------+                  |
+-----------------------------------------------------------+
                        |
                        v
+-----------------------------------------------------------+
|              Backend Registry                               |
|   Runtime Discovery & Factory Registration                  |
+-----------------------------------------------------------+
                        |
                        v
+-----------------------------------------------------------+
|                Keystore Layer                                |
|  +---------+---------+---------+---------+                  |
|  |Software |  TPM2   | PKCS#11 |  Cloud  |                  |
|  +---------+---------+---------+---------+                  |
+-----------------------------------------------------------+
                        |
                        v
+-----------------------------------------------------------+
|             Storage Abstraction                              |
|  +---------+---------+---------+----------+---------+       |
|  |  File   | Memory  | PebbleDB|  QRDB   | Custom  |       |
|  +---------+---------+---------+----------+---------+       |
+-----------------------------------------------------------+
```

## Component Relationships

### Backend Registry
- Thread-safe registration system
- Build tag-based conditional compilation
- Factory pattern for backend instantiation
- Runtime backend discovery

### Keystore Backends (Full-Service)
Full-service backends supporting complete key lifecycle: generation, signing, verification, encryption, decryption, certificate management, and sealing.

- **Software**: Software keys using PKCS#8 encoding (always available)
- **TPM2**: Hardware TPM (conditional)
- **PKCS#11**: HSM support (conditional)
- **Cloud**: AWS KMS, GCP KMS, Azure KV (conditional)
- **Vault**: HashiCorp Vault (conditional)
- **Phone**: Phone-based key storage (conditional)

### Key Providers (Partial)
Key providers support key generation and limited cryptographic operations. They are composed into backends for specialized functionality and live at `pkg/keyprovider/`:

- **PKCS#8**: Asymmetric key generation and storage (composed into Software backend)
- **Symmetric**: Symmetric encryption (AES, ChaCha20) key generation
- **Quantum**: Post-quantum cryptography (Dilithium2, Kyber768)
- **FROST**: Threshold signature scheme
- **Threshold**: Generic threshold key splitting and recovery

### Storage Abstraction
- Pluggable persistence layer
- File storage (production)
- Memory storage (testing)
- PebbleDB storage via go-qrdb engine (high-performance production)
- QRDB networked adapter (distributed mode)
- Custom implementations (database, cloud, etc.)

### Client Interfaces
- CLI: Command-line tool
- REST: HTTP/REST API
- gRPC: High-performance RPC
- QUIC: UDP-based multiplexed protocol
- MCP: Model Context Protocol
- Embedded: In-process via `XKMSService` implementing `XKMSServicer`

## Backend vs KeyProvider Distinction

### Backends (Full-Service)
Backends provide complete key lifecycle management and are registered in `XKMSService.Backends()`:

| Backend | Generation | Sign/Verify | Encrypt/Decrypt | Certificates | Seal/Unseal | SecurityLevel |
|---------|-----------|------------|-----------------|--------------|------------|---------------|
| Software | Yes | Yes | Yes | Yes | Yes | Low (0) |
| TPM2 | Yes | Yes | Yes | Yes | Yes | VeryHigh (3) |
| PKCS#11 | Yes | Yes | Yes | Yes | Yes | High (2) |
| AWS KMS | Yes | Yes | Yes | Yes | Yes | Medium (1) |
| GCP KMS | Yes | Yes | Yes | Yes | Yes | Medium (1) |
| Azure KV | Yes | Yes | Yes | Yes | Yes | Medium (1) |
| Vault | Yes | Yes | Yes | Yes | Yes | Medium (1) |
| Phone | Yes | Yes | Limited | Yes | Yes | High (2) |

### KeyProviders (Partial)
KeyProviders support key generation and limited cryptographic operations. They are accessed via `XKMSService.KeyProviders()` and retrieved individually via `XKMSService.GetKeyProvider(name)`. They can be composed into backends for specialized algorithms:

| Provider | Generation | Sign/Verify | Encrypt/Decrypt | Composition |
|----------|-----------|------------|-----------------|------------|
| PKCS#8 | Yes | Yes | No | Composed into Software backend |
| Symmetric | Yes | No | Yes | Composed into Software backend |
| Quantum | Yes | Yes | Limited | Standalone or composed |
| FROST | Yes | Yes | No | Standalone threshold signing |
| Threshold | Yes | No | No | Key splitting/recovery |

KeyProviders live in `pkg/keyprovider/` and implement specialized cryptographic schemes without full backend functionality. They allow applications to leverage specific algorithms while keeping backends clean and focused.

### XKMSService -- Full XKMSServicer Implementation

The `XKMSService` in `pkg/xkms/service.go` implements the complete `XKMSServicer` interface (15+ sub-interfaces, 106 methods). Each sub-interface is implemented in a dedicated file following the `servicer_*.go` naming convention:

| File | Sub-interface | Delegates to |
|---|---|---|
| `servicer_health.go` | HealthServicer | Version info |
| `servicer_backend.go` | BackendServicer | `s.backends` and `s.keyProviders` maps |
| `servicer_key.go` | KeyServicer | Backend key operations |
| `servicer_crypto.go` | CryptoServicer | Backend signers/encrypters |
| `servicer_cert.go` | CertServicer | Backend cert methods |
| `servicer_seal.go` | SealServicer | Backend seal/unseal |
| `servicer_barrier.go` | BarrierServicer | `s.barrier` |
| `servicer_piv.go` | PIVServicer | PIV manager |
| `servicer_fido2.go` | FIDO2Servicer | `s.webauthnService` |
| `servicer_ca.go` | CAServicer | `s.ca` |
| `servicer_pin.go` | PINServicer | `s.pinManager` (delegates to `pin.PINBackend`) |
| `servicer_user.go` | UserServicer | `s.userStore` |
| `servicer_password.go` | PasswordServicer | `s.passwordStore` |
| `servicer_platform.go` | PlatformStoreServicer | `s.platformStore` |
| `servicer_policy.go` | PolicyServicer | `s.policyManager` |

Subsystem references are set via setter methods (e.g., `SetBarrier()`, `SetPINManager()`) after initialization, since subsystems are created after `xkms.Initialize()` in the server startup sequence. Unconfigured subsystems return `ErrNotConfigured`.

This design enables the embedded SDK transport (`sdk.NewEmbedded(svc)`) to work with the full service in-process, without network overhead.

## Data Flow

```
Request: Generate Key
----------------------

1. Client Request
   CLI: xkmsctl generate --key-id test
   |
   v
2. Backend Selection
   Registry -> GetBackendInfo("software")
   |
   v
3. Backend Factory
   Factory creates software backend instance
   |
   v
4. Key Generation
   Backend generates cryptographic key
   |
   v
5. Storage Persistence
   Storage layer saves key material
   |
   v
6. Response
   Returns success + public key
```

## Directory Structure

```
go-xkms/
+-- cmd/
|   +-- cgo/              # CGO shared library entry point
|   +-- cli/              # CLI application (future)
+-- pkg/
|   +-- backend/          # Full-service backend interface definitions
|   |   +-- software/     # Unified software backend
|   |   +-- tpm2/         # TPM2 backend (build tag: tpm2)
|   |   +-- pkcs11/       # PKCS#11 backend (build tag: pkcs11)
|   |   +-- awskms/       # AWS KMS backend (build tag: awskms)
|   |   +-- gcpkms/       # GCP KMS backend (build tag: gcpkms)
|   |   +-- azurekv/      # Azure KV backend (build tag: azurekv)
|   |   +-- vault/        # HashiCorp Vault backend (build tag: vault)
|   |   +-- phone/        # Phone backend (build tag: phone)
|   +-- keyprovider/      # Partial key providers (key gen + limited ops)
|   |   +-- pkcs8/        # Asymmetric key provider
|   |   +-- symmetric/    # Symmetric encryption provider
|   |   +-- quantum/      # Post-quantum cryptography provider
|   |   +-- frost/        # Threshold signature provider
|   |   +-- threshold/    # Generic threshold provider
|   +-- xkms/             # Core xkms implementation
|   +-- storage/          # Storage abstraction
|   |   +-- file/         # File storage
|   |   +-- qrdb/         # QRDB networked adapter
|   +-- signing/          # Signing utilities
|   +-- verification/     # Verification utilities
|   +-- certstore/        # Certificate store
|   +-- encoding/         # Encoding utilities
+-- test/
|   +-- integration/      # Integration tests by backend
|       +-- backend/      # Full-service backend tests
|       +-- keyprovider/  # Key provider tests
|       +-- tpm2/         # TPM2 integration tests
|       +-- pkcs11/       # PKCS#11 integration tests
|       +-- awskms/       # AWS KMS integration tests
|       +-- gcpkms/       # GCP KMS integration tests
|       +-- azurekv/      # Azure KV integration tests
|       +-- vault/        # Vault integration tests
+-- docs/                 # Documentation
|   +-- architecture/     # Architecture docs
|   +-- testing/          # Testing documentation
+-- Makefile             # Build automation
+-- VERSION              # Version file
+-- README.md
```

## Design Patterns

### Registry Pattern

Factory-based backend registration:

```go
func init() {
    xkms.RegisterBackend(BackendInfo{
        Name:        "software",
        Type:        "software",
        Description: "Software file-based xkms",
        Features:    []string{"rsa", "ecdsa", "ed25519"},
        Available:   true,
    })
}
```

### Strategy Pattern

Pluggable storage strategies:

```go
type Backend interface {
    Get(ctx context.Context, key string) ([]byte, error)
    Put(ctx context.Context, key string, value []byte) error
    Delete(ctx context.Context, key string) error
    List(ctx context.Context, prefix string) ([]string, error)
    Scan(ctx context.Context, prefix string) (map[string][]byte, error)
    Exists(ctx context.Context, key string) (bool, error)
    Close() error
}
```

### Adapter Pattern

Software storage adapter:

```go
type StorageAdapter struct {
    storage storage.Backend
}

func (a *StorageAdapter) Get(ctx context.Context, attrs *KeyAttributes) ([]byte, error) {
    key := buildStorageKey(attrs)
    return a.storage.Get(ctx, key)
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
software  # Software backend (default: included)
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
make integration-test-software # Run software backend integration tests
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
- **Software/PKCS#8**: `sync.RWMutex` for file operations
- **Memory Storage**: `sync.RWMutex` for map access

### Lock-Free Operations

Prefer atomic operations where possible:

```go
atomic.AddInt64(&metrics.RequestCount, 1)
atomic.LoadPointer(&config)
```

## Performance Characteristics

### Backend Performance
- **Software Generation**: ~10ms (RSA-2048), ~1ms (ECDSA-P256)
- **Software Signing**: ~0.5ms (RSA-2048), ~0.1ms (ECDSA-P256)
- **TPM2**: Hardware-dependent (~5-50ms)
- **Cloud**: Network latency-dependent (50-500ms)

### Storage Performance
- **File Storage**: ~1ms write, ~0.5ms read
- **Memory Storage**: ~10us write, ~5us read
- **PebbleDB Storage**: ~0.2ms write, ~0.05ms read

## Security Architecture

### Defense in Depth

```
+--------------------------------+
|  Network Layer (TLS)           |  <- Transport encryption
+--------------------------------+
|  Authentication Layer          |  <- Client verification
+--------------------------------+
|  Authorization Layer           |  <- Access control
+--------------------------------+
|  Keystore Layer                |  <- Key operations
+--------------------------------+
|  Storage Layer (Encryption)    |  <- At-rest encryption
+--------------------------------+
```

### Key Protection

- **Software**: Password-protected PKCS#8 encoding
- **TPM2**: Hardware-backed keys in TPM
- **PKCS#11**: Keys protected by HSM
- **Cloud**: Keys never leave cloud infrastructure

### Security Levels

Each backend is assigned a `SecurityLevel` value (0-3) indicating key protection strength. This enables UIs to sort backends by security preference and recommend the most secure available option.

| Level | Value | Backends | Description |
|-------|-------|----------|-------------|
| VeryHigh | 3 | TPM 2.0 | Hardware-bound, non-exportable, attestable |
| High | 2 | PKCS#11, Phone | HSM-protected, local hardware control |
| Medium | 1 | AWS/GCP/Azure KMS, Vault | Cloud-managed, network-dependent HSMs |
| Low | 0 | Software | File-based, software-protected encryption |

Access via `Capabilities`:

```go
caps := backend.Capabilities()
level := caps.GetSecurityLevel() // types.SecurityLevel (0-3)
```

See [Security Levels](./security-levels.md) for detailed documentation.

## Extensibility Points

### Custom Backends

Implement full `Backend` interface for complete key lifecycle support:

```go
type CustomBackend struct{}

func (b *CustomBackend) GenerateKey(...) error { }
func (b *CustomBackend) Sign(...) ([]byte, error) { }
func (b *CustomBackend) Verify(...) (bool, error) { }
func (b *CustomBackend) Encrypt(...) ([]byte, error) { }
func (b *CustomBackend) Decrypt(...) ([]byte, error) { }
func (b *CustomBackend) SaveCert(...) error { }
func (b *CustomBackend) Seal(...) ([]byte, error) { }
func (b *CustomBackend) Unseal(...) ([]byte, error) { }
// ... implement all interface methods
```

### Custom KeyProviders

Implement `KeyProvider` interface for specialized algorithms:

```go
type CustomProvider struct{}

func (p *CustomProvider) GenerateKey(...) error { }
func (p *CustomProvider) Sign(...) ([]byte, error) { }
// ... implement supported operations

func init() {
    keyprovider.Register("custom", NewCustomProvider())
}
```

### Custom Storage

Implement `storage.Backend` interface:

```go
type CustomStorage struct{}

func (s *CustomStorage) Get(ctx context.Context, key string) ([]byte, error) { }
func (s *CustomStorage) Put(ctx context.Context, key string, value []byte) error { }
func (s *CustomStorage) Scan(ctx context.Context, prefix string) (map[string][]byte, error) { }
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
+----------+
|  Client  |
+----+-----+
     |
     v
+------------------+
| Keystore Server  |
+------------------+
```

### Distributed

```
+------+  +------+  +------+
|Client|  |Client|  |Client|
+---+--+  +---+--+  +---+--+
    |         |         |
    +---------+---------+
              |
         +----v----+
         |Load Bal |
         +----+----+
              |
    +---------+---------+
    |         |         |
+---v---+ +---v---+ +---v---+
|Server1| |Server2| |Server3|
+---+---+ +---+---+ +---+---+
    |         |         |
    +---------+---------+
              |
       +------v------+
       |   Storage   |
       +-------------+
```

## See Also

- [Security Levels](./security-levels.md)
- [Backend Registry](../backend-registry.md)
- [Storage Abstraction](../storage-abstraction.md)
- [Build System](../build-system.md)
- [Getting Started](../getting-started.md)
- [PKCS#11 Manager](../pkcs11/manager.md)
