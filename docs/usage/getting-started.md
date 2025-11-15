# Getting Started with go-keychain

## Overview

go-keychain is a comprehensive cryptographic key management library for Go that provides a unified interface across multiple storage backends. Whether you need software-based key storage for development, hardware security modules for production, or cloud-based key management for scalability, go-keychain offers a consistent API while leveraging the security features of each backend.

This guide will help you choose the right backend for your use case and get started quickly with practical examples.

## Installation

```bash
go get github.com/jeremyhahn/go-keychain
```

## Build Configuration

go-keychain uses build tags to enable conditional compilation of cryptographic backends. By default, **only PKCS#8 software backend is enabled**. You can selectively enable additional backends by setting their corresponding variables to 1.

### Default Build

```bash
# Builds with PKCS#8 only (default, minimal build)
go build ./...

# Or using Make
make build
```

### Enabling Backends

Use Makefile variables to enable specific backends:

```bash
# Build with PKCS#11 HSM support
make build WITH_PKCS11=1

# Build with software and hardware backends
make build WITH_PKCS11=1 WITH_TPM2=1

# Build with cloud providers
make build WITH_AWS_KMS=1 WITH_GCP_KMS=1 WITH_AZURE_KV=1

# Build with all backends
make build WITH_PKCS11=1 WITH_TPM2=1 WITH_AWS_KMS=1 WITH_GCP_KMS=1 WITH_AZURE_KV=1 WITH_VAULT=1
```

### Using Build Tags Directly

You can also use Go build tags directly:

```bash
# Build with all backends (default)
go build -tags "pkcs8 tpm2 awskms gcpkms azurekv pkcs11" ./...

# Build with only specific backends
go build -tags "pkcs8 awskms" ./...

# Run tests with specific backends
go test -tags "pkcs8 tpm2" ./...
```

### Backend Build Tags

| Backend | Build Tag | Default | Makefile Variable |
|---------|-----------|---------|-------------------|
| PKCS#8 | `pkcs8` | Enabled | WITH_PKCS8=1 |
| TPM2 | `tpm2` | Disabled | WITH_TPM2=0 |
| AWS KMS | `awskms` | Disabled | WITH_AWS_KMS=0 |
| GCP KMS | `gcpkms` | Disabled | WITH_GCP_KMS=0 |
| Azure Key Vault | `azurekv` | Disabled | WITH_AZURE_KV=0 |
| HashiCorp Vault | `vault` | Disabled | WITH_VAULT=0 |
| PKCS#11 | `pkcs11` | Disabled | WITH_PKCS11=0 |

### Why Use Build Tags?

- **Reduced Binary Size**: Exclude backends you don't need
- **Faster Compilation**: Skip unused dependencies
- **Simplified Deployment**: Avoid cloud SDK dependencies for on-premise deployments
- **Security**: Minimize attack surface by excluding unused code

### Example: Cloud-Only Build

```bash
# Build for AWS deployment only (includes PKCS#8 and AWS KMS)
make build WITH_AWS_KMS=1
```

### Example: On-Premise Build

```bash
# Build for on-premise with hardware backends
make build WITH_PKCS11=1 WITH_TPM2=1
```

## Quick Start

### Basic Example

```go
package main

import (
    "context"
    "crypto"
    "crypto/sha256"
    "fmt"
    "log"

    "github.com/jeremyhahn/go-keychain/pkg/backend"
    "github.com/jeremyhahn/go-keychain/pkg/backend/pkcs8"
)

func main() {
    ctx := context.Background()

    // Initialize PKCS#8 backend for development
    config := &pkcs8.Config{
        StoragePath: "./keys",
        Password:    "secure-password",
    }

    store, err := pkcs8.NewBackend(config)
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close(ctx)

    // Generate a key
    params := &backend.KeyParams{
        Algorithm: backend.AlgorithmRSA,
        KeySize:   2048,
    }

    if err := store.GenerateKey(ctx, "my-first-key", params); err != nil {
        log.Fatal(err)
    }

    // Sign some data
    data := []byte("Hello, go-keychain!")
    hash := sha256.Sum256(data)

    signature, err := store.Sign(ctx, "my-first-key", hash[:], crypto.SHA256)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Signature: %x\n", signature)
}
```

## Choosing a Backend

### Decision Tree

```
┌─────────────────────────────────┐
│ What is your primary use case? │
└────────────┬────────────────────┘
             │
    ┌────────┴────────┐
    │                 │
    ▼                 ▼
Development/     Production
Testing          Workload
    │                 │
    ▼                 ▼
PKCS#8          Security Level?
                     │
         ┌───────────┼────────────┐
         │           │            │
         ▼           ▼            ▼
    Software    Moderate      High
    Based       Security    Security
         │           │            │
         ▼           ▼            ▼
    PKCS#8        TPM2       PKCS#11
                            Cloud HSM
                            (AWS/GCP/Azure)
```

### Backend Comparison Matrix

| Feature | PKCS#8 | TPM2 | PKCS#11 | AWS KMS | GCP KMS | Azure KV |
|---------|--------|------|---------|---------|---------|----------|
| **Security Level** | Software | Hardware | Hardware | Cloud HSM | Cloud HSM | Cloud HSM |
| **FIPS 140-2** | No | Level 2 | Level 2/3 | Level 2 | Level 3 | Level 2/3 |
| **Key Export** | Yes | No | No | No | No | No |
| **Offline Use** | Yes | Yes | Yes | No | No | No |
| **Cost** | Free | Free | Varies | $1/key/mo | €0.06/key/mo | $1/key/mo |
| **Setup Complexity** | Low | Medium | High | Low | Low | Low |
| **Performance** | Fastest | Fast | Fast | Network | Network | Network |
| **Best For** | Dev/Test | Edge/IoT | Enterprise | AWS Cloud | GCP Cloud | Azure Cloud |

## Backend Overview

### PKCS#8 - Software-Based Storage

**When to use:**
- Development and testing
- CI/CD pipelines
- Low-security requirements
- Offline operation needed

**Pros:**
- No dependencies
- Fast operations
- Easy setup
- Portable across systems

**Cons:**
- Software-based security only
- No hardware protection
- Not suitable for production

**Quick Setup:**
```go
config := &pkcs8.Config{
    StoragePath: "./keys",
    Password:    os.Getenv("KEYSTORE_PASSWORD"),
    Iterations:  100000,
}
store, err := pkcs8.NewBackend(config)
```

**Learn More:** [PKCS#8 Documentation](backends/pkcs8.md)

### TPM 2.0 - Hardware-Backed On-Premise

**When to use:**
- Edge devices with TPM chips
- IoT deployments
- On-premise servers
- Air-gapped environments

**Pros:**
- Hardware-backed security
- Keys never leave TPM
- No recurring costs
- FIPS 140-2 Level 2

**Cons:**
- Requires TPM hardware
- Platform-specific
- Slower than software
- No Ed25519 support

**Quick Setup:**
```go
config := &tpm2.Config{
    CN:         "my-keychain",
    DevicePath: "/dev/tpmrm0",
    SRKHandle:  0x81000001,
}
store, err := tpm2.NewBackend(config, backend)
```

**Learn More:** [TPM2 Documentation](backends/tpm2.md)

### PKCS#11 - Enterprise HSM

**When to use:**
- Enterprise data centers
- Regulatory compliance (PCI DSS, HIPAA)
- Certificate authorities
- High-security applications

**Pros:**
- Vendor flexibility
- FIPS 140-2 Level 2/3
- Industry standard
- Mature ecosystem

**Cons:**
- Complex setup
- Vendor-specific quirks
- Licensing costs
- Requires HSM hardware

**Quick Setup:**
```go
config := &pkcs11.Config{
    LibraryPath: "/usr/lib/softhsm/libsofthsm2.so",
    TokenLabel:  "my-token",
    PIN:         os.Getenv("HSM_PIN"),
}
store, err := pkcs11.NewBackend(config)
```

**Learn More:** [PKCS#11 Documentation](backends/pkcs11.md)

### AWS KMS - Amazon Cloud HSM

**When to use:**
- AWS-hosted applications
- Multi-region deployments
- Scalable cloud workloads
- AWS service integration

**Pros:**
- Fully managed service
- Automatic scaling
- Multi-region support
- IAM integration

**Cons:**
- AWS vendor lock-in
- Recurring costs
- Internet connectivity required
- API rate limits

**Quick Setup:**
```go
config := &awskms.Config{
    Region: "us-east-1",
    // Uses IAM role automatically
}
store, err := awskms.NewBackend(config)
```

**Learn More:** [AWS KMS Documentation](backends/awskms.md)

### GCP KMS - Google Cloud HSM

**When to use:**
- GCP-hosted applications
- Global deployments
- Google service integration
- FIPS 140-2 Level 3 required

**Pros:**
- FIPS 140-2 Level 3
- Global availability
- Automatic replication
- GCP service integration

**Cons:**
- GCP vendor lock-in
- Recurring costs
- Internet connectivity required
- Limited to supported algorithms

**Quick Setup:**
```go
config := &gcpkms.Config{
    ProjectID: "my-project",
    Location:  "us-central1",
    KeyRing:   "production",
}
store, err := gcpkms.NewBackend(config)
```

**Learn More:** [GCP KMS Documentation](backends/gcpkms.md)

### Azure Key Vault - Microsoft Cloud HSM

**When to use:**
- Azure-hosted applications
- Microsoft ecosystem integration
- Managed HSM requirements
- Azure service integration

**Pros:**
- Managed service
- Managed HSM option (FIPS 140-2 Level 3)
- RBAC integration
- Hybrid cloud support

**Cons:**
- Azure vendor lock-in
- Recurring costs
- Internet connectivity required
- Complex permission model

**Quick Setup:**
```go
config := &azurekv.Config{
    VaultURL:           "https://my-vault.vault.azure.net/",
    UseManagedIdentity: true,
}
store, err := azurekv.NewBackend(config)
```

**Learn More:** [Azure Key Vault Documentation](backends/azurekv.md)

## Common Use Cases

### Development Environment

Use PKCS#8 for local development:

```go
func newDevKeyStore() (backend.Backend, error) {
    config := &pkcs8.Config{
        StoragePath: "./dev-keys",
        Password:    "dev-password", // Use environment variable in practice
    }
    return pkcs8.NewBackend(config)
}
```

### Production Application (Cloud)

Use cloud KMS for production applications:

```go
func newProdKeyStore() (backend.Backend, error) {
    switch os.Getenv("CLOUD_PROVIDER") {
    case "aws":
        config := &awskms.Config{
            Region: os.Getenv("AWS_REGION"),
        }
        return awskms.NewBackend(config)

    case "gcp":
        config := &gcpkms.Config{
            ProjectID: os.Getenv("GCP_PROJECT_ID"),
            Location:  os.Getenv("GCP_LOCATION"),
            KeyRing:   os.Getenv("GCP_KEYRING"),
        }
        return gcpkms.NewBackend(config)

    case "azure":
        config := &azurekv.Config{
            VaultURL:           os.Getenv("AZURE_VAULT_URL"),
            UseManagedIdentity: true,
        }
        return azurekv.NewBackend(config)

    default:
        return nil, fmt.Errorf("unsupported cloud provider")
    }
}
```

### Edge Device / IoT

Use TPM2 for edge deployments:

```go
func newEdgeKeyStore() (backend.Backend, error) {
    keyStorage, _ := file.New(&storage.Options{
        Path: "/var/lib/keychain/keys",
    })
    certStorage, _ := file.New(&storage.Options{
        Path: "/var/lib/keychain/certs",
    })

    config := tpm2.DefaultConfig()
    config.CN = "edge-device"
    config.DevicePath = "/dev/tpmrm0"

    return tpm2.NewTPM2KeyStore(config, fileBackend)
}
```

### Enterprise PKI / CA

Use PKCS#11 for certificate authority:

```go
func newCAKeyStore() (backend.Backend, error) {
    config := &pkcs11.Config{
        LibraryPath: "/opt/nfast/toolkits/pkcs11/libcknfast.so", // Thales HSM
        SlotID:      1,
        PIN:         loadPINFromVault(),
    }
    return pkcs11.NewBackend(config)
}
```

## Multi-Backend Architecture

### Environment-Based Selection

```go
type KeyStoreFactory struct{}

func (f *KeyStoreFactory) NewBackend(env string) (backend.Backend, error) {
    switch env {
    case "development":
        return f.newDevBackend()
    case "staging":
        return f.newStagingBackend()
    case "production":
        return f.newProdBackend()
    default:
        return nil, fmt.Errorf("unknown environment: %s", env)
    }
}

func (f *KeyStoreFactory) newDevBackend() (backend.Backend, error) {
    config := &pkcs8.Config{
        StoragePath: "./keys",
        Password:    "dev-password",
    }
    return pkcs8.NewBackend(config)
}

func (f *KeyStoreFactory) newStagingBackend() (backend.Backend, error) {
    config := &awskms.Config{
        Region: "us-east-1",
    }
    return awskms.NewBackend(config)
}

func (f *KeyStoreFactory) newProdBackend() (backend.Backend, error) {
    config := &awskms.Config{
        Region: "us-east-1",
    }
    return awskms.NewBackend(config)
}
```

### Hybrid Deployments

```go
type HybridKeyStore struct {
    primary   backend.Backend
    fallback  backend.Backend
}

func NewHybridKeyStore() (*HybridKeyStore, error) {
    // Primary: Cloud KMS for most operations
    primary, err := awskms.NewBackend(&awskms.Config{
        Region: "us-east-1",
    })
    if err != nil {
        return nil, err
    }

    // Fallback: Local TPM for offline capability
    fallback, err := tpm2.NewBackend(tpm2.DefaultConfig(), fileBackend)
    if err != nil {
        return nil, err
    }

    return &HybridKeyStore{
        primary:  primary,
        fallback: fallback,
    }, nil
}

func (h *HybridKeyStore) Sign(ctx context.Context, keyID string, digest []byte, hashAlgo crypto.Hash) ([]byte, error) {
    // Try primary first
    signature, err := h.primary.Sign(ctx, keyID, digest, hashAlgo)
    if err == nil {
        return signature, nil
    }

    // Fallback if primary fails
    log.Printf("Primary backend failed, using fallback: %v", err)
    return h.fallback.Sign(ctx, keyID, digest, hashAlgo)
}
```

## Key Management Patterns

### Key Generation

```go
func generateSigningKey(store backend.Backend, keyID string) error {
    ctx := context.Background()

    params := &backend.KeyParams{
        Algorithm: backend.AlgorithmECDSA,
        Curve:     backend.CurveP256,
    }

    if err := store.GenerateKey(ctx, keyID, params); err != nil {
        return fmt.Errorf("key generation failed: %w", err)
    }

    return nil
}
```

### Signing Operations

```go
func signDocument(store backend.Backend, keyID string, document []byte) ([]byte, error) {
    ctx := context.Background()

    // Hash the document
    hash := sha256.Sum256(document)

    // Sign with the key
    signature, err := store.Sign(ctx, keyID, hash[:], crypto.SHA256)
    if err != nil {
        return nil, fmt.Errorf("signing failed: %w", err)
    }

    return signature, nil
}
```

### Key Rotation

```go
func rotateKey(store backend.Backend, oldKeyID, newKeyID string) error {
    ctx := context.Background()

    // Generate new key
    params := &backend.KeyParams{
        Algorithm: backend.AlgorithmRSA,
        KeySize:   2048,
    }

    if err := store.GenerateKey(ctx, newKeyID, params); err != nil {
        return fmt.Errorf("failed to generate new key: %w", err)
    }

    // Wait for application to transition to new key
    time.Sleep(24 * time.Hour)

    // Delete old key
    if err := store.DeleteKey(ctx, oldKeyID); err != nil {
        return fmt.Errorf("failed to delete old key: %w", err)
    }

    return nil
}
```

### Key Listing

```go
func listAllKeys(store backend.Backend) ([]string, error) {
    ctx := context.Background()

    keys, err := store.ListKeys(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to list keys: %w", err)
    }

    return keys, nil
}
```

## Symmetric Encryption

All backends support AES-GCM (128/192/256-bit) symmetric encryption with AEAD (Authenticated Encryption with Associated Data) support for secure data encryption.

### Generating Symmetric Keys

```go
func generateEncryptionKey(store backend.Backend, keyID string) error {
    ctx := context.Background()

    // Get symmetric backend interface
    symBackend, ok := store.Backend().(backend.SymmetricBackend)
    if !ok {
        return fmt.Errorf("backend does not support symmetric encryption")
    }

    // Define key attributes for AES-256-GCM
    attrs := &backend.KeyAttributes{
        CN:           keyID,
        KeyType:      backend.KEY_TYPE_ENCRYPTION,
        StoreType:    backend.STORE_SW,
        KeyAlgorithm: backend.ALG_AES256_GCM,
        AESAttributes: &backend.AESAttributes{
            KeySize: 256,
        },
    }

    if err := symBackend.GenerateSymmetricKey(attrs); err != nil {
        return fmt.Errorf("key generation failed: %w", err)
    }

    return nil
}
```

### Encrypting Data

```go
func encryptData(store backend.Backend, keyID string, plaintext, aad []byte) ([]byte, error) {
    ctx := context.Background()

    // Get symmetric backend
    symBackend, ok := store.Backend().(backend.SymmetricBackend)
    if !ok {
        return nil, fmt.Errorf("backend does not support symmetric encryption")
    }

    // Get encrypter
    encrypter, err := symBackend.SymmetricEncrypter(&backend.KeyAttributes{CN: keyID})
    if err != nil {
        return nil, fmt.Errorf("failed to get encrypter: %w", err)
    }

    // Encrypt with additional authenticated data
    encrypted, err := encrypter.Encrypt(plaintext, &backend.EncryptOptions{
        AdditionalData: aad,
    })
    if err != nil {
        return nil, fmt.Errorf("encryption failed: %w", err)
    }

    return encrypted, nil
}
```

### Decrypting Data

```go
func decryptData(store backend.Backend, keyID string, ciphertext, aad []byte) ([]byte, error) {
    ctx := context.Background()

    // Get symmetric backend
    symBackend, ok := store.Backend().(backend.SymmetricBackend)
    if !ok {
        return nil, fmt.Errorf("backend does not support symmetric encryption")
    }

    // Get encrypter (handles both encrypt and decrypt)
    encrypter, err := symBackend.SymmetricEncrypter(&backend.KeyAttributes{CN: keyID})
    if err != nil {
        return nil, fmt.Errorf("failed to get encrypter: %w", err)
    }

    // Decrypt with additional authenticated data
    plaintext, err := encrypter.Decrypt(ciphertext, &backend.EncryptOptions{
        AdditionalData: aad,
    })
    if err != nil {
        return nil, fmt.Errorf("decryption failed: %w", err)
    }

    return plaintext, nil
}
```

### Complete Encrypt/Decrypt Example

```go
package main

import (
    "fmt"
    "log"

    "github.com/jeremyhahn/go-keychain/pkg/backend"
    "github.com/jeremyhahn/go-keychain/pkg/backend/pkcs8"
)

func main() {
    // Initialize backend
    config := &pkcs8.Config{
        StoragePath: "./keys",
        Password:    "secure-password",
    }

    store, err := pkcs8.NewBackend(config)
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close(context.Background())

    // Get symmetric backend
    symBackend := store.Backend().(backend.SymmetricBackend)

    // Generate AES-256-GCM key
    attrs := &backend.KeyAttributes{
        CN:           "my-encryption-key",
        KeyType:      backend.KEY_TYPE_ENCRYPTION,
        StoreType:    backend.STORE_SW,
        KeyAlgorithm: backend.ALG_AES256_GCM,
        AESAttributes: &backend.AESAttributes{KeySize: 256},
    }

    if err := symBackend.GenerateSymmetricKey(attrs); err != nil {
        log.Fatal(err)
    }

    // Get encrypter
    encrypter, err := symBackend.SymmetricEncrypter(attrs)
    if err != nil {
        log.Fatal(err)
    }

    // Encrypt data
    plaintext := []byte("sensitive data")
    aad := []byte("context information")

    encrypted, err := encrypter.Encrypt(plaintext, &backend.EncryptOptions{
        AdditionalData: aad,
    })
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Encrypted: %x\n", encrypted)

    // Decrypt data
    decrypted, err := encrypter.Decrypt(encrypted, &backend.EncryptOptions{
        AdditionalData: aad,
    })
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Decrypted: %s\n", decrypted)
}
```

### Symmetric Key Algorithms

All backends support the following symmetric encryption algorithms:

| Algorithm | Key Size | Mode | Features |
|-----------|----------|------|----------|
| AES-GCM | 128-bit | Galois/Counter Mode | AEAD, authenticated encryption |
| AES-GCM | 192-bit | Galois/Counter Mode | AEAD, authenticated encryption |
| AES-GCM | 256-bit | Galois/Counter Mode | AEAD, authenticated encryption |

**AEAD Benefits:**
- Provides both confidentiality and authenticity
- Protects against tampering and forgery
- Supports additional authenticated data (AAD)
- Industry-standard for modern encryption

## Testing

The project includes comprehensive unit and integration tests with a test coverage goal of 90%+.

### Running Tests

```bash
# Run all unit tests (fast, no system modifications)
make test

# Run all integration tests (Docker-based)
make integration-test

# Run specific backend integration tests
make integration-test-pkcs8
make integration-test-pkcs11
make integration-test-tpm2
make integration-test-awskms
make integration-test-gcpkms
make integration-test-azurekv
make integration-test-vault
```

### Test Structure

Integration tests are organized in `test/integration/{backend}/`:

```
test/integration/
├── pkcs8/              # PKCS#8 software backend tests
├── pkcs11/             # PKCS#11/SoftHSM tests
├── tpm2/               # TPM2 simulator tests
├── awskms/             # AWS KMS/LocalStack tests
├── gcpkms/             # GCP KMS mock tests
├── azurekv/            # Azure Key Vault mock tests
└── vault/              # HashiCorp Vault tests
```

Each backend directory contains:
- `docker-compose.yml` - Docker configuration for the backend
- `Dockerfile` - Test container configuration
- `*_integration_test.go` - Integration test suite

### Unit Testing with Mocks

```go
type MockBackend struct {
    backend.Backend
    GenerateKeyFunc func(ctx context.Context, keyID string, params *backend.KeyParams) error
    SignFunc        func(ctx context.Context, keyID string, digest []byte, hashAlgo crypto.Hash) ([]byte, error)
}

func (m *MockBackend) GenerateKey(ctx context.Context, keyID string, params *backend.KeyParams) error {
    if m.GenerateKeyFunc != nil {
        return m.GenerateKeyFunc(ctx, keyID, params)
    }
    return nil
}

func (m *MockBackend) Sign(ctx context.Context, keyID string, digest []byte, hashAlgo crypto.Hash) ([]byte, error) {
    if m.SignFunc != nil {
        return m.SignFunc(ctx, keyID, digest, hashAlgo)
    }
    return make([]byte, 256), nil
}

func TestSigningService(t *testing.T) {
    mock := &MockBackend{
        SignFunc: func(ctx context.Context, keyID string, digest []byte, hashAlgo crypto.Hash) ([]byte, error) {
            return []byte("mock-signature"), nil
        },
    }

    service := NewSigningService(mock)
    signature, err := service.SignData([]byte("test data"))

    assert.NoError(t, err)
    assert.Equal(t, []byte("mock-signature"), signature)
}
```

### Integration Testing

Integration tests run in Docker containers with real services. Example from `test/integration/pkcs8/`:

```bash
# Each backend has its own Docker-based test
cd test/integration/pkcs8
docker-compose run --rm test
```

Test results show:
- Total tests: 151 passing
- Coverage: 74.9% overall
- All backends tested in isolation

## Error Handling Best Practices

### Comprehensive Error Handling

```go
func handleKeyStoreOperation(store backend.Backend) error {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    params := &backend.KeyParams{
        Algorithm: backend.AlgorithmRSA,
        KeySize:   2048,
    }

    err := store.GenerateKey(ctx, "my-key", params)
    if err != nil {
        // Check for specific error types
        switch {
        case errors.Is(err, backend.ErrKeyAlreadyExists):
            log.Printf("Key already exists, using existing key")
            return nil

        case errors.Is(err, backend.ErrInvalidAlgorithm):
            return fmt.Errorf("unsupported algorithm: %w", err)

        case strings.Contains(err.Error(), "permission denied"):
            return fmt.Errorf("insufficient permissions: %w", err)

        default:
            return fmt.Errorf("key generation failed: %w", err)
        }
    }

    return nil
}
```

### Retry Logic

```go
func signWithRetry(store backend.Backend, keyID string, digest []byte, maxRetries int) ([]byte, error) {
    var signature []byte
    var err error

    for attempt := 0; attempt < maxRetries; attempt++ {
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        signature, err = store.Sign(ctx, keyID, digest, crypto.SHA256)
        cancel()

        if err == nil {
            return signature, nil
        }

        // Check if error is retryable
        if !isRetryableError(err) {
            return nil, err
        }

        // Exponential backoff
        backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
        log.Printf("Attempt %d failed, retrying in %v: %v", attempt+1, backoff, err)
        time.Sleep(backoff)
    }

    return nil, fmt.Errorf("max retries exceeded: %w", err)
}

func isRetryableError(err error) bool {
    if err == nil {
        return false
    }

    errStr := err.Error()
    retryableErrors := []string{
        "timeout",
        "connection refused",
        "temporary failure",
        "throttling",
        "rate limit",
    }

    for _, retryable := range retryableErrors {
        if strings.Contains(strings.ToLower(errStr), retryable) {
            return true
        }
    }

    return false
}
```

## Performance Optimization

### Connection Pooling

```go
var (
    globalStore backend.Backend
    storeOnce   sync.Once
    storeMu     sync.RWMutex
)

func getKeyStore() (backend.Backend, error) {
    storeMu.RLock()
    if globalStore != nil {
        defer storeMu.RUnlock()
        return globalStore, nil
    }
    storeMu.RUnlock()

    var err error
    storeOnce.Do(func() {
        storeMu.Lock()
        defer storeMu.Unlock()

        config := &awskms.Config{
            Region: os.Getenv("AWS_REGION"),
        }

        globalStore, err = awskms.NewBackend(config)
    })

    return globalStore, err
}
```

### Public Key Caching

```go
type KeyCache struct {
    store backend.Backend
    cache map[string]crypto.PublicKey
    mu    sync.RWMutex
}

func NewKeyCache(store backend.Backend) *KeyCache {
    return &KeyCache{
        store: store,
        cache: make(map[string]crypto.PublicKey),
    }
}

func (c *KeyCache) GetPublicKey(ctx context.Context, keyID string) (crypto.PublicKey, error) {
    // Check cache first
    c.mu.RLock()
    if pubKey, ok := c.cache[keyID]; ok {
        c.mu.RUnlock()
        return pubKey, nil
    }
    c.mu.RUnlock()

    // Fetch from backend
    pubKey, err := c.store.GetPublicKey(ctx, keyID)
    if err != nil {
        return nil, err
    }

    // Cache the result
    c.mu.Lock()
    c.cache[keyID] = pubKey
    c.mu.Unlock()

    return pubKey, nil
}
```

## Security Best Practices

### Password Management

```go
// Bad: Hardcoded password
config := &pkcs8.Config{
    Password: "my-password", // NEVER DO THIS
}

// Good: Environment variable
config := &pkcs8.Config{
    Password: os.Getenv("KEYSTORE_PASSWORD"),
}

// Better: Secret management service
func loadPassword() string {
    // Load from HashiCorp Vault, AWS Secrets Manager, etc.
    return secretsClient.GetSecret("keychain-password")
}

config := &pkcs8.Config{
    Password: loadPassword(),
}
```

### Access Control

```go
// Principle of least privilege
func configureCloudKMS() *awskms.Config {
    return &awskms.Config{
        Region: "us-east-1",
        // Uses IAM role with minimal permissions:
        // - kms:Sign
        // - kms:Verify
        // - kms:GetPublicKey
    }
}
```

### Audit Logging

```go
type AuditedBackend struct {
    backend.Backend
    logger *log.Logger
}

func (a *AuditedBackend) Sign(ctx context.Context, keyID string, digest []byte, hashAlgo crypto.Hash) ([]byte, error) {
    start := time.Now()
    a.logger.Printf("[AUDIT] Sign operation started for key: %s", keyID)

    signature, err := a.Backend.Sign(ctx, keyID, digest, hashAlgo)

    duration := time.Since(start)
    if err != nil {
        a.logger.Printf("[AUDIT] Sign operation failed for key %s after %v: %v", keyID, duration, err)
        return nil, err
    }

    a.logger.Printf("[AUDIT] Sign operation succeeded for key %s in %v", keyID, duration)
    return signature, nil
}
```

## Migration Guide

### From One Backend to Another

```go
func migrateBackend(oldStore, newStore backend.Backend) error {
    ctx := context.Background()

    // List all keys in old backend
    keys, err := oldStore.ListKeys(ctx)
    if err != nil {
        return fmt.Errorf("failed to list keys: %w", err)
    }

    for _, keyID := range keys {
        // Get public key from old backend
        pubKey, err := oldStore.GetPublicKey(ctx, keyID)
        if err != nil {
            log.Printf("Failed to get public key for %s: %v", keyID, err)
            continue
        }

        // Generate new key in new backend
        // Note: You cannot export private keys from secure backends
        // Must generate new keys and re-sign data

        params := &backend.KeyParams{
            Algorithm: detectAlgorithm(pubKey),
            KeySize:   detectKeySize(pubKey),
        }

        if err := newStore.GenerateKey(ctx, keyID, params); err != nil {
            log.Printf("Failed to generate key %s in new backend: %v", keyID, err)
            continue
        }

        log.Printf("Migrated key: %s", keyID)
    }

    return nil
}
```

## Troubleshooting

### Common Issues

**Issue: Key Not Found**
```go
// Solution: Check key exists before using
keys, _ := store.ListKeys(ctx)
log.Printf("Available keys: %v", keys)
```

**Issue: Permission Denied**
```go
// Solution: Verify IAM/RBAC permissions
// AWS KMS: Check IAM policy and key policy
// GCP KMS: Verify service account has cloudkms.signerVerifier role
// Azure KV: Check RBAC assignment or access policy
```

**Issue: Slow Performance**
```go
// Solution: Implement caching
cache := NewKeyCache(store)
pubKey, err := cache.GetPublicKey(ctx, keyID) // Cached after first call
```

## Next Steps

- Review backend-specific documentation for detailed configuration
- Implement audit logging for your use case
- Set up monitoring and alerting
- Plan key rotation policies
- Test disaster recovery procedures

## Additional Resources

- [PKCS#8 Backend Documentation](backends/pkcs8.md)
- [TPM2 Backend Documentation](backends/tpm2.md)
- [PKCS#11 Backend Documentation](backends/pkcs11.md)
- [AWS KMS Backend Documentation](backends/awskms.md)
- [GCP KMS Backend Documentation](backends/gcpkms.md)
- [Azure Key Vault Backend Documentation](backends/azurekv.md)

## Support

For issues, questions, or contributions, please visit the GitHub repository.
