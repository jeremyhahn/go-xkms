# PKCS#11 Backend Documentation

## Overview

The PKCS#11 backend provides integration with Hardware Security Modules (HSMs) and cryptographic tokens through the industry-standard PKCS#11 (Cryptoki) interface. This backend enables hardware-backed key generation, storage, and cryptographic operations using FIPS 140-2 validated devices from vendors including Thales, Utimaco, AWS CloudHSM, YubiKey, and software implementations like SoftHSM.

PKCS#11 (Public-Key Cryptography Standards #11) defines a platform-independent API for cryptographic tokens. The go-keychain PKCS#11 backend uses the crypto11 library to provide high-level abstractions while maintaining direct access to hardware security features.

## Features and Capabilities

### Hardware Security

- Hardware-backed private key storage with no plaintext exposure
- FIPS 140-2 Level 2/3 compliance support (device-dependent)
- Tamper-resistant key operations
- Physical security controls via HSM hardware
- Certified random number generation

### Key Management

- RSA key generation (2048, 3072, 4096 bits)
- ECDSA key generation (P-256, P-384, P-521 curves)
- Persistent key storage within HSM
- Key labeling and discovery
- Public key extraction
- Key deletion and lifecycle management

### Cryptographic Operations

- Digital signature creation (RSA-PKCS1v15, RSA-PSS, ECDSA)
- Signature verification
- Hardware random number generation
- Session management with pooling
- Thread-safe concurrent operations

### Vendor Support

- Thales nShield HSMs
- Utimaco SecurityServer
- AWS CloudHSM
- YubiKey PIV tokens
- Nitrokey HSM
- SoftHSM (software testing)
- Any PKCS#11 compliant device

## Configuration Options

### Config Structure

```go
type Config struct {
    // Path to PKCS#11 library (.so, .dylib, .dll)
    LibraryPath string

    // Slot ID for the token
    SlotID uint

    // Token label (alternative to SlotID)
    TokenLabel string

    // User PIN for authentication
    PIN string

    // Enable shared context caching (default: true)
    SharedContext bool

    // Existing crypto11 context (optional)
    Context *crypto11.Context

    // Existing PKCS#11 context (optional)
    P11Context *pkcs11.Ctx
}
```

### Configuration Parameters

**LibraryPath** (required if Context not provided)
- Absolute path to PKCS#11 shared library
- Linux: `/usr/lib/softhsm/libsofthsm2.so`
- macOS: `/usr/local/lib/softhsm/libsofthsm2.dylib`
- Windows: `C:\SoftHSM2\lib\softhsm2-x64.dll`
- YubiKey: `/usr/local/lib/libykcs11.so`
- AWS CloudHSM: `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so`

**SlotID** (required if TokenLabel not provided)
- Numeric identifier for HSM slot
- Use `pkcs11-tool --list-slots` to discover
- Example: `0` for first slot

**TokenLabel** (alternative to SlotID)
- Human-readable token identifier
- Example: `"my-hsm-token"`
- More portable across devices

**PIN** (required)
- User authentication PIN
- Minimum length depends on device (typically 4-8 characters)
- Should be cryptographically strong
- Never hardcode in source code

**SharedContext** (optional, default: true)
- Enable global context caching for performance
- Reuses PKCS#11 context across Backend instances
- Automatic reference counting
- Set to false for isolated contexts

**Context** (optional)
- Pre-initialized crypto11.Context
- Allows external context management
- Overrides LibraryPath/SlotID/PIN if provided

**P11Context** (optional)
- Pre-initialized pkcs11.Ctx
- Low-level PKCS#11 context
- Used with Context parameter

## Supported Algorithms

### RSA Keys

| Key Size | Signature Schemes | Hash Functions |
|----------|-------------------|----------------|
| 2048 bits | PKCS#1 v1.5, PSS | SHA-256, SHA-384, SHA-512 |
| 3072 bits | PKCS#1 v1.5, PSS | SHA-256, SHA-384, SHA-512 |
| 4096 bits | PKCS#1 v1.5, PSS | SHA-256, SHA-384, SHA-512 |

**Note**: All 10 backends support RSA 2048, 3072, and 4096-bit keys with full integration test coverage (151/151 tests passing).

### ECDSA Keys

| Curve | NIST Name | Key Size | Hash Functions |
|-------|-----------|----------|----------------|
| P-256 | secp256r1 | 256 bits | SHA-256 |
| P-384 | secp384r1 | 384 bits | SHA-384 |
| P-521 | secp521r1 | 521 bits | SHA-512 |

**Note**: All 10 backends support ECDSA P-256, P-384, and P-521 curves with full integration test coverage (151/151 tests passing).

### Not Supported

- Ed25519 (limited PKCS#11 device support)
- Symmetric encryption operations
- Key agreement/derivation (future enhancement)

## Complete Working Examples

### Example 1: SoftHSM Configuration and Setup

```go
package main

import (
    "context"
    "crypto"
    "crypto/rand"
    "crypto/sha256"
    "fmt"
    "log"

    "github.com/jeremyhahn/go-keychain/pkg/backend"
    "github.com/jeremyhahn/go-keychain/pkg/backend/pkcs11"
)

func main() {
    ctx := context.Background()

    // SoftHSM configuration
    config := &pkcs11.Config{
        LibraryPath: "/usr/lib/softhsm/libsofthsm2.so",
        TokenLabel:  "my-token",
        PIN:         "1234",
    }

    store, err := pkcs11.NewBackend(config)
    if err != nil {
        log.Fatalf("Failed to initialize PKCS#11 backend: %v", err)
    }
    defer store.Close(ctx)

    // Generate RSA key
    keyID := "test-rsa-key"
    params := &backend.KeyParams{
        Algorithm: backend.AlgorithmRSA,
        KeySize:   2048,
    }

    if err := store.GenerateKey(ctx, keyID, params); err != nil {
        log.Fatalf("Failed to generate key: %v", err)
    }

    fmt.Println("Key generated successfully in SoftHSM")

    // Sign data
    data := []byte("Hello, PKCS#11!")
    hash := sha256.Sum256(data)

    signature, err := store.Sign(ctx, keyID, hash[:], crypto.SHA256)
    if err != nil {
        log.Fatalf("Failed to sign: %v", err)
    }

    fmt.Printf("Signature created: %d bytes\n", len(signature))

    // Verify signature
    publicKey, err := store.GetPublicKey(ctx, keyID)
    if err != nil {
        log.Fatalf("Failed to get public key: %v", err)
    }

    fmt.Printf("Public key retrieved: %T\n", publicKey)
}
```

### Example 2: YubiKey PIV Configuration

```go
func setupYubiKey() (backend.Backend, error) {
    config := &pkcs11.Config{
        LibraryPath: "/usr/local/lib/libykcs11.so",
        SlotID:      0,
        PIN:         "123456", // YubiKey default PIN
    }

    return pkcs11.NewBackend(config)
}

func yubiKeyExample() {
    ctx := context.Background()

    store, err := setupYubiKey()
    if err != nil {
        log.Fatalf("YubiKey setup failed: %v", err)
    }
    defer store.Close(ctx)

    // Generate ECDSA key on YubiKey
    keyID := "yubikey-ecdsa-p256"
    params := &backend.KeyParams{
        Algorithm: backend.AlgorithmECDSA,
        Curve:     backend.CurveP256,
    }

    if err := store.GenerateKey(ctx, keyID, params); err != nil {
        log.Fatalf("Failed to generate key: %v", err)
    }

    fmt.Println("ECDSA key generated on YubiKey")
}
```

### Example 3: AWS CloudHSM Configuration

```go
func setupCloudHSM() (backend.Backend, error) {
    config := &pkcs11.Config{
        LibraryPath: "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
        SlotID:      1,
        PIN:         os.Getenv("CLOUDHSM_PIN"),
    }

    return pkcs11.NewBackend(config)
}

func cloudHSMExample() {
    ctx := context.Background()

    store, err := setupCloudHSM()
    if err != nil {
        log.Fatalf("CloudHSM setup failed: %v", err)
    }
    defer store.Close(ctx)

    // Generate 4096-bit RSA key
    keyID := "cloudhsm-rsa-4096"
    params := &backend.KeyParams{
        Algorithm: backend.AlgorithmRSA,
        KeySize:   4096,
    }

    if err := store.GenerateKey(ctx, keyID, params); err != nil {
        log.Fatalf("Failed to generate key: %v", err)
    }

    fmt.Println("RSA-4096 key generated in CloudHSM")

    // List all keys
    keys, err := store.ListKeys(ctx)
    if err != nil {
        log.Fatalf("Failed to list keys: %v", err)
    }

    fmt.Printf("Total keys in CloudHSM: %d\n", len(keys))
    for _, key := range keys {
        fmt.Printf("  - %s\n", key)
    }
}
```

### Example 4: Context Caching and Reuse

```go
func contextCachingExample() {
    ctx := context.Background()

    // First backend instance
    config1 := &pkcs11.Config{
        LibraryPath:   "/usr/lib/softhsm/libsofthsm2.so",
        TokenLabel:    "shared-token",
        PIN:           "1234",
        SharedContext: true, // Enable context caching
    }

    store1, err := pkcs11.NewBackend(config1)
    if err != nil {
        log.Fatal(err)
    }

    // Second backend instance reuses context
    config2 := &pkcs11.Config{
        LibraryPath:   "/usr/lib/softhsm/libsofthsm2.so",
        TokenLabel:    "shared-token",
        PIN:           "1234",
        SharedContext: true,
    }

    store2, err := pkcs11.NewBackend(config2)
    if err != nil {
        log.Fatal(err)
    }

    // Both instances share the same PKCS#11 context
    // Reference counting ensures proper cleanup

    defer store1.Close(ctx)
    defer store2.Close(ctx)

    fmt.Println("Two backend instances sharing PKCS#11 context")
}
```

### Example 5: Multiple Algorithm Key Generation

```go
func multiAlgorithmExample() {
    ctx := context.Background()

    config := &pkcs11.Config{
        LibraryPath: "/usr/lib/softhsm/libsofthsm2.so",
        TokenLabel:  "multi-algo",
        PIN:         "1234",
    }

    store, err := pkcs11.NewBackend(config)
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close(ctx)

    // Generate RSA 2048
    rsa2048Params := &backend.KeyParams{
        Algorithm: backend.AlgorithmRSA,
        KeySize:   2048,
    }
    if err := store.GenerateKey(ctx, "rsa-2048", rsa2048Params); err != nil {
        log.Fatal(err)
    }

    // Generate RSA 4096
    rsa4096Params := &backend.KeyParams{
        Algorithm: backend.AlgorithmRSA,
        KeySize:   4096,
    }
    if err := store.GenerateKey(ctx, "rsa-4096", rsa4096Params); err != nil {
        log.Fatal(err)
    }

    // Generate ECDSA P-256
    ecdsaP256Params := &backend.KeyParams{
        Algorithm: backend.AlgorithmECDSA,
        Curve:     backend.CurveP256,
    }
    if err := store.GenerateKey(ctx, "ecdsa-p256", ecdsaP256Params); err != nil {
        log.Fatal(err)
    }

    // Generate ECDSA P-384
    ecdsaP384Params := &backend.KeyParams{
        Algorithm: backend.AlgorithmECDSA,
        Curve:     backend.CurveP384,
    }
    if err := store.GenerateKey(ctx, "ecdsa-p384", ecdsaP384Params); err != nil {
        log.Fatal(err)
    }

    // Generate ECDSA P-521
    ecdsaP521Params := &backend.KeyParams{
        Algorithm: backend.AlgorithmECDSA,
        Curve:     backend.CurveP521,
    }
    if err := store.GenerateKey(ctx, "ecdsa-p521", ecdsaP521Params); err != nil {
        log.Fatal(err)
    }

    fmt.Println("Generated 5 keys with different algorithms")
}
```

### Example 6: Production Service Integration

```go
type SigningService struct {
    keychain backend.Backend
    keyID    string
}

func NewSigningService() (*SigningService, error) {
    config := &pkcs11.Config{
        LibraryPath: os.Getenv("PKCS11_LIBRARY"),
        TokenLabel:  os.Getenv("PKCS11_TOKEN"),
        PIN:         os.Getenv("PKCS11_PIN"),
    }

    store, err := pkcs11.NewBackend(config)
    if err != nil {
        return nil, fmt.Errorf("failed to init keychain: %w", err)
    }

    return &SigningService{
        keychain: store,
        keyID:    os.Getenv("SIGNING_KEY_ID"),
    }, nil
}

func (s *SigningService) SignDocument(ctx context.Context, document []byte) ([]byte, error) {
    hash := sha256.Sum256(document)

    signature, err := s.keychain.Sign(ctx, s.keyID, hash[:], crypto.SHA256)
    if err != nil {
        return nil, fmt.Errorf("signing failed: %w", err)
    }

    return signature, nil
}

func (s *SigningService) Close() error {
    return s.keychain.Close(context.Background())
}

func productionExample() {
    service, err := NewSigningService()
    if err != nil {
        log.Fatalf("Failed to create service: %v", err)
    }
    defer service.Close()

    document := []byte("Production document content")
    signature, err := service.SignDocument(context.Background(), document)
    if err != nil {
        log.Fatalf("Failed to sign document: %v", err)
    }

    fmt.Printf("Document signed: %d byte signature\n", len(signature))
}
```

## Common Use Cases

### Certificate Authority Operations

```go
func caSigningExample() {
    ctx := context.Background()

    config := &pkcs11.Config{
        LibraryPath: "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
        TokenLabel:  "ca-hsm",
        PIN:         os.Getenv("CA_PIN"),
    }

    store, err := pkcs11.NewBackend(config)
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close(ctx)

    // Generate CA root key
    caKeyParams := &backend.KeyParams{
        Algorithm: backend.AlgorithmRSA,
        KeySize:   4096,
    }

    if err := store.GenerateKey(ctx, "ca-root-key", caKeyParams); err != nil {
        log.Fatal(err)
    }

    // Sign certificate request
    certHash := sha256.Sum256([]byte("certificate data"))
    signature, err := store.Sign(ctx, "ca-root-key", certHash[:], crypto.SHA256)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("CA signature created: %d bytes\n", len(signature))
}
```

### Code Signing

```go
func codeSigningExample() {
    ctx := context.Background()

    config := &pkcs11.Config{
        LibraryPath: "/usr/local/lib/libykcs11.so",
        SlotID:      0,
        PIN:         os.Getenv("YUBIKEY_PIN"),
    }

    store, err := pkcs11.NewBackend(config)
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close(ctx)

    // Generate code signing key
    params := &backend.KeyParams{
        Algorithm: backend.AlgorithmRSA,
        KeySize:   3072,
    }

    if err := store.GenerateKey(ctx, "code-signing-key", params); err != nil {
        log.Fatal(err)
    }

    // Sign binary
    binaryHash := sha256.Sum256([]byte("compiled binary"))
    signature, err := store.Sign(ctx, "code-signing-key", binaryHash[:], crypto.SHA256)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Code signature: %d bytes\n", len(signature))
}
```

### JWT Token Signing

```go
func jwtSigningExample() {
    ctx := context.Background()

    config := &pkcs11.Config{
        LibraryPath: "/usr/lib/softhsm/libsofthsm2.so",
        TokenLabel:  "jwt-keys",
        PIN:         os.Getenv("HSM_PIN"),
    }

    store, err := pkcs11.NewBackend(config)
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close(ctx)

    // Generate ECDSA P-256 for JWT
    params := &backend.KeyParams{
        Algorithm: backend.AlgorithmECDSA,
        Curve:     backend.CurveP256,
    }

    if err := store.GenerateKey(ctx, "jwt-signing-key", params); err != nil {
        log.Fatal(err)
    }

    // Sign JWT payload
    jwtPayload := []byte("header.payload")
    hash := sha256.Sum256(jwtPayload)

    signature, err := store.Sign(ctx, "jwt-signing-key", hash[:], crypto.SHA256)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("JWT signature: %d bytes\n", len(signature))
}
```

### Document Signing Service

```go
type DocumentSigner struct {
    store backend.Backend
}

func NewDocumentSigner() (*DocumentSigner, error) {
    config := &pkcs11.Config{
        LibraryPath: os.Getenv("PKCS11_LIB"),
        TokenLabel:  "document-signer",
        PIN:         os.Getenv("PKCS11_PIN"),
    }

    store, err := pkcs11.NewBackend(config)
    if err != nil {
        return nil, err
    }

    return &DocumentSigner{store: store}, nil
}

func (d *DocumentSigner) SignPDF(ctx context.Context, pdfHash []byte) ([]byte, error) {
    return d.store.Sign(ctx, "pdf-signing-key", pdfHash, crypto.SHA256)
}

func (d *DocumentSigner) Close() error {
    return d.store.Close(context.Background())
}

func documentServiceExample() {
    signer, err := NewDocumentSigner()
    if err != nil {
        log.Fatal(err)
    }
    defer signer.Close()

    pdfHash := sha256.Sum256([]byte("PDF document"))
    signature, err := signer.SignPDF(context.Background(), pdfHash[:])
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("PDF signed: %d bytes\n", len(signature))
}
```

## SoftHSM Setup and Testing

### Installing SoftHSM

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install softhsm2
```

**macOS:**
```bash
brew install softhsm
```

**RHEL/CentOS:**
```bash
sudo yum install softhsm
```

### Initializing SoftHSM Token

```bash
# Create tokens directory
mkdir -p ~/softhsm/tokens

# Configure SoftHSM
cat > ~/softhsm/softhsm2.conf <<EOF
directories.tokendir = $HOME/softhsm/tokens
objectstore.backend = file
log.level = INFO
EOF

export SOFTHSM2_CONF=~/softhsm/softhsm2.conf

# Initialize token
softhsm2-util --init-token --slot 0 --label "my-token" \
  --so-pin 1234 --pin 1234

# Verify token
softhsm2-util --show-slots
```

### Testing with SoftHSM

```go
func testWithSoftHSM() {
    ctx := context.Background()

    // Set SOFTHSM2_CONF environment variable first
    os.Setenv("SOFTHSM2_CONF", "/home/user/softhsm/softhsm2.conf")

    config := &pkcs11.Config{
        LibraryPath: "/usr/lib/softhsm/libsofthsm2.so",
        TokenLabel:  "my-token",
        PIN:         "1234",
    }

    store, err := pkcs11.NewBackend(config)
    if err != nil {
        log.Fatalf("SoftHSM init failed: %v", err)
    }
    defer store.Close(ctx)

    // Run tests
    testKeyGeneration(store)
    testSigning(store)
    testKeyListing(store)
}

func testKeyGeneration(store backend.Backend) {
    ctx := context.Background()

    params := &backend.KeyParams{
        Algorithm: backend.AlgorithmRSA,
        KeySize:   2048,
    }

    if err := store.GenerateKey(ctx, "test-key", params); err != nil {
        log.Fatalf("Key generation failed: %v", err)
    }

    fmt.Println("Test: Key generation passed")
}

func testSigning(store backend.Backend) {
    ctx := context.Background()

    hash := sha256.Sum256([]byte("test data"))
    signature, err := store.Sign(ctx, "test-key", hash[:], crypto.SHA256)
    if err != nil {
        log.Fatalf("Signing failed: %v", err)
    }

    if len(signature) == 0 {
        log.Fatal("Invalid signature")
    }

    fmt.Println("Test: Signing passed")
}

func testKeyListing(store backend.Backend) {
    ctx := context.Background()

    keys, err := store.ListKeys(ctx)
    if err != nil {
        log.Fatalf("List keys failed: %v", err)
    }

    if len(keys) == 0 {
        log.Fatal("No keys found")
    }

    fmt.Printf("Test: Key listing passed (%d keys)\n", len(keys))
}
```

## Security Considerations

### PIN Protection

Never hardcode PINs in source code:

```go
// Bad: Hardcoded PIN
config := &pkcs11.Config{
    PIN: "1234", // NEVER DO THIS
}

// Good: Environment variable
config := &pkcs11.Config{
    PIN: os.Getenv("HSM_PIN"),
}

// Better: Secret management service
config := &pkcs11.Config{
    PIN: loadPINFromVault(),
}

func loadPINFromVault() string {
    // Load from HashiCorp Vault, AWS Secrets Manager, etc.
    return secretsClient.GetSecret("hsm-pin")
}
```

### Session Management

The backend automatically manages PKCS#11 sessions:

- Session pooling reduces overhead
- Automatic session cleanup on Close
- Thread-safe session access
- Login state management

### Key Access Control

HSMs provide fine-grained access control:

```go
// Different PINs for different security levels
userConfig := &pkcs11.Config{
    LibraryPath: "/usr/lib/hsm.so",
    TokenLabel:  "production",
    PIN:         os.Getenv("USER_PIN"),
}

soConfig := &pkcs11.Config{
    LibraryPath: "/usr/lib/hsm.so",
    TokenLabel:  "production",
    PIN:         os.Getenv("SO_PIN"), // Security Officer PIN
}
```

### Private Key Protection

Private keys never leave the HSM:

- All signing operations performed in hardware
- Private key material never exposed to application
- Keys marked as non-extractable during generation
- Hardware enforces security policies

### Audit Logging

Implement comprehensive logging:

```go
type AuditedBackend struct {
    backend.Backend
    logger *log.Logger
}

func (a *AuditedBackend) Sign(ctx context.Context, keyID string, digest []byte, hashAlgo crypto.Hash) ([]byte, error) {
    a.logger.Printf("AUDIT: Sign operation requested for key %s", keyID)

    signature, err := a.Backend.Sign(ctx, keyID, digest, hashAlgo)

    if err != nil {
        a.logger.Printf("AUDIT: Sign operation failed for key %s: %v", keyID, err)
        return nil, err
    }

    a.logger.Printf("AUDIT: Sign operation succeeded for key %s", keyID)
    return signature, nil
}
```

### Context Isolation

Disable shared contexts for security isolation:

```go
// Isolated context per instance
config := &pkcs11.Config{
    LibraryPath:   "/usr/lib/hsm.so",
    TokenLabel:    "isolated",
    PIN:           os.Getenv("PIN"),
    SharedContext: false, // No context sharing
}
```

## Best Practices

### Configuration Management

Store configuration securely:

```go
type SecureConfig struct {
    LibraryPath string
    TokenLabel  string
}

func loadConfig() (*pkcs11.Config, error) {
    // Load from secure configuration
    cfg := loadFromFile("/etc/app/hsm.conf")

    return &pkcs11.Config{
        LibraryPath: cfg.LibraryPath,
        TokenLabel:  cfg.TokenLabel,
        PIN:         loadPINFromVault(),
    }, nil
}
```

### Error Handling

Always handle errors appropriately:

```go
store, err := pkcs11.NewBackend(config)
if err != nil {
    return fmt.Errorf("PKCS#11 initialization failed: %w", err)
}
defer func() {
    if err := store.Close(ctx); err != nil {
        log.Printf("Error closing PKCS#11 backend: %v", err)
    }
}()
```

### Resource Cleanup

Ensure proper resource cleanup:

```go
func performOperation() error {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    store, err := pkcs11.NewBackend(config)
    if err != nil {
        return err
    }
    defer store.Close(ctx)

    // Perform operations
    return nil
}
```

### Key Naming Conventions

Use consistent, descriptive key identifiers:

```go
// Good: Descriptive and hierarchical
keyID := "production.api.v2.signing-key"

// Good: With purpose and date
keyID := "ca-root-2024-rsa4096"

// Avoid: Generic names
keyID := "key1" // Too generic
```

### Performance Optimization

Cache Backend instances when possible:

```go
var (
    backendInstance backend.Backend
    backendOnce     sync.Once
)

func getBackend() (backend.Backend, error) {
    var err error
    backendOnce.Do(func() {
        backendInstance, err = pkcs11.NewBackend(config)
    })
    return backendInstance, err
}
```

### Testing Strategy

Use SoftHSM for development and testing:

```go
func newTestBackend(t *testing.T) backend.Backend {
    config := &pkcs11.Config{
        LibraryPath: "/usr/lib/softhsm/libsofthsm2.so",
        TokenLabel:  t.Name(),
        PIN:         "1234",
    }

    store, err := pkcs11.NewBackend(config)
    require.NoError(t, err)
    t.Cleanup(func() {
        store.Close(context.Background())
    })

    return store
}
```

### Multi-Tenancy

Separate tokens for different tenants:

```go
func getTenantBackend(tenantID string) (backend.Backend, error) {
    config := &pkcs11.Config{
        LibraryPath: "/usr/lib/hsm.so",
        TokenLabel:  fmt.Sprintf("tenant-%s", tenantID),
        PIN:         loadTenantPIN(tenantID),
    }

    return pkcs11.NewBackend(config)
}
```

### Graceful Degradation

Handle HSM unavailability:

```go
func newBackendWithFallback() (backend.Backend, error) {
    // Try hardware HSM first
    config := &pkcs11.Config{
        LibraryPath: "/usr/lib/hsm.so",
        TokenLabel:  "production",
        PIN:         os.Getenv("HSM_PIN"),
    }

    store, err := pkcs11.NewBackend(config)
    if err != nil {
        log.Printf("HSM unavailable, falling back to SoftHSM: %v", err)

        // Fallback to SoftHSM
        fallbackConfig := &pkcs11.Config{
            LibraryPath: "/usr/lib/softhsm/libsofthsm2.so",
            TokenLabel:  "fallback",
            PIN:         os.Getenv("SOFTHSM_PIN"),
        }

        return pkcs11.NewBackend(fallbackConfig)
    }

    return store, nil
}
```

## Troubleshooting

### Library Not Found

```
Error: failed to load PKCS#11 library: /usr/lib/hsm.so: cannot open shared object file
```

Solutions:
- Verify library path: `ls -l /usr/lib/hsm.so`
- Check library dependencies: `ldd /usr/lib/hsm.so`
- Install missing packages
- Set LD_LIBRARY_PATH if needed

### Token Not Found

```
Error: token not found: my-token
```

Solutions:
- List available slots: `pkcs11-tool --list-slots`
- Verify token label matches configuration
- Check token is initialized
- Use SlotID instead of TokenLabel

### Authentication Failed

```
Error: CKR_PIN_INCORRECT
```

Solutions:
- Verify PIN is correct
- Check if token is locked after failed attempts
- Reset token if necessary
- Verify user vs SO PIN usage

### Slot Already Logged In

```
Error: CKR_USER_ALREADY_LOGGED_IN
```

Solutions:
- Normal behavior with shared contexts
- Can be safely ignored
- Disable SharedContext if isolation needed

### Key Not Found

```
Error: key not found: my-key
```

Solutions:
- List keys: `pkcs11-tool --list-objects`
- Verify key label matches
- Check correct slot/token
- Ensure key was generated successfully

### Session Handle Invalid

```
Error: CKR_SESSION_HANDLE_INVALID
```

Solutions:
- Close and reinitialize backend
- Check for context corruption
- Verify HSM connectivity
- Restart application

### Concurrent Access Issues

```
Error: CKR_OPERATION_ACTIVE
```

Solutions:
- Backend handles thread-safety automatically
- Check for external PKCS#11 access
- Verify session pooling configuration
- Report bug if persistent

## Performance Considerations

### Key Generation Performance

Hardware key generation is slower than software:

- RSA 2048: 100-500ms depending on HSM
- RSA 4096: 500-2000ms
- ECDSA P-256: 50-200ms
- Generate keys during initialization, not on-demand

### Signing Performance

HSM signing performance varies by device:

- Software SoftHSM: 1000+ ops/sec
- YubiKey: 10-50 ops/sec
- Entry HSM: 100-500 ops/sec
- Enterprise HSM: 1000-10000+ ops/sec

### Context Caching Benefits

Shared context caching provides significant benefits:

```go
// Without caching: ~100ms initialization per backend
// With caching: ~1ms initialization per backend

// Enable caching (default)
config := &pkcs11.Config{
    SharedContext: true,
}
```

### Batching Operations

Batch operations when possible:

```go
func batchSign(store backend.Backend, digests [][]byte) ([][]byte, error) {
    ctx := context.Background()
    signatures := make([][]byte, len(digests))

    for i, digest := range digests {
        sig, err := store.Sign(ctx, "batch-key", digest, crypto.SHA256)
        if err != nil {
            return nil, err
        }
        signatures[i] = sig
    }

    return signatures, nil
}
```

### Connection Pooling

The backend handles session pooling automatically:

- Reuses sessions across operations
- Automatic cleanup of idle sessions
- Thread-safe access
- No manual pooling required

## Advanced Topics

### Custom Context Management

Provide pre-initialized context:

```go
import "github.com/ThalesIgnite/crypto11"

func advancedContextManagement() error {
    // Initialize crypto11 context directly
    ctx11Config := &crypto11.Config{
        Path:       "/usr/lib/hsm.so",
        TokenLabel: "advanced",
        Pin:        "1234",
    }

    ctx11, err := crypto11.Configure(ctx11Config)
    if err != nil {
        return err
    }

    // Use custom context
    config := &pkcs11.Config{
        Context: ctx11,
    }

    store, err := pkcs11.NewBackend(config)
    if err != nil {
        return err
    }
    defer store.Close(context.Background())

    return nil
}
```

### Direct PKCS#11 Access

Access underlying PKCS#11 context:

```go
func directPKCS11Access(store *pkcs11.Backend) {
    // Access internal PKCS#11 context if needed
    // Note: This is an advanced use case
    // Most users should use the Backend interface

    // Example: Custom PKCS#11 operations
    // Use store's internal context for low-level operations
}
```

### Multi-Slot Operations

Manage multiple slots:

```go
func multiSlotExample() error {
    ctx := context.Background()

    // Backend for slot 0
    store0, err := pkcs11.NewBackend(&pkcs11.Config{
        LibraryPath: "/usr/lib/hsm.so",
        SlotID:      0,
        PIN:         os.Getenv("SLOT0_PIN"),
    })
    if err != nil {
        return err
    }
    defer store0.Close(ctx)

    // Backend for slot 1
    store1, err := pkcs11.NewBackend(&pkcs11.Config{
        LibraryPath: "/usr/lib/hsm.so",
        SlotID:      1,
        PIN:         os.Getenv("SLOT1_PIN"),
    })
    if err != nil {
        return err
    }
    defer store1.Close(ctx)

    // Use different slots for different purposes
    return nil
}
```

## Vendor-Specific Guides

### Thales nShield

```go
config := &pkcs11.Config{
    LibraryPath: "/opt/nfast/toolkits/pkcs11/libcknfast.so",
    SlotID:      1,
    PIN:         os.Getenv("NSHIELD_PIN"),
}
```

### Utimaco SecurityServer

```go
config := &pkcs11.Config{
    LibraryPath: "/usr/lib/libcs_pkcs11_R2.so",
    TokenLabel:  "utimaco-token",
    PIN:         os.Getenv("UTIMACO_PIN"),
}
```

### AWS CloudHSM

```go
config := &pkcs11.Config{
    LibraryPath: "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
    SlotID:      1,
    PIN:         fmt.Sprintf("%s:%s", username, password),
}
```

### YubiKey PIV

```go
config := &pkcs11.Config{
    LibraryPath: "/usr/local/lib/libykcs11.so",
    SlotID:      0,
    PIN:         "123456", // Default PIN
}
```

### Nitrokey HSM

```go
config := &pkcs11.Config{
    LibraryPath: "/usr/lib/opensc-pkcs11.so",
    TokenLabel:  "SmartCard-HSM",
    PIN:         os.Getenv("NITROKEY_PIN"),
}
```

## Integration Testing

### Running Integration Tests

The PKCS#11 backend has full integration test coverage using Docker and SoftHSM:

```bash
# Run PKCS#11 integration tests (recommended)
make integration-test-pkcs11

# This executes tests in Docker with SoftHSM configured
# Tests all supported algorithms: RSA 2048/3072/4096, ECDSA P-256/P-384/P-521
# Part of the full integration test suite (151/151 tests passing)
```

### Docker-based Testing

The integration tests use Docker Compose for isolated testing:

```bash
# View test configuration
cat test/integration/pkcs11/docker-compose.yml

# Run tests manually
cd test/integration/pkcs11
docker-compose run --rm test
docker-compose down -v
```

### CI/CD Integration

```yaml
# GitHub Actions example
name: PKCS11 Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run PKCS#11 integration tests
        run: make integration-test-pkcs11
```

## Migration Guide

### From Software Keys to HSM

```go
// Step 1: Generate new keys in HSM
func migrateToHSM() error {
    ctx := context.Background()

    hsmStore, err := pkcs11.NewBackend(&pkcs11.Config{
        LibraryPath: "/usr/lib/hsm.so",
        TokenLabel:  "production",
        PIN:         os.Getenv("HSM_PIN"),
    })
    if err != nil {
        return err
    }
    defer hsmStore.Close(ctx)

    // Generate equivalent keys in HSM
    params := &backend.KeyParams{
        Algorithm: backend.AlgorithmRSA,
        KeySize:   2048,
    }

    if err := hsmStore.GenerateKey(ctx, "migrated-key", params); err != nil {
        return err
    }

    // Step 2: Update application to use HSM keys
    // Step 3: Re-sign/re-encrypt data with new keys
    // Step 4: Retire old software keys

    return nil
}
```

## Native Certificate Storage

The PKCS#11 backend supports storing certificates directly in the HSM alongside keys, providing hardware-backed certificate storage with tamper resistance.

### Certificate Storage Modes

**External Mode (Default):**
```go
// Certificates stored separately (traditional mode)
certStorage, _ := file.New("./certs")

backend, _ := pkcs11.NewBackend(&pkcs11.Config{
    Library:    "/usr/lib/softhsm/libsofthsm2.so",
    TokenLabel: "my-token",
    PIN:        "1234",
})
// Keys in HSM, certificates in files
```

**Hardware Mode:**
```go
// Certificates stored in HSM
backend, _ := pkcs11.NewBackend(&pkcs11.Config{
    Library:    "/usr/lib/softhsm/libsofthsm2.so",
    TokenLabel: "my-token",
    PIN:        "1234",
})

certConfig := &pkcs11.CertStorageConfig{
    Mode:                  hardware.CertStorageModeHardware,
    EnableHardwareStorage: true,
    MaxCertificates:       100,
}

certStorage, _ := backend.CreateCertificateStorage(certConfig)
// Both keys and certificates in HSM
```

**Hybrid Mode:**
```go
// Automatic failover between hardware and external storage
externalStorage, _ := file.New("./certs")

certConfig := &pkcs11.CertStorageConfig{
    Mode:                  hardware.CertStorageModeHybrid,
    ExternalStorage:       externalStorage,
    EnableHardwareStorage: true,
    MaxCertificates:       50,
}

certStorage, _ := backend.CreateCertificateStorage(certConfig)
// Writes go to hardware first, fall back to external on capacity errors
```

### Certificate Operations

```go
// Store certificate in HSM
cert, _ := x509.ParseCertificate(certDER)
err := certStorage.SaveCert("example.com", cert)

// Retrieve certificate from HSM
cert, err := certStorage.GetCert("example.com")

// Store certificate chain
chain := []*x509.Certificate{leafCert, intermediateCert, rootCert}
err = certStorage.SaveCertChain("example.com", chain)

// Check capacity
if hwStorage, ok := certStorage.(hardware.HardwareCertStorage); ok {
    total, available, _ := hwStorage.GetCapacity()
    log.Printf("HSM capacity: %d/%d used", total-available, total)
}
```

### Hardware Requirements

**Capacity Planning:**
- Typical HSM capacity: 100-10,000 certificate objects
- Each certificate consumes one object slot
- Monitor capacity to prevent token exhaustion
- Set `MaxCertificates` conservatively

**Performance:**
- SaveCert: ~50ms (HSM latency)
- GetCert: ~20ms (HSM read latency)
- ListCerts: ~100ms (object enumeration)
- Slower than file storage but hardware-protected

**Best Practices:**
- Use hardware storage for CA certificates and high-value certificates
- Use hybrid mode for production systems (automatic overflow)
- Monitor capacity periodically
- Use external storage for bulk certificates
- Enable hardware storage only when security requirements justify the cost

See [Certificate Management Guide](../certificate-management.md) for detailed information on certificate storage configuration and best practices.

## Limitations

The PKCS#11 backend has the following limitations:

- Ed25519 not widely supported across PKCS#11 devices
- Performance depends on HSM hardware capabilities
- Requires vendor-specific PKCS#11 libraries
- Some HSMs require licensed features for full functionality
- Session limits vary by device
- Key attribute support varies by vendor
- Device-specific quirks and workarounds may be needed
- Certificate storage capacity limited by HSM token memory
- Not all HSMs support certificate deletion

For software-based key storage without HSM requirements, consider the PKCS#8 backend. For cloud-based HSM solutions, consider AWS KMS, GCP KMS, or Azure Key Vault backends.

## References

- [PKCS#11 Specification](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html)
- [crypto11 Library](https://github.com/ThalesIgnite/crypto11)
- [SoftHSM Documentation](https://www.opendnssec.org/softhsm/)
- [PKCS#11 Tools](https://github.com/OpenSC/OpenSC/wiki)
- [YubiKey PIV](https://developers.yubico.com/PIV/)
