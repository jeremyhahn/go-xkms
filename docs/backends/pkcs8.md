# PKCS#8 Backend Documentation

## Overview

The PKCS#8 backend provides software-based key storage using the industry-standard PKCS#8 private key format. This backend stores private keys encrypted on disk using PKCS#8 EncryptedPrivateKeyInfo structure with PBKDF2 key derivation and AES-256-CBC encryption.

PKCS#8 (Public-Key Cryptography Standards #8) is a standard syntax for storing private key information. The go-keychain PKCS#8 backend implements secure software-based key management suitable for development, testing, and production environments where hardware security modules are not required.

## Features and Capabilities

### Key Storage
- Encrypted private key storage using PKCS#8 format
- Password-based encryption using PBKDF2-HMAC-SHA256
- AES-256-CBC encryption for private key data
- Configurable iteration count for key derivation
- File-based persistence with secure permissions

### Cryptographic Operations
- Key generation for multiple algorithm types
- Digital signature creation and verification
- Public key export
- Key identifier management

### Supported Algorithms

#### RSA
- Key sizes: 2048, 3072, 4096, 6144, 8192 bits
- Signature schemes: PKCS#1 v1.5, PSS
- Hash functions: SHA-256, SHA-384, SHA-512

#### ECDSA
- Curves: P-256 (secp256r1), P-384 (secp384r1), P-521 (secp521r1)
- Hash functions: SHA-256, SHA-384, SHA-512

#### Ed25519
- Edwards-curve Digital Signature Algorithm
- Fixed 256-bit keys
- Native Ed25519 signatures

## Configuration Options

### Config Structure

```go
type Config struct {
    StoragePath string // Directory path for key storage
    Password    string // Password for key encryption
    Iterations  int    // PBKDF2 iteration count (default: 100,000)
}
```

### Configuration Parameters

**StoragePath** (required)
- Directory where encrypted private keys will be stored
- Must be writable by the application
- Should use restrictive file permissions (0700 recommended)
- Example: `/var/lib/keychain/pkcs8` or `./keys`

**Password** (required)
- Password used to encrypt and decrypt private keys
- Should be cryptographically strong (minimum 16 characters recommended)
- Used with PBKDF2 for key derivation
- Consider using environment variables or secret management systems

**Iterations** (optional)
- PBKDF2 iteration count for key derivation
- Default: 100,000 iterations
- Higher values increase security but slow down key operations
- Recommended range: 100,000 - 1,000,000

## Complete Working Example

```go
package main

import (
    "context"
    "crypto"
    "crypto/rand"
    "crypto/sha256"
    "fmt"
    "log"
    "os"

    "github.com/jeremyhahn/go-keychain/pkg/backend"
    "github.com/jeremyhahn/go-keychain/pkg/pkcs8"
)

func main() {
    ctx := context.Background()

    // Create storage directory
    storagePath := "./keychain-data"
    if err := os.MkdirAll(storagePath, 0700); err != nil {
        log.Fatalf("Failed to create storage directory: %v", err)
    }

    // Initialize PKCS#8 backend
    config := &pkcs8.Config{
        StoragePath: storagePath,
        Password:    "strong-password-here", // Use secure password management
        Iterations:  100000,                  // Optional, this is the default
    }

    store, err := pkcs8.NewBackend(config)
    if err != nil {
        log.Fatalf("Failed to initialize backend: %v", err)
    }
    defer store.Close(ctx)

    // Example 1: Generate RSA key
    rsaKeyID := "my-rsa-key"
    rsaParams := &backend.KeyParams{
        Algorithm: backend.AlgorithmRSA,
        KeySize:   2048,
    }

    if err := store.GenerateKey(ctx, rsaKeyID, rsaParams); err != nil {
        log.Fatalf("Failed to generate RSA key: %v", err)
    }
    fmt.Println("RSA key generated successfully")

    // Example 2: Generate ECDSA key
    ecdsaKeyID := "my-ecdsa-key"
    ecdsaParams := &backend.KeyParams{
        Algorithm: backend.AlgorithmECDSA,
        Curve:     backend.CurveP256,
    }

    if err := store.GenerateKey(ctx, ecdsaKeyID, ecdsaParams); err != nil {
        log.Fatalf("Failed to generate ECDSA key: %v", err)
    }
    fmt.Println("ECDSA key generated successfully")

    // Example 3: Generate Ed25519 key
    ed25519KeyID := "my-ed25519-key"
    ed25519Params := &backend.KeyParams{
        Algorithm: backend.AlgorithmEd25519,
    }

    if err := store.GenerateKey(ctx, ed25519KeyID, ed25519Params); err != nil {
        log.Fatalf("Failed to generate Ed25519 key: %v", err)
    }
    fmt.Println("Ed25519 key generated successfully")

    // Example 4: Sign data with RSA key
    data := []byte("Hello, World!")
    hash := sha256.Sum256(data)

    signature, err := store.Sign(ctx, rsaKeyID, hash[:], crypto.SHA256)
    if err != nil {
        log.Fatalf("Failed to sign data: %v", err)
    }
    fmt.Printf("Signature created: %d bytes\n", len(signature))

    // Example 5: Get public key
    publicKey, err := store.GetPublicKey(ctx, rsaKeyID)
    if err != nil {
        log.Fatalf("Failed to get public key: %v", err)
    }
    fmt.Printf("Public key retrieved: %T\n", publicKey)

    // Example 6: List all keys
    keys, err := store.ListKeys(ctx)
    if err != nil {
        log.Fatalf("Failed to list keys: %v", err)
    }
    fmt.Printf("Total keys stored: %d\n", len(keys))
    for _, keyID := range keys {
        fmt.Printf("  - %s\n", keyID)
    }

    // Example 7: Delete a key
    if err := store.DeleteKey(ctx, rsaKeyID); err != nil {
        log.Fatalf("Failed to delete key: %v", err)
    }
    fmt.Println("Key deleted successfully")
}
```

## Common Use Cases

### Development and Testing

The PKCS#8 backend is ideal for development and testing environments:

```go
config := &pkcs8.Config{
    StoragePath: "./test-keys",
    Password:    "test-password",
    Iterations:  100000,
}
```

### CI/CD Pipelines

Use environment variables for secure configuration:

```go
config := &pkcs8.Config{
    StoragePath: os.Getenv("KEYSTORE_PATH"),
    Password:    os.Getenv("KEYSTORE_PASSWORD"),
    Iterations:  100000,
}
```

### Microservices Key Management

Each service can maintain its own key store:

```go
config := &pkcs8.Config{
    StoragePath: "/var/lib/myservice/keys",
    Password:    loadPasswordFromVault(),
    Iterations:  250000,
}
```

### Document Signing

Generate signing keys for document workflows:

```go
// Generate signing key
params := &backend.KeyParams{
    Algorithm: backend.AlgorithmRSA,
    KeySize:   4096,
}
store.GenerateKey(ctx, "document-signer", params)

// Sign document hash
signature, err := store.Sign(ctx, "document-signer", documentHash, crypto.SHA256)
```

### Certificate Authority Operations

Manage CA private keys securely:

```go
// Generate CA key
params := &backend.KeyParams{
    Algorithm: backend.AlgorithmECDSA,
    Curve:     backend.CurveP384,
}
store.GenerateKey(ctx, "root-ca", params)

// Sign certificate
signature, err := store.Sign(ctx, "root-ca", certHash, crypto.SHA384)
```

## Security Considerations

### Password Security

The security of the PKCS#8 backend depends heavily on password strength:

- Use cryptographically strong passwords (minimum 16 characters)
- Include uppercase, lowercase, numbers, and special characters
- Never hardcode passwords in source code
- Use environment variables or secret management systems
- Rotate passwords periodically
- Consider using key derivation from hardware security modules

### File System Permissions

Protect the storage directory with appropriate permissions:

```bash
mkdir -p /var/lib/keychain
chmod 700 /var/lib/keychain
chown myapp:myapp /var/lib/keychain
```

### Iteration Count

Higher PBKDF2 iteration counts increase resistance to brute-force attacks:

- Minimum: 100,000 iterations
- Recommended: 250,000 - 600,000 iterations
- High security: 1,000,000+ iterations
- Balance security with performance requirements
- Consider hardware capabilities when setting iteration count

### Memory Protection

Private keys are held in memory during operations:

- Ensure proper cleanup after use
- Use secure memory allocation where possible
- Monitor for memory dumps and core dumps
- Consider memory encryption in high-security environments

### Key Rotation

Implement regular key rotation policies:

```go
// Generate new key
newKeyID := fmt.Sprintf("%s-v%d", baseKeyID, version)
store.GenerateKey(ctx, newKeyID, params)

// Transition signing operations to new key
// ...

// Delete old key after transition period
store.DeleteKey(ctx, oldKeyID)
```

### Audit Logging

Implement comprehensive audit logging:

- Log all key generation events
- Log all signing operations
- Log key deletion events
- Include timestamps and user context
- Store logs securely with integrity protection

## Best Practices

### Configuration Management

Store configuration securely:

```go
// Use environment variables
config := &pkcs8.Config{
    StoragePath: os.Getenv("PKCS8_STORAGE_PATH"),
    Password:    os.Getenv("PKCS8_PASSWORD"),
    Iterations:  getIterationCount(),
}

// Or use configuration files with restricted permissions
config := loadConfigFromFile("/etc/myapp/keychain.conf")
```

### Error Handling

Always handle errors appropriately:

```go
store, err := pkcs8.NewBackend(config)
if err != nil {
    return fmt.Errorf("failed to initialize keychain: %w", err)
}
defer func() {
    if err := store.Close(ctx); err != nil {
        log.Printf("Error closing keychain: %v", err)
    }
}()
```

### Context Usage

Use context for cancellation and timeouts:

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

signature, err := store.Sign(ctx, keyID, digest, hashAlgo)
if err != nil {
    return fmt.Errorf("signing operation failed: %w", err)
}
```

### Key Naming

Use descriptive, consistent key identifiers:

```go
// Good: descriptive and hierarchical
keyID := "production.api.jwt-signer.v2"

// Avoid: generic or unclear names
keyID := "key1" // Bad
```

### Backup and Recovery

Implement backup procedures:

```bash
# Backup encrypted keys
tar -czf keychain-backup-$(date +%Y%m%d).tar.gz /var/lib/keychain/

# Store backups securely
gpg --encrypt --recipient admin@example.com keychain-backup-*.tar.gz
```

### Algorithm Selection

Choose algorithms appropriate for your use case:

- **RSA 2048-3072**: General purpose, legacy compatibility
- **RSA 4096+**: Long-term security, high-value signing
- **ECDSA P-256**: Modern systems, efficient operations
- **ECDSA P-384**: Government/regulated environments
- **Ed25519**: High performance, modern applications

### Performance Optimization

Optimize for your workload:

```go
// Cache store instances when possible
var (
    storeInstance backend.Backend
    storeOnce     sync.Once
)

func getStore() (backend.Backend, error) {
    var err error
    storeOnce.Do(func() {
        storeInstance, err = pkcs8.NewBackend(config)
    })
    return storeInstance, err
}
```

### Testing

Test key operations thoroughly:

```go
func TestKeyOperations(t *testing.T) {
    config := &pkcs8.Config{
        StoragePath: t.TempDir(),
        Password:    "test-password",
        Iterations:  10000, // Lower for testing
    }

    store, err := pkcs8.NewBackend(config)
    require.NoError(t, err)
    defer store.Close(context.Background())

    // Test key generation, signing, verification
}
```

### Migration Planning

Plan for future migrations:

- Document all keys and their purposes
- Maintain key metadata separately
- Version your key identifiers
- Test migration procedures in staging
- Plan for zero-downtime migrations

## Limitations

The PKCS#8 backend has the following limitations:

- Keys are software-based, not hardware-protected
- Private keys exist in memory during operations
- No FIPS 140-2 compliance without additional modules
- File system security depends on OS-level controls
- Password strength directly impacts security
- Not suitable for applications requiring moderate to high security

For applications requiring moderate to high levels of security, consider using the TPM or HSM backends instead.
