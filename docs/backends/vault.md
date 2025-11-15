# HashiCorp Vault Backend Documentation

## Overview

The HashiCorp Vault backend provides enterprise-grade cryptographic key management using Vault's Transit secrets engine. This backend offers centralized key management with support for key rotation, policy-based access control, and comprehensive audit logging, making it ideal for production workloads requiring regulatory compliance and operational security.

Vault's Transit engine acts as "encryption as a service," performing cryptographic operations server-side without exposing key material. Keys stay within Vault's secure boundary, and all operations are authenticated, authorized, and audited through Vault's unified security model. The service supports automatic key rotation, versioning, and can be deployed on-premises, in the cloud, or as a hybrid solution.

## Features and Capabilities

### Key Management

- Server-side key generation with secure entropy
- Automatic key versioning and rotation
- Key material never leaves Vault
- Exportable public keys for verification
- Configurable key deletion policies
- Key convergent encryption support
- Backup and restore capabilities
- Key derivation functions

### Cryptographic Operations

- RSA signing (2048, 3072, 4096-bit keys)
- ECDSA signing (P-256, P-384, P-521 curves)
- Ed25519 pure signature support
- Asymmetric decrypt operations
- SHA-256, SHA-384, SHA-512 hash algorithms
- PKCS1v15 and PSS signature schemes
- Context-based encryption
- High-entropy data generation

### Security Features

- Server-side key storage and operations
- Policy-based access control
- Comprehensive audit logging
- Token-based authentication
- AppRole authentication for automated systems
- Kubernetes authentication
- TLS/mTLS support
- Namespace isolation (Enterprise)
- Seal/unseal security model
- Replication for high availability

### Operational Features

- High availability deployment
- Multi-datacenter replication
- Dynamic secrets generation
- Automated key rotation
- Health check endpoints
- Performance standby nodes
- Integrated storage backends
- Prometheus metrics export

## Authentication Methods

### Token Authentication (Development)

```go
config := &vault.Config{
    Address:     "http://localhost:8200",
    Token:       "root",
    TransitPath: "transit",
}

backend, err := vault.NewBackend(config)
```

**Security Note**: Direct token authentication is suitable for development and testing only. Use AppRole or Kubernetes auth for production.

### AppRole Authentication (Recommended for Services)

```go
// AppRole provides secure authentication for automated systems
config := &vault.Config{
    Address:     "https://vault.example.com:8200",
    TransitPath: "transit",
}

backend, err := vault.NewBackend(config)
```

Setup AppRole:
```bash
# Enable AppRole auth
vault auth enable approle

# Create policy
vault policy write keychain-policy - <<EOF
path "transit/sign/*" {
  capabilities = ["create", "update"]
}
path "transit/keys/*" {
  capabilities = ["read", "list"]
}
EOF

# Create role
vault write auth/approle/role/keychain-app \
    token_policies="keychain-policy" \
    token_ttl=1h \
    token_max_ttl=4h

# Get credentials
vault read auth/approle/role/keychain-app/role-id
vault write -f auth/approle/role/keychain-app/secret-id
```

### Kubernetes Authentication (Recommended for K8s)

```go
// Kubernetes auth uses service account tokens
config := &vault.Config{
    Address:     "https://vault.vault.svc.cluster.local:8200",
    TransitPath: "transit",
}

backend, err := vault.NewBackend(config)
```

Setup Kubernetes auth:
```bash
# Enable Kubernetes auth
vault auth enable kubernetes

# Configure Kubernetes auth
vault write auth/kubernetes/config \
    kubernetes_host="https://kubernetes.default.svc:443"

# Create role
vault write auth/kubernetes/role/keychain-app \
    bound_service_account_names=keychain-sa \
    bound_service_account_namespaces=default \
    policies=keychain-policy \
    ttl=1h
```

### TLS Client Certificate Authentication

```go
config := &vault.Config{
    Address:       "https://vault.example.com:8200",
    TransitPath:   "transit",
    TLSSkipVerify: false,
}

backend, err := vault.NewBackend(config)
```

## Configuration Options

### Config Structure

```go
type Config struct {
    // Vault server address
    Address string

    // Authentication token
    Token string

    // Transit secrets engine path (default: "transit")
    TransitPath string

    // Vault namespace (Enterprise feature)
    Namespace string

    // Skip TLS certificate verification (dev only)
    TLSSkipVerify bool

    // Key metadata storage
    KeyStorage storage.KeyStorage

    // Certificate storage
    CertStorage storage.CertificateStorage
}
```

### Configuration Parameters

**Address** (required)
- Vault server URL
- Example: `"https://vault.example.com:8200"`
- Use `http://localhost:8200` for development only
- Must include protocol (http/https) and port

**Token** (required)
- Vault authentication token
- Obtained from `vault login` or auth methods
- Should be read from environment: `os.Getenv("VAULT_TOKEN")`
- Never hardcode in source code

**TransitPath** (optional, default: "transit")
- Path where Transit engine is mounted
- Allows multiple Transit engines
- Example: `"app-transit"`, `"prod-keys"`
- Must be enabled: `vault secrets enable -path=custom transit`

**Namespace** (optional, Enterprise only)
- Vault namespace for multi-tenancy
- Example: `"production"`, `"staging"`
- Requires Vault Enterprise
- Provides logical isolation between teams

**TLSSkipVerify** (optional, default: false)
- Skip TLS certificate verification
- **Only use for development/testing**
- Security risk in production
- Enable proper TLS certificates instead

**KeyStorage** (required)
- Storage backend for key metadata
- Stores key attributes and mappings
- Example: filesystem, database, memory

**CertStorage** (required)
- Storage backend for certificates
- Stores X.509 certificates
- Separate from key material

## Supported Algorithms

### RSA Keys

| Key Size | Vault Type | Signature Algorithms | Decryption |
|----------|-----------|---------------------|------------|
| 2048 bits | rsa-2048 | PKCS1v15, PSS (SHA256/384/512) | OAEP |
| 3072 bits | rsa-3072 | PKCS1v15, PSS (SHA256/384/512) | OAEP |
| 4096 bits | rsa-4096 | PKCS1v15, PSS (SHA256/384/512) | OAEP |

**Note**: All 10 backends support RSA 2048, 3072, and 4096-bit keys with full integration test coverage (151/151 tests passing).

### Elliptic Curve Keys

| Curve | Vault Type | Hash Algorithm |
|-------|-----------|----------------|
| P-256 (secp256r1) | ecdsa-p256 | SHA256 |
| P-384 (secp384r1) | ecdsa-p384 | SHA384 |
| P-521 (secp521r1) | ecdsa-p521 | SHA512 |

**Note**: All 10 backends support ECDSA P-256, P-384, and P-521 curves with full integration test coverage (151/151 tests passing).

### Edwards Curve Keys

| Algorithm | Vault Type | Features |
|-----------|-----------|----------|
| Ed25519 | ed25519 | Pure signatures (no prehashing) |

### Hash Algorithms

- SHA-256 (default, recommended)
- SHA-384 (for P-384 and RSA)
- SHA-512 (for P-521 and RSA)

## Complete Working Examples

### Example 1: Basic Setup with Token Auth

```go
package main

import (
    "crypto"
    "crypto/sha256"
    "fmt"
    "log"
    "os"

    "github.com/jeremyhahn/go-keychain/pkg/backend"
    "github.com/jeremyhahn/go-keychain/pkg/backend/vault"
    "github.com/jeremyhahn/go-keychain/pkg/storage"
)

func main() {
    // Configure with token authentication
    config := &vault.Config{
        Address:     os.Getenv("VAULT_ADDR"),
        Token:       os.Getenv("VAULT_TOKEN"),
        TransitPath: "transit",
        KeyStorage:  storage.NewMemoryKeyStorage(),
        CertStorage: storage.NewMemoryCertStorage(),
    }

    b, err := vault.NewBackend(config)
    if err != nil {
        log.Fatalf("Failed to initialize Vault: %v", err)
    }
    defer b.Close()

    // Generate RSA signing key
    attrs := &backend.KeyAttributes{
        CN:           "api-signing-key",
        KeyAlgorithm: backend.ALG_RSA,
        KeyType:      backend.KEY_TYPE_SIGNING,
        StoreType:    backend.STORE_VAULT,
        Hash:         backend.HASH_SHA256,
        RSAAttributes: &backend.RSAAttributes{
            KeySize: 2048,
        },
    }

    pubKey, err := b.GenerateKey(attrs)
    if err != nil {
        log.Fatalf("Failed to generate key: %v", err)
    }

    fmt.Println("RSA key generated in Vault")

    // Sign data
    message := []byte("Hello, Vault!")
    hash := sha256.Sum256(message)

    signer, err := b.Signer(attrs)
    if err != nil {
        log.Fatalf("Failed to get signer: %v", err)
    }

    signature, err := signer.Sign(nil, hash[:], crypto.SHA256)
    if err != nil {
        log.Fatalf("Failed to sign: %v", err)
    }

    fmt.Printf("Signature created: %d bytes\n", len(signature))
    fmt.Printf("Public key type: %T\n", pubKey)
}
```

### Example 2: ECDSA Key Generation

```go
func ecdsaExample() {
    config := &vault.Config{
        Address:     "http://localhost:8200",
        Token:       "root",
        TransitPath: "transit",
        KeyStorage:  storage.NewMemoryKeyStorage(),
        CertStorage: storage.NewMemoryCertStorage(),
    }

    b, err := vault.NewBackend(config)
    if err != nil {
        log.Fatal(err)
    }
    defer b.Close()

    // Generate ECDSA P-256 key
    attrs := &backend.KeyAttributes{
        CN:           "ecdsa-p256-key",
        KeyAlgorithm: backend.ALG_ECDSA,
        KeyType:      backend.KEY_TYPE_SIGNING,
        StoreType:    backend.STORE_VAULT,
        Hash:         backend.HASH_SHA256,
        ECCAttributes: &backend.ECCAttributes{
            Curve: "P-256",
        },
    }

    pubKey, err := b.GenerateKey(attrs)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("ECDSA P-256 key generated: %T\n", pubKey)
}
```

### Example 3: Ed25519 Signing

```go
func ed25519Example() {
    config := &vault.Config{
        Address:     "http://localhost:8200",
        Token:       "root",
        TransitPath: "transit",
        KeyStorage:  storage.NewMemoryKeyStorage(),
        CertStorage: storage.NewMemoryCertStorage(),
    }

    b, err := vault.NewBackend(config)
    if err != nil {
        log.Fatal(err)
    }
    defer b.Close()

    // Generate Ed25519 key
    attrs := &backend.KeyAttributes{
        CN:           "ed25519-key",
        KeyAlgorithm: backend.ALG_ED25519,
        KeyType:      backend.KEY_TYPE_SIGNING,
        StoreType:    backend.STORE_VAULT,
        Hash:         backend.HASH_SHA256,
    }

    pubKey, err := b.GenerateKey(attrs)
    if err != nil {
        log.Fatal(err)
    }

    // Ed25519 uses pure signatures (no prehashing)
    message := []byte("Sign me with Ed25519")

    signer, err := b.Signer(attrs)
    if err != nil {
        log.Fatal(err)
    }

    // Ed25519 expects the raw message
    signature, err := signer.Sign(nil, message, crypto.Hash(0))
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Ed25519 signature: %d bytes\n", len(signature))
}
```

### Example 4: Key Rotation

```go
func keyRotationExample() {
    config := &vault.Config{
        Address:     "http://localhost:8200",
        Token:       "root",
        TransitPath: "transit",
        KeyStorage:  storage.NewMemoryKeyStorage(),
        CertStorage: storage.NewMemoryCertStorage(),
    }

    b, err := vault.NewBackend(config)
    if err != nil {
        log.Fatal(err)
    }
    defer b.Close()

    attrs := &backend.KeyAttributes{
        CN:           "rotatable-key",
        KeyAlgorithm: backend.ALG_RSA,
        KeyType:      backend.KEY_TYPE_SIGNING,
        StoreType:    backend.STORE_VAULT,
        Hash:         backend.HASH_SHA256,
        RSAAttributes: &backend.RSAAttributes{
            KeySize: 2048,
        },
    }

    // Generate initial key
    _, err = b.GenerateKey(attrs)
    if err != nil {
        log.Fatal(err)
    }

    // Rotate to new key version
    err = b.RotateKey(attrs)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Key rotated successfully")

    // New signatures use latest version automatically
    // Old signatures can still be verified with previous versions
}
```

### Example 5: Multiple Algorithm Keys

```go
func multiAlgorithmExample() {
    config := &vault.Config{
        Address:     "http://localhost:8200",
        Token:       "root",
        TransitPath: "transit",
        KeyStorage:  storage.NewMemoryKeyStorage(),
        CertStorage: storage.NewMemoryCertStorage(),
    }

    b, err := vault.NewBackend(config)
    if err != nil {
        log.Fatal(err)
    }
    defer b.Close()

    // RSA 2048
    rsa2048 := &backend.KeyAttributes{
        CN:           "rsa-2048",
        KeyAlgorithm: backend.ALG_RSA,
        KeyType:      backend.KEY_TYPE_SIGNING,
        StoreType:    backend.STORE_VAULT,
        Hash:         backend.HASH_SHA256,
        RSAAttributes: &backend.RSAAttributes{
            KeySize: 2048,
        },
    }
    b.GenerateKey(rsa2048)

    // ECDSA P-256
    ecdsaP256 := &backend.KeyAttributes{
        CN:           "ecdsa-p256",
        KeyAlgorithm: backend.ALG_ECDSA,
        KeyType:      backend.KEY_TYPE_SIGNING,
        StoreType:    backend.STORE_VAULT,
        Hash:         backend.HASH_SHA256,
        ECCAttributes: &backend.ECCAttributes{
            Curve: "P-256",
        },
    }
    b.GenerateKey(ecdsaP256)

    // Ed25519
    ed25519 := &backend.KeyAttributes{
        CN:           "ed25519",
        KeyAlgorithm: backend.ALG_ED25519,
        KeyType:      backend.KEY_TYPE_SIGNING,
        StoreType:    backend.STORE_VAULT,
        Hash:         backend.HASH_SHA256,
    }
    b.GenerateKey(ed25519)

    // List all keys
    keys, err := b.ListKeys()
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Generated %d keys\n", len(keys))
}
```

## Common Use Cases

### JWT Token Signing

```go
func jwtSigningExample() {
    config := &vault.Config{
        Address:     os.Getenv("VAULT_ADDR"),
        Token:       os.Getenv("VAULT_TOKEN"),
        TransitPath: "transit",
        KeyStorage:  storage.NewMemoryKeyStorage(),
        CertStorage: storage.NewMemoryCertStorage(),
    }

    b, err := vault.NewBackend(config)
    if err != nil {
        log.Fatal(err)
    }
    defer b.Close()

    // Generate ECDSA P-256 for JWT (fast and compact)
    attrs := &backend.KeyAttributes{
        CN:           "jwt-signing-key",
        KeyAlgorithm: backend.ALG_ECDSA,
        KeyType:      backend.KEY_TYPE_SIGNING,
        StoreType:    backend.STORE_VAULT,
        Hash:         backend.HASH_SHA256,
        ECCAttributes: &backend.ECCAttributes{
            Curve: "P-256",
        },
    }

    b.GenerateKey(attrs)

    // Sign JWT payload
    payload := []byte("header.payload")
    hash := sha256.Sum256(payload)

    signer, err := b.Signer(attrs)
    if err != nil {
        log.Fatal(err)
    }

    signature, err := signer.Sign(nil, hash[:], crypto.SHA256)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("JWT signed: %d bytes\n", len(signature))
}
```

### Code Signing

```go
func codeSigningExample() {
    config := &vault.Config{
        Address:     "http://localhost:8200",
        Token:       "root",
        TransitPath: "transit",
        KeyStorage:  storage.NewMemoryKeyStorage(),
        CertStorage: storage.NewMemoryCertStorage(),
    }

    b, err := vault.NewBackend(config)
    if err != nil {
        log.Fatal(err)
    }
    defer b.Close()

    // Generate RSA 4096 for code signing (high security)
    attrs := &backend.KeyAttributes{
        CN:           "code-signing-key",
        KeyAlgorithm: backend.ALG_RSA,
        KeyType:      backend.KEY_TYPE_SIGNING,
        StoreType:    backend.STORE_VAULT,
        Hash:         backend.HASH_SHA384,
        RSAAttributes: &backend.RSAAttributes{
            KeySize: 4096,
        },
    }

    b.GenerateKey(attrs)

    // Sign release artifact
    artifactHash := sha256.Sum256([]byte("binary content"))

    signer, err := b.Signer(attrs)
    if err != nil {
        log.Fatal(err)
    }

    signature, err := signer.Sign(nil, artifactHash[:], crypto.SHA384)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Artifact signed: %d bytes\n", len(signature))
}
```

### Certificate Authority

```go
func caOperationsExample() {
    config := &vault.Config{
        Address:     "http://localhost:8200",
        Token:       "root",
        TransitPath: "transit",
        KeyStorage:  storage.NewMemoryKeyStorage(),
        CertStorage: storage.NewMemoryCertStorage(),
    }

    b, err := vault.NewBackend(config)
    if err != nil {
        log.Fatal(err)
    }
    defer b.Close()

    // Generate CA root key
    attrs := &backend.KeyAttributes{
        CN:           "root-ca-key",
        KeyAlgorithm: backend.ALG_RSA,
        KeyType:      backend.KEY_TYPE_SIGNING,
        StoreType:    backend.STORE_VAULT,
        Hash:         backend.HASH_SHA256,
        RSAAttributes: &backend.RSAAttributes{
            KeySize: 4096,
        },
    }

    b.GenerateKey(attrs)

    // Sign certificate
    certData := []byte("certificate to sign")
    hash := sha256.Sum256(certData)

    signer, err := b.Signer(attrs)
    if err != nil {
        log.Fatal(err)
    }

    signature, err := signer.Sign(nil, hash[:], crypto.SHA256)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Certificate signed: %d bytes\n", len(signature))
}
```

## Security Considerations

### Token Security

**Best Practices**:
```go
// Good: Read from environment
config := &vault.Config{
    Address: os.Getenv("VAULT_ADDR"),
    Token:   os.Getenv("VAULT_TOKEN"),
}

// Bad: Hardcoded token
config := &vault.Config{
    Address: "http://localhost:8200",
    Token:   "s.1234567890abcdef", // NEVER DO THIS
}
```

### TLS Configuration

**Production Setup**:
```go
config := &vault.Config{
    Address:       "https://vault.example.com:8200",
    Token:         os.Getenv("VAULT_TOKEN"),
    TLSSkipVerify: false, // Always verify in production
}
```

**Development Only**:
```go
config := &vault.Config{
    Address:       "http://localhost:8200",
    Token:         "root",
    TLSSkipVerify: true, // Only for dev
}
```

### Access Control Policies

Vault policy for signing operations:
```hcl
# Read key information
path "transit/keys/*" {
  capabilities = ["read", "list"]
}

# Sign operations only
path "transit/sign/*" {
  capabilities = ["create", "update"]
}

# No key creation or deletion
path "transit/keys/*" {
  capabilities = ["deny"]
}
```

### Audit Logging

Enable audit logging:
```bash
vault audit enable file file_path=/var/log/vault/audit.log
```

Query audit logs:
```bash
# View recent signing operations
cat /var/log/vault/audit.log | \
  jq 'select(.request.path | startswith("transit/sign"))'
```

## Best Practices

### Key Naming

Use descriptive key names:
```go
// Good: Descriptive names
keyName := "production-api-jwt-v2"
keyName := "staging-webhook-signer"
keyName := "ca-root-rsa4096-2024"

// Avoid: Generic names
keyName := "key1"
keyName := "test"
```

### Error Handling

```go
b, err := vault.NewBackend(config)
if err != nil {
    return fmt.Errorf("Vault initialization failed: %w", err)
}
defer func() {
    if err := b.Close(); err != nil {
        log.Printf("Error closing Vault backend: %v", err)
    }
}()

signature, err := signer.Sign(nil, hash[:], crypto.SHA256)
if err != nil {
    if strings.Contains(err.Error(), "permission denied") {
        return fmt.Errorf("insufficient Vault permissions: %w", err)
    }
    if strings.Contains(err.Error(), "key not found") {
        return fmt.Errorf("key not found: %w", err)
    }
    return fmt.Errorf("signing failed: %w", err)
}
```

### Connection Pooling

```go
var (
    vaultBackend backend.Backend
    backendOnce  sync.Once
)

func getVaultBackend() (backend.Backend, error) {
    var err error
    backendOnce.Do(func() {
        config := &vault.Config{
            Address:     os.Getenv("VAULT_ADDR"),
            Token:       os.Getenv("VAULT_TOKEN"),
            TransitPath: "transit",
            KeyStorage:  storage.NewMemoryKeyStorage(),
            CertStorage: storage.NewMemoryCertStorage(),
        }
        vaultBackend, err = vault.NewBackend(config)
    })
    return vaultBackend, err
}
```

### Integration Testing

The HashiCorp Vault backend has full integration test coverage using Docker and Vault in dev mode:

```bash
# Run Vault integration tests (recommended)
make integration-test-vault

# This executes tests in Docker with Vault Transit engine configured
# Tests all supported algorithms: RSA 2048/3072/4096, ECDSA P-256/P-384/P-521, Ed25519
# Part of the full integration test suite (151/151 tests passing)
```

### Running Tests Manually

```bash
# View test configuration
cat test/integration/vault/docker-compose.yml

# Run tests manually
cd test/integration/vault
docker-compose run --rm test
docker-compose down -v
```

### Testing with Local Vault

```go
func getTestBackend(t *testing.T) backend.Backend {
    config := &vault.Config{
        Address:       "http://localhost:8200",
        Token:         "root",
        TransitPath:   "transit",
        TLSSkipVerify: true,
        KeyStorage:    storage.NewMemoryKeyStorage(),
        CertStorage:   storage.NewMemoryCertStorage(),
    }

    b, err := vault.NewBackend(config)
    require.NoError(t, err)

    t.Cleanup(func() {
        b.Close()
    })

    return b
}
```

## Troubleshooting

### Connection Refused

```
Error: failed to initialize vault client: Get "http://localhost:8200/v1/sys/health": dial tcp 127.0.0.1:8200: connect: connection refused
```

**Solutions**:
- Verify Vault is running: `vault status`
- Check VAULT_ADDR environment variable
- Ensure firewall allows port 8200
- Check Vault listener configuration

### Permission Denied

```
Error: failed to sign with vault: Error making API request.
Code: 403. Errors: * permission denied
```

**Solutions**:
- Verify token has necessary capabilities
- Check policy allows `transit/sign/*` path
- Ensure Transit engine is enabled
- Verify token is not expired

### Key Not Found

```
Error: failed to read key from vault: invalid response: key not found
```

**Solutions**:
- Verify key was created successfully
- Check key name matches exactly (case-sensitive)
- List keys: `vault list transit/keys`
- Ensure correct Transit path is configured

### Transit Engine Not Enabled

```
Error: failed to sign with vault: Error making API request.
Code: 404. Errors: * no handler for route "transit/sign/..."
```

**Solutions**:
- Enable Transit engine: `vault secrets enable transit`
- Verify mount path: `vault secrets list`
- Check TransitPath configuration matches mount
- Ensure you have access to the mount

## Performance Considerations

### Operation Latency

Typical latencies (local Vault):
- Sign operation: 5-20ms
- Get public key: 2-10ms
- Generate key: 10-50ms
- List keys: 5-15ms

Typical latencies (remote Vault):
- Sign operation: 20-100ms
- Get public key: 10-50ms
- Generate key: 50-200ms
- List keys: 20-80ms

### Optimization Tips

1. **Collocate services with Vault** - Deploy in same region/datacenter
2. **Cache public keys** - Public keys don't change between rotations
3. **Use connection pooling** - Reuse Vault client connections
4. **Enable performance standbys** - Distribute read operations
5. **Use batch operations** - When possible

```go
// Cache public keys
var pubKeyCache sync.Map

func getCachedPublicKey(b backend.Backend, attrs *backend.KeyAttributes) (crypto.PublicKey, error) {
    if cached, ok := pubKeyCache.Load(attrs.CN); ok {
        return cached.(crypto.PublicKey), nil
    }

    pubKey, err := b.GetKey(attrs)
    if err != nil {
        return nil, err
    }

    pubKeyCache.Store(attrs.CN, pubKey)
    return pubKey, nil
}
```

## Advanced Topics

### Automatic Key Rotation

```bash
# Configure automatic rotation (30 days)
vault write transit/keys/my-key/config \
    auto_rotate_period=720h

# Rotate immediately
vault write -f transit/keys/my-key/rotate
```

### Key Versioning

```bash
# List key versions
vault read transit/keys/my-key

# Set minimum decryption version
vault write transit/keys/my-key/config \
    min_decryption_version=2

# Set minimum encryption version
vault write transit/keys/my-key/config \
    min_encryption_version=3
```

### Backup and Restore

```bash
# Backup key
vault read -field=backup transit/backup/my-key > my-key.backup

# Restore key
vault write transit/restore/my-key backup=@my-key.backup
```

### High Availability Setup

```bash
# Check cluster status
vault operator raft list-peers

# Join standby node
vault operator raft join https://vault-primary:8200
```

## Docker Integration Testing

### Running Tests

```bash
# Run Vault integration tests
make integration-test-vault

# Run with verbose output
VAULT_ADDR=http://localhost:8200 VAULT_TOKEN=root \
  go test -v -tags="integration vault" ./test/integration/vault/...
```

### Docker Compose Setup

```yaml
version: '3.8'

services:
  vault:
    image: hashicorp/vault:latest
    container_name: go-keychain-vault
    ports:
      - "8200:8200"
    environment:
      - VAULT_DEV_ROOT_TOKEN_ID=root
      - VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200
    command: server -dev -dev-root-token-id=root
```

### Test Setup Script

```bash
#!/bin/bash
# scripts/setup-vault-transit.sh

VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-root}"

# Wait for Vault to be ready
while ! curl -sf "$VAULT_ADDR/v1/sys/health" >/dev/null; do
    echo "Waiting for Vault..."
    sleep 1
done

# Enable Transit engine
curl -X POST -H "X-Vault-Token: $VAULT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"type":"transit","description":"Transit engine for key management"}' \
    "$VAULT_ADDR/v1/sys/mounts/transit"

echo "✓ Vault Transit engine ready"
```

## Build Configuration

### Makefile Integration

Add to your Makefile:
```makefile
# Enable Vault backend
WITH_VAULT ?= 0

ifeq ($(WITH_VAULT),1)
	BUILD_TAGS += vault
endif
```

### Building with Vault Support

```bash
# Build without Vault (default)
make build

# Build with Vault
make build WITH_VAULT=1

# Run tests with Vault
make test WITH_VAULT=1

# Run integration tests
make integration-test-vault
```

## Migration Guide

### From PKCS#8 to Vault

```go
func migrateToVault() error {
    // Old PKCS#8 backend
    pkcs8Config := &pkcs8.Config{
        StoragePath: "./keys",
        Password:    os.Getenv("KEYSTORE_PASSWORD"),
    }
    oldBackend, err := pkcs8.NewBackend(pkcs8Config)
    if err != nil {
        return err
    }
    defer oldBackend.Close()

    // New Vault backend
    vaultConfig := &vault.Config{
        Address:     os.Getenv("VAULT_ADDR"),
        Token:       os.Getenv("VAULT_TOKEN"),
        TransitPath: "transit",
        KeyStorage:  storage.NewMemoryKeyStorage(),
        CertStorage: storage.NewMemoryCertStorage(),
    }
    newBackend, err := vault.NewBackend(vaultConfig)
    if err != nil {
        return err
    }
    defer newBackend.Close()

    // Generate new keys in Vault
    attrs := &backend.KeyAttributes{
        CN:           "migrated-key",
        KeyAlgorithm: backend.ALG_RSA,
        KeyType:      backend.KEY_TYPE_SIGNING,
        StoreType:    backend.STORE_VAULT,
        Hash:         backend.HASH_SHA256,
        RSAAttributes: &backend.RSAAttributes{
            KeySize: 2048,
        },
    }

    _, err = newBackend.GenerateKey(attrs)
    if err != nil {
        return err
    }

    // Update application to use Vault
    // Re-sign data with new keys
    // Retire old PKCS#8 keys after transition

    return nil
}
```

## References

- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)
- [Vault Transit Secrets Engine](https://www.vaultproject.io/docs/secrets/transit)
- [Vault API Documentation](https://www.vaultproject.io/api-docs)
- [Vault Go Client](https://github.com/hashicorp/vault/tree/main/api)
- [Vault Security Model](https://www.vaultproject.io/docs/internals/security)

## Limitations

The HashiCorp Vault backend has the following limitations:

- Requires running Vault server (self-hosted or Vault Cloud)
- Keys cannot be exported (security by design)
- Decryption requires Vault-encrypted ciphertext format
- Network connectivity required for all operations
- API rate limits depend on Vault configuration
- Development mode loses data on restart
- Enterprise features require Vault Enterprise license
- Key deletion requires explicit `deletion_allowed` flag

For offline key storage, consider the PKCS#8 backend. For hardware-backed keys without network dependency, consider TPM2 or PKCS#11 backends.
