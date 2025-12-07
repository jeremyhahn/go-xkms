# go-keychain Examples

This directory contains comprehensive examples demonstrating the features and capabilities of the go-keychain library.

## Prerequisites

- Go 1.21 or later
- go-keychain library installed: `go get github.com/jeremyhahn/go-keychain`

## Directory Structure

```
examples/
├── basic/                  # Basic key generation and storage
├── signing/                # Signing and verification operations
├── certificates/           # Certificate management
├── tls/                   # TLS server and client setup
├── symmetric-encryption/  # Symmetric encryption (AES-GCM)
├── webauthn/              # WebAuthn/FIDO2 passwordless authentication
└── advanced/              # Advanced features and patterns
```

## Running Examples

All examples are self-contained and can be run directly:

```bash
cd examples/basic/generate-keys
go run main.go
```

Or from the repository root:

```bash
go run examples/basic/generate-keys/main.go
```

## Examples Overview

### Basic Examples

#### 1. Key Generation (`basic/generate-keys/`)

Demonstrates generating different types of cryptographic keys:
- RSA keys (2048, 4096 bits)
- ECDSA keys (P-256, P-384, P-521 curves)
- Ed25519 keys

**Run:**
```bash
go run examples/basic/generate-keys/main.go
```

**Expected Output:**
```
=== Key Generation Examples ===

1. Generating RSA-2048 key...
   ✓ RSA-2048 key generated: rsa-example-key

2. Generating RSA-4096 key...
   ✓ RSA-4096 key generated: rsa-4096-key

3. Generating ECDSA P-256 key...
   ✓ ECDSA P-256 key generated: ecdsa-p256-key

[...]
```

**Key Concepts:**
- Creating a keychain with PKCS#8 backend
- Generating different key types
- Using KeyAttributes to specify key parameters
- Listing all generated keys

---

#### 2. Store and Retrieve (`basic/store-retrieve/`)

Shows how to store keys and retrieve them later:
- Storing keys in the keychain
- Retrieving keys by attributes
- Listing all stored keys
- Deleting keys

**Run:**
```bash
go run examples/basic/store-retrieve/main.go
```

**Expected Output:**
```
=== Store and Retrieve Keys ===

1. Generating and storing RSA key...
   ✓ RSA key generated and stored: stored-rsa-key

2. Retrieving stored RSA key...
   ✓ RSA key retrieved: *rsa.PrivateKey

[...]
```

**Key Concepts:**
- Persistent key storage
- Key retrieval by CN
- Key lifecycle management
- Verifying key deletion

---

### Signing Examples

#### 3. Sign and Verify (`signing/sign-verify/`)

Demonstrates digital signature operations:
- RSA signing (PKCS#1v15 and PSS)
- ECDSA signing
- Ed25519 signing
- Signature verification

**Run:**
```bash
go run examples/signing/sign-verify/main.go
```

**Expected Output:**
```
=== Sign and Verify Examples ===

Message to sign: Hello, go-keychain! This is a test message for signing.

1. RSA-2048 Signing...
   ✓ RSA signature created (256 bytes)
   ✓ RSA signature verified successfully

[...]
```

**Key Concepts:**
- Using crypto.Signer interface
- Hashing messages before signing
- Verifying signatures
- Understanding deterministic vs probabilistic signatures

---

#### 4. File Signing (`signing/file-signing/`)

Shows how to sign files and verify file signatures:
- Signing files with ECDSA
- Storing signatures separately
- Verifying file signatures
- Detecting tampered files
- Batch signing multiple files

**Run:**
```bash
go run examples/signing/file-signing/main.go
```

**Expected Output:**
```
=== File Signing Examples ===

Created test file: /tmp/keychain-file-signing/test-document.txt (123 bytes)

1. Generating ECDSA P-256 signing key...
   ✓ Signing key generated: file-signing-key

2. Signing the file...
   ✓ File signed successfully
   Signature file: /tmp/keychain-file-signing/test-document.txt.sig

[...]
```

**Key Concepts:**
- Hashing files with SHA-256
- Creating detached signatures
- Verifying file integrity
- Tamper detection
- Batch processing

---

### Certificate Examples

#### 5. Create CA (`certificates/create-ca/`)

Demonstrates creating a Certificate Authority:
- Generating CA private key
- Creating self-signed CA certificate
- Storing CA certificate
- Exporting CA to PEM format
- Creating trust pools

**Run:**
```bash
go run examples/certificates/create-ca/main.go
```

**Expected Output:**
```
=== Certificate Authority Creation ===

1. Generating CA private key (ECDSA P-384)...
   ✓ CA private key generated

2. Creating CA certificate template...
   Certificate template:
     Common Name: Example Root CA
     Organization: Example Organization
     Valid From: 2025-01-15T10:00:00Z
     Valid Until: 2035-01-15T10:00:00Z
     Is CA: true
     Max Path Length: 2

[...]
```

**Key Concepts:**
- CA certificate structure
- Self-signing certificates
- Certificate constraints (IsCA, MaxPathLen)
- PEM encoding
- Trust pool management

---

#### 6. Issue Certificates (`certificates/issue-cert/`)

Shows how to issue certificates signed by a CA:
- Creating server certificates
- Creating client certificates
- Creating wildcard certificates
- Verifying certificate chains
- Exporting certificates

**Run:**
```bash
go run examples/certificates/issue-cert/main.go
```

**Expected Output:**
```
=== Certificate Issuance Examples ===

1. Creating Certificate Authority...
   ✓ CA created: Example Root CA

2. Issuing server certificate...
   ✓ Server certificate issued for: server.example.com

3. Issuing client certificate...
   ✓ Client certificate issued for: client@example.com

[...]
```

**Key Concepts:**
- Server vs client certificates
- Extended Key Usage (EKU)
- DNS names and IP addresses
- Wildcard certificates
- Certificate verification

---

#### 7. Manage Certificate Chains (`certificates/manage-chain/`)

Demonstrates certificate chain management:
- Creating root CA
- Creating intermediate CA
- Creating end-entity certificates
- Building certificate chains
- Verifying chains
- Path validation

**Run:**
```bash
go run examples/certificates/manage-chain/main.go
```

**Expected Output:**
```
=== Certificate Chain Management ===

1. Creating Root CA...
   ✓ Root CA created: Example Root CA

2. Creating Intermediate CA...
   ✓ Intermediate CA created: Example Intermediate CA

3. Creating end-entity certificate...
   ✓ End-entity certificate created: server.example.com

[...]
```

**Key Concepts:**
- Certificate hierarchies
- Intermediate CAs
- Chain ordering (leaf → intermediate → root)
- Path validation
- MaxPathLen enforcement

---

### TLS Examples

#### 8. TLS Server (`tls/server/`)

Creates a TLS server using keychain certificates:
- Setting up TLS configuration
- Creating HTTPS server
- Configuring cipher suites
- Multiple endpoints
- Server information display

**Run:**
```bash
go run examples/tls/server/main.go
```

**Expected Output:**
```
=== TLS Server Example ===

1. Creating Certificate Authority...
   ✓ CA created

2. Creating server certificate...
   ✓ Server certificate created

[...]

Server listening on: https://localhost:8443
Available endpoints:
  - https://localhost:8443/
  - https://localhost:8443/health
  - https://localhost:8443/cert-info

Press Ctrl+C to stop the server
```

**Test the server (in another terminal):**
```bash
curl -k https://localhost:8443/
curl -k https://localhost:8443/cert-info
```

**Key Concepts:**
- TLS configuration
- Cipher suite selection
- HTTPS server setup
- Certificate loading from keychain
- HTTP handlers with TLS

---

#### 9. TLS Client (`tls/client/`)

Creates a TLS client with client certificates:
- Client certificate authentication
- Trusted CA pool
- TLS configuration
- Making HTTPS requests
- Connection state inspection

**Run:**
```bash
go run examples/tls/client/main.go
```

**Expected Output:**
```
=== TLS Client Example ===

1. Creating Certificate Authority...
   ✓ CA created

2. Creating client certificate...
   ✓ Client certificate created

3. Loading TLS certificate from keychain...
   ✓ TLS certificate loaded

[...]
```

**Key Concepts:**
- Client certificate authentication
- CA pool configuration
- TLS handshake
- Certificate verification
- HTTPS client setup

---

### Symmetric Encryption Examples

#### 10. AES Encryption (`symmetric-encryption/aes/`)

Demonstrates symmetric encryption using AES-256-GCM:
- Generating AES symmetric keys
- Basic encryption and decryption
- Password-protected key storage
- Additional Authenticated Data (AAD)
- AEAD authentication

**Run:**
```bash
go run examples/symmetric-encryption/aes/aes-encryption.go
```

**Expected Output:**
```
=== Symmetric Encryption Example (AES-256-GCM) ===

--- Example 1: Basic AES-256 Encryption ---
1. Generating AES-256 key...
   ✓ Generated aes256-gcm key (256 bits)

2. Creating symmetric encrypter...
   ✓ Encrypter created

3. Encrypting plaintext: "Hello, World! This is a secret message."
   ✓ Ciphertext: [base64 encoded]
   ✓ Nonce: [base64 encoded]
   ✓ Tag: [base64 encoded]

4. Decrypting ciphertext...
   ✓ Decrypted: "Hello, World! This is a secret message."
   ✓ Verification successful!

[...]
```

**Key Concepts:**
- AES-GCM authenticated encryption
- Symmetric key generation
- Password-protected keys
- Additional Authenticated Data (AAD)
- AEAD security guarantees

---

#### 11. Cloud KMS Encryption (`symmetric-encryption/cloud/`)

Shows symmetric encryption with cloud KMS providers:
- AWS KMS symmetric encryption
- GCP KMS symmetric encryption
- Azure Key Vault symmetric encryption
- Cross-cloud compatibility
- Cloud-specific features

**Run:**
```bash
# AWS KMS
go run examples/symmetric-encryption/cloud/cloud-kms.go -backend=aws

# GCP KMS
go run examples/symmetric-encryption/cloud/cloud-kms.go -backend=gcp

# Azure Key Vault
go run examples/symmetric-encryption/cloud/cloud-kms.go -backend=azure
```

**Key Concepts:**
- Cloud-based symmetric encryption
- Provider abstraction
- Unified API across clouds
- Cloud HSM integration
- Managed key rotation

---

### WebAuthn Examples

#### 14. WebAuthn Server (`webauthn/`)

Demonstrates passwordless authentication using WebAuthn/FIDO2:
- Complete WebAuthn server with REST API
- User registration with passkeys
- Authentication with security keys
- Discoverable credentials support
- Session management

**Run:**
```bash
cd examples/webauthn/server
go run main.go
```

Then open `https://localhost:8443` in your browser.

**Expected Output:**
```
=== WebAuthn Server Example ===

Configuration:
  RP ID:      localhost
  RP Name:    go-keychain Example
  RP Origins: [https://localhost:8443]
  Port:       8443

1. Initializing WebAuthn stores...
   ✓ Memory stores initialized
   ✓ Session cleanup routine started

2. Configuring WebAuthn service...
   ✓ WebAuthn service created

3. Setting up HTTP handlers...
   ✓ WebAuthn API mounted at /api/v1/webauthn
   ✓ Static files mounted at /
   ✓ Health endpoint at /health

[...]
```

**Key Concepts:**
- WebAuthn registration and authentication flows
- Relying Party configuration
- Session-based ceremony tracking
- Credential management

---

### Advanced Examples

#### 12. Key Rotation (`advanced/key-rotation/`)

Demonstrates various key rotation strategies:
- Basic key rotation
- Versioned rotation
- Blue-green rotation
- Graceful rotation with overlap
- Emergency rotation

**Run:**
```bash
go run examples/advanced/key-rotation/main.go
```

**Expected Output:**
```
=== Key Rotation Examples ===

1. Basic Key Rotation
   a. Generating initial key...
      ✓ Initial key generated: *ecdsa.PrivateKey
   b. Rotating key...
      ✓ Key rotated: *ecdsa.PrivateKey
   c. Verifying rotation...
      ✓ Current key retrieved: *ecdsa.PrivateKey
      ✓ Rotation completed successfully

[...]
```

**Key Concepts:**
- Zero-downtime rotation
- Version tracking
- Blue-green deployment
- Overlap periods
- Emergency procedures

---

#### 13. Concurrent Operations (`advanced/concurrent-ops/`)

Shows thread-safe concurrent operations:
- Concurrent key generation
- Concurrent signing
- Concurrent reads
- Mixed operations
- Load testing

**Run:**
```bash
go run examples/advanced/concurrent-ops/main.go
```

**Expected Output:**
```
=== Concurrent Operations Examples ===

1. Concurrent Key Generation
   Generating 10 keys concurrently...
   Results:
     ✓ Successful: 10 keys
     ✗ Failed: 0 keys
     Duration: 245ms
     Rate: 40.82 keys/sec

[...]
```

**Key Concepts:**
- Thread-safety
- Goroutine synchronization
- Atomic operations
- Performance testing
- Load testing patterns

---

## Common Patterns

### Creating a Keystore

```go
// Initialize filesystem
fs := afero.NewOsFs()
keyStorage := file.NewKeyStorage(fs, "/path/to/keys")
certStorage := file.NewCertStorage(fs, "/path/to/certs")

// Create backend
backend, err := pkcs8.NewBackend(keyStorage, &pkcs8.Config{
    PasswordPolicy: backend.PasswordPolicyOptional,
})

// Create keychain
ks, err := keychain.New(&keychain.Config{
    Backend:     backend,
    CertStorage: certStorage,
})
defer ks.Close()
```

### Generating Keys

```go
// RSA key
rsaAttrs := &backend.KeyAttributes{
    CN:           "my-rsa-key",
    KeyAlgorithm: x509.RSA,
    RSAAttributes: &backend.RSAAttributes{
        KeySize: 2048,
    },
}
rsaKey, err := ks.GenerateRSA(rsaAttrs)

// ECDSA key
ecdsaAttrs := &backend.KeyAttributes{
    CN:           "my-ecdsa-key",
    KeyAlgorithm: x509.ECDSA,
    ECCAttributes: &backend.ECCAttributes{
        Curve: elliptic.P256(),
    },
}
ecdsaKey, err := ks.GenerateECDSA(ecdsaAttrs)

// Ed25519 key
ed25519Attrs := &backend.KeyAttributes{
    CN:           "my-ed25519-key",
    KeyAlgorithm: x509.Ed25519,
}
ed25519Key, err := ks.GenerateEd25519(ed25519Attrs)
```

### Signing Data

```go
// Get signer
signer, err := ks.Signer(keyAttrs)

// Sign data
message := []byte("data to sign")
hash := sha256.Sum256(message)
signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
```

### Symmetric Encryption

```go
// Get symmetric backend
symBackend, ok := ks.Backend().(backend.SymmetricBackend)

// Generate AES-256-GCM key
attrs := &backend.KeyAttributes{
    CN:           "my-encryption-key",
    KeyType:      backend.KEY_TYPE_ENCRYPTION,
    StoreType:    backend.STORE_SW,
    KeyAlgorithm: backend.ALG_AES256_GCM,
    AESAttributes: &backend.AESAttributes{KeySize: 256},
}
key, err := symBackend.GenerateSymmetricKey(attrs)

// Get encrypter
encrypter, err := symBackend.SymmetricEncrypter(attrs)

// Encrypt data with AAD
plaintext := []byte("sensitive data")
aad := []byte("context information")
encrypted, err := encrypter.Encrypt(plaintext, &backend.EncryptOptions{
    AdditionalData: aad,
})

// Decrypt data
decrypted, err := encrypter.Decrypt(encrypted, &backend.DecryptOptions{
    AdditionalData: aad,
})
```

### Creating Certificates

```go
// Create certificate template
template := &x509.Certificate{
    SerialNumber: serialNumber,
    Subject: pkix.Name{
        CommonName: "example.com",
    },
    NotBefore:   time.Now(),
    NotAfter:    time.Now().Add(365 * 24 * time.Hour),
    KeyUsage:    x509.KeyUsageDigitalSignature,
    ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
}

// Create certificate
certBytes, err := x509.CreateCertificate(
    rand.Reader,
    template,
    caCert,
    publicKey,
    caPrivateKey,
)

// Store certificate
cert, _ := x509.ParseCertificate(certBytes)
err = ks.SaveCert("example.com", cert)
```

## Best Practices

### 1. Resource Management

Always close the keychain when done:

```go
ks, err := keychain.New(config)
if err != nil {
    return err
}
defer ks.Close()
```

### 2. Error Handling

Handle errors appropriately:

```go
key, err := ks.GenerateRSA(attrs)
if err != nil {
    log.Fatalf("Failed to generate key: %v", err)
}
```

### 3. Key Attributes

Use descriptive Common Names:

```go
attrs := &backend.KeyAttributes{
    CN:           "production-api-server-2025",
    KeyAlgorithm: x509.ECDSA,
    // ...
}
```

### 4. Key Sizes

Use appropriate key sizes:
- RSA: 2048 bits minimum, 4096 for high security
- ECDSA: P-256 for most cases, P-384 for high security
- Ed25519: Fixed size (recommended for signing)

### 5. Certificate Validity

Set appropriate validity periods:
- CA certificates: 10-20 years
- Intermediate CAs: 5-10 years
- End-entity certificates: 1-2 years
- Shorter periods for automated rotation

### 6. TLS Configuration

Use secure TLS settings:

```go
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS12,
    CipherSuites: []uint16{
        tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    },
}
```

## Troubleshooting

### Common Issues

**Issue: "Failed to create keychain"**
- Ensure the storage directories exist and are writable
- Check filesystem permissions

**Issue: "Key not found"**
- Verify the CN matches exactly
- Check that the key was successfully generated
- List all keys to see what's stored

**Issue: "Certificate verification failed"**
- Ensure the CA certificate is in the trust pool
- Check certificate validity periods
- Verify the certificate chain is complete

**Issue: "TLS handshake failed"**
- Check cipher suite compatibility
- Verify certificate key usage
- Ensure certificate matches server name

## Additional Resources

- [Getting Started Guide](../docs/getting-started.md)
- [Backend Documentation](../docs/backends/)
- [Testing Guide](../docs/testing/)

## Contributing

Found an issue or want to add an example? Please open an issue or pull request on GitHub.

## License

AGPL-3.0 License - See [LICENSE](../LICENSE) for details.
