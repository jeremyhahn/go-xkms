# Symmetric Encryption Examples

This directory contains comprehensive examples demonstrating symmetric encryption using the go-keychain library. These examples show how to use AES-GCM encryption with both software-based (PKCS#8) and cloud-based Key Management Services (KMS).

## Overview

Symmetric encryption uses the same key for both encryption and decryption. The go-keychain library provides a unified interface for symmetric encryption across multiple backends:

- **AES Backend**: Local AES-GCM encryption with password-protected key storage
- **AWS KMS**: Hardware-backed encryption using AWS Key Management Service
- **GCP KMS**: Hardware-backed encryption using Google Cloud KMS
- **Azure Key Vault**: Envelope encryption using Azure Key Vault for key wrapping

## Examples

### 1. AES Backend Encryption (`aes-encryption.go`)

Demonstrates symmetric encryption using the AES backend with local key storage.

**Features:**
- AES-256-GCM encryption and decryption
- Password-protected key storage
- Additional Authenticated Data (AAD) support
- Proper error handling and cleanup

**Run:**
```bash
go run aes-encryption.go
```

**Output:**
```
=== Symmetric Encryption Example (AES-256-GCM with AES Backend) ===

Key storage location: /tmp/symmetric-encryption-example

--- Example 1: Basic AES-256 Encryption ---
1. Generating AES-256 key...
   ✓ Generated aes256-gcm key (256 bits)

2. Creating symmetric encrypter...
   ✓ Encrypter created

3. Encrypting plaintext: "Hello, World! This is a secret message."
   ✓ Ciphertext: 4Kj3m9F2xR8pQ7vN1cY6tH5sL0wE9aZ8
   ✓ Nonce: xY2wQ5mN8kR7pL1t
   ✓ Tag: 9aF3nM7kL2pR5tY8

4. Decrypting ciphertext...
   ✓ Decrypted: "Hello, World! This is a secret message."
   ✓ Verification successful!
```

### 2. Cloud KMS Encryption

Demonstrates symmetric encryption using cloud KMS providers. Each provider has its own example in a separate directory.

**Supported Providers:**
- AWS Key Management Service (AWS KMS) - `aws/`
- Google Cloud Key Management Service (GCP KMS) - `gcp/`
- Azure Key Vault - `azure/`

#### AWS KMS (`aws/`)

**Prerequisites:**
```bash
export AWS_REGION="us-east-1"
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
```

**Build and Run:**
```bash
cd aws
go build -tags awskms
./aws
```

**Features:**
- AES-256-GCM encryption (AWS KMS only supports 256-bit keys)
- Key material never leaves AWS KMS
- Encryption context (AAD) support
- Server-side encryption and decryption

#### GCP KMS (`gcp/`)

**Prerequisites:**
```bash
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/credentials.json"
export GCP_PROJECT_ID="your-project-id"
export GCP_LOCATION="global"
export GCP_KEYRING="go-keychain"
```

**Build and Run:**
```bash
cd gcp
go build -tags gcpkms
./gcp
```

**Features:**
- AES-128, AES-192, and AES-256 support
- Key material never leaves GCP KMS
- Additional authenticated data (AAD) support
- Server-side encryption and decryption

#### Azure Key Vault (`azure/`)

**Prerequisites:**
```bash
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
export AZURE_VAULT_URL="https://your-vault.vault.azure.net/"
```

**Build and Run:**
```bash
cd azure
go build -tags azurekv
./azure
```

**Features:**
- AES-128, AES-192, and AES-256 support
- Envelope encryption (local AES + Azure key wrapping)
- Additional authenticated data (AAD) support
- Data encryption key (DEK) wrapped in Azure Key Vault

## Key Concepts

### AES-GCM

All examples use AES-GCM (Galois/Counter Mode), which provides:
- **Confidentiality**: Data is encrypted and cannot be read without the key
- **Authentication**: Built-in message authentication prevents tampering
- **Performance**: Fast encryption/decryption with hardware acceleration support

### Additional Authenticated Data (AAD)

AAD allows you to authenticate metadata without encrypting it. This is useful for:
- Associating context with encrypted data
- Preventing ciphertext substitution attacks
- Binding encrypted data to specific parameters

**Example:**
```go
// AAD is authenticated but NOT encrypted
aad := []byte("user:alice,document:12345,timestamp:2025-11-07")

encrypted, err := encrypter.Encrypt(plaintext, &backend.EncryptOptions{
    AdditionalData: aad,
})

// Decryption requires matching AAD
decrypted, err := encrypter.Decrypt(encrypted, &backend.DecryptOptions{
    AdditionalData: aad,
})
```

### Password Protection

The AES backend supports password-protected key storage using Argon2id:
- **Key Derivation**: Argon2id with time=1, memory=64MB, threads=4
- **Encryption**: AES-256-GCM with password-derived key
- **Format**: `[salt][nonce][ciphertext+tag]`

**Example:**
```go
password := backend.StaticPassword([]byte("my-secure-password"))

attrs := &backend.KeyAttributes{
    CN:           "my-key",
    KeyType:      backend.KEY_TYPE_ENCRYPTION,
    StoreType:    backend.STORE_SW,
    KeyAlgorithm: backend.ALG_AES256_GCM,
    AESAttributes: &backend.AESAttributes{
        KeySize: 256,
    },
    Password: password, // Key encrypted at rest
}
```

## Cloud Provider Comparison

| Feature | AWS KMS | GCP KMS | Azure Key Vault |
|---------|---------|---------|-----------------|
| Key Sizes | 256-bit only | 128, 192, 256-bit | 128, 192, 256-bit |
| Encryption Location | Server-side | Server-side | Envelope (hybrid) |
| Key Export | No | No | No |
| AAD Support | Yes (EncryptionContext) | Yes | Yes |
| Cost Model | Per-request | Per-request | Per-operation |
| FIPS 140-2 | Yes (Level 3) | Yes (Level 3) | Yes (Level 2) |

### Encryption Approaches

**AWS KMS & GCP KMS:**
- All encryption/decryption happens server-side
- Key material never leaves the HSM
- Ciphertext is an opaque blob

**Azure Key Vault:**
- Uses envelope encryption
- Generates local Data Encryption Key (DEK)
- Encrypts data locally with DEK
- Wraps DEK using Azure Key Vault
- Provides better performance for large data

## Best Practices

### 1. Key Storage Security

**AES Backend:**
- Always use password protection for keys at rest
- Use strong passwords (min 16 characters)
- Store keys in secure, access-controlled directories
- Consider using OS keyring integration

**Cloud KMS:**
- Use IAM policies to control key access
- Enable key rotation policies
- Use separate keys for different environments
- Monitor key usage with cloud logging

### 2. AAD Usage

- Include relevant context in AAD (user, resource, timestamp)
- Don't include sensitive data in AAD (it's not encrypted)
- Use consistent AAD format across your application
- Validate AAD matches expected values during decryption

### 3. Error Handling

- Always check for errors during encryption/decryption
- Handle authentication failures gracefully
- Log security events (failed decryption attempts)
- Never expose detailed error messages to users

### 4. Key Management

- Rotate keys regularly (recommend every 90 days)
- Use different keys for different data types
- Implement key versioning for graceful rotation
- Have a key recovery plan for disaster scenarios

## Common Patterns

### Encrypting Database Fields

```go
// Generate or retrieve key
attrs := &backend.KeyAttributes{
    CN:           "db-encryption-key",
    KeyType:      backend.KEY_TYPE_ENCRYPTION,
    StoreType:    backend.STORE_AWSKMS,
    KeyAlgorithm: backend.ALG_AES256_GCM,
    AESAttributes: &backend.AESAttributes{
        KeySize: 256,
    },
}

encrypter, err := backend.SymmetricEncrypter(attrs)

// Encrypt sensitive field with AAD
encrypted, err := encrypter.Encrypt(
    []byte(user.SSN),
    &backend.EncryptOptions{
        AdditionalData: []byte(fmt.Sprintf("user:%s,field:ssn", user.ID)),
    },
)

// Store encrypted.Ciphertext, encrypted.Nonce, encrypted.Tag in database
```

### Encrypting Files

```go
// Read file
data, err := os.ReadFile("sensitive.txt")

// Encrypt with filename in AAD
encrypted, err := encrypter.Encrypt(data, &backend.EncryptOptions{
    AdditionalData: []byte("file:sensitive.txt,version:1"),
})

// Write encrypted data
encryptedData := append(encrypted.Nonce, encrypted.Ciphertext...)
encryptedData = append(encryptedData, encrypted.Tag...)
os.WriteFile("sensitive.txt.enc", encryptedData, 0600)
```

### Encrypting API Payloads

```go
// Encrypt request payload
payload := []byte(`{"action": "transfer", "amount": 1000}`)
encrypted, err := encrypter.Encrypt(payload, &backend.EncryptOptions{
    AdditionalData: []byte("api:v1,endpoint:/transfer,timestamp:2025-11-07"),
})

// Send encrypted payload
resp, err := http.Post(url, "application/octet-stream",
    bytes.NewReader(encrypted.Ciphertext))
```

## Troubleshooting

### "Invalid password" error
- Ensure you're using the same password for retrieval
- Check password is correctly loaded from environment/secrets manager
- Verify key wasn't created with a different password

### "Authentication failed" during decryption
- Verify AAD matches between encryption and decryption
- Check ciphertext hasn't been corrupted or modified
- Ensure you're using the correct key

### Cloud provider authentication errors
- Verify environment variables are set correctly
- Check IAM permissions for your service account
- Ensure KMS service is enabled in your project/account
- Verify network connectivity to cloud services

## Related Documentation

- [Backend Architecture](../../docs/architecture/backends.md)
- [Key Management Guide](../../docs/guides/key-management.md)
- [Security Best Practices](../../docs/security/best-practices.md)
- [API Reference](../../docs/api/backend.md)

## License

Copyright (c) 2025 Jeremy Hahn
SPDX-License-Identifier: AGPL-3.0
