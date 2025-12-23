# Key Import/Export Guide

This guide explains how to securely import and export cryptographic keys between systems using the go-keychain library's key wrapping functionality.

## Overview

Key import/export enables secure key transport between systems while maintaining security:

- **Import**: Bring externally generated keys into an HSM/KMS
- **Export**: Extract keys from one system for import into another (when supported)
- **Key Wrapping**: Encrypts key material for secure transport over untrusted channels

The key material is encrypted (wrapped) before transmission and can only be decrypted (unwrapped) by the intended recipient.

## Supported Backends

### Software Backend
- **Import**: ✅ Supported
- **Export**: ✅ Supported
- **Unwrap**: ✅ Supported (client-side)
- **Wrapping Algorithms**: All standard algorithms
- **Use Case**: Development, testing, key migration between systems
- **Security**: Keys stored in software, not hardware-backed

### Symmetric Backend
- **Import**: ✅ Supported
- **Export**: ✅ Supported
- **Unwrap**: ✅ Supported (client-side)
- **Wrapping Algorithms**: All standard algorithms
- **Use Case**: Symmetric key import/export, key rotation
- **Security**: Supports password-protected keys

### AWS KMS
- **Import**: ✅ Supported
- **Export**: ❌ Not supported (AWS security policy)
- **Unwrap**: ❌ Happens in AWS HSM
- **Wrapping Algorithms**:
  - `RSAES_OAEP_SHA_1` - RSA-OAEP with SHA-1
  - `RSAES_OAEP_SHA_256` - RSA-OAEP with SHA-256 (recommended)
  - `RSA_AES_KEY_WRAP_SHA_1` - Hybrid RSA + AES-KWP with SHA-1
  - `RSA_AES_KEY_WRAP_SHA_256` - Hybrid RSA + AES-KWP with SHA-256 (for large keys)

### GCP KMS
- **Import**: ✅ Supported
- **Export**: ❌ Not supported (GCP security policy)
- **Unwrap**: ❌ Happens in GCP HSM
- **Wrapping Algorithms**:
  - `RSA_OAEP_3072_SHA256_AES_256` - Hybrid 3072-bit RSA + AES-KWP (recommended)
  - `RSA_OAEP_4096_SHA256_AES_256` - Hybrid 4096-bit RSA + AES-KWP
  - `RSA_OAEP_4096_SHA256` - Direct RSA-OAEP (for small keys only)

### TPM2
- **Import**: ⚠️ Partial (wrapping supported, TPM2_Import needs completion)
- **Export**: ❌ Not supported (most TPM keys are FixedTPM)
- **Unwrap**: ❌ Happens in TPM hardware
- **Wrapping Algorithms**: `RSAES_OAEP_SHA_256`, `RSA_AES_KEY_WRAP_SHA_256`
- **Use Case**: Hardware-backed key storage on devices with TPM
- **Security**: Keys are FixedTPM (cannot leave the TPM)

### PKCS#11
- **Import**: ✅ Supported (via C_UnwrapKey)
- **Export**: ⚠️ Conditional (only if key has CKA_EXTRACTABLE attribute)
- **Unwrap**: ❌ Happens in HSM
- **Wrapping Algorithms**: All standard algorithms
- **Use Case**: Hardware Security Modules (HSM), smartcards
- **Security**: Keys marked as non-extractable by default

## Key Wrapping Algorithms

### RSA-OAEP
Direct encryption using RSA public key with OAEP padding.

**Use for**: Small key material (symmetric keys, etc.)
**Limitations**: Key material must be smaller than RSA key size minus padding overhead

### Hybrid (RSA + AES-KWP)
Two-step wrapping process:
1. Generate random AES-256 key
2. Wrap AES key with RSA-OAEP
3. Wrap target key material with AES-KWP (RFC 5649)
4. Concatenate wrapped AES key + wrapped key material

**Use for**: Large key material (RSA private keys, etc.)
**Advantages**: No size limitations, supports arbitrary-length key material

## Software Backend Import/Export Example

The software backend supports full import/export with client-side unwrapping, making it ideal for development and testing.

```go
package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "fmt"

    "github.com/jeremyhahn/go-keychain/pkg/backend"
    "github.com/jeremyhahn/go-keychain/pkg/backend/software"
)

func transferKeyBetweenBackends() error {
    // Create two software backends (simulating two systems)
    backend1, err := software.NewBackend(&software.Config{
        StorageDir: "/tmp/backend1",
    })
    if err != nil {
        return err
    }
    defer backend1.Close()

    backend2, err := software.NewBackend(&software.Config{
        StorageDir: "/tmp/backend2",
    })
    if err != nil {
        return err
    }
    defer backend2.Close()

    // Generate a key in backend1
    attrs := &backend.KeyAttributes{
        CN:      "my-transferred-key",
        KeyType: backend.KeyTypeRSA,
        KeySize: 2048,
    }

    key, err := backend1.GenerateKey(attrs)
    if err != nil {
        return err
    }

    fmt.Println("Generated key in backend1")

    // Export from backend1
    wrapped, err := backend1.(backend.ImportExportBackend).ExportKey(
        attrs,
        backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
    )
    if err != nil {
        return err
    }

    fmt.Printf("Exported key (%d bytes wrapped)\n", len(wrapped.WrappedKey))

    // Import into backend2
    err = backend2.(backend.ImportExportBackend).ImportKey(attrs, wrapped)
    if err != nil {
        return err
    }

    fmt.Println("Successfully imported key into backend2")

    // Verify the key works in backend2
    signer, err := backend2.Signer(attrs)
    if err != nil {
        return err
    }

    fmt.Printf("Key successfully transferred! Public key: %v\n", signer.Public())
    return nil
}
```

## Symmetric Backend Import/Export Example

The AES backend supports importing and exporting symmetric keys with optional password protection.

```go
package main

import (
    "crypto/rand"
    "fmt"

    "github.com/jeremyhahn/go-keychain/pkg/backend"
    "github.com/jeremyhahn/go-keychain/pkg/backend/symmetric"
)

func importAESKey() error {
    // Generate external AES-256 key
    aesKey := make([]byte, 32) // 256 bits
    if _, err := rand.Read(aesKey); err != nil {
        return err
    }

    // Create AES backend
    backend, err := symmetric.NewBackend(&symmetric.Config{
        StorageDir: "/tmp/aes-keys",
    })
    if err != nil {
        return err
    }
    defer backend.Close()

    importBackend := backend.(backend.ImportExportBackend)

    // Get import parameters
    attrs := &backend.KeyAttributes{
        CN:      "imported-aes-key",
        KeyType: backend.KeyTypeSymmetric,
        KeySize: 256,
    }

    params, err := importBackend.GetImportParameters(
        attrs,
        backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
    )
    if err != nil {
        return err
    }

    // Wrap the AES key
    wrapped, err := importBackend.WrapKey(aesKey, params)
    if err != nil {
        return err
    }

    fmt.Printf("Wrapped AES key: %d bytes\n", len(wrapped.WrappedKey))

    // Import the wrapped key
    err = importBackend.ImportKey(attrs, wrapped)
    if err != nil {
        return err
    }

    fmt.Println("AES key successfully imported!")

    // Use the imported key
    encrypter, err := backend.SymmetricEncrypter(attrs)
    if err != nil {
        return err
    }

    plaintext := []byte("Hello, encrypted world!")
    encrypted, err := encrypter.Encrypt(plaintext, nil)
    if err != nil {
        return err
    }

    fmt.Printf("Encrypted %d bytes\n", len(encrypted.Ciphertext))
    return nil
}
```

## AWS KMS Import Example

```go
package main

import (
    "context"
    "crypto/rand"
    "fmt"

    "github.com/jeremyhahn/go-keychain/pkg/backend"
    "github.com/jeremyhahn/go-keychain/pkg/backend/awskms"
)

func importKeyToAWSKMS() error {
    // Create AWS KMS backend
    config := &awskms.Config{
        Region:          "us-east-1",
        AccessKeyID:     "YOUR_ACCESS_KEY",
        SecretAccessKey: "YOUR_SECRET_KEY",
    }

    kmsBackend, err := awskms.NewBackend(config)
    if err != nil {
        return fmt.Errorf("failed to create backend: %w", err)
    }
    defer kmsBackend.Close()

    // Check if backend supports import/export
    if !kmsBackend.Capabilities().SupportsImportExport() {
        return fmt.Errorf("backend does not support import/export")
    }

    // Cast to ImportExportBackend
    importExportBackend, ok := kmsBackend.(backend.ImportExportBackend)
    if !ok {
        return fmt.Errorf("backend does not implement ImportExportBackend")
    }

    // Define key attributes
    attrs := &backend.KeyAttributes{
        CN:        "my-imported-key",
        KeyType:   backend.KeyTypeRSA,
        KeySize:   2048,
    }

    // Step 1: Get import parameters
    // These include a wrapping public key and import token
    // Valid for 24 hours in AWS KMS
    params, err := importExportBackend.GetImportParameters(
        attrs,
        backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
    )
    if err != nil {
        return fmt.Errorf("failed to get import parameters: %w", err)
    }

    fmt.Printf("Import parameters valid until: %v\n", params.ExpiresAt)

    // Step 2: Generate your key material
    // In practice, this might be an existing key you want to import
    keyMaterial := make([]byte, 32) // AES-256 key
    if _, err := rand.Read(keyMaterial); err != nil {
        return fmt.Errorf("failed to generate key material: %w", err)
    }

    // Step 3: Wrap the key material
    wrapped, err := importExportBackend.WrapKey(keyMaterial, params)
    if err != nil {
        return fmt.Errorf("failed to wrap key: %w", err)
    }

    fmt.Printf("Wrapped key size: %d bytes\n", len(wrapped.WrappedKey))

    // Step 4: Import the wrapped key into AWS KMS
    err = importExportBackend.ImportKey(attrs, wrapped)
    if err != nil {
        return fmt.Errorf("failed to import key: %w", err)
    }

    fmt.Println("Key successfully imported to AWS KMS!")

    return nil
}
```

## GCP KMS Import Example

```go
package main

import (
    "context"
    "crypto/rand"
    "fmt"

    "github.com/jeremyhahn/go-keychain/pkg/backend"
    "github.com/jeremyhahn/go-keychain/pkg/backend/gcpkms"
)

func importKeyToGCPKMS() error {
    // Create GCP KMS backend
    config := &gcpkms.Config{
        ProjectID:  "your-project-id",
        LocationID: "us-central1",
        KeyRingID:  "your-keyring",
        CredentialsFile: "/path/to/credentials.json",
    }

    kmsBackend, err := gcpkms.NewBackend(config)
    if err != nil {
        return fmt.Errorf("failed to create backend: %w", err)
    }
    defer kmsBackend.Close()

    // Cast to ImportExportBackend
    importExportBackend, ok := kmsBackend.(backend.ImportExportBackend)
    if !ok {
        return fmt.Errorf("backend does not implement ImportExportBackend")
    }

    // Define key attributes
    attrs := &backend.KeyAttributes{
        CN:        "my-imported-key",
        KeyType:   backend.KeyTypeRSA,
        KeySize:   2048,
    }

    // Step 1: Get import parameters
    // Creates an import job with wrapping public key
    // Valid for 3 days in GCP KMS
    params, err := importExportBackend.GetImportParameters(
        attrs,
        backend.WrappingAlgorithmRSA_OAEP_3072_SHA256_AES_256,
    )
    if err != nil {
        return fmt.Errorf("failed to get import parameters: %w", err)
    }

    fmt.Printf("Import job valid until: %v\n", params.ExpiresAt)

    // Step 2: Generate your key material
    keyMaterial := make([]byte, 32) // AES-256 key
    if _, err := rand.Read(keyMaterial); err != nil {
        return fmt.Errorf("failed to generate key material: %w", err)
    }

    // Step 3: Wrap the key material
    wrapped, err := importExportBackend.WrapKey(keyMaterial, params)
    if err != nil {
        return fmt.Errorf("failed to wrap key: %w", err)
    }

    fmt.Printf("Wrapped key size: %d bytes\n", len(wrapped.WrappedKey))

    // Step 4: Import the wrapped key into GCP KMS
    err = importExportBackend.ImportKey(attrs, wrapped)
    if err != nil {
        return fmt.Errorf("failed to import key: %w", err)
    }

    fmt.Println("Key successfully imported to GCP KMS!")

    return nil
}
```

## Importing Large Keys (RSA Private Keys)

For large key material like RSA private keys, use hybrid wrapping algorithms:

```go
package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "fmt"

    "github.com/jeremyhahn/go-keychain/pkg/backend"
    "github.com/jeremyhahn/go-keychain/pkg/backend/awskms"
)

func importRSAPrivateKey() error {
    // Generate RSA key pair
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return err
    }

    // Marshal private key to PKCS#8
    keyMaterial, err := x509.MarshalPKCS8PrivateKey(privateKey)
    if err != nil {
        return fmt.Errorf("failed to marshal private key: %w", err)
    }

    fmt.Printf("Private key material size: %d bytes\n", len(keyMaterial))

    // Create backend
    config := &awskms.Config{
        Region: "us-east-1",
    }
    kmsBackend, err := awskms.NewBackend(config)
    if err != nil {
        return err
    }
    defer kmsBackend.Close()

    importExportBackend := kmsBackend.(backend.ImportExportBackend)

    attrs := &backend.KeyAttributes{
        CN:      "imported-rsa-key",
        KeyType: backend.KeyTypeRSA,
        KeySize: 2048,
    }

    // Use hybrid algorithm for large key material
    params, err := importExportBackend.GetImportParameters(
        attrs,
        backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
    )
    if err != nil {
        return err
    }

    // Wrap the large key material
    wrapped, err := importExportBackend.WrapKey(keyMaterial, params)
    if err != nil {
        return err
    }

    // Import into AWS KMS
    err = importExportBackend.ImportKey(attrs, wrapped)
    if err != nil {
        return err
    }

    fmt.Println("RSA private key successfully imported!")
    return nil
}
```

## Security Considerations

### Import Parameter Expiration
- **AWS KMS**: 24 hours
- **GCP KMS**: 3 days

After expiration, you must obtain new import parameters. Do not reuse expired parameters.

### Algorithm Selection

**For symmetric keys (AES, etc.)**:
- Use direct RSA-OAEP: `RSAES_OAEP_SHA_256` or `RSA_OAEP_4096_SHA256`

**For RSA private keys**:
- Use hybrid algorithms: `RSA_AES_KEY_WRAP_SHA_256` or `RSA_OAEP_3072_SHA256_AES_256`

**SHA-256 vs SHA-1**:
- Always prefer SHA-256 variants
- SHA-1 is provided for compatibility with legacy systems only

### Key Material Handling
- Generate key material using cryptographically secure random number generators
- Clear sensitive key material from memory after wrapping
- Never log or store plaintext key material
- Use secure channels when transmitting wrapped keys (even though they're encrypted)

### Hardware Security
- Wrapping happens **client-side** (outside the HSM)
- Unwrapping happens **inside the HSM** (AWS/GCP hardware)
- Plaintext key material never leaves the HSM after import
- The unwrapping private key never leaves the HSM

## Error Handling

```go
func handleImportErrors() {
    // ... setup code ...

    wrapped, err := importExportBackend.WrapKey(keyMaterial, params)
    if err != nil {
        switch {
        case errors.Is(err, backend.ErrNotSupported):
            // Backend doesn't support this operation
            fmt.Println("Import/export not supported")

        case errors.Is(err, backend.ErrInvalidKeySize):
            // Key material too large for chosen algorithm
            fmt.Println("Use hybrid algorithm for large keys")

        case errors.Is(err, backend.ErrInvalidAlgorithm):
            // Unsupported wrapping algorithm
            fmt.Println("Check supported algorithms for backend")

        default:
            // Other errors
            fmt.Printf("Wrapping failed: %v\n", err)
        }
        return
    }

    err = importExportBackend.ImportKey(attrs, wrapped)
    if err != nil {
        switch {
        case errors.Is(err, backend.ErrImportTokenExpired):
            // Import parameters have expired
            // Get new parameters and retry
            fmt.Println("Import parameters expired, get new ones")

        case errors.Is(err, backend.ErrKeyAlreadyExists):
            // Key with same attributes already exists
            fmt.Println("Key already exists, delete or use different name")

        default:
            fmt.Printf("Import failed: %v\n", err)
        }
    }
}
```

## Best Practices

1. **Always check capabilities** before attempting import/export:
   ```go
   if !backend.Capabilities().SupportsImportExport() {
       return errors.New("backend doesn't support import/export")
   }
   ```

2. **Use appropriate wrapping algorithms**:
   - Small keys: Direct RSA-OAEP
   - Large keys: Hybrid RSA + AES-KWP

3. **Validate import parameters before use**:
   ```go
   if params.ExpiresAt != nil && time.Now().After(*params.ExpiresAt) {
       return errors.New("import parameters expired")
   }
   ```

4. **Handle errors gracefully**:
   - Expired import tokens: Get new parameters
   - Key already exists: Delete or rename
   - Unsupported algorithm: Choose different algorithm

5. **Clean up sensitive data**:
   ```go
   defer func() {
       // Zero out key material
       for i := range keyMaterial {
           keyMaterial[i] = 0
       }
   }()
   ```

6. **Use context for timeouts**:
   ```go
   ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
   defer cancel()
   ```

## Troubleshooting

### "algorithm not supported"
- Check the backend's supported algorithms
- AWS and GCP have different algorithm sets

### "key material too large"
- Use hybrid wrapping algorithm
- For RSA private keys, use `RSA_AES_KEY_WRAP_*` variants

### "import token expired"
- Get new import parameters
- AWS: 24-hour validity
- GCP: 3-day validity

### "key already exists"
- Delete existing key first
- Use a different CN/name for the key

### "unwrapping failed"
- Ensure wrapped key was created with correct parameters
- Check for data corruption during transmission
- Verify algorithm matches between wrap and import

## Related Documentation

- [Backend Architecture](./backend-architecture.md)
- [AWS KMS Backend](./backends/awskms.md)
- [GCP KMS Backend](./backends/gcpkms.md)
- [Key Management Best Practices](./key-management.md)
