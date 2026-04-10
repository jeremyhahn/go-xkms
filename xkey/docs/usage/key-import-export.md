# Key Import/Export Guide

This guide explains how to securely import and export cryptographic keys between systems using go-xkms's service API and key wrapping functionality.

## Overview

Key import/export enables secure key transport between systems while maintaining security:

- **Import**: Bring externally generated keys into an HSM/KMS
- **Export**: Extract keys from one system for import into another (when supported)
- **Key Wrapping**: Encrypts key material for secure transport over untrusted channels
- **Cross-Backend Copy**: Move keys between backends with `xkms.CopyKey()`

The key material is encrypted (wrapped) before transmission and can only be decrypted (unwrapped) by the intended recipient.

## Service API Quick Reference

| Function | Description |
|----------|-------------|
| `xkms.ExportKey(kid, algorithm)` | Export a key in wrapped form |
| `xkms.ImportKey(backend, attrs, wrapped)` | Import wrapped key material |
| `xkms.CopyKey(sourceKID, destBackend, attrs)` | Copy a key between backends |
| `xkms.GetImportParameters(backend, attrs, algo)` | Get import parameters |
| `xkms.WrapKey(backend, material, params)` | Wrap key material for secure transport |
| `xkms.UnwrapKey(backend, wrapped, params)` | Unwrap key material |

## Supported Backends

### Software Backend
- **Import**: Supported
- **Export**: Supported
- **Unwrap**: Supported (client-side)
- **Wrapping Algorithms**: All standard algorithms
- **Use Case**: Development, testing, key migration between systems
- **Security**: Keys stored in software, not hardware-backed

### Symmetric Backend
- **Import**: Supported
- **Export**: Supported
- **Unwrap**: Supported (client-side)
- **Wrapping Algorithms**: All standard algorithms
- **Use Case**: Symmetric key import/export, key rotation
- **Security**: Supports password-protected keys

### AWS KMS
- **Import**: Supported
- **Export**: Not supported (AWS security policy)
- **Unwrap**: Happens in AWS HSM
- **Wrapping Algorithms**:
  - `RSAES_OAEP_SHA_1` - RSA-OAEP with SHA-1
  - `RSAES_OAEP_SHA_256` - RSA-OAEP with SHA-256 (recommended)
  - `RSA_AES_KEY_WRAP_SHA_1` - Hybrid RSA + AES-KWP with SHA-1
  - `RSA_AES_KEY_WRAP_SHA_256` - Hybrid RSA + AES-KWP with SHA-256 (for large keys)

### GCP KMS
- **Import**: Supported
- **Export**: Not supported (GCP security policy)
- **Unwrap**: Happens in GCP HSM
- **Wrapping Algorithms**:
  - `RSA_OAEP_3072_SHA256_AES_256` - Hybrid 3072-bit RSA + AES-KWP (recommended)
  - `RSA_OAEP_4096_SHA256_AES_256` - Hybrid 4096-bit RSA + AES-KWP
  - `RSA_OAEP_4096_SHA256` - Direct RSA-OAEP (for small keys only)

### TPM2
- **Import**: Partial (wrapping supported, TPM2_Import needs completion)
- **Export**: Not supported (most TPM keys are FixedTPM)
- **Unwrap**: Happens in TPM hardware
- **Wrapping Algorithms**: `RSAES_OAEP_SHA_256`, `RSA_AES_KEY_WRAP_SHA_256`
- **Use Case**: Hardware-backed key storage on devices with TPM
- **Security**: Keys are FixedTPM (cannot leave the TPM)

### PKCS#11
- **Import**: Supported (via C_UnwrapKey)
- **Export**: Conditional (only if key has CKA_EXTRACTABLE attribute)
- **Unwrap**: Happens in HSM
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

## Cross-Backend Key Copy

The simplest way to move a key between backends is `xkms.CopyKey()`:

```go
package main

import (
    "log"

    "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

func main() {
    // Initialize with multiple backends
    if err := xkms.AutoInitialize(&xkms.AutoConfig{
        DataDir: "/var/lib/xkms",
    }); err != nil {
        log.Fatal(err)
    }
    defer xkms.Close()

    // Copy a key from software backend to another backend
    // Uses RSA-OAEP-SHA256 wrapping automatically
    err := xkms.CopyKey(
        "software:::my-key",  // source key ID
        "pkcs11",             // destination backend
        nil,                  // nil = use same attributes as source
    )
    if err != nil {
        log.Fatal(err)
    }

    // The key is now available in both backends
    sig1, _ := xkms.Sign("software:::my-key", data, nil)
    sig2, _ := xkms.Sign("pkcs11:::my-key", data, nil)
}
```

## Export and Import via Service API

For more control over the export/import process:

```go
package main

import (
    "fmt"
    "log"

    "github.com/jeremyhahn/go-xkms/pkg/backend"
    "github.com/jeremyhahn/go-xkms/pkg/types"
    "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

func main() {
    if err := xkms.AutoInitialize(&xkms.AutoConfig{
        DataDir: "/var/lib/xkms",
    }); err != nil {
        log.Fatal(err)
    }
    defer xkms.Close()

    // Step 1: Export a key from the source backend (wrapped)
    wrapped, err := xkms.ExportKey(
        "software:::my-key",
        backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
    )
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Exported key (%d bytes wrapped)\n", len(wrapped.WrappedKey))

    // Step 2: Import into the destination backend
    destAttrs := &types.KeyAttributes{
        CN:      "my-key",
        KeyType: types.KeyTypeSigning,
    }

    err = xkms.ImportKey("pkcs11", destAttrs, wrapped)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Key imported successfully")
}
```

## Importing External Key Material

When importing key material generated outside of go-xkms (e.g., from an external HSM or key ceremony):

```go
package main

import (
    "crypto/rand"
    "fmt"
    "log"

    "github.com/jeremyhahn/go-xkms/pkg/backend"
    "github.com/jeremyhahn/go-xkms/pkg/types"
    "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

func main() {
    if err := xkms.AutoInitialize(&xkms.AutoConfig{
        DataDir: "/var/lib/xkms",
    }); err != nil {
        log.Fatal(err)
    }
    defer xkms.Close()

    // Define the key to import
    attrs := &types.KeyAttributes{
        CN:      "imported-aes-key",
        KeyType: types.KeyTypeSymmetric,
        KeySize: 256,
    }

    // Step 1: Get import parameters from the destination backend
    // These include a wrapping public key and import token
    params, err := xkms.GetImportParameters(
        "awskms",
        attrs,
        backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
    )
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Import parameters valid until: %v\n", params.ExpiresAt)

    // Step 2: Generate or obtain your key material
    keyMaterial := make([]byte, 32) // AES-256 key
    if _, err := rand.Read(keyMaterial); err != nil {
        log.Fatal(err)
    }

    // Step 3: Wrap the key material
    wrapped, err := xkms.WrapKey("awskms", keyMaterial, params)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Wrapped key: %d bytes\n", len(wrapped.WrappedKey))

    // Step 4: Import the wrapped key
    err = xkms.ImportKey("awskms", attrs, wrapped)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Key imported to AWS KMS")

    // Zero out sensitive material
    for i := range keyMaterial {
        keyMaterial[i] = 0
    }
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
    "log"

    "github.com/jeremyhahn/go-xkms/pkg/backend"
    "github.com/jeremyhahn/go-xkms/pkg/types"
    "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

func main() {
    if err := xkms.AutoInitialize(&xkms.AutoConfig{
        DataDir: "/var/lib/xkms",
    }); err != nil {
        log.Fatal(err)
    }
    defer xkms.Close()

    // Generate an RSA key pair externally
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        log.Fatal(err)
    }

    // Marshal private key to PKCS#8
    keyMaterial, err := x509.MarshalPKCS8PrivateKey(privateKey)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Private key material size: %d bytes\n", len(keyMaterial))

    attrs := &types.KeyAttributes{
        CN:      "imported-rsa-key",
        KeyType: types.KeyTypeRSA,
        KeySize: 2048,
    }

    // Use hybrid algorithm for large key material
    params, err := xkms.GetImportParameters(
        "awskms",
        attrs,
        backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
    )
    if err != nil {
        log.Fatal(err)
    }

    // Wrap the large key material
    wrapped, err := xkms.WrapKey("awskms", keyMaterial, params)
    if err != nil {
        log.Fatal(err)
    }

    // Import into AWS KMS
    err = xkms.ImportKey("awskms", attrs, wrapped)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("RSA private key imported to AWS KMS")

    // Zero out sensitive material
    for i := range keyMaterial {
        keyMaterial[i] = 0
    }
}
```

## GCP KMS Import Example

```go
attrs := &types.KeyAttributes{
    CN:      "my-imported-key",
    KeyType: types.KeyTypeRSA,
    KeySize: 2048,
}

// GCP uses different wrapping algorithms
params, err := xkms.GetImportParameters(
    "gcpkms",
    attrs,
    backend.WrappingAlgorithmRSA_OAEP_3072_SHA256_AES_256,
)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Import job valid until: %v\n", params.ExpiresAt)

wrapped, err := xkms.WrapKey("gcpkms", keyMaterial, params)
if err != nil {
    log.Fatal(err)
}

err = xkms.ImportKey("gcpkms", attrs, wrapped)
if err != nil {
    log.Fatal(err)
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
// Export errors
wrapped, err := xkms.ExportKey("software:::my-key", algorithm)
if err != nil {
    switch {
    case errors.Is(err, backend.ErrNotSupported):
        // Backend doesn't support export
        fmt.Println("Export not supported by this backend")
    case errors.Is(err, xkms.ErrBackendNotFound):
        // Backend not registered
        fmt.Println("Backend not available")
    default:
        fmt.Printf("Export failed: %v\n", err)
    }
    return
}

// Import errors
err = xkms.ImportKey("awskms", attrs, wrapped)
if err != nil {
    switch {
    case errors.Is(err, backend.ErrImportTokenExpired):
        // Import parameters have expired -- get new ones
        fmt.Println("Import parameters expired, get new ones")
    case errors.Is(err, backend.ErrKeyAlreadyExists):
        // Key with same attributes already exists
        fmt.Println("Key already exists, delete or use different name")
    case errors.Is(err, backend.ErrInvalidKeySize):
        // Key material too large for chosen algorithm
        fmt.Println("Use hybrid algorithm for large keys")
    default:
        fmt.Printf("Import failed: %v\n", err)
    }
}
```

## Best Practices

1. **Check backend capabilities** before attempting import/export:
   ```go
   caps, err := xkms.GetBackendCapabilities("awskms")
   if err != nil || !caps.SupportsImportExport {
       log.Fatal("backend doesn't support import/export")
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

- [Backend Registry](../architecture/backend-registry.md)
- [Key Migration Guide](key-migration.md)
- [AWS KMS Backend](../backends/awskms.md)
- [GCP KMS Backend](../backends/gcpkms.md)
