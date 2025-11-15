# JWK - JSON Web Key Package

This package provides RFC-compliant JSON Web Key (JWK) encoding/decoding and JWK thumbprint computation for go-keychain.

## Features

- ✅ **RFC 7517** - JSON Web Key (JWK) format
- ✅ **RFC 7518** - JSON Web Algorithms (JWA)
- ✅ **RFC 7638** - JWK Thumbprint computation
- ✅ **RFC 8555** - ACME key authorization

### Supported Key Types

- **RSA** - Public and private keys with CRT parameters
- **ECDSA** - P-256, P-384, P-521 curves
- **Ed25519** - Modern elliptic curve signatures
- **Symmetric (oct)** - AES and other symmetric keys

## Usage

### Converting Keys to JWK

```go
import "github.com/jeremyhahn/go-keychain/pkg/encoding/jwk"

// RSA Public Key
rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
publicJWK, err := jwk.FromPublicKey(&rsaKey.PublicKey)
if err != nil {
    log.Fatal(err)
}

// RSA Private Key (includes public key parameters)
privateJWK, err := jwk.FromPrivateKey(rsaKey)
if err != nil {
    log.Fatal(err)
}

// ECDSA Key
ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
ecJWK, err := jwk.FromPublicKey(&ecdsaKey.PublicKey)
if err != nil {
    log.Fatal(err)
}

// Ed25519 Key
pub, priv, _ := ed25519.GenerateKey(rand.Reader)
edJWK, err := jwk.FromPublicKey(pub)
if err != nil {
    log.Fatal(err)
}

// Symmetric Key
keyBytes := make([]byte, 32) // 256-bit key
rand.Read(keyBytes)
symJWK, err := jwk.FromSymmetricKey(keyBytes, "A256GCM")
if err != nil {
    log.Fatal(err)
}
```

### Converting JWK to Keys

```go
// Convert JWK to public key
pubKey, err := jwk.ToPublicKey()
if err != nil {
    log.Fatal(err)
}

// Convert JWK to private key
privKey, err := jwk.ToPrivateKey()
if err != nil {
    log.Fatal(err)
}

// Extract symmetric key bytes
keyBytes, err := jwk.ToSymmetricKey()
if err != nil {
    log.Fatal(err)
}
```

### JSON Serialization

```go
// Marshal JWK to JSON
jsonBytes, err := jwk.Marshal()
if err != nil {
    log.Fatal(err)
}

// Marshal with indentation
jsonBytes, err := jwk.MarshalIndent("", "  ")
if err != nil {
    log.Fatal(err)
}

// Unmarshal JSON to JWK
jwk, err := jwk.Unmarshal(jsonBytes)
if err != nil {
    log.Fatal(err)
}
```

### JWK Thumbprints (RFC 7638)

Compute cryptographic thumbprints of public keys for key identification:

```go
// SHA-256 thumbprint (most common)
thumbprint, err := jwk.ThumbprintSHA256(publicKey)
if err != nil {
    log.Fatal(err)
}
fmt.Println("JWK Thumbprint:", thumbprint)

// Or compute from JWK directly
thumbprint, err := myJWK.ThumbprintSHA256()

// Other hash functions
thumbprintSHA1, _ := jwk.ThumbprintSHA1(publicKey)
thumbprintSHA512, _ := jwk.ThumbprintSHA512(publicKey)

// Generic thumbprint with custom hash
thumbprint, err := jwk.Thumbprint(publicKey, crypto.SHA384)
```

### ACME Key Authorization

Compute key authorization strings for ACME challenges (RFC 8555):

```go
token := "challenge_token_from_acme_server"
keyAuth, err := jwk.KeyAuthorization(token, publicKey)
if err != nil {
    log.Fatal(err)
}
// Use keyAuth for HTTP-01 or DNS-01 ACME challenges
```

## JWK Structure

### RSA Public Key

```json
{
  "kty": "RSA",
  "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXE...",
  "e": "AQAB"
}
```

### RSA Private Key

```json
{
  "kty": "RSA",
  "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXE...",
  "e": "AQAB",
  "d": "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2...",
  "p": "83i-7IvMGXoMXCskv73TKr8637FiO7Z27n...",
  "q": "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hW...",
  "dp": "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7...",
  "dq": "s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGO...",
  "qi": "GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9..."
}
```

### EC Public Key

```json
{
  "kty": "EC",
  "crv": "P-256",
  "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
  "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"
}
```

### OKP (Ed25519) Public Key

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
}
```

### Symmetric Key

```json
{
  "kty": "oct",
  "k": "GawgguFyGrWKav7AX4VKUg",
  "alg": "A256GCM"
}
```

## Key Methods

### JWK Type Methods

```go
// Check if JWK contains private key parameters
if jwk.IsPrivate() {
    // Handle private key
}

// Check if JWK represents a public key
if jwk.IsPublic() {
    // Handle public key
}

// Check if JWK represents a symmetric key
if jwk.IsSymmetric() {
    // Handle symmetric key
}
```

## Thumbprint Algorithm

The JWK thumbprint is computed according to RFC 7638:

1. Extract required fields for the key type:
   - RSA: `e`, `kty`, `n`
   - EC: `crv`, `kty`, `x`, `y`
   - OKP: `crv`, `kty`, `x`
   - oct: `k`, `kty`

2. Create JSON object with lexicographically sorted keys
3. Hash the UTF-8 representation
4. Base64url encode (no padding)

Example:
```
RSA JWK:     {"e":"AQAB","kty":"RSA","n":"0vx7ago..."}
SHA-256:     [32 bytes of hash output]
Thumbprint:  NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs
```

## Integration with go-keychain

This package is used internally by cloud backends (Azure Key Vault, GCP KMS, AWS KMS) for key import/export operations and can be used standalone for JWK operations.

## Standards Compliance

- **RFC 7517** - JSON Web Key (JWK)
- **RFC 7518** - JSON Web Algorithms (JWA)
- **RFC 7638** - JSON Web Key (JWK) Thumbprint
- **RFC 8555** - Automatic Certificate Management Environment (ACME) - Key Authorization

## Testing

The package includes comprehensive tests with RFC test vectors:

```bash
go test -v ./pkg/encoding/jwk/...
```

## Benchmarks

```bash
go test -bench=. ./pkg/encoding/jwk/...
```

Typical performance on modern hardware:
- RSA thumbprint: ~50,000 ops/sec
- ECDSA thumbprint: ~100,000 ops/sec
- Ed25519 thumbprint: ~150,000 ops/sec

## Security Considerations

- Private key JWKs should be protected with the same care as any private key material
- Symmetric keys (oct type) contain sensitive key material in the `k` field
- Thumbprints are deterministic and can be used as public key identifiers
- Always validate JWK parameters before using keys in cryptographic operations

## Example: Complete Key Lifecycle

```go
package main

import (
    "crypto/rand"
    "crypto/rsa"
    "fmt"
    "log"

    "github.com/jeremyhahn/go-keychain/pkg/encoding/jwk"
)

func main() {
    // Generate RSA key
    rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        log.Fatal(err)
    }

    // Convert to JWK
    jwkKey, err := jwk.FromPrivateKey(rsaKey)
    if err != nil {
        log.Fatal(err)
    }

    // Set optional fields
    jwkKey.Kid = "my-key-2024"
    jwkKey.Use = "sig"
    jwkKey.Alg = "RS256"

    // Serialize to JSON
    jsonBytes, err := jwkKey.MarshalIndent("", "  ")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("JWK:", string(jsonBytes))

    // Compute thumbprint for key identification
    thumbprint, err := jwkKey.ThumbprintSHA256()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Thumbprint:", thumbprint)

    // Deserialize from JSON
    parsedJWK, err := jwk.Unmarshal(jsonBytes)
    if err != nil {
        log.Fatal(err)
    }

    // Convert back to crypto.PrivateKey
    recoveredKey, err := parsedJWK.ToPrivateKey()
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Key recovered successfully: %T\n", recoveredKey)
}
```
