# Unified Key ID Format and JWK Integration

## Overview

go-keychain uses a unified Key ID format (`backend:type:algo:keyname`) that enables seamless integration across all backends and provides bidirectional integration with JSON Web Keys (JWK).

## Key ID Format

**Format:** `backend:type:algo:keyname`

- **backend**: Backend type (case-insensitive) - e.g., `pkcs8`, `pkcs11`, `tpm2`
- **type**: Key purpose/type - e.g., `signing`, `encryption`, `attestation`
- **algo**: Algorithm - e.g., `rsa`, `ecdsa-p256`, `ed25519`
- **keyname**: The key's Common Name (CN) within that backend

### Optional Segments

All segments except keyname are **optional**. Users can omit segments by leaving them empty:

| Format | Description |
|--------|-------------|
| `my-key` | Shorthand for just keyname (uses defaults) |
| `:::my-key` | Explicit form of above |
| `pkcs11:::my-key` | Specify backend only |
| `pkcs11:signing::my-key` | Specify backend and type |
| `::rsa:my-key` | Specify algorithm only |
| `pkcs11:signing:ecdsa-p256:my-key` | Full specification |

### Supported Backends

| Backend | Example | Description |
|---------|---------|-------------|
| `pkcs8` | `pkcs8:signing:rsa:my-key` | File-based PKCS#8 asymmetric keys |
| `aes` | `aes:encryption:aes256-gcm:my-key` | File-based AES symmetric keys |
| `software` | `software:signing:ecdsa:my-key` | Unified software backend |
| `pkcs11` | `pkcs11:signing:ecdsa-p256:hsm-key` | PKCS#11 Hardware Security Module |
| `tpm2` | `tpm2:attestation:rsa:device-key` | Trusted Platform Module 2.0 |
| `awskms` | `awskms:encryption:rsa:prod-key` | AWS Key Management Service |
| `gcpkms` | `gcpkms:signing:ecdsa:gcp-key` | Google Cloud KMS |
| `azurekv` | `azurekv:encryption:rsa:azure-key` | Azure Key Vault |
| `vault` | `vault:signing:ed25519:vault-key` | HashiCorp Vault |

### Supported Key Types

| Type | Description |
|------|-------------|
| `signing` | Digital signature operations |
| `encryption` | Encryption/decryption operations |
| `attestation` | TPM attestation keys |
| `ca` | Certificate Authority keys |
| `tls` | TLS/SSL keys |
| `idevid` | IEEE 802.1AR IDevID keys |
| `storage` | Storage root keys |
| `endorsement` | TPM endorsement keys |

### Supported Algorithms

| Algorithm | Description |
|-----------|-------------|
| `rsa` | RSA (2048, 3072, 4096 bit) |
| `ecdsa-p256`, `p256` | ECDSA with P-256 curve |
| `ecdsa-p384`, `p384` | ECDSA with P-384 curve |
| `ecdsa-p521`, `p521` | ECDSA with P-521 curve |
| `ed25519` | Edwards-curve Ed25519 |
| `aes128-gcm` | AES-128 GCM |
| `aes256-gcm` | AES-256 GCM |

### Examples

```
# Full specification
pkcs11:signing:ecdsa-p256:hsm-signing-key
tpm2:attestation:rsa:device-attestation
awskms:encryption:aes256-gcm:prod-encryption-key

# Partial specification (using defaults)
pkcs11:::my-signing-key        # Backend only
:::my-key                       # All defaults
my-key                          # Shorthand for above
```

### Validation Rules

1. Backend, if specified, must be a supported type
2. Type, if specified, must be a valid key type
3. Algorithm, if specified, must be a valid algorithm
4. Keyname is required and cannot be empty
5. Keyname: alphanumeric characters, hyphens, and underscores only
6. Maximum total length: 512 characters
7. No path traversal characters (`..`, `/`, `\`)

## Keychain API

### Key Retrieval Methods

```go
// Get key by ID (full specification)
key, err := keystore.GetKeyByID("pkcs11:signing:ecdsa-p256:my-signing-key")

// Get key by ID (shorthand - just keyname)
key, err := keystore.GetKeyByID("my-signing-key")

// Get signer directly
signer, err := keystore.GetSignerByID("tpm2:attestation:rsa:attestation-key")
signature, _ := signer.Sign(rand.Reader, digest, crypto.SHA256)

// Get decrypter for RSA keys
decrypter, err := keystore.GetDecrypterByID("awskms:encryption:rsa:encryption-key")
plaintext, _ := decrypter.Decrypt(rand.Reader, ciphertext, opts)

// Parse Key ID into components
backend, keyType, algo, keyname, err := keychain.ParseKeyID("pkcs11:signing:ecdsa-p256:server-key")
// backend = "pkcs11", keyType = "signing", algo = "ecdsa-p256", keyname = "server-key"

// Parse with shorthand
backend, keyType, algo, keyname, err := keychain.ParseKeyID("my-key")
// backend = "", keyType = "", algo = "", keyname = "my-key"

// Validate Key ID format
err := keychain.ValidateKeyID("pkcs8:signing:rsa:valid-key")
```

### Error Types

```go
var (
    ErrInvalidKeyIDFormat = errors.New("keystore: invalid key ID format - expected 'backend:type:algo:keyname'")
    ErrInvalidBackendType = errors.New("keystore: invalid backend type")
    ErrBackendMismatch    = errors.New("keystore: key ID backend does not match keystore backend")
    ErrKeyNotFound        = errors.New("key not found")
)
```

## JWK Integration

### Creating JWKs from Keychain Keys

```go
// Create JWK from keychain key (public key only, for distribution)
jwk, err := jwk.FromKeychain("pkcs11:prod-signing-key", keystore)

// Result contains public key material with Key ID as kid:
// {
//   "kty": "RSA",
//   "kid": "pkcs11:prod-signing-key",
//   "n": "xGOr-H7A...",
//   "e": "AQAB",
//   "alg": "RS256",
//   "use": "sig"
// }
```

### Loading Keys from JWKs

```go
// Check if JWK references a keychain key
if jwk.IsKeychainBacked() {
    // Load private key from keychain using kid
    key, err := jwk.LoadKeyFromKeychain(keystore)

    // Or get a signer directly
    signer, err := jwk.ToKeychainSigner(keystore)
}
```

### JWK API Reference

```go
// FromKeychain creates a JWK with public key material and kid set to the Key ID
func FromKeychain(keyID string, kc keychain.KeyStore) (*JWK, error)

// LoadKeyFromKeychain loads private key using the JWK's kid field
func (jwk *JWK) LoadKeyFromKeychain(kc keychain.KeyStore) (crypto.PrivateKey, error)

// IsKeychainBacked returns true if kid matches the Key ID format
func (jwk *JWK) IsKeychainBacked() bool

// ToKeychainSigner returns a crypto.Signer backed by the keychain
func (jwk *JWK) ToKeychainSigner(kc keychain.KeyStore) (crypto.Signer, error)
```

## JWT Integration

### Signing JWTs

```go
func SignJWT(claims jwt.Claims, keyID string, kc keychain.KeyStore) (string, error) {
    signer, err := kc.GetSignerByID(keyID)
    if err != nil {
        return "", err
    }

    token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
    token.Header["kid"] = keyID

    return token.SignedString(signer)
}
```

### Verifying JWTs

```go
func VerifyJWT(tokenString string, kc keychain.KeyStore) (*jwt.Token, error) {
    return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        kid, ok := token.Header["kid"].(string)
        if !ok {
            return nil, fmt.Errorf("no kid in JWT header")
        }

        key, err := kc.GetKeyByID(kid)
        if err != nil {
            return nil, err
        }

        if pk, ok := key.(interface{ Public() crypto.PublicKey }); ok {
            return pk.Public(), nil
        }
        return nil, fmt.Errorf("key does not expose public key")
    })
}
```

## Configuration

### YAML Configuration

```yaml
keystore:
  backend: pkcs11
  pkcs11:
    library: /usr/lib/softhsm/libsofthsm2.so
    slot: 0
    pin: "${PKCS11_PIN}"

keys:
  - id: "pkcs11:server-tls"
    type: "rsa"
    size: 2048
  - id: "pkcs11:api-signing"
    type: "ecdsa"
    curve: "P-256"

jwt:
  issuer: "https://api.example.com"
  signing_key: "pkcs11:api-signing"
```

## Backend-Specific Key ID Mapping

| Backend | keyname maps to |
|---------|-----------------|
| PKCS#8 | Filename without extension |
| PKCS#11 | CKA_LABEL attribute |
| TPM2 | Persistent handle name |
| AWS KMS | Key alias |
| GCP KMS | Key name |
| Azure KV | Key name in vault |
| Vault | Key name in transit engine |
| YubiKey | PIV slot identifier |
| CanoKey | PIV slot identifier |

Backend-specific parameters (slot, PIN, region, credentials, etc.) are handled by backend configuration, not the Key ID.

## Security Considerations

### Key ID Validation

All Key IDs are validated to prevent injection attacks:

- Length limits enforced (max 512 characters)
- Path traversal blocked (`..`, `/`, `\`)
- Character whitelist: `[a-zA-Z0-9_-]`
- Backend type must be valid

### JWK Security

- Keychain-backed JWKs contain **public key material only**
- Private key operations are performed by the backend
- Always validate `kid` format before loading keys
- Verify public key matches when processing external JWKs

### JWT Security

- Validate algorithm matches expected type
- Verify `kid` exists and references valid key
- Check key purpose matches JWT use (signing vs encryption)

## References

- [RFC 7517 - JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [RFC 7518 - JSON Web Algorithms (JWA)](https://tools.ietf.org/html/rfc7518)
- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [NIST SP 800-57 - Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
