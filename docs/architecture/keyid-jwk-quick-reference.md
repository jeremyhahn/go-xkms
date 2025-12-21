# Key ID and JWK Integration - Quick Reference

**See full design:** [unified-keyid-jwk-integration.md](unified-keyid-jwk-integration.md)

## Key ID Format

**Format:** `backend:type:algo:keyname`

All segments except keyname are optional. Use shorthand `my-key` or explicit `:::my-key`.

**Examples:**
```
# Full specification
pkcs11:signing:ecdsa-p256:hsm-signing-key
tpm2:attestation:rsa:device-attestation
awskms:encryption:aes256-gcm:prod-encryption-key

# Partial specification
pkcs11:::my-key                # Backend only
my-key                         # Shorthand (keyname only)
```

**Supported Backends:**
- `pkcs8`, `aes`, `software` - File-based
- `pkcs11` - Hardware Security Module
- `tpm2` - Trusted Platform Module
- `awskms`, `gcpkms`, `azurekv`, `vault` - Cloud KMS

**Supported Key Types:**
- `signing`, `encryption`, `attestation`, `ca`, `tls`, `idevid`, `storage`, `endorsement`

**Supported Algorithms:**
- `rsa`, `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `ed25519`, `aes128-gcm`, `aes256-gcm`

## Quick Start

### 1. Get Key by ID

```go
// Get key by full specification
key, err := keystore.GetKeyByID("pkcs11:signing:ecdsa-p256:my-signing-key")

// Get key by shorthand (keyname only)
key, err := keystore.GetKeyByID("my-signing-key")

// Get signer
signer, err := keystore.GetSignerByID("tpm2:attestation:rsa:attestation-key")

// Get decrypter
decrypter, err := keystore.GetDecrypterByID("awskms:encryption:rsa:encryption-key")
```

### 2. Create JWK from Keychain

```go
// Create JWK with public key only
jwk, err := jwk.FromKeychain("pkcs11:prod-signing-key", keystore)

// Serialize to JSON
jwkJSON, _ := jwk.MarshalIndent("", "  ")
```

### 3. Load Key from JWK

```go
// Parse JWK
jwk, err := jwk.Unmarshal(jwkData)

// Load private key from keychain
if jwk.IsKeychainBacked() {
    key, err := jwk.LoadKeyFromKeychain(keystore)
    signer, err := jwk.ToKeychainSigner(keystore)
}
```

### 4. Configuration File

```yaml
keys:
  tls_server:
    id: "pkcs11:tls:rsa:server-tls"
    type: "rsa"
    size: 2048

jwt:
  signing_key: "pkcs11:signing:ecdsa-p256:api-signing"
```

## API Summary

### KeyStore Interface

```go
// Key retrieval by ID
GetKeyByID(keyID string) (crypto.PrivateKey, error)
GetSignerByID(keyID string) (crypto.Signer, error)
GetDecrypterByID(keyID string) (crypto.Decrypter, error)

// Parsing functions (in keychain package)
ParseKeyID(keyID string) (backend, keyType, algo, keyname string, err error)
ParseKeyIDToAttributes(keyID string) (*types.KeyAttributes, error)
ValidateKeyID(keyID string) error
```

### JWK Package

```go
// New functions
FromKeychain(keyID string, kc keychain.KeyStore) (*JWK, error)
(jwk *JWK) LoadKeyFromKeychain(kc keychain.KeyStore) (crypto.PrivateKey, error)
(jwk *JWK) IsKeychainBacked() bool
(jwk *JWK) ToKeychainSigner(kc keychain.KeyStore) (crypto.Signer, error)
```

## Security Notes

1. **Key IDs must use alphanumeric, hyphens, underscores only**
2. **No path traversal characters (/, .., \\)**
3. **Keychain-backed JWKs contain NO private key material**
4. **Always validate Key ID format before use**
5. **Backend type must match KeyStore backend**


## See Also

- [Full Design Document](unified-keyid-jwk-integration.md)
- [Architecture Overview](../architecture/overview.md)
- [Certificate Management](../certificate-management.md)
