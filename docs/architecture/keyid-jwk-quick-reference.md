# Key ID and JWK Integration - Quick Reference

**See full design:** [unified-keyid-jwk-integration.md](unified-keyid-jwk-integration.md)

## Key ID Format

**Format:** `backend:keyname`

**Examples:**
```
pkcs8:server-tls-key
pkcs11:hsm-signing-key
tpm2:device-attestation
awskms:prod-encryption-key
```

**Supported Backends:**
- `pkcs8`, `aes`, `software` - File-based
- `pkcs11` - Hardware Security Module
- `tpm2` - Trusted Platform Module
- `awskms`, `gcpkms`, `azurekv`, `vault` - Cloud KMS
- `yubikey`, `smartcardhsm` - SmartCard-HSM

## Quick Start

### 1. Get Key by ID

```go
// Get key directly
key, err := keystore.GetKeyByID("pkcs11:my-signing-key")

// Get signer
signer, err := keystore.GetSignerByID("tpm2:attestation-key")

// Get decrypter
decrypter, err := keystore.GetDecrypterByID("awskms:encryption-key")
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
    id: "pkcs11:server-tls"
    type: "rsa"
    size: 2048

jwt:
  signing_key: "pkcs11:api-signing"
```

## API Summary

### KeyStore Interface

```go
// New methods
GetKeyByID(keyID string) (crypto.PrivateKey, error)
GetSignerByID(keyID string) (crypto.Signer, error)
GetDecrypterByID(keyID string) (crypto.Decrypter, error)
ParseKeyID(keyID string) (backend, keyname string, err error)
ValidateKeyID(keyID string, checkExists bool) error
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
