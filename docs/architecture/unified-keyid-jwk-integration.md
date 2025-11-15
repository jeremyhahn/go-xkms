# Unified Key ID Format and JWK Integration


## Executive Summary

This document specifies a unified Key ID format for the go-keychain library that enables seamless integration across all backends (PKCS#8, AES, PKCS#11, SmartCard-HSM, TPM2, YubiKey, AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault) and provides bidirectional integration with JSON Web Keys (JWK) for modern cryptographic workflows.

The design introduces a simple, human-readable key identifier format (`backend:keyname`) that can be used consistently across all APIs, stored in JWK `kid` fields, referenced in JWT tokens, and serialized in configuration files.


## 1. Key ID Format Specification

### 1.1 Format Definition

**Format:** `backend:keyname`

Where:
- **backend**: One of the supported backend types (case-insensitive)
- **keyname**: The key's Common Name (CN) or identifier within that backend

**Supported Backend Types:**
- `pkcs8` - File-based PKCS#8 asymmetric keys
- `aes` - File-based AES symmetric keys
- `software` - Unified software backend (asymmetric + symmetric)
- `pkcs11` - PKCS#11 Hardware Security Module
- `smartcardhsm` - CardContact SmartCard-HSM with DKEK
- `yubikey` - YubiKey PIV smart card
- `tpm2` - Trusted Platform Module 2.0
- `awskms` - AWS Key Management Service
- `gcpkms` - Google Cloud KMS
- `azurekv` - Azure Key Vault
- `vault` - HashiCorp Vault

### 1.2 Examples

```
pkcs8:server-tls-key
aes:symmetric-encryption-key
software:development-key
pkcs11:hsm-signing-key
smartcardhsm:backup-key
yubikey:piv-signing-key
tpm2:device-attestation
awskms:prod-encryption-key
gcpkms:api-signing-key
azurekv:database-master-key
vault:transit-engine-key
```

### 1.3 Validation Rules

1. **Backend Component:**
   - MUST be one of the supported backend types
   - Case-insensitive (normalized to lowercase)
   - Required (cannot be empty)

2. **Keyname Component:**
   - MUST match the key's `CN` field in `backend.KeyAttributes`
   - Cannot be empty
   - Should use alphanumeric characters, hyphens, and underscores
   - Maximum length: 255 characters (practical limit)
   - Recommended: Use DNS-safe characters for portability

3. **Separator:**
   - MUST be a single colon (`:`)
   - No spaces allowed before or after separator

4. **Additional Constraints:**
   - Total Key ID length should not exceed 512 characters
   - Backend and keyname components are separated by exactly one colon
   - No additional colons allowed in keyname (use hyphens or underscores instead)

### 1.4 Parsing Algorithm

```go
func ParseKeyID(keyID string) (backend, keyname string, err error) {
    parts := strings.SplitN(keyID, ":", 2)
    if len(parts) != 2 {
        return "", "", ErrInvalidKeyIDFormat
    }
    
    backend = strings.ToLower(strings.TrimSpace(parts[0]))
    keyname = strings.TrimSpace(parts[1])
    
    if backend == "" || keyname == "" {
        return "", "", ErrInvalidKeyIDFormat
    }
    
    if !isValidBackend(backend) {
        return "", "", ErrInvalidBackendType
    }
    
    return backend, keyname, nil
}
```

### 1.5 Serialization

Key IDs are serialized as-is in:
- Configuration files (YAML, JSON, TOML)
- JWK `kid` fields
- JWT `kid` headers
- Database records
- Log entries
- API requests/responses

**Example YAML Configuration:**
```yaml
keys:
  - id: "pkcs11:prod-signing-key"
    type: "rsa"
    size: 4096
  - id: "awskms:encryption-key"
    type: "ecdsa"
    curve: "P-256"
```


## 2. Keychain API Extensions

### 2.1 New Methods

The following methods are added to the `KeyStore` interface in `pkg/keychain/keystore.go`:

```go
type KeyStore interface {
    // Existing methods...
    
    // GetKeyByID retrieves a key using the unified Key ID format.
    // The Key ID is parsed to determine the backend and key name.
    // Returns the key wrapped in an OpaqueKey for safe operations.
    //
    // Example:
    //   key, err := keystore.GetKeyByID("pkcs11:my-signing-key")
    GetKeyByID(keyID string) (crypto.PrivateKey, error)
    
    // GetSignerByID retrieves a crypto.Signer using the unified Key ID format.
    // This is a convenience method that calls GetKeyByID and returns the
    // crypto.Signer interface for signing operations.
    //
    // Example:
    //   signer, err := keystore.GetSignerByID("tpm2:attestation-key")
    //   signature, _ := signer.Sign(rand.Reader, digest, crypto.SHA256)
    GetSignerByID(keyID string) (crypto.Signer, error)
    
    // GetDecrypterByID retrieves a crypto.Decrypter using the unified Key ID format.
    // This is a convenience method for RSA decryption operations.
    //
    // Example:
    //   decrypter, err := keystore.GetDecrypterByID("awskms:rsa-key")
    //   plaintext, _ := decrypter.Decrypt(rand.Reader, ciphertext, opts)
    GetDecrypterByID(keyID string) (crypto.Decrypter, error)
    
    // ParseKeyID parses a unified Key ID into its components.
    // Returns the backend type and key name, or an error if invalid.
    //
    // Example:
    //   backend, keyname, err := keystore.ParseKeyID("pkcs8:server-key")
    //   // backend = "pkcs8", keyname = "server-key"
    ParseKeyID(keyID string) (backend, keyname string, err error)
    
    // ValidateKeyID validates a Key ID without retrieving the key.
    // Checks format, backend type, and optionally verifies key existence.
    //
    // Example:
    //   err := keystore.ValidateKeyID("invalid:key:format") // error
    //   err := keystore.ValidateKeyID("pkcs8:valid-key")    // nil
    ValidateKeyID(keyID string, checkExists bool) error
}
```

### 2.2 Backend Mapping

Key IDs are mapped to `backend.KeyAttributes` as follows:

```go
func (ks *compositeKeyStore) keyIDToAttributes(keyID string) (*backend.KeyAttributes, error) {
    backendType, keyname, err := ks.ParseKeyID(keyID)
    if err != nil {
        return nil, err
    }
    
    // Verify the backend type matches the current keystore backend
    expectedBackend := ks.backend.Type()
    if backendType != string(expectedBackend) {
        return nil, ErrBackendMismatch
    }
    
    // Create KeyAttributes with CN set to keyname
    // Note: KeyType, KeyAlgorithm, and other fields may need to be
    // retrieved from storage metadata or inferred from the key itself
    attrs := &backend.KeyAttributes{
        CN:        keyname,
        StoreType: backend.StoreType(backendType),
    }
    
    return attrs, nil
}
```

**Important Design Decision:**

The Key ID format contains only `backend:keyname` because:
1. The backend type routes to the correct KeyStore instance
2. The CN (keyname) uniquely identifies the key within that backend
3. Additional metadata (KeyType, KeyAlgorithm, etc.) is stored with the key

When retrieving a key by ID, the implementation will:
1. Parse the Key ID to extract backend and keyname
2. Verify the backend matches the current KeyStore's backend
3. Query the backend for the key using CN=keyname
4. The backend returns the complete key with all metadata

### 2.3 Error Handling

**New Error Types:**

```go
var (
    // ErrInvalidKeyIDFormat indicates the Key ID doesn't match "backend:keyname" format
    ErrInvalidKeyIDFormat = errors.New("invalid key ID format: expected 'backend:keyname'")
    
    // ErrInvalidBackendType indicates an unrecognized backend type
    ErrInvalidBackendType = errors.New("invalid backend type")
    
    // ErrBackendMismatch indicates the Key ID references a different backend
    ErrBackendMismatch = errors.New("key ID backend does not match keystore backend")
    
    // ErrKeyNotFound indicates the key doesn't exist
    ErrKeyNotFound = errors.New("key not found")
)
```

**Error Handling Strategy:**

1. **Parse Errors**: Return `ErrInvalidKeyIDFormat` with details
2. **Backend Mismatch**: Return `ErrBackendMismatch` with expected/actual backends
3. **Key Not Found**: Return `ErrKeyNotFound` from backend operations
4. **Wrap Errors**: Always wrap backend errors with context


## 3. JWK Integration

### 3.1 JWK Package Extensions

The JWK package (`pkg/encoding/jwk`) is extended with the following functions:

```go
package jwk

import (
    "crypto"
    "github.com/jeremyhahn/go-keychain/pkg/keychain"
)

// FromKeychain creates a JWK from a keychain key using the unified Key ID.
// The JWK will contain:
// - kid: The unified Key ID (e.g., "pkcs11:signing-key")
// - Public key material (n, e for RSA; x, y for EC)
// - Appropriate algorithm (alg) and use (use) fields
//
// Example:
//   jwk, err := FromKeychain("pkcs11:my-key", keystore)
//   // jwk.Kid = "pkcs11:my-key"
//   // jwk.Kty = "RSA", jwk.N = "...", jwk.E = "..."
func FromKeychain(keyID string, kc keychain.KeyStore) (*JWK, error)

// LoadKeyFromKeychain loads a private key from the keychain using
// the JWK's kid field as the Key ID.
//
// Example:
//   jwk := &JWK{Kid: "tpm2:attestation-key"}
//   key, err := jwk.LoadKeyFromKeychain(keystore)
func (jwk *JWK) LoadKeyFromKeychain(kc keychain.KeyStore) (crypto.PrivateKey, error)

// IsKeychainBacked returns true if the JWK references a keychain key
// (has a kid field matching the Key ID format) rather than containing
// embedded key material.
//
// Example:
//   jwk := &JWK{Kid: "pkcs11:key", Kty: "RSA", N: "...", E: "..."}
//   jwk.IsKeychainBacked() // true (has kid in Key ID format)
//
//   jwk := &JWK{Kty: "RSA", N: "...", E: "...", D: "..."}
//   jwk.IsKeychainBacked() // false (embedded key material, no kid)
func (jwk *JWK) IsKeychainBacked() bool

// ToKeychainSigner returns a crypto.Signer backed by the keychain.
// The JWK must have a kid field in the unified Key ID format.
//
// Example:
//   jwk := &JWK{Kid: "pkcs11:signing-key"}
//   signer, err := jwk.ToKeychainSigner(keystore)
func (jwk *JWK) ToKeychainSigner(kc keychain.KeyStore) (crypto.Signer, error)
```

### 3.2 JWK Modes

The library supports two modes for JWK usage:

#### 3.2.1 Standalone JWK (Embedded Key Material)

Traditional JWK containing the actual key material:

```json
{
  "kty": "RSA",
  "kid": "optional-identifier",
  "n": "xGOr-H7A...",
  "e": "AQAB",
  "d": "private...",
  "alg": "RS256",
  "use": "sig"
}
```

**Characteristics:**
- Contains complete key material (public + private)
- Can be used directly without external key source
- `kid` is optional and may not match Key ID format
- Serializable to JSON for storage/transport

#### 3.2.2 Keychain-Reference JWK (Key ID Only)

JWK that references a keychain-backed key:

```json
{
  "kty": "RSA",
  "kid": "pkcs11:prod-signing-key",
  "n": "xGOr-H7A...",
  "e": "AQAB",
  "alg": "RS256",
  "use": "sig"
}
```

**Characteristics:**
- `kid` field MUST match unified Key ID format
- Contains public key material for verification
- Does NOT contain private key material (`d`, `p`, `q` fields are absent)
- Private key operations require access to the keychain
- More secure as private key never leaves backend

**Detection Logic:**

```go
func (jwk *JWK) IsKeychainBacked() bool {
    if jwk.Kid == "" {
        return false
    }
    
    // Check if kid matches "backend:keyname" format
    parts := strings.Split(jwk.Kid, ":")
    if len(parts) != 2 {
        return false
    }
    
    backend := strings.ToLower(parts[0])
    validBackends := []string{
        "pkcs8", "aes", "software", "pkcs11", "tpm2",
        "awskms", "gcpkms", "azurekv", "vault",
    }
    
    for _, b := range validBackends {
        if backend == b {
            return true
        }
    }
    
    return false
}
```

### 3.3 JWK Implementation

**pkg/encoding/jwk/keychain.go:**

```go
package jwk

import (
    "crypto"
    "crypto/ecdsa"
    "crypto/rsa"
    "crypto/ed25519"
    "fmt"
    "strings"
    
    "github.com/jeremyhahn/go-keychain/pkg/keychain"
)

// FromKeychain creates a JWK from a keychain key identified by keyID.
// The resulting JWK contains:
// - kid: The unified Key ID
// - Public key material (for verification)
// - NO private key material (for security)
// - Appropriate algorithm and use fields
func FromKeychain(keyID string, kc keychain.KeyStore) (*JWK, error) {
    // Validate Key ID format
    if err := kc.ValidateKeyID(keyID, true); err != nil {
        return nil, fmt.Errorf("invalid key ID: %w", err)
    }
    
    // Retrieve the key
    key, err := kc.GetKeyByID(keyID)
    if err != nil {
        return nil, fmt.Errorf("failed to get key: %w", err)
    }
    
    // Extract public key
    var pubKey crypto.PublicKey
    if pk, ok := key.(interface{ Public() crypto.PublicKey }); ok {
        pubKey = pk.Public()
    } else {
        return nil, fmt.Errorf("key does not expose public key")
    }
    
    // Create JWK from public key
    jwk, err := FromPublicKey(pubKey)
    if err != nil {
        return nil, fmt.Errorf("failed to create JWK: %w", err)
    }
    
    // Set kid to the Key ID
    jwk.Kid = keyID
    
    // Set use field based on key algorithm
    jwk.Use = "sig" // Default to signing; could be inferred from key type
    
    return jwk, nil
}

// LoadKeyFromKeychain loads the private key from the keychain using
// the JWK's kid field as the Key ID.
func (jwk *JWK) LoadKeyFromKeychain(kc keychain.KeyStore) (crypto.PrivateKey, error) {
    if jwk.Kid == "" {
        return nil, fmt.Errorf("JWK has no kid field")
    }
    
    if !jwk.IsKeychainBacked() {
        return nil, fmt.Errorf("JWK kid is not a valid keychain Key ID")
    }
    
    return kc.GetKeyByID(jwk.Kid)
}

// IsKeychainBacked returns true if the JWK references a keychain key.
func (jwk *JWK) IsKeychainBacked() bool {
    if jwk.Kid == "" {
        return false
    }
    
    parts := strings.Split(jwk.Kid, ":")
    if len(parts) != 2 {
        return false
    }
    
    backend := strings.ToLower(parts[0])
    validBackends := []string{
        "pkcs8", "aes", "software", "pkcs11", "tpm2",
        "awskms", "gcpkms", "azurekv", "vault",
    }
    
    for _, b := range validBackends {
        if backend == b {
            return true
        }
    }
    
    return false
}

// ToKeychainSigner returns a crypto.Signer backed by the keychain.
func (jwk *JWK) ToKeychainSigner(kc keychain.KeyStore) (crypto.Signer, error) {
    if !jwk.IsKeychainBacked() {
        return nil, fmt.Errorf("JWK is not keychain-backed")
    }
    
    return kc.GetSignerByID(jwk.Kid)
}
```


## 4. JWT Integration

### 4.1 JWT Package (Future Work)

While a full JWT implementation is beyond the scope of this design, the Key ID and JWK integration enables JWT workflows:

**Signing JWTs with Keychain Keys:**

```go
import (
    "github.com/golang-jwt/jwt/v5"
    "github.com/jeremyhahn/go-keychain/pkg/encoding/jwk"
)

func SignJWT(claims jwt.Claims, keyID string, kc keychain.KeyStore) (string, error) {
    // Get signer from keychain
    signer, err := kc.GetSignerByID(keyID)
    if err != nil {
        return "", err
    }
    
    // Create JWT token
    token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
    token.Header["kid"] = keyID  // Include Key ID in JWT header
    
    // Sign using keychain-backed signer
    return token.SignedString(signer)
}
```

**Verifying JWTs with Keychain Keys:**

```go
func VerifyJWT(tokenString string, kc keychain.KeyStore) (*jwt.Token, error) {
    // Parse with key lookup function
    return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        // Extract kid from JWT header
        kid, ok := token.Header["kid"].(string)
        if !ok {
            return nil, fmt.Errorf("no kid in JWT header")
        }
        
        // Load key from keychain using JWK
        jwk := &jwk.JWK{Kid: kid}
        key, err := jwk.LoadKeyFromKeychain(kc)
        if err != nil {
            return nil, err
        }
        
        // Return public key for verification
        if pk, ok := key.(interface{ Public() crypto.PublicKey }); ok {
            return pk.Public(), nil
        }
        
        return nil, fmt.Errorf("key does not expose public key")
    })
}
```

### 4.2 JWT Example Workflow

1. **Generate Key in Keychain:**
   ```go
   attrs := &backend.KeyAttributes{
       CN:          "api-signing-key",
       KeyType:     backend.KEY_TYPE_SIGNING,
       StoreType:   backend.STORE_PKCS11,
       KeyAlgorithm: backend.ALG_RSA,
       RSAAttributes: &backend.RSAAttributes{KeySize: 2048},
   }
   key, _ := keystore.GenerateRSA(attrs)
   ```

2. **Create JWK from Key:**
   ```go
   jwk, _ := jwk.FromKeychain("pkcs11:api-signing-key", keystore)
   // jwk.Kid = "pkcs11:api-signing-key"
   ```

3. **Sign JWT:**
   ```go
   claims := jwt.MapClaims{"sub": "user123", "exp": time.Now().Add(time.Hour).Unix()}
   tokenString, _ := SignJWT(claims, "pkcs11:api-signing-key", keystore)
   // JWT header: {"kid": "pkcs11:api-signing-key", "alg": "RS256"}
   ```

4. **Verify JWT:**
   ```go
   token, _ := VerifyJWT(tokenString, keystore)
   // Keychain automatically loads key using kid from JWT header
   ```


## 5. Usage Examples

### 5.1 Retrieving Keys by ID

**Basic Key Retrieval:**

```go
// Get key by ID
key, err := keystore.GetKeyByID("pkcs11:my-signing-key")
if err != nil {
    log.Fatal(err)
}

// Use key for cryptographic operations
signer := key.(crypto.Signer)
signature, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
```

**Get Signer Directly:**

```go
// Get signer by ID (convenience method)
signer, err := keystore.GetSignerByID("tpm2:attestation-key")
if err != nil {
    log.Fatal(err)
}

// Sign data
signature, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
```

**Get Decrypter:**

```go
// Get RSA decrypter by ID
decrypter, err := keystore.GetDecrypterByID("awskms:encryption-key")
if err != nil {
    log.Fatal(err)
}

// Decrypt data
plaintext, err := decrypter.Decrypt(rand.Reader, ciphertext, &rsa.OAEPOptions{
    Hash: crypto.SHA256,
})
```

### 5.2 Creating JWKs from Keychain

**Public JWK for Distribution:**

```go
// Create JWK for key verification (public key only)
jwk, err := jwk.FromKeychain("pkcs11:prod-signing-key", keystore)
if err != nil {
    log.Fatal(err)
}

// Serialize to JSON for JWKS endpoint
jwkJSON, _ := jwk.MarshalIndent("", "  ")
fmt.Println(string(jwkJSON))

// Output:
// {
//   "kty": "RSA",
//   "kid": "pkcs11:prod-signing-key",
//   "n": "xGOr-H7A...",
//   "e": "AQAB",
//   "alg": "RS256",
//   "use": "sig"
// }
```

**JWKS Endpoint:**

```go
func JWKSHandler(w http.ResponseWriter, r *http.Request) {
    // List all signing keys
    attrs, _ := keystore.ListKeys()
    
    jwks := make([]*jwk.JWK, 0)
    for _, attr := range attrs {
        if attr.KeyType == backend.KEY_TYPE_SIGNING {
            keyID := fmt.Sprintf("%s:%s", attr.StoreType, attr.CN)
            jwk, err := jwk.FromKeychain(keyID, keystore)
            if err == nil {
                jwks = append(jwks, jwk)
            }
        }
    }
    
    response := map[string]interface{}{
        "keys": jwks,
    }
    
    json.NewEncoder(w).Encode(response)
}
```

### 5.3 Loading Keys from JWK kid

**Load Private Key:**

```go
// Parse JWK from JSON
jwkData := []byte(`{
    "kty": "RSA",
    "kid": "pkcs11:my-key",
    "n": "...",
    "e": "AQAB",
    "use": "sig"
}`)

jwk, err := jwk.Unmarshal(jwkData)
if err != nil {
    log.Fatal(err)
}

// Load private key from keychain using kid
if jwk.IsKeychainBacked() {
    key, err := jwk.LoadKeyFromKeychain(keystore)
    if err != nil {
        log.Fatal(err)
    }
    
    // Use key for signing
    signer := key.(crypto.Signer)
    signature, _ := signer.Sign(rand.Reader, digest, crypto.SHA256)
}
```

**Get Signer from JWK:**

```go
// JWK references keychain key
jwk := &jwk.JWK{
    Kty: "RSA",
    Kid: "tpm2:device-key",
}

// Get signer
signer, err := jwk.ToKeychainSigner(keystore)
if err != nil {
    log.Fatal(err)
}

// Sign data
signature, _ := signer.Sign(rand.Reader, digest, crypto.SHA256)
```

### 5.4 Configuration File Usage

**YAML Configuration:**

```yaml
# config.yaml
keystore:
  backend: pkcs11
  pkcs11:
    library: /usr/lib/softhsm/libsofthsm2.so
    slot: 0
    pin: "1234"

keys:
  tls_server:
    id: "pkcs11:server-tls"
    type: "rsa"
    size: 2048
    use: "tls"
  
  api_signing:
    id: "pkcs11:api-signing"
    type: "ecdsa"
    curve: "P-256"
    use: "signing"

jwt:
  issuer: "https://api.example.com"
  signing_key: "pkcs11:api-signing"  # Reference by Key ID
  expiration: 3600
```

**Loading Configuration:**

```go
type Config struct {
    Keystore struct {
        Backend string `yaml:"backend"`
    } `yaml:"keystore"`
    
    Keys map[string]struct {
        ID    string `yaml:"id"`
        Type  string `yaml:"type"`
        Size  int    `yaml:"size"`
        Curve string `yaml:"curve"`
        Use   string `yaml:"use"`
    } `yaml:"keys"`
    
    JWT struct {
        Issuer     string `yaml:"issuer"`
        SigningKey string `yaml:"signing_key"`
        Expiration int    `yaml:"expiration"`
    } `yaml:"jwt"`
}

func LoadConfig(path string) (*Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    
    var cfg Config
    if err := yaml.Unmarshal(data, &cfg); err != nil {
        return nil, err
    }
    
    return &cfg, nil
}

// Use configuration
cfg, _ := LoadConfig("config.yaml")
signer, _ := keystore.GetSignerByID(cfg.JWT.SigningKey)
```

### 5.5 Multi-Backend Scenario

**Scenario:** Application uses multiple backends for different purposes

```go
// Initialize multiple keystores
pkcs11Store, _ := keychain.New(&keychain.Config{
    Backend:     pkcs11Backend,
    CertStorage: certStorage,
})

awsStore, _ := keychain.New(&keychain.Config{
    Backend:     awsBackend,
    CertStorage: certStorage,
})

// Registry pattern for routing Key IDs to correct keystore
type KeyStoreRegistry struct {
    stores map[string]keychain.KeyStore
}

func (r *KeyStoreRegistry) GetSignerByID(keyID string) (crypto.Signer, error) {
    backend, _, err := keychain.ParseKeyID(keyID)
    if err != nil {
        return nil, err
    }
    
    store, ok := r.stores[backend]
    if !ok {
        return nil, fmt.Errorf("no keystore for backend: %s", backend)
    }
    
    return store.GetSignerByID(keyID)
}

// Usage
registry := &KeyStoreRegistry{
    stores: map[string]keychain.KeyStore{
        "pkcs11": pkcs11Store,
        "awskms": awsStore,
    },
}

// Automatically routes to correct backend
signer, _ := registry.GetSignerByID("pkcs11:hsm-key")
signature, _ := signer.Sign(rand.Reader, digest, crypto.SHA256)
```


## 6. Backend-Specific Considerations

### 6.1 PKCS#8 (File-based)

**Key ID Mapping:**
- keyname = filename without extension
- Example: `pkcs8:server-key` → `/keys/server-key.rsa.key`

**Storage Structure:**
```
/var/lib/keychain/keys/
├── server-key.rsa.key
├── api-key.ecdsa.key
└── device-key.ed25519.key
```

**Implementation Note:**
- KeyAttributes.CN maps directly to filename
- Extension determined by algorithm

### 6.2 PKCS#11 (HSM)

**Key ID Mapping:**
- keyname = CKA_LABEL attribute
- Example: `pkcs11:prod-signing` → HSM object with label "prod-signing"

**Backend-Specific Parameters:**
- Slot, PIN, Token Label handled by backend config
- Not part of Key ID

**Example:**
```go
attrs := &backend.KeyAttributes{
    CN:        "prod-signing",    // Maps to CKA_LABEL
    StoreType: backend.STORE_PKCS11,
}
// Key ID: "pkcs11:prod-signing"
```

### 6.3 TPM2

**Key ID Mapping:**
- keyname = persistent handle name or object name
- Example: `tpm2:ak-key` → TPM persistent handle 0x81010001

**Backend-Specific Parameters:**
- Hierarchy, auth values managed by backend
- Not exposed in Key ID

**Example:**
```go
attrs := &backend.KeyAttributes{
    CN:        "ak-key",          // Maps to TPM object name
    StoreType: backend.STORE_TPM2,
}
// Key ID: "tpm2:ak-key"
```

### 6.4 AWS KMS

**Key ID Mapping:**
- keyname = KMS key alias or key ID
- Example: `awskms:prod-key` → alias/prod-key or key-id

**Backend-Specific Parameters:**
- Region, credentials handled by backend config
- Not part of Key ID

**Example:**
```go
attrs := &backend.KeyAttributes{
    CN:        "prod-key",        // Maps to KMS alias
    StoreType: backend.STORE_AWSKMS,
}
// Key ID: "awskms:prod-key"
// Actual AWS ARN: arn:aws:kms:us-east-1:123456789:alias/prod-key
```

### 6.5 GCP KMS

**Key ID Mapping:**
- keyname = key name (not full resource path)
- Example: `gcpkms:signing-key` → projects/*/locations/*/keyRings/*/cryptoKeys/signing-key

**Backend-Specific Parameters:**
- Project ID, location, key ring handled by backend config
- Not part of Key ID

**Example:**
```go
attrs := &backend.KeyAttributes{
    CN:        "signing-key",
    StoreType: backend.STORE_GCPKMS,
}
// Key ID: "gcpkms:signing-key"
// Full path: projects/my-project/locations/us-east1/keyRings/prod/cryptoKeys/signing-key
```

### 6.6 Azure Key Vault

**Key ID Mapping:**
- keyname = key name in vault
- Example: `azurekv:prod-key` → https://vault.vault.azure.net/keys/prod-key

**Backend-Specific Parameters:**
- Vault URL, credentials handled by backend config
- Not part of Key ID

**Example:**
```go
attrs := &backend.KeyAttributes{
    CN:        "prod-key",
    StoreType: backend.STORE_AZUREKV,
}
// Key ID: "azurekv:prod-key"
// Actual URL: https://myvault.vault.azure.net/keys/prod-key
```

### 6.7 HashiCorp Vault

**Key ID Mapping:**
- keyname = key name in transit engine
- Example: `vault:encryption-key` → /transit/keys/encryption-key

**Backend-Specific Parameters:**
- Vault address, token, mount path handled by backend config
- Not part of Key ID

**Example:**
```go
attrs := &backend.KeyAttributes{
    CN:        "encryption-key",
    StoreType: backend.STORE_VAULT,
}
// Key ID: "vault:encryption-key"
// Actual path: https://vault.example.com:8200/v1/transit/keys/encryption-key
```


## 7. Security Considerations

### 7.1 Key ID Format Security

**Potential Risks:**
1. **Injection Attacks**: Malicious Key IDs with special characters
2. **Path Traversal**: Key IDs like `pkcs8:../../etc/passwd`
3. **Backend Confusion**: Requesting keys from wrong backend

**Mitigations:**

1. **Strict Validation:**
   ```go
   func ValidateKeyID(keyID string) error {
       // Length check
       if len(keyID) > 512 {
           return ErrKeyIDTooLong
       }
       
       // Format check
       parts := strings.SplitN(keyID, ":", 2)
       if len(parts) != 2 {
           return ErrInvalidKeyIDFormat
       }
       
       backend, keyname := parts[0], parts[1]
       
       // Backend validation
       if !isValidBackend(backend) {
           return ErrInvalidBackendType
       }
       
       // Keyname validation (no path traversal)
       if strings.Contains(keyname, "..") || 
          strings.Contains(keyname, "/") ||
          strings.Contains(keyname, "\\") {
           return ErrInvalidKeyName
       }
       
       // Character whitelist
       if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(keyname) {
           return ErrInvalidKeyNameChars
       }
       
       return nil
   }
   ```

2. **Backend Verification:**
   - Always verify Key ID backend matches KeyStore backend
   - Prevent cross-backend key access

3. **Access Control:**
   - Implement RBAC at KeyStore level
   - Audit all key access with Key IDs

### 7.2 JWK kid Validation

**Risks:**
1. **Untrusted JWKs**: JWK from external source with malicious kid
2. **Key Confusion**: kid references wrong key or backend

**Mitigations:**

1. **Validate Before Loading:**
   ```go
   func (jwk *JWK) LoadKeyFromKeychain(kc keychain.KeyStore) (crypto.PrivateKey, error) {
       // Validate kid format
       if err := kc.ValidateKeyID(jwk.Kid, false); err != nil {
           return nil, fmt.Errorf("invalid kid: %w", err)
       }
       
       // Check if key exists
       if err := kc.ValidateKeyID(jwk.Kid, true); err != nil {
           return nil, fmt.Errorf("key not found: %w", err)
       }
       
       // Load key
       return kc.GetKeyByID(jwk.Kid)
   }
   ```

2. **Public Key Verification:**
   - Compare JWK public key with keychain public key
   - Prevent kid/key mismatch attacks

3. **Allowlist:**
   - Maintain allowlist of valid Key IDs for JWK operations
   - Reject unknown kid values

### 7.3 JWT kid Security

**Risks:**
1. **Algorithm Confusion**: JWT with kid but wrong algorithm
2. **Key Substitution**: Attacker provides JWT with valid kid but malicious payload

**Mitigations:**

1. **Algorithm Validation:**
   ```go
   func ValidateJWT(token *jwt.Token) error {
       // Verify algorithm matches expected
       if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
           return fmt.Errorf("unexpected signing method: %v", token.Method.Alg())
       }
       
       // Verify kid exists and is valid
       kid, ok := token.Header["kid"].(string)
       if !ok {
           return fmt.Errorf("missing kid in JWT header")
       }
       
       if err := keystore.ValidateKeyID(kid, true); err != nil {
           return fmt.Errorf("invalid kid: %w", err)
       }
       
       return nil
   }
   ```

2. **Key Purpose Validation:**
   - Check KeyType matches JWT use (signing, encryption)
   - Prevent using encryption keys for signing

3. **Issuer Verification:**
   - Verify JWT issuer matches expected value
   - Prevent cross-tenant key confusion

### 7.4 Private Key Exposure Prevention

**Design Principle:**
- Keychain-backed JWKs MUST NOT contain private key material
- Private key operations MUST be performed by the backend

**Implementation:**

```go
func FromKeychain(keyID string, kc keychain.KeyStore) (*JWK, error) {
    // ... retrieve key ...
    
    // Create JWK from PUBLIC key only
    jwk, err := FromPublicKey(pubKey)  // Never use FromPrivateKey
    if err != nil {
        return nil, err
    }
    
    // Ensure no private fields
    jwk.D = ""   // Private exponent (RSA)
    jwk.P = ""   // Prime factors
    jwk.Q = ""
    jwk.K = ""   // Symmetric key
    
    return jwk, nil
}
```

**Audit Check:**
- Unit tests verify keychain JWKs never contain private material
- Security audit before production deployment

### 7.5 Multi-Tenancy Considerations

**Scenario:** Multiple tenants share same keychain instance

**Security Requirements:**
1. Tenant isolation via separate backends or partitions
2. Key ID namespacing to prevent collisions
3. Access control based on tenant identity

**Example Approach:**

```go
// Tenant-scoped Key ID format: "backend:tenant:keyname"
type TenantKeyStore struct {
    keystore keychain.KeyStore
    tenantID string
}

func (tks *TenantKeyStore) GetKeyByID(keyID string) (crypto.PrivateKey, error) {
    // Inject tenant ID into Key ID
    backend, keyname, _ := keychain.ParseKeyID(keyID)
    scopedKeyID := fmt.Sprintf("%s:%s-%s", backend, tks.tenantID, keyname)
    
    return tks.keystore.GetKeyByID(scopedKeyID)
}
```


## 8. Testing Strategy

### 8.1 Unit Tests

**Key ID Parsing:**
```go
func TestParseKeyID(t *testing.T) {
    tests := []struct {
        name      string
        keyID     string
        wantBackend string
        wantKeyname string
        wantErr   bool
    }{
        {"valid pkcs8", "pkcs8:server-key", "pkcs8", "server-key", false},
        {"valid pkcs11", "pkcs11:hsm-key", "pkcs11", "hsm-key", false},
        {"valid tpm2", "tpm2:ak-key", "tpm2", "ak-key", false},
        {"invalid format", "invalid", "", "", true},
        {"missing keyname", "pkcs8:", "", "", true},
        {"missing backend", ":keyname", "", "", true},
        {"multiple colons", "pkcs8:key:name", "", "", true},
        {"invalid backend", "unknown:key", "", "", true},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            backend, keyname, err := keychain.ParseKeyID(tt.keyID)
            if (err != nil) != tt.wantErr {
                t.Errorf("ParseKeyID() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if backend != tt.wantBackend || keyname != tt.wantKeyname {
                t.Errorf("ParseKeyID() = (%v, %v), want (%v, %v)",
                    backend, keyname, tt.wantBackend, tt.wantKeyname)
            }
        })
    }
}
```

**JWK Keychain Integration:**
```go
func TestJWKKeychainIntegration(t *testing.T) {
    // Setup test keystore
    keystore := setupTestKeystore(t)
    
    // Generate test key
    attrs := &backend.KeyAttributes{
        CN:          "test-key",
        StoreType:   backend.STORE_PKCS8,
        KeyAlgorithm: backend.ALG_RSA,
        RSAAttributes: &backend.RSAAttributes{KeySize: 2048},
    }
    _, err := keystore.GenerateRSA(attrs)
    require.NoError(t, err)
    
    // Test FromKeychain
    jwk, err := jwk.FromKeychain("pkcs8:test-key", keystore)
    require.NoError(t, err)
    assert.Equal(t, "pkcs8:test-key", jwk.Kid)
    assert.Equal(t, "RSA", jwk.Kty)
    assert.NotEmpty(t, jwk.N)
    assert.NotEmpty(t, jwk.E)
    assert.Empty(t, jwk.D) // No private key
    
    // Test LoadKeyFromKeychain
    key, err := jwk.LoadKeyFromKeychain(keystore)
    require.NoError(t, err)
    assert.NotNil(t, key)
    
    // Verify it's a usable signer
    signer, ok := key.(crypto.Signer)
    assert.True(t, ok)
    
    digest := sha256.Sum256([]byte("test"))
    signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
    require.NoError(t, err)
    assert.NotEmpty(t, signature)
}
```

### 8.2 Integration Tests

**Multi-Backend Test:**
```go
func TestMultiBackendKeyIDs(t *testing.T) {
    backends := []struct {
        name    string
        backend backend.Backend
    }{
        {"pkcs8", setupPKCS8Backend(t)},
        {"pkcs11", setupPKCS11Backend(t)},
        {"tpm2", setupTPM2Backend(t)},
        {"awskms", setupAWSKMSBackend(t)},
    }
    
    for _, b := range backends {
        t.Run(b.name, func(t *testing.T) {
            keystore, _ := keychain.New(&keychain.Config{
                Backend:     b.backend,
                CertStorage: setupCertStorage(t),
            })
            defer keystore.Close()
            
            // Generate key
            attrs := &backend.KeyAttributes{
                CN:          "test-key",
                StoreType:   b.backend.Type(),
                KeyAlgorithm: backend.ALG_RSA,
                RSAAttributes: &backend.RSAAttributes{KeySize: 2048},
            }
            _, err := keystore.GenerateRSA(attrs)
            require.NoError(t, err)
            
            // Test GetKeyByID
            keyID := fmt.Sprintf("%s:test-key", b.backend.Type())
            key, err := keystore.GetKeyByID(keyID)
            require.NoError(t, err)
            assert.NotNil(t, key)
            
            // Test JWK integration
            jwk, err := jwk.FromKeychain(keyID, keystore)
            require.NoError(t, err)
            assert.Equal(t, keyID, jwk.Kid)
        })
    }
}
```

### 8.3 Security Tests

**Injection Attack Prevention:**
```go
func TestKeyIDInjectionAttacks(t *testing.T) {
    keystore := setupTestKeystore(t)
    
    attacks := []string{
        "pkcs8:../../etc/passwd",
        "pkcs8:key;rm -rf /",
        "pkcs8:key\x00malicious",
        "pkcs8:key<script>alert('xss')</script>",
        "pkcs8:key' OR '1'='1",
    }
    
    for _, attack := range attacks {
        t.Run(attack, func(t *testing.T) {
            _, err := keystore.GetKeyByID(attack)
            assert.Error(t, err, "Attack should be rejected: %s", attack)
        })
    }
}
```

**Backend Mismatch Prevention:**
```go
func TestBackendMismatch(t *testing.T) {
    // Create PKCS8 keystore
    pkcs8Store := setupPKCS8Keystore(t)
    
    // Try to access TPM2 key from PKCS8 keystore
    _, err := pkcs8Store.GetKeyByID("tpm2:some-key")
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "backend mismatch")
}
```

### 8.4 Performance Tests

**Benchmark Key Retrieval:**
```go
func BenchmarkGetKeyByID(b *testing.B) {
    keystore := setupBenchKeystore(b)
    
    // Generate test keys
    for i := 0; i < 100; i++ {
        attrs := &backend.KeyAttributes{
            CN:          fmt.Sprintf("bench-key-%d", i),
            StoreType:   backend.STORE_PKCS8,
            KeyAlgorithm: backend.ALG_RSA,
            RSAAttributes: &backend.RSAAttributes{KeySize: 2048},
        }
        keystore.GenerateRSA(attrs)
    }
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        keyID := fmt.Sprintf("pkcs8:bench-key-%d", i%100)
        _, err := keystore.GetKeyByID(keyID)
        if err != nil {
            b.Fatal(err)
        }
    }
}
```




## 10. Migration Guide

### 10.1 Existing Code Migration

**Before (using KeyAttributes):**
```go
attrs := &backend.KeyAttributes{
    CN:          "my-key",
    StoreType:   backend.STORE_PKCS11,
    KeyType:     backend.KEY_TYPE_SIGNING,
    KeyAlgorithm: backend.ALG_RSA,
}

key, err := keystore.GetKey(attrs)
signer, err := keystore.Signer(attrs)
```

**After (using Key ID):**
```go
// Simple Key ID
keyID := "pkcs11:my-key"

// Direct retrieval
key, err := keystore.GetKeyByID(keyID)
signer, err := keystore.GetSignerByID(keyID)
```

**Compatibility:**
- Old `GetKey(attrs)` method remains unchanged
- New `GetKeyByID(keyID)` method added
- Both methods supported indefinitely

### 10.2 Configuration Migration

**Before (per-key configuration):**
```yaml
keys:
  - name: "server-key"
    backend: "pkcs11"
    type: "rsa"
    size: 2048
```

**After (using Key IDs):**
```yaml
keys:
  - id: "pkcs11:server-key"
    type: "rsa"
    size: 2048
```

### 10.3 JWK Migration

**Before (standalone JWKs):**
```go
// Generate key
key, _ := rsa.GenerateKey(rand.Reader, 2048)

// Create JWK with embedded key
jwk, _ := jwk.FromPrivateKey(key)
jwk.Kid = "my-key"

// Use directly
signer := key
```

**After (keychain-backed JWKs):**
```go
// Generate key in keychain
attrs := &backend.KeyAttributes{...}
key, _ := keystore.GenerateRSA(attrs)

// Create JWK reference
jwk, _ := jwk.FromKeychain("pkcs11:my-key", keystore)

// Use via keychain
signer, _ := jwk.ToKeychainSigner(keystore)
```




## 11. References

### 11.1 Specifications

- [RFC 7517 - JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [RFC 7518 - JSON Web Algorithms (JWA)](https://tools.ietf.org/html/rfc7518)
- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [PKCS #8 - Private-Key Information Syntax Specification](https://tools.ietf.org/html/rfc5208)
- [PKCS #11 - Cryptographic Token Interface Standard](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html)
- [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)

### 11.2 Best Practices

- [NIST SP 800-57 - Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)

### 11.3 Related Documentation

- [go-keychain Architecture Overview](docs/architecture/overview.md)
- [Backend Implementation Guide](docs/architecture/implementation-guide.md)
- [Certificate Management Guide](docs/certificate-management.md)
- [Symmetric Encryption Design](docs/design/symmetric-encryption.md)


## Appendix A: Complete API Reference

### A.1 KeyStore Interface Extensions

```go
package keychain

// GetKeyByID retrieves a key by its unified Key ID.
func (ks *compositeKeyStore) GetKeyByID(keyID string) (crypto.PrivateKey, error)

// GetSignerByID retrieves a crypto.Signer by Key ID.
func (ks *compositeKeyStore) GetSignerByID(keyID string) (crypto.Signer, error)

// GetDecrypterByID retrieves a crypto.Decrypter by Key ID.
func (ks *compositeKeyStore) GetDecrypterByID(keyID string) (crypto.Decrypter, error)

// ParseKeyID parses a Key ID into backend and keyname components.
func (ks *compositeKeyStore) ParseKeyID(keyID string) (backend, keyname string, err error)

// ValidateKeyID validates a Key ID format and optionally checks existence.
func (ks *compositeKeyStore) ValidateKeyID(keyID string, checkExists bool) error
```

### A.2 JWK Package Extensions

```go
package jwk

// FromKeychain creates a JWK from a keychain key.
func FromKeychain(keyID string, kc keychain.KeyStore) (*JWK, error)

// LoadKeyFromKeychain loads the private key using the JWK's kid.
func (jwk *JWK) LoadKeyFromKeychain(kc keychain.KeyStore) (crypto.PrivateKey, error)

// IsKeychainBacked returns true if the JWK references a keychain key.
func (jwk *JWK) IsKeychainBacked() bool

// ToKeychainSigner returns a crypto.Signer backed by the keychain.
func (jwk *JWK) ToKeychainSigner(kc keychain.KeyStore) (crypto.Signer, error)
```

### A.3 Error Types

```go
package keychain

var (
    ErrInvalidKeyIDFormat = errors.New("invalid key ID format")
    ErrInvalidBackendType = errors.New("invalid backend type")
    ErrBackendMismatch    = errors.New("backend mismatch")
    ErrKeyNotFound        = errors.New("key not found")
    ErrInvalidKeyName     = errors.New("invalid key name")
    ErrKeyIDTooLong       = errors.New("key ID too long")
)
```


## Appendix B: Backend Support Matrix

| Backend | Key ID Format | GetKeyByID | GetSignerByID | GetDecrypterByID | JWK Support |
|---------|---------------|------------|---------------|------------------|-------------|
| PKCS#8 | `pkcs8:name` | Yes | Yes | Yes | Yes |
| AES | `aes:name` | Yes | No | No | Partial (symmetric only) |
| Software | `software:name` | Yes | Yes | Yes | Yes |
| PKCS#11 | `pkcs11:name` | Yes | Yes | Yes | Yes |
| TPM2 | `tpm2:name` | Yes | Yes | Yes | Yes |
| AWS KMS | `awskms:name` | Yes | Yes | Yes | Yes |
| GCP KMS | `gcpkms:name` | Yes | Yes | Yes | Yes |
| Azure KV | `azurekv:name` | Yes | Yes | Yes | Yes |
| Vault | `vault:name` | Yes | Yes | Yes | Yes |

**Legend:**
- Yes Fully supported
- Partial Partially supported
- No Not applicable


## Appendix C: Example Code Repository

Complete example code is available in the repository:

```
examples/
├── keyid/
│   ├── basic/              # Basic Key ID usage
│   ├── multi-backend/      # Multiple backends
│   └── validation/         # Key ID validation examples
├── jwk/
│   ├── keychain-backed/    # Keychain-backed JWKs
│   ├── standalone/         # Standalone JWKs
│   └── jwks-server/        # JWKS endpoint example
└── jwt/
    ├── signing/            # JWT signing with keychain
    ├── verification/       # JWT verification
    └── oauth/              # OAuth/OIDC integration
```


