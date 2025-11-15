# Key Agreement (ECDH)

The go-keychain library supports Elliptic Curve Diffie-Hellman (ECDH) key agreement for secure shared secret derivation. This allows two parties to establish a common secret without ever transmitting it.

## Supported Curves

### X25519 (Recommended)
- **Security**: 128-bit
- **Performance**: ~1 microsecond per operation
- **Features**: Fast, simple, constant-time
- **Use Cases**: Modern protocols, IoT, high-performance systems
- **Standards**: RFC 7748

```go
attrs := &types.KeyAttributes{
    X25519Attributes: &types.X25519Attributes{},
}
key, _ := backend.GenerateKey(attrs)
```

### NIST Curves (P-256, P-384, P-521)
- **P-256**: 128-bit security (~3 microseconds)
- **P-384**: 192-bit security (~8 microseconds)
- **P-521**: 256-bit security (~12 microseconds)
- **Standards**: FIPS 186-4, RFC 5480

```go
import "crypto/elliptic"

attrs := &types.KeyAttributes{
    KeyAlgorithm: x509.ECDSA,
    ECCAttributes: &types.ECCAttributes{
        Curve: elliptic.P256(),
    },
}
key, _ := backend.GenerateKey(attrs)
```

## Basic Usage

### 1. Generate Key Pairs

Alice and Bob each generate their own key pair:

```go
// Alice's key pair
aliceAttrs := &types.KeyAttributes{
    CN:               "alice",
    X25519Attributes: &types.X25519Attributes{},
}
aliceKey, _ := backend.GenerateKey(aliceAttrs)
alicePublicKey := aliceKey.Public()

// Bob's key pair
bobAttrs := &types.KeyAttributes{
    CN:               "bob",
    X25519Attributes: &types.X25519Attributes{},
}
bobKey, _ := backend.GenerateKey(bobAttrs)
bobPublicKey := bobKey.Public()
```

### 2. Exchange Public Keys

Alice and Bob exchange their public keys (can be done over insecure channels):

```go
// Alice sends her public key to Bob
// Bob sends his public key to Alice
// Both keep their private keys secret
```

### 3. Derive Shared Secret

Both parties independently derive the same shared secret:

```go
// Alice's side
aliceSharedSecret, _ := backend.DeriveSharedSecret(aliceAttrs, bobPublicKey)

// Bob's side
bobSharedSecret, _ := backend.DeriveSharedSecret(bobAttrs, alicePublicKey)

// aliceSharedSecret == bobSharedSecret
```

### 4. Derive Encryption Keys

Use HKDF to derive encryption keys from the shared secret:

```go
ka := x25519.New()

// Encryption key
encKey, _ := ka.DeriveKey(
    sharedSecret,
    nil,                    // optional salt
    []byte("encryption"),   // context
    32,                     // 256 bits for AES-256
)

// MAC key (for authenticated encryption)
macKey, _ := ka.DeriveKey(
    sharedSecret,
    nil,
    []byte("mac"),
    32,
)
```

## Backend Support

### Software Backend
- **X25519**: ✓ Supported
- **P-256**: ✓ Supported
- **P-384**: ✓ Supported
- **P-521**: ✓ Supported
- **PKCS#8 Storage**: ✓ Yes

### PKCS#8 Backend
- **X25519**: ✓ Supported
- **P-256**: ✓ Supported
- **P-384**: ✓ Supported
- **P-521**: ✓ Supported

### Other Backends
Key agreement support varies by backend. Check `Capabilities().KeyAgreement`:

```go
if backend.Capabilities().KeyAgreement {
    // This backend supports key agreement
}
```

## Security Best Practices

### 1. Use Ephemeral Keys
Generate fresh key pairs for each session to achieve Perfect Forward Secrecy (PFS):

```go
// For each session/connection
sessionKey, _ := backend.GenerateKey(attrs)
sessionPublicKey := sessionKey.Public()
```

### 2. Authenticate Public Keys
Always authenticate the public keys to prevent man-in-the-middle attacks:

```go
// Option 1: Digital signatures
signature, _ := signer.Sign(rand.Reader, publicKeyBytes, crypto.SHA256)

// Option 2: Certificates
cert := // validate certificate chain

// Option 3: Out-of-band verification
// Share fingerprint through phone call, in-person meeting, etc.
```

### 3. Use HKDF for Key Derivation
Always use HKDF to derive cryptographic keys:

```go
// ✓ Good: Different keys for different purposes
encKey, _ := ka.DeriveKey(secret, nil, []byte("encryption"), 32)
macKey, _ := ka.DeriveKey(secret, nil, []byte("mac"), 32)

// ✗ Bad: Using raw shared secret
cipher.NewGCM(sharedSecret) // Raw secret has poor distribution
```

### 4. Prevent Nonce Reuse
With derived AES-GCM keys, never reuse nonces:

```go
// Enable nonce tracking (default)
opts := &types.AEADOptions{
    NonceTracking:  true,  // Prevent nonce reuse
    BytesTracking:  true,  // Enforce byte limits
}

attrs.AEADOptions = opts
key, _ := backend.GenerateSymmetricKey(attrs)
```

### 5. Forward Secrecy
Discard both the shared secret and derived keys after use:

```go
// After deriving keys
// 1. Use keys for encryption
// 2. Delete keys from memory
// 3. Create new keys for next session
```

## Advanced Topics

### Multiple Key Derivation

Derive many keys from one shared secret:

```go
// Derive different keys for different purposes
keys := make(map[string][]byte)
for _, purpose := range []string{"encryption", "mac", "session", "backup"} {
    key, _ := ka.DeriveKey(sharedSecret, nil, []byte(purpose), 32)
    keys[purpose] = key
}
```

### Salt Usage

Use salt when shared secret comes from multiple sources:

```go
// Recommended: include random salt
salt := make([]byte, 32)
rand.Read(salt)

key, _ := ka.DeriveKey(sharedSecret, salt, []byte("encryption"), 32)
```

### Custom HKDF

Use HKDF directly for custom parameters:

```go
import "golang.org/x/crypto/hkdf"

reader := hkdf.New(
    sha256.New,
    sharedSecret,
    salt,
    []byte("custom context"),
)

customKey := make([]byte, 32)
reader.Read(customKey)
```

## Common Patterns

### Secure Messaging Channel
```go
// Alice initiates
aliceKey, _ := backend.GenerateKey(attrs)
// Send aliceKey.Public() to Bob

// Bob responds
bobKey, _ := backend.GenerateKey(attrs)
// Send bobKey.Public() to Alice

// Both derive shared secret
secret, _ := backend.DeriveSharedSecret(attrs, peerPublicKey)

// Both derive encryption key
encKey, _ := ka.DeriveKey(secret, nil, []byte("msg"), 32)

// Encrypt/decrypt messages with same key
```

### Perfect Forward Secrecy
```go
// Use ephemeral key pairs for each message
ephemeralKey, _ := backend.GenerateKey(attrs)
ephemeralPublicKey := ephemeralKey.Public()

// Share ephemeral public key with each message
messageSecret, _ := backend.DeriveSharedSecret(
    myAttrs,
    ephemeralPublicKey,
)

// Derive key and use it
msgKey, _ := ka.DeriveKey(messageSecret, nil, []byte("msg"), 32)

// Discard ephemeral key after use
```

### Hybrid Encryption
```go
// Use ECDH for key agreement
secret, _ := backend.DeriveSharedSecret(attrs, peerPublicKey)
encKey, _ := ka.DeriveKey(secret, nil, []byte("encryption"), 32)

// Use derived key for AES-GCM
symmetricAttrs := &types.KeyAttributes{
    SymmetricAlgorithm: types.SymmetricAES256GCM,
}
encrypter, _ := backend.SymmetricEncrypter(symmetricAttrs)
encrypted, _ := encrypter.Encrypt(plaintext, &types.EncryptOptions{})
```

## Examples

See `/examples/advanced/x25519-ecdh/` for a complete working example demonstrating:

- X25519 key generation
- ECDH key agreement
- HKDF key derivation
- Backend key persistence
- Multiple key derivation

Run with: `go run examples/advanced/x25519-ecdh/main.go`

## References

- [RFC 7748 - Elliptic Curves for Security](https://tools.ietf.org/html/rfc7748)
- [RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function](https://tools.ietf.org/html/rfc5869)
- [Curve25519](https://cr.yp.to/ecdh.html) - Original design
- [NIST SP 800-186 - Recommendations for Discrete Logarithm-based Cryptography](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf)
