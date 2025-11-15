# ChaCha20-Poly1305 Encryption Examples

This directory contains examples demonstrating ChaCha20-Poly1305 and XChaCha20-Poly1305 AEAD encryption using the go-keychain library.

## Overview

ChaCha20-Poly1305 is a modern AEAD (Authenticated Encryption with Associated Data) cipher that provides:

- **Fast encryption** on systems without AES hardware acceleration (AES-NI)
- **256-bit key security** with only 256-bit keys (no 128 or 192-bit variants)
- **96-bit (12-byte) nonces** for standard ChaCha20-Poly1305
- **192-bit (24-byte) nonces** for XChaCha20-Poly1305 (safer for random nonce generation)
- **128-bit (16-byte) authentication tags** via Poly1305 MAC
- **Constant-time implementation** resistant to timing attacks
- **AEAD properties**: Authentication and encryption-then-MAC construction

## When to Use ChaCha20-Poly1305

### Advantages

1. **No AES-NI Required**: Faster than AES on CPUs without hardware acceleration (mobile, embedded systems)
2. **Simpler Hardware**: Less complex than AES, good for resource-constrained devices
3. **Modern Design**: Designed for the post-AES era, used in modern protocols (TLS 1.3, WireGuard)
4. **Constant-Time**: Resistant to timing side-channel attacks
5. **Large Nonce Space**: XChaCha20 with 24-byte nonce is safer for random nonce generation

### Disadvantages

1. **No Hardware Acceleration**: Slower on AES-NI capable systems
2. **Newer**: Less battle-tested than AES-GCM in production
3. **Key Size Only**: Only 256-bit keys (no 128/192-bit options)

### Use Cases

- **Mobile/Embedded Systems**: Where AES hardware is unavailable
- **WireGuard/Modern Protocols**: Where ChaCha20 is the standard
- **Random Nonce Generation**: Use XChaCha20 for safer random nonce handling
- **Performance-Critical Systems**: On non-AES-NI hardware
- **Backward Compatibility**: With protocols using ChaCha20

## Running the Examples

### Basic ChaCha20-Poly1305 Example

```bash
cd examples/symmetric-encryption/chacha20
go run main.go
```

This will demonstrate:
1. Generating a ChaCha20-Poly1305 key
2. Encrypting plaintext
3. Decrypting and verifying the result
4. Inspecting ciphertext, nonce, and tag

### Example Output

```
Example 1: ChaCha20-Poly1305 Encryption
=========================================
Generated key: my-chacha20-key
Algorithm: chacha20-poly1305
Key size: 256 bits

Plaintext: Hello, ChaCha20-Poly1305!
Ciphertext: a1b2c3d4e5f6...
Nonce: 01020304050607... (length: 12 bytes)
Tag: f1e2d3c4b5a6... (length: 16 bytes)
Decrypted: Hello, ChaCha20-Poly1305!
Match: true
```

## Key Examples in main.go

### Example 1: Basic ChaCha20-Poly1305 Encryption

```go
// Create key attributes for ChaCha20-Poly1305
attrs := &types.KeyAttributes{
    CN:                 "my-chacha20-key",
    KeyType:            backend.KEY_TYPE_SECRET,
    StoreType:          backend.STORE_SW,
    SymmetricAlgorithm: types.SymmetricChaCha20Poly1305,
}

// Generate key (always 256 bits, no AESAttributes needed)
key, err := symBackend.GenerateSymmetricKey(attrs)

// Create encrypter and encrypt
encrypter, _ := symBackend.SymmetricEncrypter(attrs)
encrypted, _ := encrypter.Encrypt(plaintext, &types.EncryptOptions{})

// Decrypt
decrypted, _ := encrypter.Decrypt(encrypted, &types.DecryptOptions{})
```

### Example 2: XChaCha20-Poly1305 (Extended Nonce)

```go
attrs := &types.KeyAttributes{
    CN:                 "my-xchacha20-key",
    SymmetricAlgorithm: types.SymmetricXChaCha20Poly1305,  // 24-byte nonce
    // ... other fields
}

// XChaCha20 uses 24-byte nonces instead of 12 bytes
// Safer for random nonce generation without counter management
```

### Example 3: Additional Authenticated Data (AAD)

```go
plaintext := []byte("Secret payment amount: $1000")
aad := []byte("PaymentID: 12345, Recipient: Alice")

// Encrypt with AAD (authenticated but not encrypted)
encrypted, _ := encrypter.Encrypt(plaintext, &types.EncryptOptions{
    AdditionalData: aad,
})

// Decrypt with same AAD
decrypted, _ := encrypter.Decrypt(encrypted, &types.DecryptOptions{
    AdditionalData: aad,  // Must match!
})

// Wrong AAD will cause authentication failure
decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{
    AdditionalData: []byte("wrong aad"),  // This fails!
})
// err: decryption failed (authentication error)
```

### Example 4: Tampering Detection

```go
// ChaCha20-Poly1305 detects any tampering with ciphertext or tag
encrypted.Ciphertext[0] ^= 0xFF  // Flip a bit

// Decryption fails with authentication error
decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{})
// err: decryption failed (authentication error)
```

## Security Considerations

### Nonce Management

- **ChaCha20-Poly1305 (12-byte nonce)**: Use counter-based nonce generation or maintain unique nonces
- **XChaCha20-Poly1305 (24-byte nonce)**: Safe for random nonce generation; larger nonce space prevents collisions

### Key Rotation

Keys should be rotated:
- When the bytes encrypted limit is reached
- Periodically (recommended: annual or more frequent)
- After any suspected compromise

### AEAD Safety Tracking

The backend includes AEAD safety tracking:
- Nonce uniqueness checking (prevents catastrophic nonce reuse)
- Bytes encrypted tracking (enforces NIST limits)
- Automatic warning when rotation is needed

```go
// Custom AEAD options
aeadOpts := &types.AEADOptions{
    NonceTracking:      true,
    BytesTracking:      true,
    BytesTrackingLimit: 1 * 1024 * 1024 * 1024,  // 1 GB limit
}

attrs.AEADOptions = aeadOpts
key, _ := symBackend.GenerateSymmetricKey(attrs)
```

## Comparison: ChaCha20 vs AES-GCM

| Feature | ChaCha20-Poly1305 | AES-GCM |
|---------|-------------------|---------|
| **Key Size** | 256 bits only | 128, 192, 256 bits |
| **Nonce Size** | 12 bytes (96 bits) | 12 bytes (96 bits) |
| **Tag Size** | 16 bytes (128 bits) | 16 bytes (128 bits) |
| **AES-NI** | No | Yes (fast) |
| **Mobile/Embedded** | Fast | Slower |
| **Hardware Accel** | Not widespread | Widespread |
| **Speed (AES-NI)** | Slower | Faster |
| **Speed (No AES-NI)** | Faster | Slower |

## Testing

Run the ChaCha20 backend tests:

```bash
# Run all AES/ChaCha20 backend tests
make test-backend-aes

# Run specific ChaCha20 tests
go test -run TestChaCha20 ./pkg/backend/aes/

# Run with verbose output
go test -v -run TestChaCha20 ./pkg/backend/aes/
```

## References

- [ChaCha20-Poly1305 IETF RFC 8439](https://tools.ietf.org/html/rfc8439)
- [XChaCha20-Poly1305 IETF Draft](https://tools.ietf.org/html/draft-ietf-xvapor-xchacha-poly1305)
- [WireGuard Protocol Using ChaCha20](https://www.wireguard.com/)
- [Go crypto/chacha20poly1305 Package](https://golang.org/x/crypto/chacha20poly1305)

## Performance Tips

1. **Reuse Encrypters**: Create an encrypter once and reuse it for multiple operations
2. **Batch Operations**: Encrypt multiple messages with different keys in parallel
3. **Stream Processing**: For large files, use streaming encryption (future enhancement)
4. **Hardware RNG**: Use hardware RNG for nonce generation when available

## Advanced Usage

### Custom AEAD Options

```go
attrs.AEADOptions = &types.AEADOptions{
    NonceTracking:      true,
    BytesTracking:      true,
    BytesTrackingLimit: 10 * 1024 * 1024 * 1024,  // 10 GB
    NonceSize:          12,  // Standard for ChaCha20
}
```

### Using with Password-Protected Keys

```go
// Generate with password protection
attrs.Password = backend.StaticPassword("my-secret-password")
key, _ := symBackend.GenerateSymmetricKey(attrs)

// Retrieve password-protected key
attrs2 := *attrs  // Copy attributes
attrs2.Password = backend.StaticPassword("my-secret-password")
key2, _ := symBackend.GetSymmetricKey(&attrs2)
```

## License

Copyright (c) 2025 Jeremy Hahn. SPDX-License-Identifier: AGPL-3.0
