# Symmetric Encryption

go-keychain provides symmetric encryption capabilities using AEAD (Authenticated Encryption with Associated Data) algorithms across all backends that support it.

## Supported Algorithms

### AES-GCM (Advanced Encryption Standard - Galois/Counter Mode)

| Algorithm | Key Size | Nonce Size | Tag Size | Use Case |
|-----------|----------|------------|----------|----------|
| `aes128-gcm` | 128-bit | 96-bit | 128-bit | General purpose |
| `aes192-gcm` | 192-bit | 96-bit | 128-bit | Extended security |
| `aes256-gcm` | 256-bit | 96-bit | 128-bit | Maximum security (recommended) |

### ChaCha20-Poly1305 (RFC 8439)

| Algorithm | Key Size | Nonce Size | Tag Size | Use Case |
|-----------|----------|------------|----------|----------|
| `chacha20-poly1305` | 256-bit | 96-bit | 128-bit | Software-optimized, no AES-NI needed |
| `xchacha20-poly1305` | 256-bit | 192-bit | 128-bit | Extended nonce for safe random generation |

### Algorithm Selection

go-keychain automatically selects the optimal algorithm based on the environment:

- **Hardware-backed keys** (HSM, TPM, Cloud KMS): Always use AES-256-GCM
- **Software keys with AES-NI**: Use AES-256-GCM (hardware acceleration)
- **Software keys without AES-NI**: Use ChaCha20-Poly1305 (faster in software)

## Supported Backends

| Backend | AES-GCM | ChaCha20-Poly1305 | Notes |
|---------|---------|-------------------|-------|
| Software | 128/192/256 | Yes | Full support |
| AWS KMS | 256 only | No | HSM-backed |
| GCP KMS | 256 only | No | HSM-backed |
| Azure Key Vault | 256 only | No | Premium tier for HSM |
| HashiCorp Vault | 256 | No | Transit engine |
| PKCS#11 | Varies | No | HSM-dependent |
| TPM2 | 128/256 | No | Hardware constraints |

## Usage

### Generate Symmetric Key

```go
// AES-256-GCM key
attrs := &types.KeyAttributes{
    CN:                 "my-aes-key",
    KeyType:            types.KeyTypeSecret,
    StoreType:          types.StoreSoftware,
    SymmetricAlgorithm: types.SymmetricAES256GCM,
}
key, err := keychain.GenerateSymmetricKey("sw", attrs)

// ChaCha20-Poly1305 key
attrs := &types.KeyAttributes{
    CN:                 "my-chacha-key",
    KeyType:            types.KeyTypeSecret,
    StoreType:          types.StoreSoftware,
    SymmetricAlgorithm: types.SymmetricChaCha20Poly1305,
}
key, err := keychain.GenerateSymmetricKey("sw", attrs)

// XChaCha20-Poly1305 key (extended nonce)
attrs := &types.KeyAttributes{
    CN:                 "my-xchacha-key",
    KeyType:            types.KeyTypeSecret,
    StoreType:          types.StoreSoftware,
    SymmetricAlgorithm: types.SymmetricXChaCha20Poly1305,
}
key, err := keychain.GenerateSymmetricKey("sw", attrs)
```

### Encrypt Data

```go
encrypter, err := keychain.SymmetricEncrypter(attrs)

encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{
    AdditionalData: []byte("context"),
})
```

### Decrypt Data

```go
plaintext, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{
    AdditionalData: []byte("context"),
})
```

## Password Protection

Keys can be encrypted with a password using Argon2id key derivation:

```go
attrs := &types.KeyAttributes{
    CN:                 "protected-key",
    KeyType:            types.KeyTypeSecret,
    StoreType:          types.StoreSoftware,
    SymmetricAlgorithm: types.SymmetricAES256GCM,
    Password:           types.NewPassword([]byte("secret")),
}
```

## AEAD Safety Tracking

go-keychain enforces AEAD safety limits to prevent cryptographic failures:

### Nonce Tracking
- Prevents nonce reuse (catastrophic for GCM security)
- Tracks all nonces used per key
- Rejects duplicate nonces

### Bytes Tracking
- Enforces NIST-recommended encryption limits
- AES-GCM: ~64GB per key (2^36 bytes)
- ChaCha20-Poly1305: ~256GB per key (2^38 bytes)
- Warns before limits reached

### Key Rotation
Rotating a key resets all tracking counters:

```go
err := keychain.RotateSymmetricKey(attrs)
// Nonce and bytes counters reset to zero
```

## Security Considerations

### AES-GCM
- Requires unique nonces (never reuse with same key)
- Hardware acceleration via AES-NI when available
- FIPS 140-2 compliant
- Preferred for compliance requirements

### ChaCha20-Poly1305
- Constant-time implementation (timing attack resistant)
- No special CPU instructions required
- RFC 8439 compliant
- Preferred for software-only environments

### Best Practices

1. **Use AES-256-GCM or ChaCha20-Poly1305** - Both provide 256-bit security
2. **Never reuse nonces** - Let go-keychain generate them automatically
3. **Use Additional Authenticated Data (AAD)** - Bind ciphertext to context
4. **Rotate keys before limits** - Monitor AEAD tracking warnings
5. **Password-protect sensitive keys** - Use strong passwords with Argon2id

## See Also

- [AEAD Auto-Selection](../configuration/aead-auto-selection.md)
- [Key Management](../usage/cli/key.md)
- [Backend Configuration](../backends/README.md)
