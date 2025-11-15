# X25519 ECDH Key Agreement Example

This example demonstrates how to perform ECDH (Elliptic Curve Diffie-Hellman) key agreement using X25519 with the go-keychain Software backend.

## What is X25519?

X25519 is a key agreement mechanism providing 128-bit security level. It is:

- **Fast**: Optimized for speed and constant-time execution
- **Simple**: Straightforward implementation without complex operations
- **Secure**: Based on Curve25519, designed by cryptographers
- **Modern**: Used in WireGuard, age, and other modern protocols

## How ECDH Works

1. **Alice and Bob each generate a key pair**
   - Each has a private key (kept secret) and public key (can be shared)

2. **Exchange public keys**
   - Alice shares her public key with Bob
   - Bob shares his public key with Alice
   - Public keys can be transmitted over insecure channels

3. **Derive shared secret**
   - Alice uses her private key + Bob's public key → shared secret
   - Bob uses his private key + Alice's public key → same shared secret
   - The private keys never leave their respective parties

4. **Use shared secret for encryption**
   - Apply HKDF-SHA256 to derive encryption keys
   - Use keys for AES-GCM, ChaCha20-Poly1305, etc.

## Running the Example

```bash
cd examples/advanced/x25519-ecdh
go run main.go
```

Expected output shows:

1. **Key generation**: Both parties generate X25519 key pairs
2. **ECDH operation**: Perform key agreement
3. **Verification**: Confirm shared secrets match
4. **Key derivation**: Derive encryption keys using HKDF
5. **Key persistence**: Store and retrieve keys from backend

## Code Structure

```go
// Create backend
backend, _ := software.NewBackend(config)

// Generate X25519 key pair
key, _ := backend.GenerateKey(&types.KeyAttributes{
    X25519Attributes: &types.X25519Attributes{},
})

// Perform ECDH with peer's public key
sharedSecret, _ := backend.DeriveSharedSecret(attrs, peerPublicKey)

// Derive encryption key using HKDF
encKey, _ := ka.DeriveKey(sharedSecret, nil, []byte("encryption"), 32)
```

## Use Cases

### Instant Messaging
- Secure channel establishment between users
- Perfect forward secrecy with ephemeral keys
- Derive separate keys for each message

### File Transfer
- Secure key exchange before transmission
- Derive keys for both encryption and MAC
- Prevent man-in-the-middle attacks

### IoT Communication
- Lightweight key agreement (X25519 is smaller than NIST curves)
- Low power consumption
- Fast computation on embedded devices

### Zero-Knowledge Applications
- Anonymous but secure communication
- Parties never need to authenticate identity upfront
- Deniability through ephemeral keys

## Security Considerations

1. **Use Ephemeral Keys**: Generate new key pairs for each session to achieve Perfect Forward Secrecy (PFS)

2. **Authentication**: ECDH alone doesn't authenticate parties. Add:
   - Digital signatures on public keys
   - Certificate authorities
   - Out-of-band verification

3. **Key Derivation**: Always use HKDF to derive multiple keys from shared secret:
   - Different keys for encryption, MAC, session IDs
   - Prevents key reuse issues
   - Binds keys to application context

4. **Nonce Management**: For AES-GCM, never reuse nonce with same key:
   - Use random nonces (96 bits for GCM)
   - Backend provides nonce tracking to prevent reuse
   - Rotate keys when approaching limits

## Performance

X25519 ECDH is much faster than NIST curve ECDH:

- **X25519**: ~1 microsecond (typical)
- **P-256**: ~3 microseconds
- **P-384**: ~8 microseconds
- **P-521**: ~12 microseconds

Total time to establish secure channel with X25519 and derive keys: < 10 microseconds

## Compatibility

X25519 is compatible with:

- **age**: Modern encryption tool
- **WireGuard**: VPN protocol
- **TLS 1.3**: When configured
- **Signal Protocol**: Secure messaging
- **ZRTP**: Secure voice calls

## Further Reading

- [RFC 7748](https://tools.ietf.org/html/rfc7748) - X25519 Specification
- [RFC 5869](https://tools.ietf.org/html/rfc5869) - HKDF
- [Curve25519](https://cr.yp.to/ecdh.html) - Original design
- [go-keychain Documentation](../../docs/key-agreement.md)
