# Advanced Cryptography Guide

This guide covers advanced cryptographic operations in go-keychain, including public key encryption schemes, key derivation, and hybrid encryption approaches.

## Table of Contents

1. [ECIES (Elliptic Curve Integrated Encryption Scheme)](#ecies)
2. [ECDH (Elliptic Curve Diffie-Hellman)](#ecdh)
3. [Comparing Encryption Schemes](#encryption-schemes-comparison)
4. [Key Derivation Functions](#key-derivation-functions)
5. [Symmetric vs Asymmetric Encryption](#symmetric-vs-asymmetric)
6. [Best Practices](#best-practices)

## ECIES

### Overview

ECIES (Elliptic Curve Integrated Encryption Scheme) is a standardized public key encryption scheme that combines elliptic curve cryptography with symmetric encryption for optimal security and performance.

ECIES integrates four cryptographic operations:
- **ECDH** - Performs key agreement between ephemeral and recipient keys
- **HKDF** - Derives an encryption key from the shared secret
- **AES-256-GCM** - Encrypts the message with authentication
- **MAC** - Provides authentication tag for integrity verification

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                    ECIES Architecture                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Sender                             Recipient              │
│  ──────                             ──────────             │
│                                                              │
│  1. Generate ephemeral key pair                           │
│  2. Perform ECDH with recipient's public key             │
│                     ├──────────────────────────┐           │
│                     │   Shared Secret (X)      │           │
│                     └──────────────────────────┘           │
│  3. Derive AES key using HKDF                            │
│  4. Encrypt message using AES-256-GCM                    │
│  5. Send: [ephemeral_pub || nonce || tag || ciphertext]  │
│                                                              │
│                                                              │
│                  Recipient receives message                  │
│                                                              │
│                     1. Extract ephemeral public key        │
│                     2. Perform ECDH with private key      │
│                     3. Derive same AES key                │
│                     4. Decrypt and verify                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Ciphertext Format

The encrypted output has a well-defined structure:

```
Offset  Length      Component
──────  ──────      ──────────────────────
0       65/97/133   Ephemeral Public Key (uncompressed)
65/97   12          Nonce (GCM standard)
77/109  16          Authentication Tag (GCM)
93/125+ Variable    Ciphertext (same size as plaintext)

Total Overhead: 93-161 bytes (depending on curve)
```

### Elliptic Curves Supported

| Curve | Bits | Point Size | Public Key Size | Recommended Use |
|-------|------|-----------|-----------------|-----------------|
| P-256 | 128-bit equiv | 32 bytes (x,y) | 65 bytes | General purpose, IoT |
| P-384 | 192-bit equiv | 48 bytes (x,y) | 97 bytes | High security systems |
| P-521 | 256-bit equiv | 66 bytes (x,y) | 133 bytes | Government/military |

### Basic Usage

```go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"

	"github.com/jeremyhahn/go-keychain/pkg/crypto/ecies"
)

func main() {
	// Recipient generates a key pair
	recipientPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	// Sender encrypts a message with recipient's public key
	message := []byte("Secret message")
	ciphertext, err := ecies.Encrypt(rand.Reader, &recipientPriv.PublicKey, message, nil)
	if err != nil {
		log.Fatal(err)
	}

	// Recipient decrypts with their private key
	plaintext, err := ecies.Decrypt(recipientPriv, ciphertext, nil)
	if err != nil {
		log.Fatal(err)
	}

	println(string(plaintext)) // Output: Secret message
}
```

### Advanced Features

#### Additional Authenticated Data (AAD)

ECIES supports authenticating additional data without encrypting it:

```go
// Encrypt with context information
context := []byte("transaction-12345")
ciphertext, _ := ecies.Encrypt(rand.Reader, pubKey, message, context)

// Decrypt with same context
plaintext, _ := ecies.Decrypt(privKey, ciphertext, context)

// Decryption fails if context doesn't match
_, err := ecies.Decrypt(privKey, ciphertext, []byte("wrong-context"))
// Error: authentication failed
```

#### Non-Deterministic Encryption

Each encryption produces a different ciphertext even for the same plaintext:

```go
ct1, _ := ecies.Encrypt(rand.Reader, pubKey, message, nil)
ct2, _ := ecies.Encrypt(rand.Reader, pubKey, message, nil)

ct1 != ct2  // true - different ephemeral keys and nonces
```

This property provides:
- **CPA Security** - Protects against chosen plaintext attacks
- **Replay Protection** - Each message is uniquely encrypted
- **Forward Secrecy** - Compromising one ciphertext doesn't compromise others

### Security Properties

| Property | Status | Notes |
|----------|--------|-------|
| Confidentiality | ✓ | AES-256-GCM with proper key derivation |
| Authenticity | ✓ | GCM authentication tag |
| Integrity | ✓ | GCM authentication tag |
| Forward Secrecy | ✓ | Ephemeral key for each message |
| CPA Security | ✓ | Non-deterministic encryption |
| CCA Security | ✓ | GCM's built-in authentication |

### Performance Characteristics

Approximate performance on modern hardware:

```
Operation           P-256      P-384      P-521
─────────────────   ─────────  ─────────  ─────────
Encrypt 1 KB        0.5 ms     1.5 ms     3.0 ms
Decrypt 1 KB        0.5 ms     1.5 ms     3.0 ms
Key Generation      5.0 ms     15.0 ms    30.0 ms
─────────────────   ─────────  ─────────  ─────────
Throughput (1KB)    ~2 MB/s    ~0.7 MB/s  ~0.3 MB/s
```

### When to Use ECIES

**Use ECIES when:**
- You need public key encryption with small keys
- You want high performance on resource-constrained devices
- You need authenticated encryption
- You're encrypting for a single specific recipient
- You need non-deterministic encryption

**Don't use ECIES when:**
- You need broadcast encryption (encrypt once for many recipients)
- You need deterministic encryption (same plaintext → same ciphertext)
- You need post-quantum security
- You need to support legacy systems requiring RSA

### Examples

See `/examples/advanced/ecies/` for comprehensive examples:
- Basic encryption/decryption
- Using different curves
- Backend-managed keys
- Multi-party communication

## ECDH

### Overview

ECDH (Elliptic Curve Diffie-Hellman) is a key agreement protocol that allows two parties to establish a shared secret over an insecure channel.

### How ECDH Works

```
Alice                               Bob
─────                               ───

Generate private key a              Generate private key b
Compute public key A = a·G          Compute public key B = b·G

Send A                              Send B
                    ↓
Receive B                           Receive A
                    ↓
Compute: S = a·B = a·(b·G) = (a·b)·G = b·(a·G) = b·A = S
                    ↓
Shared Secret: S (same for both)
```

### Key Derivation from ECDH

The raw ECDH output is not suitable for direct use as an encryption key. HKDF (HMAC-based Key Derivation Function) derives usable keys:

```go
import "github.com/jeremyhahn/go-keychain/pkg/crypto/ecdh"

// Derive shared secret
sharedSecret, _ := ecdh.DeriveSharedSecret(alicePriv, bobPub)

// Derive encryption key from shared secret
encryptionKey, _ := ecdh.DeriveKey(sharedSecret, nil,
	[]byte("encryption-context"), 32)

// Derive authentication key
authKey, _ := ecdh.DeriveKey(sharedSecret, nil,
	[]byte("authentication-context"), 32)
```

### ECIES Implementation

ECIES internally uses ECDH for key agreement:

```
Encryption:
1. Generate ephemeral private key e
2. Compute ephemeral public key E = e·G
3. ECDH: shared_secret = e·R (where R is recipient's public key)
4. Derive encryption key: K = HKDF(shared_secret, ...)
5. Encrypt: C = AES-GCM-Encrypt(K, plaintext)
6. Output: [E || C]

Decryption:
1. Extract ephemeral public key E from ciphertext
2. ECDH: shared_secret = d·E (where d is recipient's private key)
3. Derive encryption key: K = HKDF(shared_secret, ...) (same K!)
4. Decrypt: M = AES-GCM-Decrypt(K, ciphertext)
```

## Encryption Schemes Comparison

### ECIES vs RSA-OAEP

| Aspect | ECIES | RSA-OAEP |
|--------|-------|----------|
| **Key Sizes** | | |
| Private Key | 32-66 bytes | 256-512 bytes |
| Public Key | 65-133 bytes | 256-512 bytes |
| | | |
| **Performance** | | |
| Encryption | ~0.5-3 ms | ~10-50 ms |
| Decryption | ~0.5-3 ms | ~10-50 ms |
| Key Generation | ~5-30 ms | ~100-500 ms |
| | | |
| **Ciphertext** | | |
| Expansion | +93-161 bytes | +128-256 bytes |
| Deterministic | No | Yes* |
| | | |
| **Security** | | |
| CPA | Yes | No (deterministic) |
| CCA | Yes | Yes (with OAEP) |
| Forward Secrecy | Yes (ephemeral) | No |
| | | |
| **Use Cases** | | |
| IoT/Embedded | ✓ | Limited |
| Mobile | ✓ | Limited |
| Web Services | ✓ | ✓ |
| Legacy Systems | Limited | ✓ |
| Post-Quantum | No | No |

*RSA-OAEP is deterministic without randomization; ECIES is inherently non-deterministic due to ephemeral keys and nonces.

### ECIES vs AES-256

| Aspect | ECIES (Asymmetric) | AES-256 (Symmetric) |
|--------|-------------------|-------------------|
| **Key Agreement** | Not needed | Pre-shared key required |
| **Sender Authentication** | No | No |
| **Receiver Authentication** | Yes | Yes |
| **Performance** | ~1 ms per 1KB | ~0.01 ms per 1KB |
| **Key Size** | Public key distribution | Secure key exchange needed |
| **Use Case** | Single recipient | Many-to-many, pre-established keys |

### Hybrid Encryption Pattern

For large files, use ECIES for key agreement + AES-256 for data:

```go
// Generate random AES key
aesKey := make([]byte, 32)
rand.Read(aesKey)

// Encrypt AES key with ECIES
encryptedKey, _ := ecies.Encrypt(rand.Reader, pubKey, aesKey, nil)

// Encrypt file with AES-256-GCM using derived key
// (use crypto/cipher package)

// Send: [encryptedKey || encryptedFile]
```

Benefits:
- Fast file encryption (AES)
- Public key encryption of the key (ECIES)
- No key agreement overhead for large data

## Key Derivation Functions

### HKDF (HMAC-based KDF)

Used internally by ECIES for deriving encryption keys from shared secrets.

**Process:**
```
Extract: PRK = HMAC-Hash(salt, IKM)
Expand:  OKM = HKDF-Expand(PRK, info, L)
```

**Example Usage:**
```go
import "github.com/jeremyhahn/go-keychain/pkg/crypto/ecdh"

// Derive multiple keys from one shared secret
key1, _ := ecdh.DeriveKey(sharedSecret, salt, []byte("key1"), 32)
key2, _ := ecdh.DeriveKey(sharedSecret, salt, []byte("key2"), 32)
key3, _ := ecdh.DeriveKey(sharedSecret, salt, []byte("key3"), 32)
```

## Symmetric vs Asymmetric Encryption

### When to Use Symmetric (AES)

**Use symmetric encryption for:**
- Encrypting large amounts of data
- Scenarios where key distribution is solved
- High-performance requirements
- Local file/disk encryption
- Database encryption

**Example:**
```go
// Pre-shared key (already established)
key := []byte("32-byte-shared-secret-key-here!")

// Encrypt file
block, _ := aes.NewCipher(key)
gcm, _ := cipher.NewGCM(block)
nonce := make([]byte, gcm.NonceSize())
rand.Read(nonce)
ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
```

### When to Use Asymmetric (ECIES)

**Use asymmetric encryption for:**
- Public key distribution without pre-shared keys
- Sending encrypted data to many unknown recipients
- Key exchange and negotiation
- Digital signatures and verification
- Authentication with public keys

**Example:**
```go
// Public key published/distributed
ciphertext, _ := ecies.Encrypt(rand.Reader, publicKey, plaintext, nil)
```

### Hybrid Approach (Recommended for Large Data)

```go
// 1. Encrypt large file with AES-256
sessionKey := make([]byte, 32)
rand.Read(sessionKey)
// ... encrypt file with AES-256-GCM ...

// 2. Encrypt session key with ECIES
encryptedSessionKey, _ := ecies.Encrypt(rand.Reader, recipientPub, sessionKey, nil)

// 3. Send both
message := append(encryptedSessionKey, encryptedFile...)

// Recipient:
// 1. Decrypt session key with ECIES
sessionKey, _ := ecies.Decrypt(recipientPriv, encryptedSessionKey[:size], nil)

// 2. Decrypt file with AES-256
plaintext := decryptAES256(sessionKey, encryptedFile)
```

**Advantages:**
- Small overhead (ECIES only on 32-byte key, not whole file)
- Combines security of both schemes
- Scales to large files

## Best Practices

### Security Best Practices

1. **Use Strong Curves**
   - Prefer P-256 or P-384 for security-sensitive applications
   - Use P-521 for long-term archival of sensitive data

2. **Protect Private Keys**
   ```go
   // Store in secure backend (TPM, HSM, etc.)
   privKey, _ := backend.GetPrivateKey(keyID, password)
   defer backend.ClearMemory() // Clear sensitive data
   ```

3. **Use AAD for Context**
   ```go
   // Bind encryption to specific context
   context := []byte("user-id:" + userID)
   ciphertext, _ := ecies.Encrypt(rand.Reader, pubKey, data, context)
   ```

4. **Validate Inputs**
   ```go
   if plaintext == nil {
       return fmt.Errorf("plaintext cannot be nil")
   }
   if len(ciphertext) < expectedMinSize {
       return fmt.Errorf("ciphertext too short")
   }
   ```

5. **Secure Random Generation**
   ```go
   // Always use crypto/rand, never math/rand
   ciphertext, _ := ecies.Encrypt(rand.Reader, pubKey, data, nil)
   ```

### Performance Best Practices

1. **Reuse Keys for Multiple Messages**
   ```go
   // Good - derive once, use many times
   pubKey, _ := backend.GetPublicKey(keyID)
   for _, msg := range messages {
       ct, _ := ecies.Encrypt(rand.Reader, pubKey, msg, nil)
   }
   ```

2. **Use Appropriate Curve for Security Level**
   ```go
   // Good - match curve to security requirements
   if highSecurity {
       key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
   } else {
       key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
   }
   ```

3. **Batch Operations**
   ```go
   // Encrypt multiple messages in parallel
   errs := make(chan error, len(messages))
   for _, msg := range messages {
       go func(m []byte) {
           _, err := ecies.Encrypt(rand.Reader, pubKey, m, nil)
           errs <- err
       }(msg)
   }
   ```

4. **Use Hybrid Encryption for Large Data**
   ```go
   // Don't encrypt 1GB file directly with ECIES
   // Instead: encrypt with AES-256, wrap key with ECIES
   ```

### Error Handling Best Practices

1. **Check All Error Returns**
   ```go
   // Good
   ciphertext, err := ecies.Encrypt(rand.Reader, pubKey, data, nil)
   if err != nil {
       return fmt.Errorf("encryption failed: %w", err)
   }

   // Bad - ignoring errors
   ciphertext, _ := ecies.Encrypt(rand.Reader, pubKey, data, nil)
   ```

2. **Handle Different Error Types**
   ```go
   ciphertext, err := ecies.Decrypt(privKey, ct, nil)
   if err != nil {
       if strings.Contains(err.Error(), "authentication") {
           // AAD mismatch or corrupted ciphertext
       } else if strings.Contains(err.Error(), "too short") {
           // Invalid ciphertext format
       }
   }
   ```

3. **Don't Leak Error Details**
   ```go
   // Bad - exposes internal details
   return fmt.Sprintf("Error: %v", err)

   // Good - generic message for users
   log.Errorf("Decryption failed: %v", err)
   return fmt.Errorf("failed to decrypt message")
   ```

### Testing Best Practices

1. **Test All Curves**
   ```go
   curves := []elliptic.Curve{
       elliptic.P256(),
       elliptic.P384(),
       elliptic.P521(),
   }
   for _, curve := range curves {
       // Test with each curve
   }
   ```

2. **Test Edge Cases**
   ```go
   // Empty message
   ecies.Encrypt(rand.Reader, pubKey, []byte{}, nil)

   // Large message (> 1GB)
   largeMsg := make([]byte, 2*1024*1024*1024)
   ecies.Encrypt(rand.Reader, pubKey, largeMsg, nil)

   // AAD with special characters
   ecies.Encrypt(rand.Reader, pubKey, msg, []byte{0xFF, 0xFE, 0xFD})
   ```

3. **Test Error Cases**
   ```go
   // Wrong AAD
   _, err := ecies.Decrypt(privKey, ct, []byte("wrong"))
   assert.Error(t, err)

   // Corrupted ciphertext
   ct[10] ^= 0xFF
   _, err := ecies.Decrypt(privKey, ct, nil)
   assert.Error(t, err)
   ```

## Summary

| Task | Recommended Solution |
|------|----------------------|
| Single recipient encryption | ECIES |
| Large file encryption | AES-256-GCM (after key agreement) |
| Key exchange | ECDH + HKDF |
| Multi-recipient encryption | AES-256 with separate keys per recipient |
| Authentication | ECIES + digital signatures |
| Long-term archival | ECIES with P-521 |
| IoT devices | ECIES with P-256 |

## See Also

- [ECIES Examples](/examples/advanced/ecies/)
- [ECDH Documentation](/pkg/crypto/ecdh/)
- [Backend Management](/docs/backends/)
- [Key Management](/docs/usage/key-import-export.md)
