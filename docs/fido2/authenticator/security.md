# Security Considerations

This document outlines security considerations, best practices, and threat mitigations for the native FIDO2 authenticator.

## Overview

The native FIDO2 authenticator is a software-based implementation designed for development, testing, and scenarios where hardware security is not available. Understanding its security characteristics is essential for proper deployment.

## Security Model

### Comparison with Hardware Authenticators

| Property | Hardware Authenticator | Native Authenticator |
|----------|----------------------|---------------------|
| Key Storage | Secure element | Process memory / storage |
| Key Extraction | Physically protected | Software protected |
| Side-channel resistance | Hardware mitigations | Limited |
| Tamper resistance | Physical security | None |
| Attestation | Hardware-rooted | Self-signed |

### Threat Model

The native authenticator provides security against:
- Remote network attacks
- Protocol-level attacks
- Credential phishing (origin binding)
- Replay attacks (signature counters)

The native authenticator does NOT protect against:
- Physical access to the host system
- Privileged malware on the host
- Memory dumping attacks
- Side-channel attacks

## Key Storage Security

### Private Key Protection

Private keys are stored in PKCS#8 format. Security depends on the storage backend:

**MemoryStorage:**
- Keys exist only in process memory
- Lost on process termination
- No persistence vulnerability
- No encryption at rest

**BackendStorage (Persistent):**
- Keys written to disk or database
- Should use encrypted storage
- Should use proper file permissions
- Consider encryption at rest

### Recommendations

1. **Use encrypted storage** for persistent credentials
2. **Restrict file permissions** (0600 for credential files)
3. **Consider memory encryption** for high-security scenarios
4. **Clear memory** after key operations

```go
// Example: Zeroing sensitive memory
func clearBytes(b []byte) {
    for i := range b {
        b[i] = 0
    }
}
```

## PIN Protocol Security

### PIN Protocol v1 Implementation

The authenticator implements CTAP2.0 PIN Protocol v1:

```
Platform                    Authenticator
    |                            |
    |  GetKeyAgreement           |
    |--------------------------->|
    |                            | Generate ECDH key pair
    |                            |
    |  authenticator_pub_key     |
    |<---------------------------|
    |                            |
    | SetPIN(platform_pub, enc_pin, auth) |
    |--------------------------->|
    |                            | K = ECDH(authenticator_priv, platform_pub)
    |                            | sharedSecret = SHA-256(K)
    |                            | Verify HMAC auth
    |                            | Decrypt and validate PIN
    |                            | Store SHA-256(PIN)[:16]
```

### PIN Security Properties

| Property | Implementation |
|----------|---------------|
| PIN Transport | AES-256-CBC encrypted |
| PIN Storage | SHA-256 truncated to 16 bytes |
| Key Agreement | ECDH P-256 |
| Auth Verification | HMAC-SHA-256 |
| Brute Force Protection | Retry counter with lockout |

### PIN Attack Mitigations

**Brute Force:**
- Configurable retry limit (default: 8)
- Counter persisted to storage
- Authenticator locks when exhausted
- Requires factory reset to recover

**Eavesdropping:**
- PIN encrypted with ECDH-derived key
- Ephemeral key per session
- HMAC authentication prevents tampering

### Recommendations

1. **Set minimum PIN length** >= 6 characters
2. **Reduce retry count** for high-security (3-5 attempts)
3. **Persist retry counter** atomically with credentials
4. **Regenerate ECDH keys** after PIN operations

```go
config := &authenticator.Config{
    PINMinLength:  6,  // Longer minimum
    PINMaxRetries: 5,  // Fewer attempts
}
```

## hmac-secret Extension Security

### Key Derivation Security

The hmac-secret extension enables deriving symmetric secrets:

```
credential_hmac_key (32 bytes, random)
    |
    v
HMAC-SHA-256(credential_hmac_key, salt)
    |
    v
derived_secret (32 bytes)
```

### Security Properties

| Property | Value |
|----------|-------|
| Secret Key Size | 32 bytes (256 bits) |
| Algorithm | HMAC-SHA-256 |
| Key Isolation | Per-credential key |
| Salt Size | 32 bytes required |

### Protocol Flow Security

```
Platform                    Authenticator
    |                            |
    | GetAssertion with hmac-secret |
    | - keyAgreement (platform_pub) |
    | - saltEnc (encrypted salt)    |
    | - saltAuth (HMAC)             |
    |--------------------------->|
    |                            | K = ECDH(auth_priv, platform_pub)
    |                            | sharedSecret = SHA-256(K)
    |                            | Verify saltAuth
    |                            | salt = decrypt(saltEnc)
    |                            | output = HMAC(cred_key, salt)
    |                            | encOutput = encrypt(output)
    |                            |
    | Encrypted HMAC output      |
    |<---------------------------|
```

### Attack Mitigations

**Salt Manipulation:**
- Salt encrypted in transit
- HMAC verification prevents tampering
- Invalid salts rejected

**Key Extraction:**
- HMAC key never leaves authenticator
- Only derived outputs returned
- Requires valid GetAssertion

### Recommendations

1. **Use random salts** (32 bytes from CSPRNG)
2. **Never reuse salts** across derivations
3. **Bind to credential** - different credential = different derived key
4. **Protect derived secrets** appropriately

## Credential Protection

### credProtect Extension

Per-credential protection levels:

| Level | Name | Protection |
|-------|------|------------|
| 1 | userVerificationOptional | Always visible |
| 2 | userVerificationOptionalWithList | Visible in allowList or with UV |
| 3 | userVerificationRequired | Requires user verification |

### Recommendations

1. **Use level 3** for high-value credentials
2. **Require PIN** for credential management
3. **Audit credential access** patterns

```go
extensions := map[string]interface{}{
    "credProtect": uint8(3), // Maximum protection
}
```

## Attestation Security

### Self-Attestation

The native authenticator uses self-attestation:

```go
type AuthenticatorState struct {
    AttestationKey  *ecdsa.PrivateKey // Generated on init
    AttestationCert []byte             // Self-signed
}
```

**Implications:**
- No hardware root of trust
- Cannot prove authenticator identity
- Relying parties should accept self-attestation for testing only

### AAGUID Considerations

- Zero AAGUID acceptable for testing
- Custom AAGUID should be registered for production
- AAGUID does not prove authenticator identity without attestation

## Thread Safety

### Concurrency Security

The authenticator uses mutexes for thread safety:

```go
type Authenticator struct {
    mu sync.RWMutex // Protects state
}
```

**Protected Operations:**
- Credential storage access
- PIN state modifications
- Assertion context

**Atomic Operations:**
- Closed flag
- PIN retry counter
- UV retry counter

### Recommendations

1. **Don't share authenticator** across security boundaries
2. **Use separate instances** for isolation
3. **Check IsClosed()** before operations

## Storage Security

### File-Based Storage

For persistent storage:

```go
// Secure file permissions
os.Chmod(credentialPath, 0600)

// Secure directory permissions
os.Chmod(storageDir, 0700)
```

### Database Storage

For database-backed storage:

1. **Encrypt connections** (TLS)
2. **Use parameterized queries** (prevent injection)
3. **Encrypt sensitive columns** (private keys)
4. **Audit access** (logging)

### Memory Clearing

Clear sensitive data when done:

```go
func (a *Authenticator) Close() error {
    a.mu.Lock()
    defer a.mu.Unlock()

    // Clear PIN state
    if a.state != nil {
        clearBytes(a.state.PINHash)
    }

    // Clear PIN protocol state
    if a.pinState.protocol != nil {
        clearBytes(a.pinState.protocol.pinUvAuthToken)
        clearBytes(a.pinState.protocol.sharedSecret)
    }

    return a.storage.Close()
}
```

## Deployment Recommendations

### Development/Testing

```go
config := &authenticator.Config{
    EnablePIN:        true,
    EnableHMACSecret: true,
    Storage:          authenticator.NewMemoryStorage(), // Ephemeral
}
```

### Production (Hardware Unavailable)

```go
config := &authenticator.Config{
    PINMinLength:     8,
    PINMaxRetries:    5,
    EnablePIN:        true,
    EnableHMACSecret: true,
    Storage:          encryptedPersistentStorage,
}
```

### High-Security Recommendations

1. **Use hardware authenticators** when possible
2. **If software-only:**
   - Run in isolated environment (VM, container)
   - Use encrypted storage
   - Implement additional access controls
   - Monitor for anomalies
   - Consider HSM integration for key storage

## Known Limitations

1. **No hardware protection** - Keys exist in software
2. **No side-channel protection** - Timing attacks possible
3. **No physical presence** - UP flag is simulated
4. **Self-attestation only** - No hardware root of trust
5. **Memory exposure** - Keys in process memory

## Security Checklist

- [ ] Storage backend configured with encryption
- [ ] File permissions restricted (0600/0700)
- [ ] PIN minimum length >= 6
- [ ] PIN retry limit <= 5
- [ ] AAGUID set appropriately
- [ ] Authenticator closed when done
- [ ] Error handling doesn't leak info
- [ ] Logging doesn't include secrets
- [ ] Deployment environment hardened
