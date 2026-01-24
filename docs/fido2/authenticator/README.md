# Authenticator Overview

The native FIDO2 authenticator package provides a complete software implementation of the CTAP2 specification. This document provides an overview of the architecture and capabilities.

## Architecture Overview

```
+---------------------------------------------------------------+
|                     Application Layer                          |
|  (WebAuthn RP, FIDO2 Client, go-keychain integration)        |
+---------------------------------------------------------------+
                              |
                              v
+---------------------------------------------------------------+
|                    CTAP-HID Protocol Layer                     |
|  CTAPHIDHandler - HID packet framing/reassembly               |
|  - Channel management                                          |
|  - Message fragmentation                                       |
+---------------------------------------------------------------+
                              |
                              v
+---------------------------------------------------------------+
|                    Authenticator Core                          |
|  +------------------+  +------------------+                    |
|  | Command Handlers |  | PIN Protocol     |                    |
|  | - MakeCredential |  | - ECDH P-256     |                    |
|  | - GetAssertion   |  | - AES-256-CBC    |                    |
|  | - GetInfo        |  | - HMAC-SHA-256   |                    |
|  | - ClientPIN      |  +------------------+                    |
|  | - CredMgmt       |                                          |
|  +------------------+                                          |
|                                                                |
|  +------------------+  +------------------+                    |
|  | Extensions       |  | State Manager    |                    |
|  | - hmac-secret    |  | - PIN retries    |                    |
|  | - credProtect    |  | - UV retries     |                    |
|  +------------------+  | - Assertion ctx  |                    |
|                        +------------------+                    |
+---------------------------------------------------------------+
                              |
                              v
+---------------------------------------------------------------+
|                    Cryptographic Layer                         |
|  - ECDSA (P-256, P-384, P-521)                                |
|  - Ed25519 (EdDSA)                                            |
|  - COSE key encoding                                          |
|  - Signature generation                                        |
+---------------------------------------------------------------+
                              |
                              v
+---------------------------------------------------------------+
|                    Storage Layer                               |
|  StatefulCredentialStorage interface                          |
|  +------------------+  +------------------+                    |
|  | MemoryStorage    |  | BackendStorage   |                    |
|  | (ephemeral)      |  | (persistent)     |                    |
|  +------------------+  +------------------+                    |
+---------------------------------------------------------------+
```

## Supported CTAP2 Commands

### Core Commands

| Command | Description | Status |
|---------|-------------|--------|
| GetInfo (0x04) | Returns authenticator capabilities | Implemented |
| MakeCredential (0x01) | Creates a new credential | Implemented |
| GetAssertion (0x02) | Authenticates with a credential | Implemented |
| GetNextAssertion (0x08) | Returns next assertion for multi-credential | Implemented |

### PIN/UV Commands

| Command | Description | Status |
|---------|-------------|--------|
| ClientPIN (0x06) | PIN management and token operations | Implemented |
| - GetRetries | Returns PIN retry count | Implemented |
| - GetKeyAgreement | Returns ECDH public key | Implemented |
| - SetPIN | Sets initial PIN | Implemented |
| - ChangePIN | Changes existing PIN | Implemented |
| - GetPINToken | Gets encrypted PIN token | Implemented |
| - GetPINTokenWithPermissions | Gets token with permissions | Implemented |

### Management Commands

| Command | Description | Status |
|---------|-------------|--------|
| Reset (0x07) | Factory reset authenticator | Implemented |
| CredentialManagement (0x0A) | Manage stored credentials | Implemented |
| - GetCredsMetadata | Returns credential counts | Implemented |
| - EnumerateRPs | Lists relying parties | Implemented |
| - EnumerateCredentials | Lists credentials per RP | Implemented |
| - DeleteCredential | Removes a credential | Implemented |
| - UpdateUserInfo | Updates user display name | Implemented |
| Selection (0x0B) | Confirms user presence | Implemented |

### Not Implemented

| Command | Reason |
|---------|--------|
| BioEnrollment (0x09) | Software authenticator has no biometric hardware |
| LargeBlobs (0x0C) | Not required for core functionality |
| Config (0x0D) | Reserved for future use |

## Supported Extensions

### hmac-secret Extension

The hmac-secret extension enables deriving symmetric secrets from credentials during authentication. This is critical for go-keychain's key derivation functionality.

**MakeCredential Input:**
```go
extensions := map[string]interface{}{
    "hmac-secret": true,
}
```

**GetAssertion Input:**
```go
extensions := map[string]interface{}{
    "hmac-secret": map[interface{}]interface{}{
        1: platformPublicKeyCOSE,  // keyAgreement
        2: encryptedSalts,         // saltEnc
        3: saltAuth,               // saltAuth (HMAC)
        4: 1,                      // pinUvAuthProtocol
    },
}
```

### credProtect Extension

The credProtect extension sets per-credential protection levels.

**Protection Levels:**

| Level | Value | Description |
|-------|-------|-------------|
| userVerificationOptional | 1 | Credential always visible |
| userVerificationOptionalWithList | 2 | Visible in allowList or with UV |
| userVerificationRequired | 3 | Requires user verification |

**MakeCredential Input:**
```go
extensions := map[string]interface{}{
    "credProtect": uint8(3), // userVerificationRequired
}
```

## Pluggable Storage

The authenticator supports pluggable credential storage through the `StatefulCredentialStorage` interface.

### Interface Definition

```go
type CredentialStorage interface {
    Store(credential *StoredCredential) error
    Load(credentialID []byte) (*StoredCredential, error)
    LoadByRPID(rpID string) ([]*StoredCredential, error)
    Delete(credentialID []byte) error
    Count() (int, error)
    CountDiscoverable() (int, error)
}

type StatefulCredentialStorage interface {
    CredentialStorage
    SaveState(state *AuthenticatorState) error
    LoadState() (*AuthenticatorState, error)
    Close() error
}
```

### Included Implementations

1. **MemoryStorage** - In-memory storage for testing
2. **BackendStorage** - Persistent storage using go-keychain storage backends

## Thread Safety

All public methods of the Authenticator are safe for concurrent use. Internal state is protected by a read-write mutex. Atomic operations are used for frequently accessed state like closed flags and retry counters.

## Error Handling

The authenticator uses typed errors that map to CTAP2 status codes. All errors are defined in `errors.go` and can be compared using `errors.Is()`.

```go
if errors.Is(err, authenticator.ErrCredentialNotFound) {
    // Handle missing credential
}
```

## Next Steps

- [Architecture Details](architecture.md) - Deep dive into component design
- [Usage Examples](usage.md) - Comprehensive code examples
- [Configuration Options](configuration.md) - All configuration parameters
- [API Reference](api.md) - Complete API documentation
- [Security Considerations](security.md) - Security best practices
