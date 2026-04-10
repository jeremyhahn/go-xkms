# Authenticator Overview

The native FIDO2 authenticator package provides a complete software implementation of the CTAP2 specification with **full FIDO 2.1 compliance**. This document provides an overview of the architecture and capabilities.

## Architecture Overview

```
+---------------------------------------------------------------+
|                     Application Layer                          |
|  (WebAuthn RP, FIDO2 Client, go-xkms integration)             |
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
|  | Command Handlers |  | PIN Protocols    |                    |
|  | - MakeCredential |  | V1: SHA-256 ECDH |                    |
|  | - GetAssertion   |  | V2: HKDF-SHA-256 |                    |
|  | - GetInfo        |  | AES-256-CBC      |                    |
|  | - ClientPIN      |  | HMAC-SHA-256     |                    |
|  | - CredMgmt       |  +------------------+                    |
|  +------------------+  +------------------+                    |
|                        | User Presence    |                    |
|  +------------------+  | - AutoGrant      |                    |
|  | Extensions       |  | - Interactive    |                    |
|  | - hmac-secret    |  +------------------+                    |
|  | - credProtect    |                                          |
|  +------------------+  +------------------+                    |
|                        | State Manager    |                    |
|                        | - PIN retries    |                    |
|                        | - UV retries     |                    |
|                        | - Assertion ctx  |                    |
|                        +------------------+                    |
+---------------------------------------------------------------+
                              |
                              v
+---------------------------------------------------------------+
|                    Key Backend Layer                           |
|  FIDO2KeyBackend interface (pluggable)                        |
|  +------------------+  +------------------+                    |
|  | SoftwareBackend  |  | TPM2Backend      |                    |
|  | (in-process)     |  | (hardware-backed)|                    |
|  +------------------+  +------------------+                    |
|                                                                |
|  Legacy Cryptographic Path (when no KeyBackend configured)    |
|  - ECDSA (P-256, P-384, P-521)                                |
|  - Ed25519 (EdDSA)                                            |
|  - COSE key encoding                                          |
|  - Signature generation                                        |
+---------------------------------------------------------------+
                              |
                              v
+---------------------------------------------------------------+
|                    Storage Layer                               |
|  CredentialStorage / StatefulCredentialStorage interfaces     |
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

Both pinUvAuthProtocol 1 and 2 are supported. GetInfo advertises `pinUvAuthProtocols: [2, 1]` (Protocol 2 preferred). The client selects the protocol version per-request.

| Command | Description | Status |
|---------|-------------|--------|
| ClientPIN (0x06) | PIN management and token operations | Implemented |
| - GetRetries | Returns PIN retry count | Implemented |
| - GetKeyAgreement | Returns ECDH public key for selected protocol | Implemented |
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

| Config (0x0D) | Authenticator configuration | Implemented |

### Not Implemented

| Command | Reason |
|---------|--------|
| BioEnrollment (0x09) | Software authenticator has no biometric hardware |
| LargeBlobs (0x0C) | Not required for core functionality |

## Supported Extensions

### hmac-secret Extension

The hmac-secret extension enables deriving symmetric secrets from credentials during authentication. This is critical for go-xkms's key derivation functionality.

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
        4: 2,                      // pinUvAuthProtocol (1 or 2)
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

## Pluggable Key Backends

The authenticator supports pluggable key backends through the `FIDO2KeyBackend` interface (defined in `keybackend` sub-package). When a `KeyBackend` is configured, the authenticator delegates key generation, signing, and key lifecycle operations to it. When no backend is configured, the authenticator falls back to the legacy `crypto.go` path.

### FIDO2KeyBackend Interface

```go
type FIDO2KeyBackend interface {
    Type() FIDO2KeyBackendType
    Capabilities() FIDO2KeyCapabilities
    GenerateCredentialKey(algorithm int, credentialID []byte) (KeyHandle, []byte, error)
    Sign(handle KeyHandle, algorithm int, data []byte) ([]byte, error)
    LoadKey(credentialID []byte, algorithm int) (KeyHandle, error)
    DeleteKey(handle KeyHandle) error
    ExportPrivateKey(handle KeyHandle) ([]byte, error)
    ImportPrivateKey(credentialID []byte, algorithm int, pkcs8Key []byte) (KeyHandle, error)
    Close() error
}
```

### Included Key Backend Implementations

1. **SoftwareKeyBackend** (`keybackend/software`) - In-process software keys with PKCS#8 export/import
2. **TPM2KeyBackend** (`keybackend/tpm2`) - Hardware-backed keys via TPM 2.0 (no export/import)

## User Presence Handlers

The authenticator supports pluggable user presence and verification through the `UserPresenceHandler` interface. This controls how user presence (UP) and user verification (UV) are handled during CTAP2 operations.

### UserPresenceHandler Interface

```go
type UserPresenceHandler interface {
    RequestUserPresence(ctx context.Context, req *UserPresenceRequest) (*UserPresenceResult, error)
    RequestUserVerification(ctx context.Context, req *UserVerificationRequest) (*UserVerificationResult, error)
}
```

### Included Implementations

1. **AutoGrantHandler** - Automatically approves all UP/UV requests (default, used for testing and automation)
2. **InteractiveHandler** - Prompts the user via terminal for presence confirmation and PIN entry

Custom implementations can be created for other use cases (IPC-based, notification-based, etc.).

## Pluggable Storage

The authenticator supports pluggable credential storage through the `CredentialStorage` and `StatefulCredentialStorage` interfaces. The `Config.Storage` field accepts a `CredentialStorage`, but the authenticator requires it to also implement `StatefulCredentialStorage` at runtime for state persistence.

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
2. **BackendStorage** - Persistent storage using go-xkms storage backends

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

- [Architecture Details](fido2-authenticator-architecture.md) - Deep dive into component design
- [Usage Examples](fido2-authenticator-examples.md) - Comprehensive code examples
- [Configuration Options](fido2-authenticator-config.md) - All configuration parameters
- [API Reference](fido2-authenticator-api.md) - Complete API documentation
- [Security Considerations](fido2-authenticator-security.md) - Security best practices
