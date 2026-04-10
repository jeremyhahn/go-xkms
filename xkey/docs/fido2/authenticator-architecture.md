# Authenticator Architecture

This document describes the detailed architecture of the native FIDO2 authenticator, including component design, data flow, and protocol implementations.

## Component Architecture

### Core Components

```
+------------------------------------------------------------------+
|                        Authenticator                              |
|                                                                   |
|  config: *Config           # Configuration (immutable after init) |
|  storage: StatefulCredentialStorage  # Credential persistence     |
|  state: *AuthenticatorState          # Runtime state              |
|  keyBackend: FIDO2KeyBackend         # Pluggable key backend      |
|  upHandler: UserPresenceHandler      # User presence handler      |
|  pinState: authenticatorPINState     # PIN protocol state         |
|  credMgmtState: *credMgmtEnumerationState  # Enumeration state   |
|  pinCoordinator: PINCoordinator  # PIN change notification dispatch |
|  closed: atomic.Bool       # Lifecycle flag                       |
|  mu: sync.RWMutex          # State protection                     |
|                                                                   |
|  +-- matchingCredentials: []*StoredCredential  # GetNextAssertion |
|  +-- currentCredentialIndex: int               # state            |
|  +-- lastClientDataHash: []byte                #                  |
+------------------------------------------------------------------+
```

### State Management

```
+------------------------------------------------------------------+
|                    AuthenticatorState                             |
|                                                                   |
|  AAGUID: [16]byte          # Authenticator Attestation GUID       |
|  PINHash: []byte           # SHA-256(PIN)[:16]                    |
|  PINSet: bool              # PIN configured flag                  |
|  pinRetries: atomic.Int32  # Remaining PIN attempts               |
|  uvRetries: atomic.Int32   # Remaining UV attempts                |
|  AttestationKey: *ecdsa.PrivateKey  # Self-attestation key        |
|  AttestationCert: []byte   # Self-attestation certificate         |
|  PINSyncPending: bool      # Awaiting SOPIN unlock to sync PIN    |
+------------------------------------------------------------------+
```

## Data Flow Diagrams

### MakeCredential Flow

```
Client                 Authenticator                Storage
  |                         |                          |
  |  MakeCredential(req)   |                          |
  |----------------------->|                          |
  |                         |                          |
  |                         | validate request         |
  |                         |------------------------->|
  |                         |                          |
  |                         | check excludeList        |
  |                         |<-------------------------|
  |                         |                          |
  |                         | select algorithm         |
  |                         |                          |
  |                         | check limits             |
  |                         |------------------------->|
  |                         |                          |
  |                         | generate key pair        |
  |                         |                          |
  |                         | generate credential ID   |
  |                         |                          |
  |                         | build authData           |
  |                         |                          |
  |                         | store credential         |
  |                         |------------------------->|
  |                         |                          |
  |                         | build response           |
  |                         |                          |
  |  MakeCredentialResponse |                          |
  |<------------------------|                          |
```

### GetAssertion Flow

```
Client                 Authenticator                Storage
  |                         |                          |
  |  GetAssertion(req)      |                          |
  |------------------------>|                          |
  |                         |                          |
  |                         | decode request           |
  |                         |                          |
  |                         | find matching creds      |
  |                         |------------------------->|
  |                         |<-------------------------|
  |                         |                          |
  |                         | check credProtect        |
  |                         |                          |
  |                         | process extensions       |
  |                         | (hmac-secret)           |
  |                         |                          |
  |                         | build authData           |
  |                         |                          |
  |                         | increment signCount      |
  |                         |------------------------->|
  |                         |                          |
  |                         | sign(authData || cdHash) |
  |                         |                          |
  |  GetAssertionResponse   |                          |
  |<------------------------|                          |
```

### PIN Protocol Flow

The authenticator supports both pinUvAuthProtocol 1 and 2. The client selects the protocol version per-request based on the GetInfo `pinUvAuthProtocols` advertisement `[2, 1]`.

**Protocol 1** (CTAP 2.0):
- Shared secret: `SHA-256(ECDH(a, bG).x)`
- Encryption: AES-256-CBC with zero IV
- Authentication: HMAC-SHA-256 truncated to 16 bytes

**Protocol 2** (FIDO 2.1, preferred):
- Key derivation: `HKDF-SHA-256(Z)` with salt=32 zero bytes
  - `hmacKey = HKDF(Z, info="CTAP2 HMAC key")`
  - `aesKey = HKDF(Z, info="CTAP2 AES key")`
- Encryption: AES-256-CBC with random IV prepended to ciphertext
- Authentication: HMAC-SHA-256 full 32 bytes

```
Platform                Authenticator
   |                         |
   | GetKeyAgreement(proto)  |
   |------------------------>|
   |                         | generate ECDH key pair
   |                         |
   | aG (auth public key)    |
   |<------------------------|
   |                         |
   | SetPIN(bG, enc(PIN))    |
   | bG = platform pub key   |
   |------------------------>|
   |                         | Z = ECDH(a, bG)
   |                         | V1: sharedSecret = SHA-256(Z.x)
   |                         | V2: hmacKey, aesKey = HKDF(Z)
   |                         | PIN = decrypt(enc(PIN))
   |                         | store(SHA-256(PIN)[:16])
   |                         |
   | success                 |
   |<------------------------|
   |                         |
   | GetPINToken(bG, enc(pinHash)) |
   |------------------------>|
   |                         | derive keys per protocol
   |                         | verify pinHash
   |                         | generate token
   |                         | encrypt(token)
   |                         |
   | enc(pinToken)           |
   |<------------------------|
```

### Unified PIN Coordination

The authenticator's `pinCoordinator` field dispatches PIN change notifications to
registered subscribers (e.g., KeyManager). `SetPIN` and `ChangePIN` in
`cmd_clientpin.go` fire async notifications after state is persisted, providing
both the new PIN and its hash. `handleVendorResetUserPIN` fires hash-only
notifications for admin-initiated resets. When a PIN change occurs while the
KeyManager is locked, `PINSyncPending` is set on the authenticator state;
`KeyManager.UnlockWithSOPIN()` resolves the pending flag and re-derives its
wrapping key from the updated PIN hash.

See [Unified PIN Architecture](../../../docs/architecture/pin-architecture.md) for the full design.

### hmac-secret Extension Flow

The hmac-secret extension uses the PIN protocol selected by `pinUvAuthProtocol` in the extension input. Both Protocol 1 and 2 are supported.

```
Platform                Authenticator
   |                         |
   | GetAssertion with       |
   | hmac-secret extension   |
   |------------------------>|
   |                         |
   | Input:                  |
   | - keyAgreement (bG)     | Z = ECDH(ephemeral, bG)
   | - saltEnc               | derive keys per protocol
   | - saltAuth              |
   | - pinUvAuthProtocol     | verify saltAuth
   |                         | salt1 = decrypt(saltEnc)
   |                         |
   |                         | output1 = HMAC-SHA-256(
   |                         |   credentialHMACKey,
   |                         |   salt1)
   |                         |
   |                         | encOutput = encrypt(output1)
   |                         |
   | Output:                 |
   | - encrypted HMAC output |
   |<------------------------|
```

## Key Backend Architecture

The authenticator supports pluggable key backends via the `FIDO2KeyBackend` interface
(defined in the `keybackend` sub-package). When `Config.KeyBackend` is set, the authenticator
delegates all key generation and signing operations to the backend. When nil, it falls back
to the legacy `crypto.go` path.

### Backend Types

```
FIDO2KeyBackend (interface)
    |
    +-- SoftwareKeyBackend (keybackend/software)
    |   - In-process key storage
    |   - Supports export/import (PKCS#8)
    |   - Algorithms: ES256, ES384, ES512, EdDSA
    |
    +-- TPM2KeyBackend (keybackend/tpm2)
    |   - Hardware-backed via TPM 2.0 (via TPMSignerAdapter)
    |   - No export/import
    |   - Algorithms: ES256, ES384
    |
    +-- PhoneKeyBackend (planned: BLE phone backend)
    +-- (Cloud KMS backends - planned: awskms, gcpkms, azurekv)
    +-- (Proxy backend - planned)
    +-- (PKCS#11 backend - planned)
```

### Key Lifecycle

```
MakeCredential
    |
    +-- GenerateCredentialKey(algorithm, credentialID) -> KeyHandle, publicKeyCOSE
    |
    +-- ExportPrivateKey(handle) -> PKCS#8 bytes (stored in credential)
        (Software only; TPM returns ErrExportNotSupported)

GetAssertion
    |
    +-- LoadKey(credentialID, algorithm) -> KeyHandle
    |   OR ImportPrivateKey(credentialID, algorithm, pkcs8Key) -> KeyHandle
    |
    +-- Sign(handle, algorithm, data) -> signature
```

## User Presence Architecture

The authenticator uses a `UserPresenceHandler` interface to request user presence (UP) and
user verification (UV). This is invoked during MakeCredential, GetAssertion, and Reset.

```
UserPresenceHandler (interface)
    |
    +-- AutoGrantHandler
    |   - Automatically approves all requests
    |   - Optionally returns a simulated PIN
    |   - Default handler when none is configured
    |
    +-- InteractiveHandler
        - Terminal-based prompts
        - Requires 'y' + ENTER for presence
        - Hidden PIN entry via term.ReadPassword
        - Configurable timeout (default 30s)
```

## Credential Storage

### StoredCredential Structure

```go
type StoredCredential struct {
    CredentialID    []byte    // 32 bytes, random
    RPID            string    // Relying party ID
    RPName          string    // Relying party name
    UserID          []byte    // User handle
    UserName        string    // Username
    UserDisplayName string    // Display name
    PrivateKey      []byte    // PKCS#8 encoded
    PublicKeyCOSE   []byte    // CBOR COSE_Key
    Algorithm       int       // COSE algorithm ID
    SignCount       uint32    // Signature counter
    Discoverable    bool      // Resident key flag
    HMACSecretKey   []byte    // 32 bytes for hmac-secret
    CredProtect     uint8     // Credential protection level (0-3)
    CreatedAt       int64     // Unix timestamp
}
```

### Storage Interface Hierarchy

```
CredentialStorage (base)
    |
    +-- StatefulCredentialStorage (+ state persistence)
            |
            +-- MemoryStorage (in-memory)
            |
            +-- BackendStorage (persistent)

Optional interfaces:
    +-- CredentialEnumerator (for credential management)
    +-- ClearableStorage (for reset operations)
    +-- ListableStorage (for enumeration)
```

## Cryptographic Operations

### Key Generation

```
Algorithm       Curve         Signature Hash
---------       -----         --------------
ES256 (-7)      P-256         SHA-256
ES384 (-35)     P-384         SHA-384
ES512 (-36)     P-521         SHA-512
EdDSA (-8)      Ed25519       (intrinsic)
```

### COSE Key Encoding

EC2 Key (P-256 example):
```
{
    1: 2,      // kty: EC2
    3: -7,     // alg: ES256
   -1: 1,      // crv: P-256
   -2: x,      // x coordinate (32 bytes)
   -3: y       // y coordinate (32 bytes)
}
```

OKP Key (Ed25519):
```
{
    1: 1,      // kty: OKP
    3: -8,     // alg: EdDSA
   -1: 6,      // crv: Ed25519
   -2: pub     // public key (32 bytes)
}
```

### Authenticator Data Structure

```
+------------------+--------+-----------------------------------+
| Field            | Bytes  | Description                       |
+------------------+--------+-----------------------------------+
| rpIdHash         | 32     | SHA-256(rpId)                     |
| flags            | 1      | UP, UV, AT, ED bits               |
| signCount        | 4      | Big-endian counter                |
| attestedCredData | var    | Present if AT flag set            |
|   - aaguid       | 16     | Authenticator ID                  |
|   - credIdLen    | 2      | Big-endian                        |
|   - credId       | var    | Credential ID                     |
|   - pubKeyCOSE   | var    | CBOR-encoded public key           |
| extensions       | var    | Present if ED flag set (CBOR)     |
+------------------+--------+-----------------------------------+
```

### Flags Byte

```
Bit 0 (0x01): UP - User Present
Bit 2 (0x04): UV - User Verified
Bit 6 (0x40): AT - Attested Credential Data present
Bit 7 (0x80): ED - Extension Data present
```

## CTAP-HID Layer

The CTAPHIDHandler provides HID protocol framing for virtual device usage.

### Packet Format

**Initialization Packet:**
```
+----------+------+--------+---------+
| CID (4B) | CMD  | LEN(2) | DATA    |
+----------+------+--------+---------+
| bytes    | 1    | BE     | 0-57B   |
+----------+------+--------+---------+
```

**Continuation Packet:**
```
+----------+------+---------+
| CID (4B) | SEQ  | DATA    |
+----------+------+---------+
| bytes    | 1    | 0-59B   |
+----------+------+---------+
```

### HID Commands

| Command | Code | Description |
|---------|------|-------------|
| PING | 0x81 | Echo data back |
| INIT | 0x86 | Allocate channel |
| CBOR | 0x90 | CTAP2 command |
| CANCEL | 0x91 | Cancel operation |
| WINK | 0x88 | Visual indicator (advertised in capabilities) |
| ERROR | 0xBF | Error response |

## Thread Safety

### Mutex Strategy

```go
type Authenticator struct {
    config     *Config
    storage    StatefulCredentialStorage
    keyBackend keybackend.FIDO2KeyBackend  // pluggable key backend
    upHandler  UserPresenceHandler          // user presence handler
    pinCoordinator PINCoordinator             // PIN change notification dispatch

    // Protected by mu
    state           *AuthenticatorState
    pinState        authenticatorPINState
    credMgmtState   *credMgmtEnumerationState
    matchingCredentials    []*StoredCredential
    currentCredentialIndex int
    lastClientDataHash     []byte

    // Atomic (lock-free)
    closed atomic.Bool

    mu sync.RWMutex
}
```

### Lock Ordering

1. Authenticator.mu (outer)
2. Storage operations (inner)

Never hold authenticator lock when calling external callbacks.

## Error Mapping

CTAP2 errors map to Go typed errors:

```go
switch {
case errors.Is(err, ErrCredentialNotFound):
    return StatusNoCredentials      // 0x2E
case errors.Is(err, ErrPINBlocked):
    return StatusPINBlocked         // 0x32
case errors.Is(err, ErrPINInvalid):
    return StatusPINInvalid         // 0x31
// ... etc
}
```

## Extension Points

### Adding New Extensions

1. Add input parsing in command handler
2. Implement extension processing logic
3. Include output in response/authData
4. Update GetInfo to advertise support

### Adding New Storage Backend

1. Implement `StatefulCredentialStorage` interface
2. Optionally implement `CredentialEnumerator`
3. Handle serialization of `StoredCredential`
4. Handle atomic state persistence

## TPM2 Signer Adapter

The TPM2 key backend uses a `TPMSignerAdapter` to bridge the full `pkg/tpm2.TrustedPlatformModule` interface to the minimal `TPMSigner` interface needed by the FIDO2 backend.

```
TPMSigner (interface)
    |
    +-- TPMSignerAdapter
        - Wraps pkg/tpm2.TrustedPlatformModule
        - ReadPublicKey: reads ECC point from TPM persistent handle
        - Sign: delegates to TPM, converts ASN.1/DER to P1363
        - Close: releases TPM resources
        - Thread-safe via atomic.Bool closed flag
```

### Signature Format Conversion

The TPM returns ECDSA signatures in ASN.1/DER format. FIDO2 requires IEEE P1363 (r || s) fixed-size encoding:

```
ASN.1/DER (variable length):
  SEQUENCE { INTEGER r, INTEGER s }

P1363 (fixed size = 2 * keySize):
  [r padded to keySize] || [s padded to keySize]

  ES256: keySize = 32 -> 64 bytes total
  ES384: keySize = 48 -> 96 bytes total
```

The adapter determines the curve and hash algorithm from digest length:
- 32 bytes -> SHA-256 / P-256 (ES256)
- 48 bytes -> SHA-384 / P-384 (ES384)

## Planned Backends

### Cloud KMS FIDO2 Backends

Future cloud KMS backends will use a key-ID-based signer interface (unlike TPMSigner which uses persistent handle IDs):

```
CloudKMSSigner (interface)
    |
    +-- AWSKMSKeyBackend (keybackend/awskms)
    |   - AWS KMS asymmetric signing keys
    |   - Build tag: //go:build awskms
    |
    +-- GCPKMSKeyBackend (keybackend/gcpkms)
    |   - Google Cloud KMS asymmetric signing keys
    |   - Build tag: //go:build gcpkms
    |
    +-- AzureKVKeyBackend (keybackend/azurekv)
        - Azure Key Vault keys
        - Build tag: //go:build azurekv
```

```go
type CloudKMSSigner interface {
    CreateKey(algorithm int) (keyID string, err error)
    GetPublicKey(keyID string) (*ecdsa.PublicKey, error)
    Sign(keyID string, digest []byte, algorithm int) ([]byte, error)
    DeleteKey(keyID string) error
    Close() error
}
```

**Key mapping**: Deterministic naming `fido2-<hex(credentialID)>` allows `LoadKey()` to reconstruct the cloud KMS key reference without a separate registry.

**Capabilities**: Same as TPM2 -- no export, no import, hardware-backed, ES256/ES384 only. Build tags per provider avoid pulling cloud SDKs into lean builds.

**Backend type constants**:
```go
BackendTypeAWSKMS   FIDO2KeyBackendType = "awskms"
BackendTypeGCPKMS   FIDO2KeyBackendType = "gcpkms"
BackendTypeAzureKV  FIDO2KeyBackendType = "azurekv"
BackendTypeVault    FIDO2KeyBackendType = "vault"
BackendTypeProxy    FIDO2KeyBackendType = "proxy"
```

### Proxy Mode Backend

Delegates FIDO2 key operations to a remote xkmsd service via the SDK transport layer.

```
ProxyKeyBackend (keybackend/proxy)
    |
    +-- Uses sdk/go/transport/ (unix, gRPC, REST, QUIC, MCP)
    +-- Delegates to remote xkmsd key backend
    +-- Supports any remote backend (TPM2, cloud KMS, etc.)
```

**Configuration**:
```go
type Config struct {
    Protocol  xkms.Protocol  // unix, grpc, rest, quic, mcp
    Address   string             // xkmsd endpoint
    Backend   string             // remote backend name
    TLS       *TLSConfig         // TLS settings for network protocols
    KeyPrefix string             // default: "fido2-"
}
```

**RPC mapping** (using existing keystore RPCs):

| FIDO2 Operation | xKMSd RPC | Notes |
|---|---|---|
| `GenerateCredentialKey` | `GenerateKey` | Maps COSE alg to key type/curve |
| `Sign` | `Sign` | Sends pre-hashed digest |
| `LoadKey` | `GetKey` | Reconstructs proxy key handle |
| `DeleteKey` | `DeleteKey` | Uses credential ID as key ID |
| `ExportPrivateKey` | -- | Returns `ErrExportNotSupported` |
| `ImportPrivateKey` | -- | Returns `ErrImportNotSupported` |

**CLI usage**: `--backend proxy --proxy-protocol grpc --proxy-address localhost:9090 --proxy-backend tpm2`
