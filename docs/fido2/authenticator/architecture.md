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
|  pinState: authenticatorPINState     # PIN protocol state         |
|  credMgmtState: *credMgmtEnumerationState  # Enumeration state   |
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

```
Platform                Authenticator
   |                         |
   | GetKeyAgreement         |
   |------------------------>|
   |                         | generate ECDH key pair
   |                         |
   | aG (auth public key)    |
   |<------------------------|
   |                         |
   | SetPIN(bG, enc(PIN))    |
   | bG = platform pub key   |
   |------------------------>|
   |                         | K = ECDH(a, bG)
   |                         | sharedSecret = SHA-256(K)
   |                         | PIN = decrypt(enc(PIN))
   |                         | store(SHA-256(PIN)[:16])
   |                         |
   | success                 |
   |<------------------------|
   |                         |
   | GetPINToken(bG, enc(pinHash)) |
   |------------------------>|
   |                         | K = ECDH(a, bG)
   |                         | verify pinHash
   |                         | generate token
   |                         | encrypt(token)
   |                         |
   | enc(pinToken)           |
   |<------------------------|
```

### hmac-secret Extension Flow

```
Platform                Authenticator
   |                         |
   | GetAssertion with       |
   | hmac-secret extension   |
   |------------------------>|
   |                         |
   | Input:                  |
   | - keyAgreement (bG)     | K = ECDH(ephemeral, bG)
   | - saltEnc               | sharedSecret = SHA-256(K)
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
| WINK | 0x88 | Visual indicator |
| ERROR | 0xBF | Error response |

## Thread Safety

### Mutex Strategy

```go
type Authenticator struct {
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
