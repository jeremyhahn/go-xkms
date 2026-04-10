# Architecture

The PKCS#11 module is implemented as a pure Go library that connects to go-xkms via the SDK transport client.

## System Overview

```
+-----------------------------------------------------------------------+
|                      PKCS#11 Applications                             |
|            (OpenSSL, SSH, NSS, pkcs11-tool, Java)                     |
+-----------------------------------------------------------------------+
                                |
                                v
+-----------------------------------------------------------------------+
|                    PKCS#11 Module (Go)                                |
|                  pkg/pkcs11/module                                    |
+-----------------------------------------------------------------------+
|  Module    |  Session   |  Object    |  Crypto    |  Token           |
|  Manager   |  Manager   |  Manager   |  Manager   |  Manager         |
+------------+------------+------------+------------+------------------+
                                |
                                v (SDK Transport)
+-----------------------------------------------------------------------+
|                        go-xkms Server                             |
|                    (Key Storage & Crypto Ops)                         |
+-----------------------------------------------------------------------+
```

## Module Structure

```
pkg/pkcs11/module/
|-- module.go      # Main Module struct, C_Initialize/C_Finalize
|-- transport.go   # PKCS11Transport interface (15-method consumer-side interface)
|-- session.go     # Session management, login/logout
|-- object.go      # Object (key/cert) management
|-- token.go       # Slot and token management
|-- crypto.go      # Cryptographic operations
|-- mechanism.go   # Mechanism definitions and parameters
|-- handle.go      # Handle allocation and mapping
|-- config.go      # Configuration loading
|-- errors.go      # PKCS#11 error codes (CKR_*)
```

## Component Architecture

### Module

The central orchestrator managing the PKCS#11 lifecycle:

```go
type Module struct {
    initialized     atomic.Bool
    config          *Config
    client          PKCS11Transport    // 15-method consumer-side interface
    slotManager     *SlotManager
    sessionManagers map[SlotID]*SessionManager
    objectManager   *ObjectManager
    cryptoManager   *CryptoManager
    info            CK_INFO
    mu              sync.RWMutex
}
```

Key responsibilities:
- Initialize/Finalize lifecycle management
- Route operations to appropriate managers
- Maintain global module state
- Thread-safe operation coordination

### Session Manager

Manages PKCS#11 sessions per slot:

```
Session State Machine:
                    +-------------------+
                    |                   |
                    v                   |
              +-----------+             |
              |   OPEN    |             |
              +-----------+             |
                    |                   |
                    | C_Login           |
                    v                   |
              +-----------+             |
              |  LOGGED   |-------------+
              |    IN     |    C_Logout
              +-----------+
                    |
                    | C_CloseSession
                    v
              +-----------+
              |  CLOSED   |
              +-----------+
```

Session types:
- **R/O Public**: Read-only, no login required
- **R/W Public**: Read-write, no login required
- **R/O User**: Read-only, user login required
- **R/W User**: Read-write, user login required
- **R/W SO**: Security Officer for token management

### Object Manager

Manages PKCS#11 objects (keys, certificates, data):

```
+------------------+
| Object Table     |
+------------------+
| Handle | Type    |
+--------+---------+
| 0x0001 | RSA Key |
| 0x0002 | EC Key  |
| 0x0003 | Cert    |
+--------+---------+
```

Handle characteristics:
- 64-bit unsigned integers
- Monotonically increasing within session
- Never reused within a session
- Session-scoped invalidation

### Crypto Manager

Routes cryptographic operations to the backend:

Operations flow:
```
Application              PKCS#11 Module           go-xkms
    |                         |                       |
    |-- C_SignInit ---------->|                       |
    |                         |-- sign_init --------->|
    |<-- CKR_OK --------------|                       |
    |                         |                       |
    |-- C_Sign -------------->|                       |
    |                         |-- sign ------------->|
    |                         |                       |-- KeyStore.Sign()
    |                         |<-- signature ---------|
    |<-- signature, len ------|                       |
```

### Token Manager

Manages slots and tokens:

```go
type SlotManager struct {
    slots         map[SlotID]*Slot
    mechanismInfo map[MechanismType]MechanismInfo
    mu            sync.RWMutex
}
```

Default slot configuration:
- Slot 0: Primary token (GO-XKMS)
- Token flags: login required, user PIN change enabled

## Thread Safety

The module supports multi-threaded access per PKCS#11 specification:

```go
CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
    CK_C_INITIALIZE_ARGS_PTR args = pInitArgs;
    if (args && args->flags & CKF_OS_LOCKING_OK) {
        // Use OS-provided locking (pthread mutexes)
    }
}
```

Thread safety guarantees:
- Global state protected by sync.RWMutex
- Per-session state protected independently
- Handle table uses atomic operations where possible
- Backend calls serialized per-session

Locking hierarchy:
1. Module mutex (coarse-grained)
2. Session manager mutex (per-slot)
3. Object manager mutex (global objects)

## Memory Management

PKCS#11 memory conventions:

1. **Caller-allocated buffers**: Output uses caller-provided buffers
2. **Two-call pattern**: First call returns required size, second gets data

```go
// First call: get required size
sig, rv := module.Sign(session, data)  // sig == nil returns size

// Second call: get actual data
sig, rv = module.Sign(session, data)   // sig contains signature
```

The Go implementation handles this internally, allocating and returning
slices as needed.

## Error Handling

PKCS#11 errors (CK_RV) map from Go errors:

| Go Error | PKCS#11 Return |
|----------|----------------|
| ErrKeyNotFound | CKR_KEY_HANDLE_INVALID |
| ErrInvalidKeyType | CKR_KEY_TYPE_INCONSISTENT |
| ErrAuthFailed | CKR_PIN_INCORRECT |
| ErrSessionClosed | CKR_SESSION_HANDLE_INVALID |
| ErrNotInitialized | CKR_CRYPTOKI_NOT_INITIALIZED |

Error classification helpers:
- `IsRetryable(err)` - Transient errors that may succeed on retry
- `IsAuthenticationError(err)` - PIN/login related errors
- `IsSessionError(err)` - Session management errors
- `IsKeyError(err)` - Key operation errors
- `IsCryptographicError(err)` - Crypto operation errors

## Transport Layer

The module uses a minimal `PKCS11Transport` interface (15 methods) rather than the full
`transport.Client` (116 methods). The module handles sessions, slots, tokens, objects,
mechanisms, digesting, multi-part operations, and random generation internally — only
backend-delegated operations require transport calls.

### PKCS11Transport Interface

```go
type PKCS11Transport interface {
    Connect(ctx context.Context) error
    Close() error
    GenerateKey(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error)
    Sign(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error)
    Verify(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error)
    Encrypt(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error)
    Decrypt(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error)
    DeriveKey(ctx context.Context, req *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error)
    DeriveKeyECDH(ctx context.Context, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error)
    WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error)
    UnwrapKeyByID(ctx context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error)
    ExportKeyMaterial(ctx context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error)
    ListPIVSlots(ctx context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error)
    GetPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error)
    GeneratePIVKey(ctx context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error)
}
```

All existing transports (gRPC, REST, Unix, embedded) satisfy this interface automatically
via Go structural typing since they implement the full `transport.Client`.

### Transport Modes

**Remote (server-based)**:
- **Unix socket**: `unix:///var/run/xkms/xkms.sock`
- **TCP/gRPC**: `dns:///host:port` or `host:port`

**Embedded (in-process, xkey)**:
- `xkey/pkg/pkcs11.EmbeddedTransport` implements `PKCS11Transport` directly
- Delegates to the xkms singleton with zero network overhead
- All 15 methods have real implementations — zero stubs

## Data Flow

### Key Generation

```
Application              Module                  Backend
    |                      |                       |
    |-- GenerateKeyPair -->|                       |
    |                      |-- GenerateKey ------->|
    |                      |                       |-- Create key
    |                      |<-- keyID, handle -----|
    |                      |-- CreateObject ------>|
    |<-- pub, priv handles-|                       |
```

### Signing

```
Application              Module                  Backend
    |                      |                       |
    |-- SignInit --------->|                       |
    |                      |-- InitOperation ----->|
    |<-- CKR_OK -----------|                       |
    |                      |                       |
    |-- Sign ------------->|                       |
    |                      |-- GetKey ------------>|
    |                      |<-- key data ---------|
    |                      |-- Sign -------------->|
    |                      |<-- signature ---------|
    |<-- signature --------|                       |
```

## PKCS#11 v3.0 Extensions

### Interface Discovery

The v3.0 interface system allows applications to discover available PKCS#11 interfaces:

```go
// C_GetInterfaceList returns available interfaces
interfaces, count := module.GetInterfaceList()
// Returns: [{"PKCS 11", version: 3.0, flags: 0}]

// C_GetInterface retrieves a specific interface
interface := module.GetInterface("PKCS 11", version, flags)
// Returns: CK_INTERFACE with function pointers
```

### Message-Based Cryptography

v3.0 introduces message-based functions for AEAD (Authenticated Encryption with Associated Data):

```
Traditional Flow:              Message-Based Flow (v3.0):
EncryptInit                    MessageEncryptInit
Encrypt/EncryptUpdate          EncryptMessage (single)
EncryptFinal                     -or-
                               EncryptMessageBegin
                               EncryptMessageNext (multi)
                               MessageEncryptFinal
```

Message-based operations support:
- **Single-message**: Process entire message in one call with AAD
- **Multi-part**: Stream processing with explicit message boundaries
- **IV generation**: Automatic nonce/IV handling per message

### v3.0 Function List Structure

```go
// CK_FUNCTION_LIST_3_0 extends CK_FUNCTION_LIST with v3.0 additions
type FunctionList30 struct {
    // All 68 PKCS#11 v2.x functions...

    // v3.0 Interface functions
    C_GetInterfaceList       func(...) CK_RV
    C_GetInterface           func(...) CK_RV

    // v3.0 Session functions
    C_LoginUser              func(...) CK_RV
    C_SessionCancel          func(...) CK_RV

    // v3.0 Message-based encryption (5 functions)
    C_MessageEncryptInit     func(...) CK_RV
    C_EncryptMessage         func(...) CK_RV
    C_EncryptMessageBegin    func(...) CK_RV
    C_EncryptMessageNext     func(...) CK_RV
    C_MessageEncryptFinal    func(...) CK_RV

    // v3.0 Message-based decryption (5 functions)
    C_MessageDecryptInit     func(...) CK_RV
    // ... and 4 more

    // v3.0 Message-based signing (5 functions)
    C_MessageSignInit        func(...) CK_RV
    // ... and 4 more

    // v3.0 Message-based verification (5 functions)
    C_MessageVerifyInit      func(...) CK_RV
    // ... and 4 more
}
```

### v3.0 Type Definitions

New types for AEAD message operations:

```c
// GCM message parameters for per-message IV handling
typedef struct CK_GCM_MESSAGE_PARAMS {
    CK_BYTE_PTR   pIv;
    CK_ULONG      ulIvLen;
    CK_ULONG      ulIvFixedBits;
    CK_GENERATOR_FUNCTION ivGenerator;
    CK_BYTE_PTR   pTag;
    CK_ULONG      ulTagBits;
} CK_GCM_MESSAGE_PARAMS;

// CCM message parameters
typedef struct CK_CCM_MESSAGE_PARAMS {
    CK_ULONG      ulDataLen;
    CK_BYTE_PTR   pNonce;
    CK_ULONG      ulNonceLen;
    CK_ULONG      ulNonceFixedBits;
    CK_GENERATOR_FUNCTION nonceGenerator;
    CK_BYTE_PTR   pMAC;
    CK_ULONG      ulMACLen;
} CK_CCM_MESSAGE_PARAMS;
```

### Current Implementation Status

| v3.0 Feature | Status | Notes |
|--------------|--------|-------|
| Interface discovery | ✅ Complete | C_GetInterfaceList, C_GetInterface |
| Session extensions | ✅ Complete | C_LoginUser with CKU_CONTEXT_SPECIFIC, C_SessionCancel |
| Message encryption | ✅ Complete | C_MessageEncryptInit, C_EncryptMessage, C_EncryptMessageBegin, C_EncryptMessageNext, C_MessageEncryptFinal |
| Message decryption | ✅ Complete | C_MessageDecryptInit, C_DecryptMessage, C_DecryptMessageBegin, C_DecryptMessageNext, C_MessageDecryptFinal |
| Message signing | ✅ Complete | C_MessageSignInit, C_SignMessage, C_SignMessageBegin, C_SignMessageNext, C_MessageSignFinal |
| Message verification | ✅ Complete | C_MessageVerifyInit, C_VerifyMessage, C_VerifyMessageBegin, C_VerifyMessageNext, C_MessageVerifyFinal |

All 20 message-based functions (v3.0 AEAD operations) are fully implemented with proper AAD (Additional Authenticated Data) support for AES-GCM and other AEAD mechanisms.

## Advanced Cryptographic Operations

### Key Derivation

The module supports multiple key derivation mechanisms:

| Mechanism | Description |
|-----------|-------------|
| CKM_HKDF_DERIVE | HMAC-based Key Derivation Function |
| CKM_HKDF_KEY_GEN | HKDF for key generation |
| CKM_SP800_108_COUNTER_KDF | NIST SP 800-108 Counter Mode KDF |
| CKM_SP800_108_FEEDBACK_KDF | NIST SP 800-108 Feedback Mode KDF |
| CKM_SP800_108_DOUBLE_PIPELINE_KDF | NIST SP 800-108 Double Pipeline Mode KDF |
| CKM_ECDH1_DERIVE | Elliptic Curve Diffie-Hellman |
| CKM_ECDH1_COFACTOR_DERIVE | ECDH with cofactor multiplication |

ECDH key derivation supports multiple KDF types:
- `CKD_NULL` - No KDF, raw shared secret
- `CKD_SHA1_KDF` - SHA-1 based KDF
- `CKD_SHA256_KDF` - SHA-256 based KDF
- `CKD_SHA384_KDF` - SHA-384 based KDF
- `CKD_SHA512_KDF` - SHA-512 based KDF

### SignRecover and VerifyRecover

SignRecover and VerifyRecover operations are supported for mechanisms that allow data recovery from signatures:

```go
// SignRecoverInit initializes a sign-recover operation
rv := module.SignRecoverInit(session, mechanism, key)

// SignRecover signs data with message recovery
signature, rv := module.SignRecover(session, data)

// VerifyRecoverInit initializes a verify-recover operation
rv := module.VerifyRecoverInit(session, mechanism, key)

// VerifyRecover verifies and recovers original data
data, rv := module.VerifyRecover(session, signature)
```

Supported mechanisms:
- CKM_RSA_X_509 (raw RSA)
- CKM_RSA_PKCS (PKCS#1 v1.5 padding)

### Dual-Function Operations

The module implements dual-function cryptographic operations that combine digest with encrypt/decrypt or sign/verify:

| Function | Description |
|----------|-------------|
| C_DigestEncryptUpdate | Updates digest and encrypts in one operation |
| C_DecryptDigestUpdate | Decrypts and updates digest in one operation |
| C_SignEncryptUpdate | Updates signature and encrypts in one operation |
| C_DecryptVerifyUpdate | Decrypts and updates verification in one operation |

These operations are useful for protocols that require authenticated encryption with additional integrity protection.

### DigestKey

The DigestKey operation digests the value of a secret key:

```go
// Initialize digest operation
rv := module.DigestInit(session, &Mechanism{Type: CKM_SHA256})

// Digest a secret key value
rv := module.DigestKey(session, keyHandle)

// Get the final digest
digest, rv := module.DigestFinal(session)
```

## Complete Implementation Status

All PKCS#11 v2.40 and v3.0 functions are fully implemented:

### Core Functions (68 v2.x functions)
- ✅ General-purpose: C_Initialize, C_Finalize, C_GetInfo, C_GetFunctionList
- ✅ Slot/Token: C_GetSlotList, C_GetSlotInfo, C_GetTokenInfo, C_GetMechanismList, C_GetMechanismInfo, C_InitToken, C_InitPIN, C_SetPIN
- ✅ Session: C_OpenSession, C_CloseSession, C_CloseAllSessions, C_GetSessionInfo, C_GetOperationState, C_SetOperationState, C_Login, C_Logout
- ✅ Object: C_CreateObject, C_CopyObject, C_DestroyObject, C_GetObjectSize, C_GetAttributeValue, C_SetAttributeValue, C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal
- ✅ Encryption: C_EncryptInit, C_Encrypt, C_EncryptUpdate, C_EncryptFinal
- ✅ Decryption: C_DecryptInit, C_Decrypt, C_DecryptUpdate, C_DecryptFinal
- ✅ Digesting: C_DigestInit, C_Digest, C_DigestUpdate, C_DigestKey, C_DigestFinal
- ✅ Signing: C_SignInit, C_Sign, C_SignUpdate, C_SignFinal, C_SignRecoverInit, C_SignRecover
- ✅ Verification: C_VerifyInit, C_Verify, C_VerifyUpdate, C_VerifyFinal, C_VerifyRecoverInit, C_VerifyRecover
- ✅ Dual-function: C_DigestEncryptUpdate, C_DecryptDigestUpdate, C_SignEncryptUpdate, C_DecryptVerifyUpdate
- ✅ Key Management: C_GenerateKey, C_GenerateKeyPair, C_WrapKey, C_UnwrapKey, C_DeriveKey
- ✅ Random: C_SeedRandom (returns CKR_RANDOM_SEED_NOT_SUPPORTED), C_GenerateRandom
- ✅ Parallel: C_GetFunctionStatus, C_CancelFunction (legacy, return CKR_FUNCTION_NOT_PARALLEL)
- ✅ Slot Events: C_WaitForSlotEvent

### v3.0 Extensions (24 functions)
- ✅ Interface: C_GetInterfaceList, C_GetInterface
- ✅ Session: C_LoginUser, C_SessionCancel
- ✅ Message Encryption: C_MessageEncryptInit, C_EncryptMessage, C_EncryptMessageBegin, C_EncryptMessageNext, C_MessageEncryptFinal
- ✅ Message Decryption: C_MessageDecryptInit, C_DecryptMessage, C_DecryptMessageBegin, C_DecryptMessageNext, C_MessageDecryptFinal
- ✅ Message Signing: C_MessageSignInit, C_SignMessage, C_SignMessageBegin, C_SignMessageNext, C_MessageSignFinal
- ✅ Message Verification: C_MessageVerifyInit, C_VerifyMessage, C_VerifyMessageBegin, C_VerifyMessageNext, C_MessageVerifyFinal
