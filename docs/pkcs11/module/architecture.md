# Architecture

The PKCS#11 Provider Module is implemented as a pure C shared library that communicates with go-keychain through a configurable backend abstraction layer.

## System Overview

```
+-----------------------------------------------------------------------+
|                   Pure C PKCS#11 Module                               |
|                   (libkeychain_pkcs11.so)                           |
+-----------------------------------------------------------------------+
|  Backend Selection (KEYCHAIN_PKCS11_MODE env/config)                |
+---------------+---------------+---------------+---------------+-------+
|   EMBEDDED    |     UNIX      |     REST      |     gRPC      | QUIC  |
|               |               |               |               |       |
| libkeychain   | Direct IPC    |  HTTP/JSON    |  Protobuf     | HTTP/3|
|     .so       | to service    |   Client      |   Client      | Client|
|               |    layer      |               |               |       |
+---------------+---------------+---------------+---------------+-------+
                                |
                                v
+-----------------------------------------------------------------------+
|                        go-keychain                                    |
|            Service Layer (pkg/keychain/service.go)                    |
+-----------------------------------------------------------------------+
```

## Component Architecture

### PKCS#11 Module (C)

The main shared library implementing the PKCS#11 interface:

```
pkg/api/pkcs11/
+-- include/
|   +-- pkcs11.h          # OASIS PKCS#11 v3.0 header
|   +-- pkcs11t.h         # PKCS#11 v3.0 types
|   +-- pkcs11f.h         # PKCS#11 v3.0 function prototypes
|   +-- keychain.h        # libkeychain.so C API header
+-- src/
|   +-- pkcs11_module.c   # Main module, C_GetFunctionList
|   +-- pkcs11_functions.c# C_* function implementations
|   +-- session.c         # Session management
|   +-- object.c          # Object/key management
|   +-- crypto.c          # Cryptographic operations
|   +-- token.c           # Slot/token management
|   +-- config.c          # Configuration loading
|   +-- backends/
|       +-- backend.h     # Backend interface
|       +-- embedded.c    # libkeychain.so integration
|       +-- unix.c        # Direct Unix socket IPC
|       +-- rest.c        # REST/HTTP client
|       +-- grpc.c        # gRPC-C client
|       +-- quic.c        # QUIC/HTTP3 client
+-- CMakeLists.txt
+-- Makefile
```

### libkeychain.so (CGO)

The C-callable API to go-keychain, built with CGO:

```
cmd/cgo/
+-- main.go               # CGO exports
+-- keystore.go           # KeyStore C API wrappers
+-- types.go              # C type conversions
+-- keychain.h            # Generated header
```

## Backend Abstraction Layer

All backends implement a common interface that maps PKCS#11 operations to go-keychain operations:

```c
typedef struct pkcs11_backend {
    const char* name;

    // Lifecycle
    int (*init)(const char* config);
    void (*cleanup)(void);

    // Key operations
    int (*generate_keypair)(int key_type, int bits, const char* label,
                           uint64_t* priv_handle, uint64_t* pub_handle);
    int (*find_objects)(uint64_t session, CK_ATTRIBUTE* attrs, int attr_count,
                       uint64_t* handles, int* count);
    int (*get_attribute)(uint64_t handle, CK_ATTRIBUTE* attr);
    int (*destroy_object)(uint64_t handle);

    // Crypto operations
    int (*sign_init)(uint64_t session, CK_MECHANISM* mech, uint64_t key);
    int (*sign)(uint64_t session, uint8_t* data, size_t len,
               uint8_t* sig, size_t* sig_len);
    int (*verify_init)(uint64_t session, CK_MECHANISM* mech, uint64_t key);
    int (*verify)(uint64_t session, uint8_t* data, size_t len,
                 uint8_t* sig, size_t sig_len);

    // Random
    int (*generate_random)(uint8_t* buffer, size_t len);
} pkcs11_backend_t;
```

### Backend Implementations

| Backend | Source | Dependencies | Communication |
|---------|--------|--------------|---------------|
| Embedded | `embedded.c` | libkeychain.so | dlopen/dlsym |
| Unix | `unix.c` | None | go-codec (CBOR/MsgPack) |
| REST | `rest.c` | libcurl | JSON over HTTP |
| gRPC | `grpc.c` | grpc-c, protobuf-c | Protocol Buffers |
| QUIC | `quic.c` | quiche or ngtcp2 | HTTP/3 |

## Handle Management

PKCS#11 uses opaque handles to reference objects. The module maintains a thread-safe handle table that maps PKCS#11 handles to internal object references:

```
+------------------+
| Handle Table     |
+------------------+
| Handle | Object  |
+--------+---------+
| 0x0001 | RSA Key |
| 0x0002 | EC Key  |
| 0x0003 | Cert    |
| ...    | ...     |
+--------+---------+
```

Handle characteristics:
- 64-bit unsigned integers
- Monotonically increasing
- Never reused within a session
- Session-scoped (handles invalidated when session closes)

## Session State Machine

PKCS#11 sessions follow a defined state machine:

```
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
- **R/O Public Session**: Read-only, no login required
- **R/W Public Session**: Read-write, no login required
- **R/O User Session**: Read-only, user login required
- **R/W User Session**: Read-write, user login required
- **R/W SO Session**: Security Officer session for token management

## Threading Model

The module supports multi-threaded access as required by PKCS#11:

```c
// Thread-safe initialization
CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
    CK_C_INITIALIZE_ARGS_PTR args = pInitArgs;

    if (args && args->flags & CKF_OS_LOCKING_OK) {
        // Use OS-provided locking (pthread mutexes)
        g_use_os_locking = true;
    } else if (args && args->CreateMutex) {
        // Use application-provided locking
        g_create_mutex = args->CreateMutex;
        g_destroy_mutex = args->DestroyMutex;
        g_lock_mutex = args->LockMutex;
        g_unlock_mutex = args->UnlockMutex;
    }
}
```

Thread safety guarantees:
- All global state protected by mutex
- Session state protected per-session
- Handle table uses lock-free reads where possible
- Backend calls are serialized per-session

## Memory Management

The module follows PKCS#11 memory conventions:

1. **Caller-allocated buffers**: Most output uses caller-provided buffers
2. **Two-call pattern**: First call with NULL buffer returns required size
3. **No internal allocation exposure**: All allocations freed by module

Example two-call pattern:
```c
// First call: get required size
CK_BYTE_PTR sig = NULL;
CK_ULONG sig_len = 0;
C_Sign(session, data, data_len, NULL, &sig_len);

// Second call: get actual data
sig = malloc(sig_len);
C_Sign(session, data, data_len, sig, &sig_len);
```

## Error Handling

PKCS#11 errors are mapped from go-keychain errors:

| go-keychain Error | PKCS#11 Return |
|-------------------|----------------|
| `ErrKeyNotFound` | `CKR_KEY_HANDLE_INVALID` |
| `ErrInvalidKeyType` | `CKR_KEY_TYPE_INCONSISTENT` |
| `ErrAuthFailed` | `CKR_PIN_INCORRECT` |
| `ErrSessionClosed` | `CKR_SESSION_HANDLE_INVALID` |
| `ErrNotInitialized` | `CKR_CRYPTOKI_NOT_INITIALIZED` |
| `ErrBufferTooSmall` | `CKR_BUFFER_TOO_SMALL` |

## Data Flow

### Key Generation Flow

```
Application                PKCS#11 Module              Backend
    |                           |                         |
    |-- C_GenerateKeyPair ----->|                         |
    |                           |-- generate_keypair ---->|
    |                           |                         |-- go-keychain
    |                           |                         |   GenerateKey()
    |                           |<-- priv, pub handles ---|
    |                           |                         |
    |<-- handles ---------------|                         |
```

### Signing Flow

```
Application                PKCS#11 Module              Backend
    |                           |                         |
    |-- C_SignInit ------------>|                         |
    |                           |-- sign_init ----------->|
    |<-- CKR_OK ----------------|                         |
    |                           |                         |
    |-- C_Sign ---------------->|                         |
    |                           |-- sign ---------------->|
    |                           |                         |-- go-keychain
    |                           |                         |   Sign()
    |                           |<-- signature -----------|
    |<-- signature, len --------|                         |
```

## Unix Socket IPC Protocol

The Unix backend uses a 12-byte binary header followed by go-codec encoded payload:

```
+-------------------------------------------------------------------+
|  0   1   2   3   4   5   6   7   8   9  10  11  12  ...           |
+-------------------------------------------------------------------+
| Op  | Flags | StreamID |  Request ID  |  Payload Length  | ...    |
| (1) |  (1)  |   (2)    |     (4)      |       (4)        | Payload|
+-------------------------------------------------------------------+
```

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| Op | 0 | 1 | Operation code (0x00-0xFF) |
| Flags | 1 | 1 | HAS_FD=0x01, STREAM_START=0x02, STREAM_END=0x04 |
| StreamID | 2 | 2 | Stream identifier (big-endian) |
| RequestID | 4 | 4 | Unique request ID (big-endian) |
| PayloadLen | 8 | 4 | Payload length (big-endian) |
| Payload | 12 | N | go-codec encoded data |

Operation code ranges:
| Range | Category |
|-------|----------|
| 0x00-0x0F | Health/Control |
| 0x10-0x1F | Key Operations |
| 0x20-0x2F | Crypto Operations |
| 0x30-0x3F | Certificate Operations |
| 0xF0-0xFF | Reserved/Debug |
