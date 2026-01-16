# Implementation Checklist

This document tracks the implementation status of the PKCS#11 v3.0 Provider Module.

## Prerequisites

### Unix Socket Architecture (go-codec Based)

Required before Phase 4 (Unix backend) can be implemented.

#### Service Layer
- [ ] Create `pkg/keychain/service_interface.go` - Clean service interface
- [ ] Implement `pkg/keychain/service.go` - Default service implementation

#### Protocol and Types (pkg/api/unix/)
- [ ] `protocol.go` - Operation codes, status codes, codec selection
- [ ] `frame.go` - 12-byte header struct, read/write frame functions
- [ ] `types.go` - Request/response types for all operations
- [ ] `errors.go` - Typed error definitions

#### Server Implementation
- [ ] `server.go` - Main IPC server with handler registration
- [ ] `credentials.go` - SO_PEERCRED extraction and validation
- [ ] `fdpass.go` - SCM_RIGHTS file descriptor passing
- [ ] `handlers.go` - Handler implementations for key/crypto operations

#### Client Implementation
- [ ] `client.go` - IPC client with Call/Stream methods
- [ ] `options.go` - Client options (codec, timeout, buffer sizes)

#### Testing and Migration
- [ ] Unit tests for all components
- [ ] Integration tests for go-codec protocol
- [ ] Integration tests for SO_PEERCRED/SCM_RIGHTS
- [ ] Benchmark tests (old vs new performance)
- [ ] Update existing Unix socket clients
- [ ] Documentation at `docs/api/unix/`

---

## PKCS#11 Module Implementation

### Phase 1: C API Foundation (2 weeks)

#### CGO Exports (cmd/cgo/)
- [ ] `main.go` - Main CGO exports file
- [ ] `keystore.go` - KeyStore C API wrappers
- [ ] `types.go` - C type conversions

#### C API Functions
- [ ] `keychain_init()` - Initialize library
- [ ] `keychain_cleanup()` - Cleanup resources
- [ ] `keychain_generate_rsa()` - Generate RSA key pair
- [ ] `keychain_generate_ecdsa()` - Generate ECDSA key pair
- [ ] `keychain_generate_ed25519()` - Generate Ed25519 key pair
- [ ] `keychain_get_key()` - Retrieve existing key
- [ ] `keychain_delete_key()` - Delete key
- [ ] `keychain_list_keys()` - List all keys
- [ ] `keychain_free_key_list()` - Free key list
- [ ] `keychain_sign()` - Sign data
- [ ] `keychain_free_signature()` - Free signature
- [ ] `keychain_verify()` - Verify signature
- [ ] `keychain_get_public_key()` - Export public key
- [ ] `keychain_free_public_key()` - Free public key
- [ ] `keychain_generate_random()` - Generate random bytes
- [ ] `keychain_error_string()` - Get error message

#### Build System
- [ ] Update Makefile `lib-capi` target
- [ ] Generate `keychain.h` header
- [ ] Test libkeychain.so loading

---

### Phase 2: PKCS#11 v3.0 Core (3-4 weeks)

#### Headers and Setup
- [ ] Download PKCS#11 v3.0 headers from OASIS
- [ ] Create `pkg/api/pkcs11/include/` directory
- [ ] Implement `CK_FUNCTION_LIST` structure
- [ ] Implement `CK_INTERFACE` support (v3.0)

#### Baseline Provider Functions (Section 3.3.2)

##### Initialization
- [ ] `C_GetFunctionList` - Get function pointer list
- [ ] `C_GetInterfaceList` - Get interface list (v3.0)
- [ ] `C_GetInterface` - Get specific interface (v3.0)
- [ ] `C_Initialize` - Initialize library
- [ ] `C_Finalize` - Cleanup library
- [ ] `C_GetInfo` - Get library info

##### Slot/Token Management
- [ ] `C_GetSlotList` - Get slot list
- [ ] `C_GetSlotInfo` - Get slot information
- [ ] `C_GetTokenInfo` - Get token information

##### Session Management
- [ ] `C_OpenSession` - Open session
- [ ] `C_CloseSession` - Close session
- [ ] `C_GetSessionInfo` - Get session info

##### Object Management
- [ ] `C_FindObjectsInit` - Start object search
- [ ] `C_FindObjects` - Continue object search
- [ ] `C_FindObjectsFinal` - End object search
- [ ] `C_GetAttributeValue` - Get object attributes

#### Extended Provider Functions (Section 3.5.2)

##### Mechanism Functions
- [ ] `C_GetMechanismList` - List mechanisms
- [ ] `C_GetMechanismInfo` - Get mechanism info

##### Authentication
- [ ] `C_Login` - User login
- [ ] `C_LoginUser` - Extended login (v3.0)
- [ ] `C_Logout` - User logout

#### Authentication Token Functions (Section 3.6.2)

##### Signing
- [ ] `C_SignInit` - Initialize signing
- [ ] `C_Sign` - Single-part signing
- [ ] `C_SignUpdate` - Multi-part signing
- [ ] `C_SignFinal` - Finalize signing

#### Additional Functions

##### Key Generation
- [ ] `C_GenerateKeyPair` - Generate asymmetric key pair
- [ ] `C_GenerateKey` - Generate symmetric key

##### Verification
- [ ] `C_VerifyInit` - Initialize verification
- [ ] `C_Verify` - Single-part verification

##### Encryption
- [ ] `C_EncryptInit` - Initialize encryption
- [ ] `C_Encrypt` - Single-part encryption
- [ ] `C_DecryptInit` - Initialize decryption
- [ ] `C_Decrypt` - Single-part decryption

##### Random
- [ ] `C_GenerateRandom` - Generate random data

##### Object Creation
- [ ] `C_CreateObject` - Create object
- [ ] `C_DestroyObject` - Delete object

#### Profile Objects (v3.0)
- [ ] `CKO_PROFILE` with `CKP_EXTENDED_PROVIDER`
- [ ] `CKO_PROFILE` with `CKP_AUTHENTICATION_TOKEN`
- [ ] `CKO_PROFILE` with `CKP_PUBLIC_CERTIFICATES_TOKEN`

#### Module Infrastructure
- [ ] Session state machine
- [ ] Handle table implementation
- [ ] Thread safety (mutexes)
- [ ] Error code mapping
- [ ] Configuration loading

---

### Phase 3: Embedded Backend (1-2 weeks)

- [ ] Implement `pkg/api/pkcs11/src/backends/embedded.c`
- [ ] Dynamic loading with `dlopen()`/`dlsym()`
- [ ] Handle mapping (PKCS#11 <-> libkeychain)
- [ ] Error translation
- [ ] Unit tests
- [ ] Integration tests with pkcs11-tool

---

### Phase 4: Unix Backend (1-2 weeks)

**Note:** Requires Unix Socket Architecture prerequisite to be complete.

- [ ] Implement `pkg/api/pkcs11/src/backends/unix.c`
- [ ] Socket connection management
- [ ] go-codec serialization (CBOR/MsgPack)
- [ ] 12-byte header protocol
- [ ] Request/response handling
- [ ] Unit tests
- [ ] Integration tests

---

### Phase 5: REST Backend (1-2 weeks)

- [ ] Implement `pkg/api/pkcs11/src/backends/rest.c`
- [ ] libcurl HTTP client
- [ ] JSON serialization
- [ ] TLS configuration
- [ ] Error handling
- [ ] Unit tests
- [ ] Integration tests

---

### Phase 6: gRPC Backend (2 weeks)

- [ ] Implement `pkg/api/pkcs11/src/backends/grpc.c`
- [ ] grpc-c integration
- [ ] Proto file generation
- [ ] Protobuf serialization
- [ ] TLS configuration
- [ ] Unit tests
- [ ] Integration tests

---

### Phase 7: QUIC Backend (2 weeks)

- [ ] Implement `pkg/api/pkcs11/src/backends/quic.c`
- [ ] quiche or ngtcp2 integration
- [ ] HTTP/3 client
- [ ] 0-RTT support
- [ ] TLS configuration
- [ ] Unit tests
- [ ] Integration tests

---

### Phase 8: Testing (2-3 weeks)

#### Compatibility Testing
- [ ] pkcs11-tool basic operations
- [ ] pkcs11-tool key generation (RSA, EC, Ed25519)
- [ ] pkcs11-tool signing operations
- [ ] OpenSSL pkcs11 engine
- [ ] p11-kit integration
- [ ] NSS modutil integration
- [ ] SSH PKCS#11 provider

#### Backend Testing
- [ ] Embedded backend stress tests
- [ ] Unix backend stress tests
- [ ] REST backend stress tests
- [ ] gRPC backend stress tests
- [ ] QUIC backend stress tests

#### Quality Assurance
- [ ] Valgrind memory leak check
- [ ] AddressSanitizer testing
- [ ] Thread sanitizer testing
- [ ] Concurrent session tests
- [ ] Error handling tests
- [ ] Edge case coverage

---

### Phase 9: Production (2 weeks)

#### Security
- [ ] Security audit
- [ ] Penetration testing
- [ ] Code review

#### Performance
- [ ] Benchmark suite
- [ ] Latency optimization
- [ ] Memory optimization
- [ ] Connection pooling tuning

#### Documentation
- [ ] API documentation complete
- [ ] Configuration guide complete
- [ ] Security guide complete
- [ ] Troubleshooting guide

#### Packaging
- [ ] DEB package
- [ ] RPM package
- [ ] Homebrew formula
- [ ] Docker image

#### Examples
- [ ] Basic usage example
- [ ] OpenSSL integration example
- [ ] SSH integration example
- [ ] TLS server example

---

## Effort Summary

| Phase | Effort | Status |
|-------|--------|--------|
| Prerequisite: Unix Socket | 2-3 weeks | Not Started |
| Phase 1: C API | 2 weeks | Not Started |
| Phase 2: PKCS#11 Core | 3-4 weeks | Not Started |
| Phase 3: Embedded Backend | 1-2 weeks | Not Started |
| Phase 4: Unix Backend | 1-2 weeks | Blocked |
| Phase 5: REST Backend | 1-2 weeks | Not Started |
| Phase 6: gRPC Backend | 2 weeks | Not Started |
| Phase 7: QUIC Backend | 2 weeks | Not Started |
| Phase 8: Testing | 2-3 weeks | Not Started |
| Phase 9: Production | 2 weeks | Not Started |
| **Total** | **18-23 weeks** | |

## Milestones

| Milestone | Target | Status |
|-----------|--------|--------|
| First working PKCS#11 module (Embedded) | Phases 1-3 | Not Started |
| Local IPC support (Unix) | Phase 4 | Blocked on prerequisite |
| Full remote support (REST/gRPC/QUIC) | Phases 5-7 | Not Started |
| Production ready | Phase 9 | Not Started |
