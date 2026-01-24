# go-keychain Development Roadmap

This document tracks the development progress of go-keychain.

## Completed Features

- [x] **FROST Threshold Signatures** - Multi-party Schnorr signatures
- [x] **CanoKey Integration** - Hardware FIDO2/PIV token support
- [x] **Hardware Certificate Storage** - X.509 certificate management on hardware
- [x] **PKCS#11 Client Backend** - Connect TO external HSMs via PKCS#11
- [x] **TPM2 Backend** - Trusted Platform Module 2.0 key storage
- [x] **Software Backend** - File-based key storage with encryption
- [x] **Cloud KMS Backends** - AWS KMS, GCP Cloud KMS, Azure Key Vault
- [x] **Unix Socket IPC** - Direct go-codec based IPC (`pkg/api/unix/`)

## Planned Features

### PKCS#11 v3.0 Provider Module (14-18 weeks)

Implementation approach: Go logic with CGO exports (namecoin/pkcs11mod pattern)

#### Phase 1: PKCS#11 Core - Pure Go (3-4 weeks)
- [ ] `pkg/api/pkcs11/module/module.go` - Main module struct
- [ ] `pkg/api/pkcs11/module/session.go` - Session state management
- [ ] `pkg/api/pkcs11/module/objects.go` - Object/handle management
- [ ] `pkg/api/pkcs11/module/slots.go` - Slot/token management
- [ ] `pkg/api/pkcs11/module/mechanisms.go` - Mechanism registry
- [ ] `pkg/api/pkcs11/module/crypto.go` - Crypto operation wrappers
- [ ] `pkg/api/pkcs11/module/errors.go` - PKCS#11 error types (CKR_*)

#### Phase 2: CGO Export Layer (2 weeks)
- [ ] `pkg/api/pkcs11/exports/exports.go` - `//export` CGO functions
- [ ] `pkg/api/pkcs11/exports/types.go` - C type conversions
- [ ] `pkg/api/pkcs11/exports/function_list.go` - CK_FUNCTION_LIST
- [ ] `pkg/api/pkcs11/include/pkcs11.h` - OASIS v3.0 headers
- [ ] `cmd/cgo/pkcs11_module.go` - Build entry point

#### Phase 3: PKCS#11 v3.0 Functions
**Baseline Provider Functions:**
- [ ] `C_GetFunctionList`, `C_GetInterfaceList`, `C_GetInterface`
- [ ] `C_Initialize`, `C_Finalize`, `C_GetInfo`
- [ ] `C_GetSlotList`, `C_GetSlotInfo`, `C_GetTokenInfo`
- [ ] `C_OpenSession`, `C_CloseSession`, `C_GetSessionInfo`
- [ ] `C_FindObjectsInit`, `C_FindObjects`, `C_FindObjectsFinal`
- [ ] `C_GetAttributeValue`

**Extended Provider Functions:**
- [ ] `C_GetMechanismList`, `C_GetMechanismInfo`
- [ ] `C_Login`, `C_LoginUser`, `C_Logout`

**Authentication Token Functions:**
- [ ] `C_SignInit`, `C_Sign`, `C_SignUpdate`, `C_SignFinal`

**Additional Functions:**
- [ ] `C_GenerateKeyPair`, `C_GenerateKey`
- [ ] `C_VerifyInit`, `C_Verify`
- [ ] `C_EncryptInit`, `C_Encrypt`, `C_DecryptInit`, `C_Decrypt`
- [ ] `C_GenerateRandom`
- [ ] `C_CreateObject`, `C_DestroyObject`

**Profile Objects:**
- [ ] `CKO_PROFILE` with `CKP_EXTENDED_PROVIDER`
- [ ] `CKO_PROFILE` with `CKP_AUTHENTICATION_TOKEN`
- [ ] `CKO_PROFILE` with `CKP_PUBLIC_CERTIFICATES_TOKEN`

#### Phase 4: Embedded Backend (1-2 weeks)
- [ ] `pkg/api/pkcs11/module/embedded.go`
- [ ] Direct in-process go-keychain service calls
- [ ] Handle mapping between PKCS#11 and KeychainService

#### Phase 5: Unix Backend (1-2 weeks)
- [ ] `pkg/api/pkcs11/module/remote_unix.go`
- [ ] Use `pkg/api/unix` client for direct IPC
- [ ] go-codec integration (CBOR default)

#### Phase 6: REST Backend (1-2 weeks)
- [ ] `pkg/api/pkcs11/module/remote_rest.go`
- [ ] HTTP client using net/http
- [ ] JSON serialization

#### Phase 7: gRPC Backend (1-2 weeks)
- [ ] `pkg/api/pkcs11/module/remote_grpc.go`
- [ ] gRPC-Go client integration
- [ ] Use existing keychain.proto definitions

#### Phase 8: QUIC Backend (1-2 weeks)
- [ ] `pkg/api/pkcs11/module/remote_quic.go`
- [ ] quic-go HTTP/3 client

#### Phase 9: Testing (2-3 weeks)
- [ ] pkcs11-tool compatibility tests
- [ ] OpenSSL pkcs11 engine tests
- [ ] All backend stress tests
- [ ] Go race detector tests (`go test -race`)
- [ ] Concurrent session tests
- [ ] Memory profiling with pprof

#### Phase 10: Production (2 weeks)
- [ ] Security audit
- [ ] Performance optimization
- [ ] Documentation completion
- [ ] Packaging (RPM, DEB)
- [ ] Example applications

## Environment Variables (PKCS#11 Module)

| Variable | Default | Description |
|----------|---------|-------------|
| `KEYCHAIN_PKCS11_MODE` | `embedded` | Backend: embedded, unix, rest, grpc, quic |
| `KEYCHAIN_PKCS11_BACKEND` | `software` | go-keychain backend: software, tpm2, pkcs11, awskms |
| `KEYCHAIN_SOCKET_PATH` | `/var/run/keychain/keychain.sock` | Unix socket path |
| `KEYCHAIN_REST_ENDPOINT` | `http://localhost:8080` | REST API endpoint |
| `KEYCHAIN_GRPC_ENDPOINT` | `localhost:50051` | gRPC endpoint |

## Build Targets (PKCS#11 Module)

```makefile
# Build PKCS#11 module shared library
pkcs11-module:
	CGO_ENABLED=1 go build -buildvcs=false \
		-tags="pkcs11_module" \
		-buildmode=c-shared \
		-o build/lib/libkeychain_pkcs11.so \
		./cmd/cgo/pkcs11_module.go

# Test with pkcs11-tool
test-pkcs11-module: pkcs11-module
	pkcs11-tool --module build/lib/libkeychain_pkcs11.so --show-info
	pkcs11-tool --module build/lib/libkeychain_pkcs11.so --list-slots
```

## References

- [PKCS#11 Base Specification v3.0](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html)
- [PKCS#11 Profiles v3.0](https://docs.oasis-open.org/pkcs11/pkcs11-profiles/v3.0/pkcs11-profiles-v3.0.html)
- [Unix IPC Documentation](api/unix/README.md)
- [PKCS#11 Module Documentation](pkcs11/module/README.md)
