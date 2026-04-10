# go-xkms Development Roadmap

This document tracks the development progress of go-xkms.

## Completed Features

### Core Backends
- [x] **Software Backend** - File-based key storage with encryption (`pkg/backend/software/`)
- [x] **TPM2 Backend** - Trusted Platform Module 2.0 key storage (`pkg/tpm2/`, `pkg/backend/tpm2/`)
- [x] **PKCS#11 Client Backend** - Connect TO external HSMs via PKCS#11 (`pkg/backend/pkcs11/`)
- [x] **Cloud KMS Backends** - AWS KMS, GCP Cloud KMS, Azure Key Vault (`pkg/backend/awskms/`, `pkg/backend/gcpkms/`, `pkg/backend/azurekv/`)
- [x] **HashiCorp Vault Backend** - Transit engine integration (`pkg/backend/vault/`)
- [x] **Symmetric Encryption KeyProvider** - AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305 (`pkg/keyprovider/symmetric/`)
- [x] **FROST Threshold Signatures** - Multi-party Schnorr signatures (RFC 9591) (`pkg/keyprovider/frost/`)
- [x] **Threshold Cryptography** - Shamir Secret Sharing (`pkg/keyprovider/threshold/`)
- [x] **Quantum-Safe Cryptography** - ML-DSA (Dilithium2), ML-KEM (Kyber768) (`pkg/keyprovider/quantum/`)
- [x] **Hardware Certificate Storage** - X.509 certificate management on hardware (`pkg/storage/hardware/`)

### API Interfaces
- [x] **REST API** - Chi-based HTTP API with RBAC and WebAuthn (`pkg/api/rest/`)
- [x] **gRPC API** - Full gRPC service with protobuf definitions (`pkg/api/grpc/`)
- [x] **QUIC API** - HTTP/3 transport (`pkg/api/quic/`)
- [x] **MCP API** - Model Context Protocol (JSON-RPC) (`pkg/api/mcp/`)
- [x] **Unix Socket IPC** - gRPC over Unix domain sockets (`pkg/api/unix/`)

### PKCS#11 v3.2 Provider Module
- [x] **Core Pure Go** - Module, session state machine, object/handle management, slot/token management, 100+ mechanism types, multi-part crypto operations, error types (`pkg/pkcs11/module/`)
- [x] **CGO Export Layer** - 92+ exported C functions, CK_FUNCTION_LIST, OASIS v3.2 headers (`cmd/pkcs11-module/`)
- [x] **PKCS#11 v3.0 Functions** - 68 v2.x core + 24 v3.0 additions (interface discovery, message-based AEAD, context-specific login, session cancel)
- [x] **PKCS#11 v3.2 Functions** - API surface complete: 16 new v3.2 functions with correct OASIS signatures and input validation; pending hardware backend implementations (currently return CKR_FUNCTION_NOT_SUPPORTED)
- [x] **Post-Quantum Standard Mechanisms** - 39 mechanisms: ML-KEM (0x0f, 0x17), ML-DSA (0x1c-0x2c), SLH-DSA (0x2d-0x3f), HSS/LMS (0x4032-0x4033), XMSS/XMSS^MT (0x4034-0x4037), ECDH key wrap (0x4038-0x4039), CKM_PUB_KEY_FROM_PRIV_KEY (0x403a), TLS 1.2 extended master key (0x56-0x57); vendor-defined backward compatibility mapping retained
- [ ] **KEM Operations** - C_EncapsulateKey, C_DecapsulateKey API defined (`pkg/pkcs11/module/module_kem.go`); pending KEM-capable backend
- [ ] **Authenticated Wrapping** - C_WrapKeyAuthenticated, C_UnwrapKeyAuthenticated with AEAD associated data (`pkg/pkcs11/module/module_authwrap.go`); pending backend
- [ ] **Signature-First Verification** - 9 functions for PQC streaming verification (`pkg/pkcs11/module/module_verifysig.go`); pending PQC backend
- [ ] **Async Operations** - C_AsyncComplete, C_AsyncGetID, C_AsyncJoin identified by function name (`pkg/pkcs11/module/module_async.go`); pending backend
- [x] **Validation Framework** - C_GetSessionValidationFlags returns 0 (no validation) by default; will return CKF_VALIDATION_PROTECTED in certified configurations (`pkg/pkcs11/module/module_validation.go`)
- [x] **Profile Objects** - CKP_EXTENDED_PROVIDER, CKP_AUTHENTICATION_TOKEN, CKP_PUBLIC_CERTIFICATES_TOKEN
- [x] **Embedded Backend** - Direct in-process xkms calls via EmbeddedTransport (`xkey/pkg/pkcs11/service.go`)
- [x] **Unix/IPC Backend** - Socket-based IPC with JSON serialization (`xkey/pkg/pkcs11/ipc_transport.go`)
- [x] **REST Backend** - HTTP/HTTPS via SDK transport (`sdk/go/transport/rest/`)
- [x] **gRPC Backend** - Protocol buffer transport via SDK (`sdk/go/transport/grpc/`)
- [x] **QUIC Backend** - HTTP/3 transport via SDK (`sdk/go/transport/quic/`)
- [x] **PIV Integration** - Full PIV slot discovery, certificate retrieval, and object mapping (`pkg/pkcs11/module/module_piv.go`)
- [x] **Testing** - Unit tests (14k+ lines), integration tests (22 test files), conformance suite, pkcs11-tool compatibility, OpenSSL/SSH interop
- [x] **Documentation** - Architecture, configuration, usage, mechanisms, API reference, security (`docs/pkcs11/module/`)

### Authentication & FIDO2
- [x] **WebAuthn** - Server-side WebAuthn/FIDO2 registration and authentication (`pkg/webauthn/`)
- [x] **FIDO2 Client** - CTAP2 client library with device discovery, enrollment, authentication, and hmac-secret (`pkg/fido2/`)
- [x] **CTAP2 Authenticator** - Full virtual authenticator with UHID interface (`xkey/pkg/authenticator/`)
- [x] **Attestation Verification** - Attestation statement verification (`pkg/attestation/`)

### Key Management
- [x] **Key Versioning** - Version lifecycle management across all APIs (`pkg/versioning/`)
- [x] **Key Migration** - Cross-backend key migration (`pkg/migration/`)

### Security Infrastructure
- [x] **Barrier Encryption** - AES-256-GCM data-at-rest encryption with seal/unseal lifecycle (`pkg/server/`)
- [x] **Shamir Secret Sharing** - Threshold-based barrier key management with quorum unsealing
- [x] **Recovery Keys** - Disaster recovery with root token generation
- [x] **Bootstrap Trust** - DANE/TLSA, SPKI pinning, Noise protocol, direct HTTPS (go-truststrap)
- [x] **Init System** - Ceremony service with threshold initialization, credential strategies, RBAC roles (`pkg/init/`)

### Binaries & SDK
- [x] **xkmsd** - Server daemon with config reload, signal handling (`cmd/xkmsd/`)
- [x] **xkmsctl** - CLI with admin, key, cert, fido2, frost, migrate, seal, tls, user, init, credential commands (`cmd/xkmsctl/`)
- [x] **xkey** - Virtual FIDO2/WebAuthn authenticator with OATH, PIV, SSH, OIDC, LUKS support (`xkey/cmd/xkey/`)
  - Full CTAP2 authenticator implementation with Linux UHID virtual USB HID interface
  - Barrier-encrypted data storage, GUI with Fyne
- [x] **Go SDK** - Multi-protocol client SDK (REST, gRPC, QUIC, MCP, Unix, USB) (`sdk/go/`)

## Environment Variables (PKCS#11 Module)

| Variable | Default | Description |
|----------|---------|-------------|
| `XKMS_PKCS11_MODE` | `embedded` | Backend: embedded, unix, rest, grpc, quic |
| `XKMS_PKCS11_BACKEND` | `software` | go-xkms backend: software, tpm2, pkcs11, awskms |
| `XKMS_SOCKET_PATH` | `/var/run/xkms/xkms.sock` | Unix socket path |
| `XKMS_REST_ENDPOINT` | `http://localhost:8080` | REST API endpoint |
| `XKMS_GRPC_ENDPOINT` | `localhost:50051` | gRPC endpoint |

## Build Targets (PKCS#11 Module)

```makefile
# Build PKCS#11 module shared library
pkcs11-module:
	CGO_ENABLED=1 go build -buildvcs=false \
		-tags="pkcs11_module" \
		-buildmode=c-shared \
		-o build/lib/libxkms_pkcs11.so \
		./cmd/cgo/pkcs11_module.go

# Test with pkcs11-tool
test-pkcs11-module: pkcs11-module
	pkcs11-tool --module build/lib/libxkms_pkcs11.so --show-info
	pkcs11-tool --module build/lib/libxkms_pkcs11.so --list-slots
```

## References

- [PKCS#11 v3.2 Specification](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html)
- [PKCS#11 Base Specification v3.0](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html)
- [PKCS#11 Profiles v3.0](https://docs.oasis-open.org/pkcs11/pkcs11-profiles/v3.0/pkcs11-profiles-v3.0.html)
- [Unix IPC Documentation](api/unix/README.md)
- [PKCS#11 Module Documentation](pkcs11/module/README.md)
