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
- [x] **CGO Export Layer** - 104 exported C functions, CK_FUNCTION_LIST, OASIS v3.2 headers (`cmd/pkcs11-module/`)
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
- [x] **Testing** - Unit tests (~58k lines across `pkg/pkcs11/module/*_test.go`), integration tests (24 files in `test/integration/pkcs11/module/`), conformance suite, pkcs11-tool compatibility (`make test-pkcs11-compat`), OpenSSL/SSH interop
- [x] **Documentation** - Architecture, configuration, usage, mechanisms, API reference, security (`docs/pkcs11/module/`)

### Authentication & FIDO2
- [x] **WebAuthn** - Server-side WebAuthn/FIDO2 registration and authentication (`pkg/webauthn/`)
- [x] **FIDO2 Client** - CTAP2 client library with device discovery, enrollment, authentication, and hmac-secret (`pkg/fido2/`)
- [x] **CTAP2 Authenticator** - Full virtual authenticator with UHID interface (`xkey/pkg/authenticator/`)
- [x] **Attestation Verification** - Attestation statement verification (`pkg/attestation/`)

### Key Management
- [x] **Key Rotation** - Generate a replacement key of the same type, retiring the old one (`pkg/xkms/servicer_key.go`, `xkmsctl key rotate`)
- [x] **Key Migration** - Cross-backend key migration (`pkg/migration/`)
- [ ] **Key Versioning** - Version lifecycle (list/enable/disable individual and all versions). The RPCs are declared in `pkg/api/grpc/proto/xkmsv1/xkms.proto` and the Go SDK lists them, but no server implements them; rotation is the only version operation that currently ships.

### Security Infrastructure
- [x] **Barrier Encryption** - AES-256-GCM data-at-rest encryption with seal/unseal lifecycle. The barrier implementation itself is go-qrdb's `StorageBarrier`, consumed through `go-qrdb/sdk/go`; xkms composes it and owns the hardware/cloud seal strategies. Node-barrier mode adopts the embedded node's barrier (`pkg/server/qrdb_node.go:34-38`, `pkg/server/node_seal.go`); own-barrier mode builds one over the store for non-qrdb storage (`pkg/server/server.go:1366`, `pkg/server/seal_strategies.go`). See [seal/README.md](seal/README.md).
- [x] **Shamir Secret Sharing** - Threshold-based barrier key management with quorum unsealing (owned by go-qrdb's barrier; see [custodian/README.md](custodian/README.md) for the custodian roster that names the share holders)
- [x] **Recovery Keys** - Disaster recovery with root token generation, exposed on the barrier surface as `BarrierGenerateRecoveryKeys` / `BarrierRecoverWithKeys` / `BarrierDeleteRecoveryKeys` / `BarrierHasRecoveryKeys` / `BarrierGenerateRootToken` (`pkg/api/transport/client.go:193-205`)
- [x] **Bootstrap Trust** - Canonical mode dispatch in `pkg/trust/bootstrap`: `auto`, `dane`, `noise`, `spki`, `direct`, and `tofu` (`pkg/trust/bootstrap/bootstrap.go:63-92`), composing `github.com/jeremyhahn/go-truststrap` (`go.mod:30`). Re-exported to SDK consumers via `sdk/go/bootstrap`. See [trust/bootstrap.md](trust/bootstrap.md).
- [x] **Init System** - Ceremony service with threshold initialization, credential strategies, RBAC roles (`pkg/init/`)

### Binaries & SDK
- [x] **xkmsd** - Server daemon with config reload, signal handling (`cmd/xkmsd/`)
- [x] **xkmsctl** - CLI (`cmd/xkmsctl/`). Top-level commands registered on the root:
  `admin`, `algorithms`, `audit`, `auth`, `backends`, `barrier`, `bootstrap`, `ca`,
  `can-seal`, `ceremony`, `cert`, `cluster`, `credential`, `custodian`, `fido2`,
  `frost`, `init`, `key`, `migrate`, `password`, `pin`, `piv`, `pkcs11`, `platform`,
  `policy`, `seal`, `share`, `ssh`, `status`, `tenant`, `tls`, `unseal`, `user`,
  `version`
- [x] **xkey** - Virtual FIDO2/WebAuthn authenticator with OATH, PIV, SSH, OIDC, LUKS support (`xkey/cmd/xkey/`)
  - Full CTAP2 authenticator implementation with Linux UHID virtual USB HID interface
  - Barrier-encrypted data storage; the desktop GUI is built on Wails v2
    (`xkey/go.mod:39`, `xkey/frontend/`), with `fyne.io/systray` used only for
    the system-tray icon (`xkey/pkg/gui/systray.go:19`)
- [x] **Go SDK** - Multi-protocol client SDK. Transports under `sdk/go/transport/`: `rest`, `grpc`, `quic`, `mcp`, `unix`, `usb`, and `embedded`

## Environment Variables (PKCS#11 Module)

The module reads its configuration from `/etc/xkms/pkcs11.conf`
(`DefaultConfigPath`) and overrides it from the environment. The variable names
and defaults below come from `pkg/pkcs11/module/config.go:32-66`.

| Variable | Default | Description |
|----------|---------|-------------|
| `XKMS_PKCS11_TARGET` | `unix:///var/run/xkms/xkms.sock` | gRPC target: `unix:///path`, `dns:///host:port`, or `host:port` |
| `XKMS_PKCS11_DEFAULT_BACKEND` | `software` | go-xkms backend: software, tpm2, pkcs11 |
| `XKMS_PKCS11_TIMEOUT` | `30s` | Timeout for gRPC operations |
| `XKMS_PKCS11_TLS_ENABLED` | unset | Enable TLS on the gRPC connection |
| `XKMS_PKCS11_TLS_CERT` / `_TLS_KEY` / `_TLS_CA` | unset | Client certificate, key, and CA for mTLS |
| `XKMS_PKCS11_ALLOW_INSECURE_TRANSPORT` | `false` | Opt out of the mandatory-TLS guard for non-`unix://` targets; dev/test only |
| `XKMS_PKCS11_SO_PIN` / `_USER_PIN` / `_TOKEN_LABEL` / `_AUTO_INIT_TOKEN` | unset | Token auto-initialization parameters |
| `XKMS_PKCS11_STORAGE_TYPE` / `_STORAGE_PATH` | unset | Object storage (`memory` or `file`) and its path |
| `XKMS_PKCS11_PIV_BACKENDS` | unset | PIV backends to expose as slots |

There is no `XKMS_PKCS11_MODE`, `XKMS_PKCS11_BACKEND`, `XKMS_REST_ENDPOINT`, or
`XKMS_GRPC_ENDPOINT` variable; the transport is selected by the `XKMS_PKCS11_TARGET`
scheme. `XKMS_SOCKET_PATH` exists but belongs to the daemon configuration loader
(`pkg/config/config.go:1131`), not to the PKCS#11 module.

## Default Ports

`xkmsd` binds whatever the YAML configuration names -- it defines no port flags
and applies no port defaults of its own (`cmd/xkmsd/main.go:67-74`,
`pkg/config/config.go:1026-1049`). The shipped configurations in `configs/` are
therefore the effective defaults, and they differ from the fallback values the
API server packages substitute when they are embedded as libraries with a zero
port.

| Protocol | Shipped `configs/*.yaml` | Library fallback | SDK client default |
|----------|--------------------------|------------------|--------------------|
| REST | `rest_port: 8443` | `8443` (`pkg/api/rest/server.go:311`) | `http://localhost:8443` (`sdk/go/options.go:30`) |
| gRPC | `grpc_port: 9443` | none | `localhost:9443` (`sdk/go/options.go:31`) |
| QUIC | `quic_port: 8444` | `localhost:8444` (`pkg/api/quic/server.go:119`) | `localhost:8444` (`sdk/go/options.go:32`) |
| MCP | `mcp_port: 8445` | `localhost:9444` (`pkg/api/mcp/server.go:178`) | `localhost:9444` (`sdk/go/options.go:33`) |
| Noise | `noise_port: 8447` (`configs/xkmsd-local.yaml:10`) | `8445` (`pkg/trust/bootstrap/bootstrap.go:98`) | `8445` (`sdk/go/bootstrap/bootstrap.go:68`) |
| Metrics | `port: 9090` | none | n/a |

The MCP and Noise rows are the two live disagreements: the shipped daemon
configurations bind MCP on 8445, which is the same number `DefaultNoisePort`
hard-codes, while the MCP library and the SDK client both fall back to 9444.
An `xkmsd` started from `configs/xkmsd.yaml` will not be reachable at the SDK's
default MCP address, and `configs/xkmsd-local.yaml` moves Noise to 8447 to keep
it off the MCP port.

## Build Targets (PKCS#11 Module)

The real targets live in the root `Makefile`. `build-pkcs11-module` builds the
shared library from the `./cmd/pkcs11-module` package with no build tags
(`Makefile:509-517`); `test-pkcs11-module` runs the Go unit tests
(`Makefile:519-524`); `test-pkcs11-compat` is the one that shells out to
`pkcs11-tool` (`Makefile:551-563`).

```makefile
# Build PKCS#11 module shared library -> build/lib/libxkms_pkcs11.so
build-pkcs11-module:
	CGO_ENABLED=1 go build -buildmode=c-shared \
		-o $(LIB_DIR)/libxkms_pkcs11.so \
		./cmd/pkcs11-module

# Run the module's Go unit tests
test-pkcs11-module:
	go test ./pkg/pkcs11/module/...

# Exercise the built .so with pkcs11-tool (skipped when opensc is absent)
test-pkcs11-compat: build-pkcs11-module
	pkcs11-tool --module $(LIB_DIR)/libxkms_pkcs11.so --list-slots
	pkcs11-tool --module $(LIB_DIR)/libxkms_pkcs11.so --list-mechanisms
```

## References

- [PKCS#11 v3.2 Specification](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html)
- [PKCS#11 Base Specification v3.0](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html)
- [PKCS#11 Profiles v3.0](https://docs.oasis-open.org/pkcs11/pkcs11-profiles/v3.0/pkcs11-profiles-v3.0.html)
- [PKCS#11 Module Documentation](pkcs11/module/README.md)
- Unix IPC: the gRPC-over-Unix-socket server is `pkg/api/unix/grpc_server.go`; it has no
  standalone document yet. The socket configuration keys are covered in
  [configs/README.md](../configs/README.md), and the ACME variant is documented in
  [acme/protocols/unix-socket.md](acme/protocols/unix-socket.md).
