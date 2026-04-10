# go-xkms Project Overview

## Purpose
Enterprise-grade Key Management System (KMS) library for Go. Primarily serves as the KMS library for the go-trusted-platform project. Provides modular cryptographic backend support with pluggable storage, multiple API protocols, and hardware security module integration.

## Version
0.2.3-alpha (Go 1.26.0)

## Module
`github.com/jeremyhahn/go-xkms`

## Architecture

### Two-Tier Key Management
- **Backends** (full-service, `pkg/backend/`): software, tpm2, pkcs11, awskms, gcpkms, azurekv, vault, phone
- **KeyProviders** (partial, `pkg/keyprovider/`): pkcs8, symmetric, quantum, frost, threshold

### API Protocols (all in `pkg/api/`)
- REST (go-chi)
- gRPC (with protobuf)
- QUIC (HTTP/3, requires TLS 1.3)
- MCP (Model Context Protocol)
- Unix (gRPC over UDS)

### CLI & Server Binaries (`cmd/`)
- `xkmsd` — unified server daemon (all protocols)
- `xkmsctl` — CLI client (pure Go, no CGO)
- `cgo` — shared library (libxkms.so) via CGO
- `pkcs11-module` — PKCS#11 shared library (libxkms_pkcs11.so)

### xkey Subdirectory (`xkey/`)
Separate Go module for the desktop/mobile application with:
- FIDO2/CTAP2 authenticator (`xkey/pkg/authenticator/`)
- Wails GUI (`xkey/pkg/gui/`)
- Browser extension IPC (`xkey/pkg/ipc/`)
- OATH, OIDC, Static passwords, PIV certs
- Barrier encryption (AES-256-GCM per-tenant DEK)

### Go SDK (`sdk/go/`)
Separate Go module providing client SDK with transport abstraction (REST, gRPC, QUIC, MCP, Unix, Embedded).

### Key Packages
| Package | Purpose |
|---------|---------|
| `pkg/xkms/` | Core XKMSService facade |
| `pkg/server/` | Server wiring, backend factories |
| `pkg/seal/` | Barrier encryption, tenant isolation |
| `pkg/ca/` | Certificate Authority operations |
| `pkg/init/` | Ceremony/initialization service |
| `pkg/config/` | Configuration management |
| `pkg/storage/` | Memory, file, hardware storage |
| `pkg/crypto/` | AEAD, ECDH, ECIES, X25519, wrapping, rand |
| `pkg/encoding/` | JWK, JWT, JWE, PEM, PKCS8 |
| `pkg/quantum/` | Post-quantum (ML-DSA, ML-KEM via circl) |
| `pkg/threshold/` | Shamir secret sharing |
| `pkg/webauthn/` | WebAuthn/passkey service |
| `pkg/fido2/` | FIDO2 client library |
| `pkg/attestation/` | Key attestation |
| `pkg/certstore/` | Certificate storage |
| `pkg/metrics/` | Prometheus metrics |
| `pkg/health/` | Health check service |
| `pkg/user/` | User management, RBAC |
| `pkg/custodian/` | Custodian group management |
| `pkg/bootstrap/` | DANE/TLSA bootstrap |

### Build Tags
Backends are conditionally compiled via build tags:
`pkcs8`, `pkcs11`, `awskms`, `gcpkms`, `azurekv`, `vault`, `frost`, `tpm_simulator`, `fido2`, `webauthn`, `integration`

### Docker Infrastructure
- `Dockerfile.builder` — CGO build image
- `Dockerfile.server` — unified xkmsd
- `Dockerfile.rest`, `.grpc`, `.quic`, `.mcp` — protocol-specific
- `Dockerfile.cli` — xkmsctl
- `.devcontainer/` — dev environment with all deps
- `docker-compose.emulators.yml` — LocalStack, Azure emulator
- Each `test/integration/<pkg>/` has its own `docker-compose.yml`
