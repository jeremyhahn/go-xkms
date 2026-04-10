# Codebase Structure

```
go-xkms/
├── cmd/                          # CLI and server entry points
│   ├── xkmsd/                    # Unified server daemon
│   ├── xkmsctl/                  # CLI client (pure Go)
│   ├── cgo/                      # Shared library (libxkms.so)
│   └── pkcs11-module/            # PKCS#11 shared library
├── pkg/                          # Core library packages
│   ├── xkms/                     # Core XKMSService facade
│   ├── server/                   # Server wiring, backend factories
│   ├── api/                      # API protocol implementations
│   │   ├── rest/                 #   REST (go-chi)
│   │   ├── grpc/                 #   gRPC + protobuf
│   │   ├── quic/                 #   QUIC/HTTP3
│   │   ├── mcp/                  #   Model Context Protocol
│   │   └── unix/                 #   gRPC over Unix domain socket
│   ├── backend/                  # Full-service crypto backends
│   │   ├── software/             #   Software keys
│   │   ├── tpm2/                 #   TPM 2.0
│   │   ├── pkcs11/               #   PKCS#11/HSM
│   │   ├── awskms/               #   AWS KMS
│   │   ├── gcpkms/               #   GCP KMS
│   │   ├── azurekv/              #   Azure Key Vault
│   │   ├── vault/                #   HashiCorp Vault
│   │   └── phone/                #   Phone-based keys
│   ├── keyprovider/              # Partial key providers
│   │   ├── pkcs8/                #   PKCS#8 file keys
│   │   ├── symmetric/            #   Symmetric encryption
│   │   ├── quantum/              #   Post-quantum (ML-DSA, ML-KEM)
│   │   ├── frost/                #   FROST threshold sigs
│   │   └── threshold/            #   Threshold crypto
│   ├── seal/                     # Barrier encryption, tenant isolation
│   ├── ca/                       # Certificate Authority
│   ├── init/                     # Initialization ceremony
│   ├── config/                   # Configuration
│   ├── storage/                  # Storage layer (memory, file, hardware)
│   ├── crypto/                   # Crypto primitives
│   │   ├── aead/                 #   AEAD (AES-GCM, ChaCha20)
│   │   ├── ecdh/                 #   ECDH key agreement
│   │   ├── ecies/                #   ECIES encryption
│   │   ├── x25519/               #   X25519 key agreement
│   │   ├── chacha20poly1305/     #   ChaCha20-Poly1305
│   │   ├── wrapping/             #   Key wrapping
│   │   └── rand/                 #   Random number generation
│   ├── encoding/                 # Encoding formats
│   │   ├── jwk/                  #   JSON Web Key
│   │   ├── jwt/                  #   JSON Web Token
│   │   └── jwe/                  #   JSON Web Encryption
│   ├── tpm2/                     # TPM 2.0 operations
│   ├── pkcs11/                   # PKCS#11 module
│   ├── quantum/                  # Quantum primitives (Dilithium, Kyber)
│   ├── webauthn/                 # WebAuthn/passkey service
│   ├── fido2/                    # FIDO2 client
│   ├── user/                     # User management, RBAC
│   ├── adapters/                 # Service adapters
│   │   ├── auth/                 #   Authentication
│   │   ├── audit/                #   Audit logging
│   │   ├── rbac/                 #   Role-based access control
│   │   ├── policy/               #   Policy engine
│   │   ├── metrics/              #   Metrics
│   │   ├── kdf/                  #   Key derivation
│   │   ├── backup/               #   Backup
│   │   └── versioning/           #   Key versioning
│   ├── types/                    # Shared types
│   ├── certstore/                # Certificate storage
│   ├── attestation/              # Key attestation
│   ├── signing/                  # Signing operations
│   ├── verification/             # Signature verification
│   ├── metrics/                  # Prometheus metrics
│   ├── health/                   # Health checks
│   ├── correlation/              # Request correlation IDs
│   ├── ratelimit/                # Rate limiting
│   ├── migration/                # Key migration
│   ├── password/                 # Password hashing
│   ├── custodian/                # Custodian groups
│   ├── bootstrap/                # DANE/TLSA bootstrap
│   └── testutil/                 # Test utilities
├── sdk/go/                       # Go client SDK (separate module)
│   └── transport/                # Transport implementations
│       ├── rest/                 #   REST client
│       ├── grpc/                 #   gRPC client
│       ├── quic/                 #   QUIC client
│       ├── mcp/                  #   MCP client
│       ├── unix/                 #   Unix socket client
│       └── embedded/             #   In-process client
├── xkey/                         # Desktop/mobile app (separate module)
│   ├── cmd/xkey/                 # xkey CLI/GUI entry point
│   ├── pkg/                      # xkey packages
│   │   ├── authenticator/        #   FIDO2/CTAP2 authenticator
│   │   ├── gui/                  #   Wails GUI
│   │   ├── ipc/                  #   Browser extension IPC
│   │   ├── oath/                 #   OATH TOTP/HOTP
│   │   ├── oidc/                 #   OpenID Connect
│   │   ├── staticpw/             #   Static passwords
│   │   ├── backendregistry/      #   Backend registry
│   │   └── ...                   #   More xkey packages
│   ├── frontend/                 # Svelte frontend
│   └── extension/                # Browser extension
├── test/integration/             # Integration tests (Docker-based)
│   ├── api/                      # API protocol tests
│   ├── bootstrap/                # Bootstrap/DANE tests
│   ├── storage/                  # Storage tests
│   ├── pkcs8/, pkcs11/, tpm2/    # Backend tests
│   ├── awskms/, gcpkms/, azurekv/, vault/  # Cloud backend tests
│   ├── quantum/, frost/          # Crypto tests
│   └── ...                       # More integration suites
├── examples/                     # Usage examples
├── configs/                      # Configuration templates
├── deploy/                       # Deployment configs (systemd, openrc)
├── docs/                         # Documentation
├── .devcontainer/                # Dev container configuration
├── .github/                      # CI/CD workflows
├── Makefile                      # Build system (~3100 lines)
├── go.mod                        # Go module definition
└── VERSION                       # Version file (0.2.3-alpha)
```
