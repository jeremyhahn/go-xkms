# go-xkms Documentation

Comprehensive documentation for the go-xkms cryptographic key management library.

## Overview

go-xkms is a unified cryptographic key management library for Go that provides a consistent interface across multiple storage backends, from software-based file storage to hardware security modules and cloud key management services.

## Feature documentation

Each feature below has a folder holding five documents — `architecture.md`,
`engineering.md`, `cli.md`, `api.md`, `user.md`. Together they are the
feature's requirements: read the folder before reading the code, and change
the folder in the same commit that changes the behavior.

| Feature | What it covers |
|---------|----------------|
| [acme-issuance](acme-issuance/) | ACME RFC 8555 server and client, ARI, DNS-01/HTTP-01, TPM enrollment |
| [audit-log](audit-log/) | Tamper-evident audit records and their signing chain |
| [auth-factors](auth-factors/) | Factor composition, adapters, and the identity/key-domain split |
| [certificate-authority](certificate-authority/) | `TrustedCA` — cross-signed root pool, AIA import, DANE TLSA publishing |
| [crypto-backends](crypto-backends/) | The `Backend` contract and every software, hardware and cloud implementation |
| [fido2-ctap2](fido2-ctap2/) | The canonical FIDO2 CTAP2 implementation |
| [init-ceremony](init-ceremony/) | `xkmsd init` — the KMS+CA half and the delegated IAM half |
| [key-management](key-management/) | Key lifecycle, key providers, symmetric and asymmetric operations |
| [multi-tenancy](multi-tenancy/) | Per-tenant isolation, tenant barriers, tenant-scoped keys |
| [password-vault](password-vault/) | Stored password credentials and their access modes |
| [pin-management](pin-management/) | The PIN service and its TPM 2.0 backend |
| [piv-smartcard](piv-smartcard/) | PIV slot operations as a factor and as a CLI/SDK verb |
| [pkcs11-provider-module](pkcs11-provider-module/) | The `pkcs11-module` cgo provider and its slot/token lifecycle |
| [platform-secrets](platform-secrets/) | Platform secret storage and resolution |
| [sealing-and-barrier](sealing-and-barrier/) | Hardware and cloud seal strategies contributed to the qrdb barrier |
| [share-custody](share-custody/) | Shamir share custody, custodians, escrow and the share store |
| [tpm2](tpm2/) | EK/SRK lifecycle, IDevID/LDevID, PCR policy, attestation, sealed objects |
| [trust-bootstrap](trust-bootstrap/) | The DANE / Noise / SPKI / Direct / Auto mode-dispatch library |
| [webauthn](webauthn/) | The canonical WebAuthn relying party |

xkey has its own feature folders under [xkey/docs/](../xkey/docs/).

Everything below this section predates the feature-folder convention. It is
**unconverted debt, not a precedent** — a new feature gets a five-file folder
regardless of what the rest of this tree looks like. The migration state, and
which legacy folders are superseded by which feature folder, is recorded in
the repository's `CLAUDE.md`.

## Documentation Structure

### [Architecture](architecture/)
Core architectural concepts, design patterns, and technical specifications:
- [Overview](architecture/overview.md) - System architecture and design philosophy
- [API Specifications](architecture/api-specifications.md) - API design and interface contracts
- [Server Architecture](architecture/server-architecture.md) - Server design and backend registry
- [Storage](architecture/storage.md) - Storage interfaces and abstraction layer
- [Symmetric Encryption](architecture/symmetric-encryption.md) - Symmetric key support architecture
- [Hardware Certificate Storage](architecture/hardware-certificate-storage.md) - HSM certificate storage design
- [RBAC](architecture/rbac.md) - Role-based access control

### [Backends](backends/)
Backend-specific documentation for all supported storage systems:
- **Software**: [Software](backends/software.md) (asymmetric + symmetric, default backend; [PKCS#8](backends/pkcs8.md) key provider)
- **Hardware**: [TPM 2.0](backends/tpm2.md), [PKCS#11](backends/pkcs11.md), [Nitrokey HSM](backends/nitrokey-hsm.md)
- **Cloud**: [AWS KMS](backends/awskms.md), [GCP KMS](backends/gcpkms.md), [Azure Key Vault](backends/azurekv.md), [HashiCorp Vault](backends/vault.md)
- **Quantum**: [Post-Quantum Cryptography](backends/quantum.md)

### [Configuration](configuration/)
Configuration guides for various components:
- [Build System](configuration/build-system.md) - Build tags and compilation options
- [AEAD Configuration](configuration/aead-auto-selection.md) - Authenticated encryption setup
- [Symmetric Encryption](configuration/symmetric-encryption.md) - Symmetric key configuration
- [TPM2 Session Encryption](configuration/tpm2-session-encryption.md) - TPM session security

### [Bootstrap](bootstrap/)
Secure trust establishment and server initialization:
- [Overview](bootstrap/README.md) - Bootstrap architecture, DANE/Noise/SPKI/Direct trust methods, custodian setup

### [Trust](trust/)
Canonical trust-bootstrap dispatch library:
- [Trust Bootstrap Library](trust/bootstrap.md) - `pkg/trust/bootstrap` Mode enum, Fetch entry point, and the four consumers (xkmsctl, xkey GUI, QuicBaaS SDK, go-trusted-platform via SDK)

### [Init](init/)
First-boot server initialization ceremony:
- [Init System](init/README.md) - The `xkmsd init` KMS+CA half plus the IAM half that delegates to the embedded qrdb node's first-boot

### [Auth](auth/)
Authentication, authorization, and bootstrap:
- [Bootstrap Authentication](auth/bootstrap.md) - Cert-based admin enrollment: the `xkmsd init` ceremony, officer claim protocol, and `xkmsctl admin` mTLS/FIDO2 enrollment
- [Layering](auth/layering.md) - Identity (qrdb) vs key-domain (xkms) split, Factor adapter composition

### [WebAuthn](webauthn/)
Converted to the five-file feature layout — see [Feature documentation](#feature-documentation) below.
- [Architecture](webauthn/architecture.md) - Canonical RP implementation consumed by every binary in the stack via the QuicBaaS SDK re-export
- [Engineering](webauthn/engineering.md) - Exported surface, ceremony invariants, the headless client used by `xkmsctl` and tests

### [PIN](pin/)
- [PIN Management](pin/README.md) - PIN service (qrdb) + TPM2 backend (xkms `pkg/pintpm2`) + composition via `WithPINBackend`

### [Seal](seal/)
- [Barrier Encryption Architecture](seal/README.md) - qrdb owns the barrier and StrategyRegistry; xkms owns every hardware/cloud strategy

### [Custodian](custodian/)
- [Custodian Groups](custodian/README.md) - M-of-N roster naming who holds each Shamir share; service API, REST routes, and `xkmsctl custodian`
- [Share Collection Plane](custodian/shares.md) - submitting, inspecting, and removing returned shares
- [Key Share Persistence](sharestore/README.md) - client-side storage of received shares

### [Usage](../xkey/docs/usage/)
CLI usage guides and tutorials have moved to [xkey/docs/usage/](../xkey/docs/usage/README.md).

### [xKey Application](../xkey/docs/)
xKey is the desktop GUI and CLI application built on go-xkms. All xKey documentation (setup wizard, auto-unseal, FIDO2 daemon, enterprise mode, password management, etc.) lives in [xkey/docs/](../xkey/docs/README.md).

### [Testing](testing/)
Testing documentation and best practices:
- [Integration Tests](testing/integration-tests.md) - End-to-end testing guide
- [Docker Testing](testing/docker-testing.md) - Isolated test environments

### [Deployment](deployment/)
Deployment guides and production configurations:
- [Docker Deployment](deployment/docker.md) - Complete Docker deployment guide
- [Docker Quick Start](deployment/docker-quickstart.md) - 5-minute Docker setup

### [Sealed Storage](sealed-storage/)
Encrypted-at-rest storage and credential management:
- [Sealed Backend](sealed-storage/README.md) - Transparent value encryption via types.Sealer
- [PlatformStore](platform-store/README.md) - Named-secret credential store (macOS Keychain analog)
- [Static Passwords](staticpw/README.md) - Password manager with multi-tenant support and encryption

### [FIPS 140](fips/)
FIPS compliance and algorithm selection:
- [FIPS Strategy](fips/README.md) - GOFIPS140 detection, KDF selection, and PasswordHasher

### [Development](development/)
Development and contributor documentation:
- [Encoding Interop Status](development/encoding-interop-status.md) - JWK/JWT/JWE test implementation status

## Quick Start

The simplest way to get started is with `AutoInitialize`, which discovers all compiled-in backends and sets them up automatically:

```go
import (
    "crypto/elliptic"
    "crypto/x509"
    "fmt"
    "log"

    "github.com/jeremyhahn/go-xkms/pkg/types"
    "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

func main() {
    // See what backends are compiled in
    fmt.Println("Available backends:", xkms.SupportedBackends())

    // Auto-initialize all compiled-in backends with defaults
    if err := xkms.AutoInitialize(nil); err != nil {
        log.Fatal(err)
    }
    defer xkms.Close()

    // Generate a key using the service API
    key, err := xkms.GenerateKey(&types.KeyAttributes{
        CN:           "my-signing-key",
        StoreType:    types.BackendType("software"),
        KeyAlgorithm: x509.ECDSA,
        ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
    })
    if err != nil {
        log.Fatal(err)
    }

    // Sign data
    sig, err := xkms.Sign("software:::my-signing-key", []byte("hello"), nil)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Signature: %x\n", sig)
}
```

For client/server deployments, use the Go SDK:

```go
import xkms "github.com/jeremyhahn/go-xkms/sdk/go"

client, _ := xkms.NewFromURL("https://localhost:8443")
defer client.Close()
client.Connect(ctx)

resp, _ := client.GenerateKey(ctx, &xkms.GenerateKeyRequest{
    KeyID:   "my-key",
    Backend: "software",
    KeyType: "EC",
    Curve:   "P-256",
})
```

See the [Getting Started](../xkey/docs/usage/getting-started.md) guide for all initialization patterns.

## Key Features

- **Unified Interface**: Single API across all backends
- **Auto-Discovery**: Registry auto-discovers compiled-in backends at startup
- **Multiple Backends**: Support for file, HSM, TPM, and cloud storage
- **Key Types**: RSA, ECDSA, Ed25519, AES
- **Standards Compliant**: PKCS#8, PKCS#11, TPM 2.0, JWK, JWT
- **Certificate Management**: X.509 certificate lifecycle management
- **High Performance**: Lock-free algorithms, optimized for low latency
- **Type Safe**: No pointer magic or unsafe operations
- **Well Tested**: 90%+ code coverage with meaningful tests

## Examples

See the `examples/` directory for complete working examples:

- `examples/basic/` - Basic key operations
- `examples/certificates/` - Certificate management
- `examples/signing/` - Digital signatures
- `examples/symmetric-encryption/` - Symmetric encryption
- `examples/tls/` - TLS client and server
- `examples/advanced/` - Advanced patterns

## Building

```bash
# Build with all backends
make build

# Build with specific backends
go build -tags="pkcs11 tpm2" ./...

# Run tests
make test

# Run integration tests
make integration-test
```

## Contributing

There is no `CONTRIBUTING.md` yet. The contribution guidelines currently live in
the [Contributing section of the root README](../README.md#contributing), and the
coding, testing, and documentation rules agents and contributors must follow are
in [CLAUDE.md](../CLAUDE.md).

## License

Copyright (c) 2025 Jeremy Hahn. Licensed under the AGPL-3.0 License.
