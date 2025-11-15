# Build System

go-keychain uses a modular build system that allows you to include only the backends you need, reducing binary size, compilation time, and dependencies.

## Quick Start

```bash
# Build with all backends (default)
make lib

# Build with only PKCS#8 (minimal, 6.4MB)
make lib WITH_PKCS11=0 WITH_TPM2=0 WITH_AWSKMS=0 WITH_GCPKMS=0 WITH_AZUREKV=0

# Build with software + hardware backends (no cloud)
make lib WITH_AWSKMS=0 WITH_GCPKMS=0 WITH_AZUREKV=0

# Show current configuration
make show-backends
```

## Backend Configuration

### WITH_* Variables

Control which backends are included in the build:

| Variable | Default | Description |
|----------|---------|-------------|
| `WITH_PKCS8` | 1 | Software key storage (filesystem) |
| `WITH_PKCS11` | 0 | Hardware Security Modules (HSM) |
| `WITH_TPM2` | 0 | Trusted Platform Module 2.0 |
| `WITH_AWS_KMS` | 0 | AWS Key Management Service |
| `WITH_GCP_KMS` | 0 | Google Cloud Platform KMS |
| `WITH_AZURE_KV` | 0 | Microsoft Azure Key Vault |
| `WITH_VAULT` | 0 | HashiCorp Vault |

### Server Feature Configuration

Control which server interfaces are included:

| Variable | Default | Description |
|----------|---------|-------------|
| `WITH_CLI` | 1 | Command-line interface |
| `WITH_REST` | 1 | HTTP/JSON REST API |
| `WITH_GRPC` | 1 | gRPC API |
| `WITH_QUIC` | 1 | HTTP/3 over QUIC |
| `WITH_MCP` | 1 | Model Context Protocol (AI) |

## Usage Examples

### Minimal Build (PKCS#8 Only)

For embedded systems or when you only need software key storage:

```bash
make lib
# Default build is already minimal (PKCS#8 only)
```

**Binary Size**: ~6-8MB
**Dependencies**: None (Go standard library only)
**Use Cases**: Testing, development, lightweight applications

### Software + Hardware Build

For on-premises deployments with HSM or TPM:

```bash
make lib WITH_PKCS11=1 WITH_TPM2=1
```

**Dependencies**: SoftHSM2 or hardware HSM, libtss2 for TPM
**Use Cases**: Enterprise deployments, FIPS compliance, hardware-backed keys

### Cloud-Only Build

For cloud-native applications:

```bash
make lib WITH_AWS_KMS=1 WITH_GCP_KMS=1 WITH_AZURE_KV=1
```

**Dependencies**: AWS SDK, GCP SDK, Azure SDK
**Use Cases**: Cloud deployments, serverless, managed services

### Full Build (All Backends)

For development, testing, or maximum flexibility:

```bash
# Enable all backends
make lib WITH_PKCS11=1 WITH_TPM2=1 WITH_AWS_KMS=1 WITH_GCP_KMS=1 WITH_AZURE_KV=1 WITH_VAULT=1
```

**Binary Size**: ~23MB
**Dependencies**: All backend dependencies
**Use Cases**: Development, testing, migration scenarios

## Direct Go Builds

You can also use Go build tags directly:

```bash
# Minimal build
go build -tags="pkcs8" -o keychain ./cmd/cli

# Custom combination
go build -tags="pkcs8,pkcs11,awskms" -o keychain ./cmd/cli

# Server with specific backends and features
go build -tags="pkcs8,awskms,rest,grpc" -o server ./cmd/server
```

## Build Targets

### Library Builds

```bash
make lib                  # Build shared library (.so)
make build-minimal        # PKCS#8 only
make build-software       # Software backends
make build-hardware       # Hardware backends (PKCS11, TPM2)
make build-cloud          # Cloud backends
make build-full           # All backends
make build-matrix         # Build all configurations
```

### Binary Builds

```bash
make build                # Build CLI binary
make build-server         # Build server binary
make server               # Build server with current config
make cli                  # Build CLI with current config
```

### Testing

```bash
make test                    # Run unit tests
make integration-test        # Run all integration tests
make integration-test-pkcs8  # Run PKCS#8 integration tests
make integration-test-pkcs11 # Run PKCS#11/SoftHSM integration tests
make integration-test-tpm2   # Run TPM2 simulator integration tests
make integration-test-awskms # Run AWS KMS/LocalStack integration tests
make integration-test-gcpkms # Run GCP KMS integration tests
make integration-test-azurekv # Run Azure Key Vault integration tests
make integration-test-vault  # Run HashiCorp Vault integration tests
make coverage                # Generate coverage report
```

## How It Works

### Build Tags

Each backend is protected by Go build tags:

```go
//go:build pkcs11

package pkcs11

// This file only compiles when pkcs11 tag is specified
```

### Backend Registry

The backend registry at `pkg/backend/registry.go` automatically registers only the backends that are compiled:

```go
// Each backend self-registers via init()
func init() {
    RegisterBackend(BackendInfo{
        Name:        "pkcs11",
        Type:        "hardware",
        Description: "PKCS#11 HSM backend",
        Features:    []string{"rsa", "ecdsa"},
        Available:   true,
    })
}
```

### Server Layer Exclusion

Server handlers automatically exclude references to unavailable backends:

- CLI commands check `registry.IsBackendAvailable("pkcs11")` before showing PKCS#11 options
- REST API endpoints return 404 for unavailable backends
- gRPC services return UNIMPLEMENTED for unavailable backends
- QUIC handlers skip unavailable backend routes
- MCP tools exclude unavailable backend operations

## Makefile Helpers

### Show Current Configuration

```bash
make show-backends
```

Output:
```
Current Backend Configuration:

  Software Backends:
    ✓ PKCS8 (Software key storage)

  Hardware Backends:
    ✗ PKCS11
    ✗ TPM2

  Cloud Backends:
    ✗ AWS KMS
    ✗ GCP KMS
    ✗ Azure Key Vault

  Build Tags: pkcs8
```

### Backend Help

```bash
make help-backends
```

Shows detailed information about each backend, dependencies, and example builds.

### Size Comparison

```bash
make size-comparison
```

Builds multiple configurations and compares binary sizes.

## Binary Size Impact

| Configuration | Binary Size | Savings |
|--------------|-------------|---------|
| Minimal (PKCS#8) | 6.4MB | Baseline |
| + PKCS#11 | ~10MB | +56% |
| + TPM2 | ~15MB | +134% |
| Full (all 6) | ~23MB | +259% |

## Dependencies by Backend

### PKCS#8
- **Runtime**: None (Go standard library)
- **Build**: None

### PKCS#11
- **Runtime**: PKCS#11 library (e.g., SoftHSM2, CloudHSM, Luna HSM)
- **Build**: None (dynamically loaded)

### TPM 2.0
- **Runtime**: libtss2
- **Build**: CGO enabled, tss2 headers

### AWS KMS
- **Runtime**: Network access to AWS
- **Build**: AWS SDK for Go v2

### GCP KMS
- **Runtime**: Network access to GCP
- **Build**: Google Cloud Go libraries

### Azure Key Vault
- **Runtime**: Network access to Azure
- **Build**: Azure SDK for Go

## Environment Variables

You can set WITH_* variables as environment variables:

```bash
export WITH_PKCS8=1
export WITH_PKCS11=0
export WITH_TPM2=0
export WITH_AWSKMS=1
export WITH_GCPKMS=1
export WITH_AZUREKV=0

make lib  # Uses environment variables
```

## CI/CD Integration

### Build Matrix Example

```yaml
# .github/workflows/build.yml
strategy:
  matrix:
    config:
      - name: minimal
        backends: "WITH_PKCS11=0 WITH_TPM2=0 WITH_AWSKMS=0 WITH_GCPKMS=0 WITH_AZUREKV=0"
      - name: full
        backends: "WITH_PKCS8=1 WITH_PKCS11=1 WITH_TPM2=1 WITH_AWSKMS=1 WITH_GCPKMS=1 WITH_AZUREKV=1"

steps:
  - name: Build
    run: make lib ${{ matrix.backends }}
```

## Troubleshooting

### Backend Not Available at Runtime

If you get "backend not available" errors:

1. Check which backends are compiled: `make show-backends`
2. Verify build tags were used: `go version -m ./build/lib/libkeychain.so | grep build`
3. Rebuild with required backend: `make lib WITH_<BACKEND>=1`

### Linker Errors

If you get undefined symbol errors:

1. Ensure all required backends are enabled
2. Check that CGO is enabled for TPM2: `CGO_ENABLED=1 make lib WITH_TPM2=1`
3. Verify system dependencies are installed

### Large Binary Size

If your binary is larger than expected:

1. Check which backends are enabled: `make show-backends`
2. Disable unused backends
3. Use `make build-minimal` for smallest size
4. Strip debug symbols: `go build -ldflags="-s -w"`

## Best Practices

1. **Development**: Use full build for maximum flexibility
   ```bash
   make lib
   ```

2. **Production**: Include only required backends
   ```bash
   make lib WITH_PKCS8=1 WITH_AWSKMS=1  # Example: software + AWS
   ```

3. **Testing**: Use build matrix to test all configurations
   ```bash
   make build-matrix
   make test-matrix
   ```

4. **Containers**: Use minimal build to reduce image size
   ```bash
   make build-minimal
   ```

5. **Security**: Minimize attack surface by excluding unused backends
   ```bash
   # Only include what you need
   make lib WITH_TPM2=0 WITH_AWSKMS=0 WITH_GCPKMS=0 WITH_AZUREKV=0
   ```

## See Also

- [Getting Started](getting-started.md)
- [Backend Registry](backend-registry.md)
- [Storage Abstraction](storage-abstraction.md)
- [Architecture Overview](architecture/overview.md)
