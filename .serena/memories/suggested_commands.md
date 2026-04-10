# Suggested Commands

## Build Commands
```bash
make build                  # Build everything (lib, CLI, server, xkey)
make build-cli              # Build xkmsctl CLI (CGO_ENABLED=0)
make build-server           # Build xkmsd server (Docker for CGO)
make build-xkey             # Build xkey desktop app (Docker for CGO+GUI)
make lib                    # Build libxkms shared library
make build-pkcs11-module    # Build PKCS#11 shared library
make release-binaries       # Cross-compile for all platforms
```

## Unit Testing
```bash
make test                   # Run all unit tests with coverage
make test-all               # Unit tests + import/export tests
make race                   # Tests with race detector (all backends)

# Package-specific unit tests (pattern: test-<package>)
make test-backend           # Backend package
make test-software          # Software backend
make test-storage           # Storage package
make test-signing           # Signing package
make test-encoding          # Encoding (JWK/JWT/JWE/PEM)
make test-ca                # Certificate Authority
make test-quantum           # All quantum tests
make test-frost             # FROST threshold signatures
make test-seal              # Barrier/seal package
make test-auth              # Auth adapters
make test-rbac              # RBAC adapters
make test-xkmsctl           # CLI unit tests
make test-sdk-go            # Go SDK unit tests
make test-xkey              # xkey command tests (cd xkey)
make test-staticpw          # Static password tests (cd xkey)
make test-ipc               # IPC package tests (cd xkey)
```

## Integration Testing
```bash
make integration-test       # ALL integration tests (Docker-based, ~30min)

# Package-specific integration tests (pattern: integration-test-<package>)
make integration-test-software   # Software backend (devcontainer)
make integration-test-pkcs8      # PKCS8 (Docker)
make integration-test-pkcs11     # PKCS11/SoftHSM (Docker)
make integration-test-tpm2       # TPM2 simulator (Docker)
make integration-test-awskms     # AWS KMS/LocalStack (Docker)
make integration-test-gcpkms     # GCP KMS mock (Docker)
make integration-test-azurekv    # Azure Key Vault mock (Docker)
make integration-test-vault      # HashiCorp Vault (Docker)
make integration-test-storage    # All storage tests (Docker)
make integration-test-quantum    # Quantum crypto (Docker)
make integration-test-frost      # FROST threshold (Docker)
make integration-test-webauthn   # WebAuthn (devcontainer)
make integration-test-fido2      # FIDO2 (devcontainer)
make integration-test-cli        # CLI E2E (Docker)
make integration-test-api-all    # All API protocols (Docker)
make integration-test-sdk-go     # Go SDK (devcontainer)
make integration-test-bootstrap  # Bootstrap/DANE (Docker)

# API protocol-specific
make integration-test-api-unix
make integration-test-api-rest
make integration-test-api-grpc
make integration-test-api-quic

# PKCS#11 module tests
make integration-test-pkcs11-module      # Multi-protocol
make integration-test-pkcs11-tool        # pkcs11-tool compat
make integration-test-pkcs11-openssl     # OpenSSL compat
make integration-test-pkcs11-ssh         # SSH compat
```

## Code Coverage
```bash
make coverage               # Unit test coverage report
make coverage-full          # Unit + integration coverage

# Package-specific coverage (pattern: coverage-<package>)
make coverage-quantum
make coverage-ca
make coverage-storage
make coverage-seal
make coverage-auth
make coverage-rbac
make coverage-sdk-go
make coverage-pkcs11-module
```

## Benchmarks
```bash
make bench                  # All benchmarks
make bench-storage          # Storage benchmarks
make bench-backend          # Backend benchmarks
make bench-quantum          # Quantum benchmarks
make bench-certs            # Certificate storage benchmarks
make bench-baseline         # Create baseline results
make bench-compare          # Compare with baseline (needs benchstat)
```

## Code Quality
```bash
make fmt                    # Format code (gofmt -s -w .)
make fmt-check              # Check formatting
make vet                    # Run go vet
make lint                   # Run golangci-lint (or fallback to vet)
make gosec                  # Security scanner
make vuln                   # Vulnerability scan (govulncheck)
make check                  # fmt-check + vet + lint + gosec
make verify                 # check + test (pre-commit)
```

## Docker
```bash
make docker-build           # Build default Docker image
make docker-build-server    # Build xkmsd server image
make docker-build-all       # Build all Docker images
make docker-run             # Run container
make docker-test            # Run tests in Docker
make docker-clean           # Clean Docker artifacts
make clean-test-containers  # Clean integration test containers
```

## Cloud Emulators
```bash
make emulator-start         # Start LocalStack, Azure emulator
make emulator-stop          # Stop emulators
make emulator-status        # Check health
make emulator-logs          # View logs
```

## Protobuf
```bash
make proto                  # Generate Go code from .proto files
make proto-check            # Verify generated code is up to date
```

## Misc
```bash
make deps                   # Install Go dependencies
make clean                  # Clean all build artifacts
make help                   # Show all targets with descriptions
make show-backends          # Show enabled backends
make version                # Show version
```
