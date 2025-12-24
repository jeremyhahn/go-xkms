# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2-alpha] - 2025-12-24

### Added
- **Unified Symmetric Backend**: New `pkg/backend/symmetric/` consolidating AES and ChaCha20-Poly1305
  - Single backend supporting AES-128-GCM, AES-192-GCM, AES-256-GCM
  - ChaCha20-Poly1305 and XChaCha20-Poly1305 support
  - Password-protected key storage with Argon2 key derivation
  - AEAD nonce tracking and bytes limit enforcement
  - Import/export functionality for key portability
- **Algorithm Type System**: New `pkg/types/algorithms.go` with comprehensive type definitions
  - `KeyAlgorithmString` for asymmetric key algorithm identifiers (RSA, ECDSA, Ed25519)
  - `EllipticCurve` constants (P224, P256, P384, P521, Curve25519)
  - `HashName` constants matching Go crypto standards
  - `SignatureAlgorithmName` for signature algorithm identifiers
  - `AEADAlgorithm` and `KeyWrapAlgorithm` for encryption operations
  - `CLIKeyType` for CLI key type parsing
  - Parsing and validation functions for all algorithm types
- **FROST Protocol Stubs**: Infrastructure for future FROST threshold signature support
  - Handler stubs for REST, gRPC, QUIC, Unix, and MCP protocols
  - Backend factory stubs for FROST initialization
  - CLI command stubs for FROST operations

### Changed
- **Test Coverage Improvements**: Increased coverage across 7 packages to 90%+ target
  - `pkg/types`: 66.6% → 97.0% (+30.4%)
  - `pkg/keychain`: 86.8% → 90.6% (+3.8%)
  - `pkg/backend/symmetric`: 88.4% → 90.0% (+1.6%)
  - `pkg/client`: 86.3% → 90.1% (+3.8%)
  - `pkg/crypto/ecies`: 89.6% (all reachable code covered)
  - `pkg/adapters/backup`: 89.7% → 91.0% (+1.3%)
  - `pkg/webauthn/http`: 87.9% (improved edge case coverage)
- **Consolidated AESAttributes**: Removed deprecated `AESAttributes` type, using `KeyAttributes` with `SymmetricAlgorithm` field
- **TPM2 Symmetric Tests**: Updated tests for symmetric key generation and encryption validation
- **Cloud Backend Tests**: Cleaned up symmetric encryption tests for AWS KMS, Azure Key Vault, GCP KMS, and Vault backends

### Removed
- **pkg/backend/aes/**: Deprecated AES-only backend (functionality moved to `pkg/backend/symmetric/`)
  - `aes.go`, `aes_test.go`, `aes_bench_test.go`
  - `aes_importexport_test.go`, `aes_tracking_test.go`
  - `errors.go`
- **test/integration/backend/aes_integration_test.go**: Replaced by symmetric backend integration tests

### Fixed
- **Code Formatting**: Fixed gofmt issues in test files blocking CI
- **Linting Errors**: Resolved staticcheck and ineffassign warnings
- **Build Errors**: Fixed undefined `AESAttributes` references after consolidation

## [0.2.1-alpha] - 2025-12-21

### Added
- **TPM2 ProdCaData**: New `ProdCaData` structure for carrying TPM attestation data (Quote, Signature, Nonce, PCRs) from client to server during IDevID enrollment
  - Enables server-side storage of client attestation state upon successful enrollment
  - Binary serialization with `PackProdCaData`/`UnpackProdCaData` functions
  - Conversion to/from `Quote` structure for TPM operations

### Changed
- **Unified Key ID Format**: Consolidated key ID parsing to 4-part format `backend:type:algo:keyname` with optional segments
  - Shorthand `my-key` now supported (equivalent to `:::my-key`)
  - All segments except keyname are optional
  - Refactored `ParseKeyID`, `ParseKeyIDToAttributes`, and validation to use unified format
- **Keychain Service API**: Refactored service functions to use unified key ID format
  - Added `BackendFor(attrs)` helper for backend resolution based on StoreType
  - Added `ParseCertificateID()` using unified format
  - Renamed `getKeystoreForKey` to `getKeystoreForKID` with proper 4-part parsing
  - `Signer()`, `Decrypter()`, `Key()` now use `BackendFor()` for backend resolution
- **TPM2 Provisioning**: Simplified golden measurement and platform policy handling
  - Removed deprecated file integrity monitoring code (use IMA via PCR 10 instead)
  - `Install()` now uses config's `EK.HierarchyAuth` for already-provisioned TPMs
  - Improved logging with INFO level for provisioning operations
  - `GoldenMeasurements()` returns empty if no PCRs configured (skip platform policy)
- **Client Config**: Changed default Unix socket path to `keychain-data/keychain.sock`, removed `APIKey` field (use JWT via FIDO2 flow)
- **Validation**: Updated `ValidateKeyReference()` to enforce 4-part key ID format

### Fixed
- **AWS KMS Lock Contention**: Fixed test timeout by implementing double-checked locking in `Backend.initClient()`
- **Azure Key Vault Lock Contention**: Applied same double-checked locking fix for consistency
- **CI Go Version**: Updated `Dockerfile.ci` from Go 1.24.4 to 1.25.5
- **TPM Test Config**: Added missing `GoldenPCRs` to `TestTPMOperations` config

## [0.2.0-alpha] - 2025-12-13

### Added
- **Key Versioning API**: Full key version lifecycle management across all client interfaces
  - `ListKeyVersions` - List all versions of a key with status and metadata
  - `EnableKeyVersion` / `DisableKeyVersion` - Enable or disable specific key versions
  - `EnableAllKeyVersions` / `DisableAllKeyVersions` - Bulk version state management
  - gRPC, REST, QUIC, and Unix socket client support
  - Proto definitions in `api/proto/keychainv1/keychain.proto`
- **JWT Authentication Adapter**: `pkg/adapters/auth/jwt.go` for token-based authentication
  - Configurable issuer, audience, and signing key validation
  - Support for RS256, ES256, and EdDSA signing algorithms
- **Adaptive Authentication**: `pkg/adapters/auth/adaptive.go` for multi-method auth
  - Automatic fallback between authentication methods (mTLS → JWT → API Key)
  - Configurable authentication chain with priority ordering
- **WebAuthn JWT Generator**: `pkg/webauthn/jwt_generator.go` for token generation after FIDO2 authentication
- **CLI Certificate Commands**: `internal/cli/cert.go` for certificate management operations
- **TPM2 Backend Integration**: Server-side TPM2 backend factory and operations
  - `internal/server/backend_factory_tpm2.go` - TPM2 backend initialization
  - `internal/server/backend_tpm2.go` - TPM2 server operations
- **CanoKey Backend**: Complete PIV-compatible backend for CanoKey hardware tokens
  - `pkg/backend/canokey/` - Full backend implementation with PKCS#11 wrapper
  - Hardware and virtual (QEMU) device support for CI/CD testing
  - PIV slot management (9a, 9c, 9d, 9e, 82-95) matching YubiKey compatibility
  - Ed25519/X25519 support on firmware 3.0+
  - Symmetric encryption via envelope encryption pattern
  - Sealing/unsealing operations with hardware-backed keys
  - Comprehensive documentation in `docs/backends/canokey.md`
- **YubiKey Sealer Interface**: Hardware-backed data sealing for YubiKey PIV
  - `pkg/backend/yubikey/yubikey_sealer.go` - Envelope encryption sealing
  - RSA-OAEP key wrapping for DEK protection
  - AES-256-GCM authenticated encryption
- **YubiKey Symmetric Encryption**: AES-GCM envelope encryption using PIV keys
  - `pkg/backend/yubikey/yubikey_symmetric.go` - Full symmetric backend
  - DEK wrapping with RSA-OAEP, ECIES (P-256/P-384), and X25519
  - Ed25519 to X25519 key conversion for key agreement
- **Configurable Hardware-Backed RNG**: Support for TPM2 and PKCS#11 hardware random number generators
  - `pkg/crypto/rand/` Resolver interface now implements `io.Reader` for crypto/rand compatibility
  - New `RNGConfig` in server configuration for RNG source selection
  - Modes: `auto` (default), `software`, `tpm2`, `pkcs11`
  - Fallback mode support when primary RNG fails
  - Environment variable overrides: `KEYCHAIN_RNG_MODE`, `KEYCHAIN_RNG_FALLBACK`, `KEYCHAIN_RNG_TPM2_*`, `KEYCHAIN_RNG_PKCS11_*`
- **Unix Socket Client Package**: `pkg/client/` for Go applications to communicate with keychain server
- **CLI Configuration Tests**: `internal/cli/config_test.go` with comprehensive config validation
- **Extended CLI Integration Tests**: Multi-protocol and complete lifecycle tests
- **User Documentation**: `docs/usage/user.md` for end-user documentation
- **Daemon Configuration**: Complete daemon operation support for `keychaind`
  - Configuration file support (`--config`, `KEYCHAIN_CONFIG`)
  - Signal handling: SIGTERM/SIGINT for graceful shutdown, SIGHUP for config reload
  - PID file management with automatic creation and cleanup
  - Runtime configuration reload without restart
  - Unix socket protocol selection (gRPC or HTTP)
  - systemd service file with security hardening
  - Installation script and comprehensive documentation in `configs/`
- **Comprehensive Test Suites**: New test files for sealer and symmetric operations
  - `pkg/backend/canokey/canokey_sealer_test.go` (26 tests)
  - `pkg/backend/canokey/canokey_symmetric_test.go` (20 tests)
  - `pkg/backend/yubikey/yubikey_sealer_test.go` (14 test functions)
  - `pkg/backend/yubikey/yubikey_symmetric_test.go` (20 tests)
- **Deployment Documentation**: systemd and OpenRC service files for production deployments
  - `deploy/systemd/` - systemd service unit, sysusers, and tmpfiles configurations
  - `deploy/openrc/` - OpenRC init script and configuration for Alpine Linux
  - `deploy/README.md` - Comprehensive deployment guide with installation steps
- **Enhanced README**: Expanded quick start guide with FIDO2 admin setup
  - Server Quick Start section with first-time setup instructions
  - Complete CLI examples for key, certificate, and admin management
  - Keychain Service API overview with all service functions documented
  - Multi-backend configuration examples
- **Admin CLI Commands**: `internal/cli/admin.go` for administrator management
  - Create, list, delete admin users
  - Role assignment and permissions management
- **FIDO2 CLI Commands**: `internal/cli/fido2.go` for passwordless authentication setup
  - Register and manage FIDO2 credentials
  - Authenticate using hardware security keys
- **RBAC Middleware**: `internal/rest/rbac_middleware.go` for role-based access control
  - Permission-based route protection
  - Role hierarchy support
- **User Management API**: `internal/rest/user_handlers.go` for user operations
  - REST endpoints for user CRUD operations
  - Integration with RBAC system
- **Unix Socket HTTP Server**: `internal/unix/` for local IPC
  - HTTP server over Unix domain sockets
  - Handlers for all keychain operations

### Changed
- **Test Coverage Improvements**: Increased coverage across multiple packages
  - `pkg/versioning`: 76.1% → 93.9%
  - `pkg/client`: 79.1% → 86.1%
  - `internal/config`: 83.1% → 96.0%
  - Testable code (excluding hardware) now at 93.4% average coverage
- Extended environment variable configuration support for RNG, rate limiting, and logging
- **API Naming**: Renamed `KeychainFacade` to `KeychainService` for clarity
  - `FacadeConfig` → `ServiceConfig`
  - `facade.go` → `service.go`
  - Updated all documentation, tests, and code references
- **Documentation**: Updated terminology from "facade" to "service" throughout
- **Typed Errors**: Replaced all `fmt.Errorf` with typed errors in PIV backends
  - CanoKey: 38 typed error variables, ~118 replacements
  - YubiKey: 37 typed error variables, ~139 replacements
  - Enables proper `errors.Is()` and `errors.As()` error handling
- Extended `Resolver` interface with `Read(p []byte) (n int, err error)` method for `io.Reader` compatibility
- Hardware RNG (TPM2/PKCS#11) can now be used as drop-in replacement for `crypto/rand.Reader`
- Updated example configurations with RNG settings documentation
- **Documentation Cleanup**: Streamlined architecture documentation
  - `docs/architecture/unified-keyid-jwk-integration.md` reduced from 1,580 to 245 lines
  - Removed all legacy/migration content, kept only current API documentation
- **CI/CD**: Added FIPS 140-2/3 compliant builds to CI and release workflows
  - BoringCrypto-enabled binaries for environments requiring FIPS certification

### Fixed
- **Makefile**: Fixed `bc` dependency error in coverage calculation (replaced with pure shell/awk)
- **Ed25519 to X25519 Conversion**: Fixed SHA256 → SHA512 for RFC 7748 compliance in YubiKey symmetric
- **TestMCPStreamingNotifications**: Fixed flaky integration test for async MCP notifications
- **PlatformPassword Race Condition**: Fixed concurrent cache access in `pkg/tpm2/password.go`
  - Multiple goroutines calling `Bytes()` could bypass cache and trigger excessive TPM unseal operations
  - Implemented double-checked locking pattern to ensure only one goroutine performs unseal when cache is empty
  - `TestPlatformPassword_CacheConcurrency` now passes with race detector enabled
- Improved error handling and logging for ignored HTTP write errors
- Integration test stability improvements across all backends
- **Configuration**: Server socket path now defaults to `/var/run/keychain/keychain.sock` to match client defaults
- **Configuration**: Added `keychaind-dev.yaml` for development/testing with `/tmp` paths
- **Configuration**: Added `keychain-client.yaml` example client configuration
- **Scripts**: Moved test scripts from `scripts/` to `test/scripts/`

### Removed
- **API Key Authentication**: Removed `pkg/adapters/auth/apikey.go` (replaced by JWT adapter)
- **Logo**: Removed `logo.svg` from repository root
- `test/integration/encoding/README_FIX.md` - Development-only fix notes
- `pkg/metrics/implementation-summary.md` - Development-only implementation notes

### Known Limitations (Alpha)
- **TPM2 Server Integration**: The `pkg/tpm2` library is fully functional for direct Go usage, but server-side integration (REST/gRPC/CLI/MCP) is not yet complete. Use `pkg/tpm2` directly for TPM2 operations.
- **Vault Import/Export**: HashiCorp Vault Transit backend does not support key import/export operations
- **PKCS#11 Attestation**: Some attestation methods are not yet implemented

## [0.1.9-alpha] - 2025-12-07

### Added
- **WebAuthn/FIDO2 Server Support**: Complete server-side passwordless authentication
  - `pkg/webauthn/` - Core WebAuthn service with user, session, and credential management
  - `pkg/webauthn/http/` - HTTP handlers for REST API integration
  - Registration flow: begin/finish ceremonies with session management
  - Authentication flow: discoverable credentials and user-specific login
  - Pluggable store interfaces for UserStore, SessionStore, CredentialStore
  - Memory-based stores for development and testing
  - Full test coverage with testify mocks
- **WebAuthn REST API Endpoints**:
  - `GET /api/v1/webauthn/registration/status` - Check registration status
  - `POST /api/v1/webauthn/registration/begin` - Start registration ceremony
  - `POST /api/v1/webauthn/registration/finish` - Complete registration
  - `POST /api/v1/webauthn/login/begin` - Start authentication ceremony
  - `POST /api/v1/webauthn/login/finish` - Complete authentication
- **Shared Mock Infrastructure**: `pkg/keychain/mocks/mock_keystore.go` for unit testing
- **WebAuthn Integration Tests**: Docker-based tests in `test/integration/api/`
- **WebAuthn Documentation**: `docs/usage/webauthn.md`
- **Unified Rate Limiting**: Consistent rate limiting across all public APIs
  - Integrated rate limiting into REST server via middleware
  - Added gRPC unary and stream server interceptors for rate limiting
  - QUIC/HTTP3 server rate limiting via HTTP middleware
  - MCP JSON-RPC server connection-level rate limiting
  - New configuration options: `burst`, `cleanup_interval_sec`, `max_idle_sec`
  - Environment variable overrides: `KEYSTORE_RATELIMIT_ENABLED`, `KEYSTORE_RATELIMIT_REQUESTS_PER_MIN`, `KEYSTORE_RATELIMIT_BURST`

### Changed
- Refactored REST server tests to use shared mock infrastructure
- Improved test organization with centralized mocks
- Extended `RateLimitConfig` with additional options for burst and cleanup intervals

## [0.1.8-alpha] - 2025-12-06

### Changed
- **Storage Independence**: Removed go-objstore dependency, go-keychain now has its own storage implementations
  - Local `pkg/storage/memory.go` provides in-memory storage backend
  - Local `pkg/storage/file/` provides file-based storage backend
  - Storage interface remains compatible with go-objstore for higher-level app integration
- **Docker Cleanup**: Removed all GOPRIVATE workarounds from integration test Dockerfiles
  - Cleaned up main Dockerfile (removed sed/GOPRIVATE/GOPROXY hacks)
  - All integration tests now use standard Go module proxy

### Removed
- `pkg/storage/objstore_adapter.go` - go-objstore adapter (no longer needed)
- `pkg/tpm2/store/objstore_*.go` - All go-objstore adapters for TPM store
- `pkg/tpm2/store/factory.go` - go-objstore factory (replaced with local implementations)
- `pkg/tpm2/store/testing.go` - go-objstore test helpers
- GOPRIVATE environment variables from all Dockerfiles

### Dependencies
- Removed go-objstore dependency entirely (go-keychain is now self-contained for storage)

## [0.1.7-alpha] - 2025-12-05

### Added
- **Unified Sealer Interface**: Backend-agnostic sealing abstraction across all backends
  - `pkg/tpm2/sealer.go` - TPM2 sealer with PCR policy support
  - `pkg/backend/pkcs8/sealer.go` - Software sealer using HKDF + AES-256-GCM
  - `pkg/backend/pkcs11/sealer.go` - HSM hardware-backed AES-GCM sealing
  - `pkg/backend/awskms/sealer.go` - AWS KMS cloud-managed encryption
  - `pkg/backend/azurekv/sealer.go` - Azure Key Vault symmetric key sealing
  - `pkg/backend/gcpkms/sealer.go` - GCP KMS cloud-managed encryption
  - `pkg/backend/vault/sealer.go` - HashiCorp Vault Transit engine encryption
- **JWT SigningMethodSigner**: Hardware-backed JWT signing via `crypto.Signer` interface
  - Supports RS256/384/512, PS256/384/512, ES256/384/512, EdDSA
  - `SignWithSigner()` and `SignWithSignerAndKID()` convenience methods
- **Certificate Display Functions**: `pkg/certstore/types.go` with OID parsing, key usage display
- **Composite Sealing**: `pkg/keychain/composite_seal.go` for multi-backend seal operations
- **TPM2 Enhancements**: Certificate conversion, type re-exports, store abstraction
- **Logging Package**: Structured logging infrastructure (`pkg/logging/`)
- **Architecture Documentation**: Storage interfaces and BlobStorer refactoring guides

### Changed
- Extended `pkg/types/types.go` with Password, SealData, and Sealer interfaces
- Refactored internal TPM store with cleaner interfaces and helpers
- Improved overall test coverage from 85.8% to 91.2%

### Fixed
- Test coverage gaps across multiple packages:
  - `pkg/certstore`: 46.1% → 90.2%
  - `pkg/encoding/jwt`: 59.5% → 94.3%
  - `pkg/types`: 62.0% → 96.1%
  - `pkg/backend/threshold`: 72.5% → 81.7%
  - `pkg/storage/file`: 86.8% → 92.3%

## [0.1.6-alpha] - 2025-11-22

### Added
- Unified service pattern for simplified multi-backend management
- Backend factory pattern with auto-detection and configuration
- Comprehensive test coverage for service and factory (40+ test cases)
- Input validation for all API endpoints to prevent injection attacks
- Path traversal protection in file storage backend

### Changed
- Simplified API: `server.Initialize()` instead of `server.InitializeService()`
- Refactored keychain initialization with auto-backend detection
- Updated documentation and examples to reflect simplified API
- Improved code coverage from 72.8% to 92.5% in keychain package

### Security
- Centralized validation at service layer protects ALL public APIs (REST, gRPC, QUIC, CLI, MCP)
- All user inputs validated before reaching any backend or storage layer
- Created shared `pkg/validation` package for consistent validation across codebase
- Service layer validates all keyIDs, backend names, and key references
- Defense in depth: Storage layer also validates (though service should prevent bad input)
- Rejects special characters, null bytes, and directory traversal attempts
- Backend names: whitelist pattern `[a-z0-9\-]+` only (max 64 chars)
- KeyIDs: whitelist pattern `[a-zA-Z0-9_\-\.]+` only (max 255 chars)
- Key references support "backend:key-id" format with validation of both parts
- File storage protected against path traversal attacks
- Log injection prevention via sanitization of all logged user input

### Fixed
- Test coverage gaps in service and backend factory code
- Documentation examples now demonstrate clean, simple API usage
- Potential path traversal vulnerability in file storage operations

## [0.1.5-alpha] - 2025-11-19

### Changed
- Replaced minimal TPM2 implementation with full production-grade TPM support
- Complete TPM 2.0 integration with hierarchies, policies, and provisioning
- Enhanced TPM attestation and cryptographic operations
- Updated all security-critical dependencies to latest versions
  - golang.org/x/crypto: v0.42.0 → v0.45.0
  - google.golang.org/grpc: v1.76.0 → v1.77.0
  - AWS SDK v2, Prometheus, OpenTelemetry, TPM libraries
- Updated golangci-lint to v2.6.2 with action v7 for Go 1.25 compatibility
- Fixed TPM2 backend API compatibility with new config structure
- Removed redundant release tarballs (direct binary downloads only)

### Fixed
- Fixed TPM2 integration test build tags to properly include `tpm2` tag requirement
- Fixed TPM2 event log parsing to use absolute paths
- Resolved all 51 linting errors preventing CI builds (17 errcheck, 34 staticcheck)
  - Added proper error handling for unchecked error returns
  - Fixed JSON marshaling of function types (SessionCloser)
  - Resolved duplicate package imports and syntax errors
  - Suppressed false positive style warnings for embedded field accessors

## [0.1.4-alpha] - 2025-11-18

### Changed
- Internal refactoring and optimizations

## [0.1.3-alpha] - 2025-11-18

### Changed
- Refactored KeyAttributes to common library for better code reuse
- Improved type organization and reduced import cycles

## [0.1.2-alpha] - 2025-11-18

### Added
- Threshold cryptography package with Shamir Secret Sharing
- Split and combine secrets with configurable threshold

## [0.1.1-alpha] - 2025-11-17

### Added
- Quantum-safe signing support (post-quantum cryptography)
- Key encapsulation mechanisms (KEM) for quantum resistance

## [0.1.0-alpha] - 2025-01-15

### Overview

Initial alpha release of go-keychain - a production-ready cryptographic key and certificate management library for Go with 10 backends, 5 client interfaces, and dual licensing (AGPL-3.0 + Commercial).

### Added

#### Core Features
- Unified KeyStore interface for consistent key and certificate operations across all backends
- CompositeKeyStore pattern combining backend storage with certificate management
- Thread-safe concurrent operations with proper synchronization primitives
- Pluggable architecture for easy backend and storage extension

#### Key Management
- **Asymmetric Keys**: RSA (2048/3072/4096), ECDSA (P-256/P-384/P-521), Ed25519
- **Symmetric Keys**: AES-GCM (128/192/256-bit) with AEAD support
- **Operations**: Generate, store, retrieve, rotate, delete, import/export, wrap/unwrap
- **Standards**: Implements Go's `crypto.Signer` and `crypto.Decrypter` interfaces
- **Protection**: Password-protected PKCS#8 key storage with secure key derivation

#### Cryptographic Backends (10 Production-Ready)
1. **PKCS#8**: File-based asymmetric key storage
2. **AES**: File-based symmetric encryption backend
3. **Software**: Pure Go implementation for testing
4. **PKCS#11**: Hardware Security Module (HSM) integration
5. **SmartCard-HSM**: CardContact SmartCard-HSM with DKEK support
6. **TPM2**: Trusted Platform Module 2.0 with hierarchies and policies
7. **YubiKey**: YubiKey PIV (Smart Card) support
8. **AWS KMS**: Amazon Key Management Service integration
9. **GCP KMS**: Google Cloud Key Management Service integration
10. **HashiCorp Vault**: Vault Transit Engine integration

All backends support symmetric encryption (AES-GCM) and AEAD operations.

#### Certificate Management
- **CRUD Operations**: Store, retrieve, delete, list X.509 certificates
- **Certificate Chains**: Full chain management, building, and validation
- **CRL Support**: Certificate Revocation List management and checking
- **Validation**: Certificate verification with configurable `x509.VerifyOptions`
- **Hardware Storage**: Native PKCS#11 HSM and TPM2 NV RAM certificate storage
- **Hybrid Mode**: Automatic failover between hardware and external storage
- **Capacity Monitoring**: Certificate storage capacity management

#### Client Interfaces (100% API Coverage)
- **REST API**: HTTP/HTTPS web services with Fiber framework
- **gRPC**: High-performance RPC with Protocol Buffers
- **QUIC**: HTTP/3 over QUIC for ultra-low latency
- **CLI**: Full-featured command-line interface with Cobra
- **MCP**: Model Context Protocol (JSON-RPC) for AI integration

All interfaces expose the complete KeyStore API (17/17 methods).

#### Cryptographic Operations
- **Signing**: RSASSA-PSS, RSASSA-PKCS1-v1_5, ECDSA-SHA2, Ed25519
- **Verification**: Multi-algorithm signature verification
- **Asymmetric Encryption**: RSA-OAEP, RSA-PKCS1v15
- **Symmetric Encryption**: AES-128/192/256-GCM with nonce and tag management
- **AEAD**: Authenticated Encryption with Additional Data support
- **Hash Functions**: SHA-256, SHA-384, SHA-512, SHA3

#### Encoding & Interoperability
- **JWK**: JSON Web Key encoding/decoding (RSA, ECDSA, Ed25519, symmetric)
- **JWT**: JSON Web Token generation and validation (RS256, RS384, RS512, ES256, ES384, ES512, EdDSA)
- **JWE**: JSON Web Encryption with key wrapping (RSA-OAEP, AES-GCM)
- **PKCS#8**: Private/public key encoding with password protection
- **PEM**: PEM format encoding/decoding
- **Cross-Library Testing**: Verified interoperability with jose-go, go-jose, jwt-go

#### Security & Access Control
- **Authentication**: mTLS, API Key, NoOp (configurable per interface)
- **Authorization**: RBAC (Role-Based Access Control) integration
- **Audit Logging**: Comprehensive audit trail with structured logging
- **Policy Engine**: Configurable security policies
- **Metrics**: Prometheus-compatible metrics export
- **Correlation IDs**: Request tracing across all interfaces

#### Storage Abstraction
- **File Storage**: Production file-based storage with atomic operations
- **Memory Storage**: In-memory storage for testing
- **Filesystem Interface**: Custom FS implementation support (similar to io/fs)
- **Atomic Operations**: Safe concurrent file operations

#### Testing & Quality
- **Unit Tests**: 93.3% average code coverage across 25+ packages
- **Integration Tests**: 151 passing tests across all 10 backends
- **Benchmark Tests**: Performance benchmarks for critical operations
- **Docker Integration**: Complete Docker Compose test environments
- **Security Scanning**: gosec integration for vulnerability detection
- **Linting**: golangci-lint with comprehensive rulesets

#### Build System
- **Makefile**: 50+ targets for building, testing, and deployment
- **Version Injection**: Automatic version embedding in binaries via ldflags
- **Build Tags**: Conditional compilation for optional backends
- **Binary Builds**: CLI and 5 server binaries with proper versioning
- **Shared Library**: CGO-based libkeychain.so with version numbering
- **Cross-Platform**: Linux and macOS support (Windows experimental)
- **CI/CD Ready**: GitLab CI configuration included

#### Documentation
- Getting Started guide with step-by-step instructions
- Backend-specific configuration guides (10 backends)
- Certificate Management best practices
- Symmetric Encryption guide
- API Parity documentation (REST/gRPC/QUIC/CLI/MCP)
- Build System documentation
- 15+ working examples covering all features

#### Licensing
- **Dual Licensed**: AGPL-3.0 (open source) + Commercial License
- **Copyright**: Jeremy Hahn & Automate The Things, LLC
- **Source Headers**: All 502 Go files updated with dual-license notice
- **Commercial Options**: Available from Automate The Things, LLC
- **SPDX Compliant**: Proper license identifiers throughout

### Changed
- Updated from Apache 2.0 to dual licensing model (AGPL-3.0 + Commercial)
- Reorganized documentation structure to match standard patterns
- Consolidated type definitions into pkg/types to prevent import cycles
- Enhanced error handling with typed errors and proper error wrapping

### Fixed
- Import/export functionality across all backends
- Symmetric encryption support in cloud KMS backends (AWS, GCP, Azure)
- Test coverage gaps in backend implementations
- Race conditions in concurrent operations
- Memory leaks in long-running server processes

### Security
- All source code scanned with gosec
- No high-severity vulnerabilities
- Secure random number generation for all cryptographic operations
- Protection against timing attacks in key operations
- Safe handling of sensitive data with proper zeroing

### Known Limitations (Alpha Release)
- API may change before v1.0.0 (backward compatibility maintained where possible)
- Some cloud KMS operations require active network connectivity
- TPM2 integration requires hardware TPM or software simulator (swtpm)
- YubiKey support requires physical device
- Windows support is experimental and not fully tested
- Azure Key Vault backend requires valid Azure credentials

### Performance
- Key generation: <100ms for RSA-2048, <50ms for ECDSA-P256, <10ms for Ed25519
- Signing: <10ms for RSA, <5ms for ECDSA, <1ms for Ed25519
- Symmetric encryption: <1ms for AES-256-GCM (1KB payload)
- Certificate operations: <5ms for storage/retrieval

### Contributors
- Jeremy Hahn (@jeremyhahn)

### Links
- Repository: https://github.com/jeremyhahn/go-keychain
- Documentation: https://github.com/jeremyhahn/go-keychain/tree/master/docs
- Commercial Licensing: licensing@automatethethings.com
- AGPL-3.0 License: https://www.gnu.org/licenses/agpl-3.0.html

[0.2.2-alpha]: https://github.com/jeremyhahn/go-keychain/releases/tag/v0.2.2-alpha
[0.2.1-alpha]: https://github.com/jeremyhahn/go-keychain/releases/tag/v0.2.1-alpha
[0.2.0-alpha]: https://github.com/jeremyhahn/go-keychain/releases/tag/v0.2.0-alpha
[0.1.9-alpha]: https://github.com/jeremyhahn/go-keychain/releases/tag/v0.1.9-alpha
[0.1.8-alpha]: https://github.com/jeremyhahn/go-keychain/releases/tag/v0.1.8-alpha
[0.1.7-alpha]: https://github.com/jeremyhahn/go-keychain/releases/tag/v0.1.7-alpha
[0.1.6-alpha]: https://github.com/jeremyhahn/go-keychain/releases/tag/v0.1.6-alpha
[0.1.5-alpha]: https://github.com/jeremyhahn/go-keychain/releases/tag/v0.1.5-alpha
[0.1.4-alpha]: https://github.com/jeremyhahn/go-keychain/releases/tag/v0.1.4-alpha
[0.1.3-alpha]: https://github.com/jeremyhahn/go-keychain/releases/tag/v0.1.3-alpha
[0.1.2-alpha]: https://github.com/jeremyhahn/go-keychain/releases/tag/v0.1.2-alpha
[0.1.1-alpha]: https://github.com/jeremyhahn/go-keychain/releases/tag/v0.1.1-alpha
[0.1.0-alpha]: https://github.com/jeremyhahn/go-keychain/releases/tag/v0.1.0-alpha
