# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.6-alpha] - 2025-11-22

### Added
- Unified facade pattern for simplified multi-backend management
- Backend factory pattern with auto-detection and configuration
- Comprehensive test coverage for facade and factory (40+ test cases)
- Input validation for all API endpoints to prevent injection attacks
- Path traversal protection in file storage backend

### Changed
- Simplified API: `server.Initialize()` instead of `server.InitializeFacade()`
- Refactored keychain initialization with auto-backend detection
- Updated documentation and examples to reflect simplified API
- Improved code coverage from 72.8% to 92.5% in keychain package

### Security
- Centralized validation at facade layer protects ALL public APIs (REST, gRPC, QUIC, CLI, MCP)
- All user inputs validated before reaching any backend or storage layer
- Created shared `pkg/validation` package for consistent validation across codebase
- Facade layer validates all keyIDs, backend names, and key references
- Defense in depth: Storage layer also validates (though facade should prevent bad input)
- Rejects special characters, null bytes, and directory traversal attempts
- Backend names: whitelist pattern `[a-z0-9\-]+` only (max 64 chars)
- KeyIDs: whitelist pattern `[a-zA-Z0-9_\-\.]+` only (max 255 chars)
- Key references support "backend:key-id" format with validation of both parts
- File storage protected against path traversal attacks
- Log injection prevention via sanitization of all logged user input

### Fixed
- Test coverage gaps in facade and backend factory code
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

[0.1.6-alpha]: https://github.com/jeremyhahn/go-keychain/releases/tag/v0.1.6-alpha
[0.1.5-alpha]: https://github.com/jeremyhahn/go-keychain/releases/tag/v0.1.5-alpha
[0.1.4-alpha]: https://github.com/jeremyhahn/go-keychain/releases/tag/v0.1.4-alpha
[0.1.3-alpha]: https://github.com/jeremyhahn/go-keychain/releases/tag/v0.1.3-alpha
[0.1.2-alpha]: https://github.com/jeremyhahn/go-keychain/releases/tag/v0.1.2-alpha
[0.1.1-alpha]: https://github.com/jeremyhahn/go-keychain/releases/tag/v0.1.1-alpha
[0.1.0-alpha]: https://github.com/jeremyhahn/go-keychain/releases/tag/v0.1.0-alpha
