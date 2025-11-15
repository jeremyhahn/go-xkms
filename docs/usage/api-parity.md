# API Parity Status

This document tracks the implementation status of KeyStore interface methods across all client interfaces.

## Overview

go-keychain exposes its functionality through five client interfaces:
- **REST** - HTTP/HTTPS API
- **gRPC** - High-performance RPC
- **CLI** - Command-line interface
- **MCP** - Model Context Protocol (JSON-RPC)
- **QUIC** - HTTP/3 over QUIC

## KeyStore Interface (20 methods)

Located in: `pkg/keychain/keystore.go`

### Key Operations (7 methods)
1. `GenerateRSA` - Generate RSA private key
2. `GenerateECDSA` - Generate ECDSA private key
3. `GenerateEd25519` - Generate Ed25519 private key
4. `GetKey` - Retrieve existing private key
5. `DeleteKey` - Delete a private key
6. `ListKeys` - List all keys in backend
7. `RotateKey` - Rotate/update a key

## SymmetricBackend Interface (3 methods)

Located in: `pkg/backend/backend.go`

Access via: `keystore.Backend().(backend.SymmetricBackend)`

### Symmetric Key Operations (3 methods)
1. `GenerateSymmetricKey` - Generate AES symmetric key (128/192/256-bit)
2. `GetSymmetricKey` - Retrieve existing symmetric key
3. `SymmetricEncrypter` - Get encrypter interface for AEAD operations (Encrypt/Decrypt)

### Crypto Operations (2 methods)
8. `Signer` - Get crypto.Signer for key
9. `Decrypter` - Get crypto.Decrypter for key

### Certificate Operations (7 methods)
10. `SaveCert` - Save X.509 certificate
11. `GetCert` - Retrieve certificate
12. `DeleteCert` - Delete certificate
13. `SaveCertChain` - Save certificate chain
14. `GetCertChain` - Retrieve certificate chain
15. `ListCerts` - List all certificates
16. `CertExists` - Check if certificate exists

### TLS Helpers (1 method)
17. `GetTLSCertificate` - Get complete TLS certificate (key + cert + chain)

### Lifecycle (3 methods)
18. `Backend` - Get underlying backend
19. `CertStorage` - Get certificate storage
20. `Close` - Close keystore

## Implementation Status

| Method | REST | gRPC | CLI | MCP | QUIC | Notes |
|--------|------|------|-----|-----|------|-------|
| **Key Operations** |
| GenerateRSA | Yes | Yes | Yes | Yes | Yes | Full coverage |
| GenerateECDSA | Yes | Yes | Yes | Yes | Yes | P-256/P256 variants supported |
| GenerateEd25519 | Yes | Yes | Yes | Yes | Yes | Full coverage |
| GetKey | Yes | Yes | Yes | Yes | Yes | Full coverage |
| DeleteKey | Yes | Yes | Yes | Yes | Yes | Full coverage |
| ListKeys | Yes | Yes | Yes | Yes | Yes | Full coverage |
| RotateKey | Yes | Yes | Yes | Yes | Yes | Full coverage |
| **Symmetric Key Operations** |
| GenerateSymmetricKey | Yes | Pending | Yes | Yes | Yes | gRPC pending tooling |
| GetSymmetricKey | Yes | Pending | Yes | Yes | Yes | gRPC pending tooling |
| SymmetricEncrypter (Encrypt/Decrypt) | Yes | Pending | Yes | Yes | Yes | AES-GCM AEAD support |
| **Crypto Operations** |
| Signer (Sign) | Yes | Yes | Yes | Yes | Yes | Full coverage |
| Decrypter (Decrypt) | Yes | Yes | Yes | Yes | Yes | Full coverage |
| **Certificate Operations** |
| SaveCert | Yes | Yes | Yes | Yes | Yes | Full coverage |
| GetCert | Yes | Yes | Yes | Yes | Yes | Full coverage |
| DeleteCert | Yes | Yes | Yes | Yes | Yes | Full coverage |
| SaveCertChain | Yes | Yes | Yes | Yes | Yes | Full coverage |
| GetCertChain | Yes | Yes | Yes | Yes | Yes | Full coverage |
| ListCerts | Yes | Yes | Yes | Yes | Yes | Full coverage |
| CertExists | Yes | Yes | Yes | Yes | Yes | Full coverage |
| **TLS Helpers** |
| GetTLSCertificate | Yes | Yes | Yes | Yes | Yes | Full coverage |
| **Lifecycle** |
| Backend | No | No | No | No | No | Not exposed (internal) |
| CertStorage | No | No | No | No | No | Not exposed (internal) |
| Close | No | No | No | No | No | Not exposed (internal) |

## Coverage Summary

| Interface | Functional Methods | Coverage | Status |
|-----------|-------------------|----------|--------|
| **REST** | 20/20 | 100% | Complete |
| **gRPC** | 17/20 | 85% | Symmetric pending |
| **QUIC** | 20/20 | 100% | Complete |
| **CLI** | 20/20 | 100% | Complete |
| **MCP** | 20/20 | 100% | Complete |

**Note:** Lifecycle methods (Backend, CertStorage, Close) are intentionally not exposed in client APIs for security and encapsulation. Total functional methods: 20 (17 KeyStore + 3 SymmetricBackend).

## Additional Features

### REST
- Health check endpoint (`/health`)
- Backend listing (`/api/v1/backends`)
- Signature verification (not in KeyStore interface)

### gRPC
- Health check RPC
- Backend listing RPC
- Signature verification

### CLI
- Version command
- Config management
- Multiple output formats (text, JSON, table)
- Backend information commands

### MCP
- Event subscription system
- Health check method
- Backend listing
- Batch request support

### QUIC
- HTTP/3 transport
- Health check endpoint
- Backend listing

## Testing Status

All implemented methods have:
- Unit tests
- Integration tests
- End-to-end tests (Docker-based)

