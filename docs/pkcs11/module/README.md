# PKCS#11 v3.0 Provider Module

The PKCS#11 Provider Module exposes go-keychain's key management capabilities through the standard PKCS#11 (Cryptoki) interface, enabling integration with OpenSSL, NSS, and any application supporting PKCS#11 tokens.

**Target Specification**: OASIS PKCS#11 v3.0 (June 2020)

## Purpose

This module turns go-keychain into a PKCS#11-compliant cryptographic token, allowing:

- OpenSSL applications to use go-keychain for key storage and signing
- SSH clients to use hardware-backed keys via PKCS#11
- Browser-based TLS client authentication
- Code signing tools requiring PKCS#11 tokens
- Any PKCS#11-aware application to access go-keychain keys

## Supported Communication Modes

| Mode | Library | Description | Use Case |
|------|---------|-------------|----------|
| **Embedded** | `libkeychain.so` | Links against libkeychain.so directly | Single-process apps, simple deployments |
| **Unix** | Direct IPC | go-codec based Unix socket IPC | Fast local IPC, same-host multi-process |
| **REST** | libcurl | HTTP/HTTPS JSON API | Remote access, web integrations |
| **gRPC** | grpc-c | Protocol Buffers RPC | High-performance remote access |
| **QUIC** | quiche/ngtcp2 | HTTP/3 over UDP | Low-latency remote access |

## Quick Start

### List Available Slots

```bash
export KEYCHAIN_PKCS11_MODE=embedded
pkcs11-tool --module /usr/lib/libkeychain_pkcs11.so --list-slots
```

### Generate an RSA Key Pair

```bash
pkcs11-tool --module /usr/lib/libkeychain_pkcs11.so \
  --login --pin 123456 \
  --keypairgen --key-type rsa:2048 \
  --label "my-signing-key"
```

### Generate an EC Key Pair

```bash
pkcs11-tool --module /usr/lib/libkeychain_pkcs11.so \
  --login --pin 123456 \
  --keypairgen --key-type EC:secp256r1 \
  --label "my-ec-key"
```

### Sign Data

```bash
pkcs11-tool --module /usr/lib/libkeychain_pkcs11.so \
  --login --pin 123456 \
  --sign --mechanism RSA-PKCS \
  --label "my-signing-key" \
  --input-file message.txt \
  --output-file signature.bin
```

### OpenSSL Integration

```bash
# Generate a certificate signing request
openssl req -engine pkcs11 \
  -keyform engine \
  -key "pkcs11:token=GO-KEYCHAIN;object=my-signing-key;type=private" \
  -new -out request.csr

# Sign with PKCS#11 key
openssl dgst -sha256 -engine pkcs11 \
  -keyform engine \
  -sign "pkcs11:token=GO-KEYCHAIN;object=my-signing-key;type=private" \
  -out signature.bin message.txt
```

### Remote Backend (Unix Socket)

```bash
# Start the keychain daemon
keychain daemon --unix /var/run/keychain/keychain.sock

# Use the Unix backend
export KEYCHAIN_PKCS11_MODE=unix
export KEYCHAIN_PKCS11_SOCKET=/var/run/keychain/keychain.sock

pkcs11-tool --module /usr/lib/libkeychain_pkcs11.so --list-slots
```

### Remote Backend (REST)

```bash
# Start the keychain REST server
keychain server --rest --listen :8443

# Use the REST backend
export KEYCHAIN_PKCS11_MODE=rest
export KEYCHAIN_PKCS11_URL=https://localhost:8443

pkcs11-tool --module /usr/lib/libkeychain_pkcs11.so --list-slots
```

## Supported Profiles

The module implements three PKCS#11 v3.0 profiles:

| Profile | Description | Use Case |
|---------|-------------|----------|
| **CKP_EXTENDED_PROVIDER** | Full mechanism support with login/logout | General purpose HSM replacement |
| **CKP_AUTHENTICATION_TOKEN** | Signing operations for authentication | TLS client auth, SSH, code signing |
| **CKP_PUBLIC_CERTIFICATES_TOKEN** | Certificate storage and retrieval | PKI integration, certificate management |

See [profiles.md](profiles.md) for detailed compliance information.

## Supported Mechanisms

| Mechanism | Description |
|-----------|-------------|
| `CKM_RSA_PKCS` | RSA PKCS#1 v1.5 signing/encryption |
| `CKM_RSA_PKCS_PSS` | RSA PSS signing |
| `CKM_RSA_PKCS_OAEP` | RSA OAEP encryption |
| `CKM_RSA_PKCS_KEY_PAIR_GEN` | RSA key generation |
| `CKM_ECDSA` | ECDSA signing |
| `CKM_ECDSA_SHA256` | ECDSA with SHA-256 |
| `CKM_EC_KEY_PAIR_GEN` | EC key generation |
| `CKM_EC_EDWARDS_KEY_PAIR_GEN` | Ed25519/Ed448 key generation |
| `CKM_EDDSA` | EdDSA signing |
| `CKM_AES_KEY_GEN` | AES key generation |
| `CKM_AES_CBC` | AES-CBC encryption |
| `CKM_AES_GCM` | AES-GCM authenticated encryption |

## Documentation

- [Architecture](architecture.md) - System design and component overview
- [Configuration](configuration.md) - Configuration options and environment variables
- [Usage](usage.md) - CLI and integration examples
- [API Reference](api.md) - C API documentation (keychain.h)
- [Profiles](profiles.md) - PKCS#11 v3.0 profile conformance
- [Security](security.md) - Security considerations
- [Implementation Checklist](implementation-checklist.md) - Development progress tracking

## Requirements

- go-keychain v0.3.0+
- CMake 3.16+
- C compiler (GCC or Clang)
- libcurl (for REST backend)
- grpc-c (for gRPC backend)
- quiche or ngtcp2 (for QUIC backend)

## Building

```bash
# Build libkeychain.so C API
make lib-capi

# Build PKCS#11 module (embedded backend)
make pkcs11-embedded

# Build with all backends (runtime selection)
make pkcs11-full

# Install
sudo make install-pkcs11
```

## References

- [PKCS#11 Base Specification v3.0](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html)
- [PKCS#11 Profiles v3.0](https://docs.oasis-open.org/pkcs11/pkcs11-profiles/v3.0/pkcs11-profiles-v3.0.html)
- [PKCS#11 Current Mechanisms v3.0](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/pkcs11-curr-v3.0.html)

## License

This module is part of go-keychain and is dual-licensed under AGPL-3.0 and Commercial licenses.
