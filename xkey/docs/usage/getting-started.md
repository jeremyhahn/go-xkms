# Getting Started with go-xkms

> **Status: REFERENCE** · Last verified: 2026-10-13
> Library walkthrough for the `pkg/xkms` service API and the Go SDK; superseded by [crypto-backends](../../../docs/crypto-backends/user.md) and the [Go SDK README](../../../sdk/go/README.md). Where they disagree, those win.

## Overview

go-xkms is a cryptographic key management library for Go that provides one interface across software, hardware and cloud backends.

This guide covers three initialization patterns: auto-discovery, manual multi-backend setup, and the client/server Go SDK.

## Installation

```bash
go get github.com/jeremyhahn/go-xkms
```

## Build Configuration

go-xkms uses build tags to compile its optional backends. Through `make`,
**every backend is compiled in by default** (`Makefile:19-41`); opt one out
with its `WITH_*=0` variable. A configuration that names a backend the binary
was built without fails `AutoInitialize` with an `*xkms.FeatureNotCompiledError`
(`pkg/xkms/errors_auto.go:35`) naming the toggle to set.

### Build Profiles

```bash
# Every backend (the default)
make build-full

# No optional backend
make build-minimal

# The default build without the cloud providers (umbrella toggles, Makefile:52-54)
make build WITH_AWS=0 WITH_GCP=0 WITH_AZURE=0

# The default build without PKCS#11 and Vault
make build WITH_PKCS11=0 WITH_VAULT=0
```

### Using Build Tags Directly

A plain `go build ./...` passes no tags, so it builds the minimal set. Pass
the tags yourself to choose backends:

```bash
# Every backend
go build -tags "pkcs8 tpm2 pkcs11 awskms gcpkms azurekv vault frost" ./...

# Software plus AWS KMS
go build -tags "awskms" ./...
```

### Backend Build Tags

| Backend | Build Tag | Makefile Variable |
|---------|-----------|-------------------|
| Software | none | — |
| PKCS#8 | `pkcs8` | `WITH_PKCS8` |
| TPM2 | `tpm2` | `WITH_TPM2` |
| PKCS#11 | `pkcs11` | `WITH_PKCS11` |
| AWS KMS | `awskms` | `WITH_AWS_KMS` |
| GCP KMS | `gcpkms` | `WITH_GCP_KMS` |
| Azure Key Vault | `azurekv` | `WITH_AZURE_KV` |
| HashiCorp Vault | `vault` | `WITH_VAULT` |
| FROST | `frost` | `WITH_FROST` |

The full toggle list, provider umbrellas and profile targets are in
[Build toggles](../../../docs/crypto-backends/engineering.md#build-toggles).

## Quick Start (Pattern A: Auto-Initialize)

`AutoInitialize` (`pkg/xkms/auto.go:71`) discovers all compiled-in backends and sets them up. Every key, sign and certificate call takes a `context.Context`:

```go
package main

import (
    "context"
    "crypto/elliptic"
    "crypto/x509"
    "fmt"
    "log"

    "github.com/jeremyhahn/go-xkms/pkg/types"
    "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

func main() {
    ctx := context.Background()

    // Discover what's compiled in
    fmt.Println("Available backends:", xkms.SupportedBackends())

    // Auto-initialize all compiled-in backends (nil = in-memory storage)
    if err := xkms.AutoInitialize(nil); err != nil {
        log.Fatal(err)
    }
    defer xkms.Close()

    // Generate a key
    key, err := xkms.GenerateKey(ctx, &types.KeyAttributes{
        CN:            "my-signing-key",
        Backend:       "software",
        KeyAlgorithm:  x509.ECDSA,
        ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Generated key: %T\n", key)

    // Sign data using the key ID format "backend:type:algo:keyname"
    sig, err := xkms.Sign(ctx, "software:::my-signing-key", []byte("Hello, go-xkms!"), nil)
    if err != nil {
        log.Fatal(err)
    }

    // Verify the signature
    if err := xkms.Verify(ctx, "software:::my-signing-key", []byte("Hello, go-xkms!"), sig, nil); err != nil {
        log.Fatal(err)
    }
    fmt.Println("Signature verified")
}
```

`KeyAttributes.Backend` is the registry name that routes the call;
`StoreType` is derived from the resolved backend and is not used for routing
(`pkg/types/types.go:1178-1195`).

### Auto-Initialize with Persistent Storage

`AutoConfig` (`pkg/xkms/auto.go:23`) has three fields: `Datastore`,
`DefaultBackend` and `BackendConfigs`. The package never opens a directory
itself; pass a `storage.Backend` as `Datastore` and every backend's key
storage is a prefixed view of it:

```go
err := xkms.AutoInitialize(&xkms.AutoConfig{
    Datastore:      datastore, // a storage.Backend, e.g. from pkg/storage/file
    DefaultBackend: "software",
})
defer xkms.Close()
```

### Auto-Initialize with Backend-Specific Configuration

`BackendConfigs` overrides one backend's settings. The common key is
`key_storage`, a pre-built `storage.Backend`:

```go
err := xkms.AutoInitialize(&xkms.AutoConfig{
    Datastore: datastore,
    BackendConfigs: map[xkms.BackendType]map[string]interface{}{
        xkms.BackendSoftware: {
            "key_storage": softwareKeys,
        },
    },
})
defer xkms.Close()
```

## Multi-Backend Architecture (Pattern B: Manual Init)

For full control over which backends are initialized, build them yourself and call `Initialize` (`pkg/xkms/service.go:507`):

```go
package main

import (
    "context"
    "crypto/elliptic"
    "crypto/x509"
    "log"

    "github.com/jeremyhahn/go-xkms/pkg/backend/software"
    "github.com/jeremyhahn/go-xkms/pkg/storage/file"
    "github.com/jeremyhahn/go-xkms/pkg/types"
    "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

func main() {
    ctx := context.Background()

    keyStore, err := file.New("/var/lib/xkms/keys")
    if err != nil {
        log.Fatal(err)
    }
    certStore, err := file.New("/var/lib/xkms/certs")
    if err != nil {
        log.Fatal(err)
    }

    // A software key provider
    keyProvider, err := software.NewBackend(&software.Config{
        KeyStorage: keyStore,
    })
    if err != nil {
        log.Fatal(err)
    }

    // Wrap it in xkms.Backend (adds certificate storage, TLS, unified API)
    softwareBackend, err := xkms.New(&xkms.BackendConfig{
        Backend:     keyProvider,
        CertStorage: certStore,
    })
    if err != nil {
        log.Fatal(err)
    }

    err = xkms.Initialize(&xkms.ServiceConfig{
        Backends:       map[string]xkms.Backend{"software": softwareBackend},
        DefaultBackend: "software",
    })
    if err != nil {
        log.Fatal(err)
    }
    defer xkms.Close()

    // The service API is identical to Pattern A
    if _, err := xkms.GenerateKey(ctx, &types.KeyAttributes{
        CN:            "my-key",
        Backend:       "software",
        KeyAlgorithm:  x509.ECDSA,
        ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
    }); err != nil {
        log.Fatal(err)
    }
}
```

`file.New` is `pkg/storage/file/storage.go:59`, `software.NewBackend` is
`pkg/backend/software/software.go:147`, and `xkms.New` with `BackendConfig` is
`pkg/xkms/keystore.go:217-248`. `ServiceConfig` also has a `KeyProviders` map
for partial providers (`service.go:216`).

### Multiple Backends

Register several backends and route by key ID prefix:

```go
err := xkms.Initialize(&xkms.ServiceConfig{
    Backends: map[string]xkms.Backend{
        "software": softwareBackend,
        "tpm2":     tpm2Backend,
        "awskms":   awsBackend,
    },
    DefaultBackend: "software",
})
defer xkms.Close()

sig1, err := xkms.Sign(ctx, "software:::app-key", data, nil)
sig2, err := xkms.Sign(ctx, "tpm2:::device-key", data, nil)
sig3, err := xkms.Sign(ctx, "awskms:::cloud-key", data, nil)
```

How to construct each hardware or cloud backend is in its feature docs:
[TPM2](../../../docs/tpm2/user.md), [PKCS#11](../../../docs/pkcs11-backend/user.md)
and [crypto-backends](../../../docs/crypto-backends/user.md) for the cloud
providers.

## Go SDK - Client/Server (Pattern C)

For client/server deployments, use the Go SDK to talk to a running xkmsd:

```go
package main

import (
    "context"
    "fmt"
    "log"

    xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

func main() {
    ctx := context.Background()

    // Connect via URL (protocol chosen from the scheme)
    client, err := xkms.NewFromURL("https://kms.example.com:8443")
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    if err := client.Connect(ctx); err != nil {
        log.Fatal(err)
    }

    resp, err := client.GenerateKey(ctx, &xkms.GenerateKeyRequest{
        KeyID:   "my-signing-key",
        Backend: "software",
        KeyType: "EC",
        Curve:   "P-256",
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Generated key: %s\n", resp.KeyID)

    signResp, err := client.Sign(ctx, &xkms.SignRequest{
        Backend: "software",
        KeyID:   "my-signing-key",
        Data:    []byte("Hello, World!"),
        Hash:    "SHA256",
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Signature: %x\n", signResp.Signature)
}
```

`NewFromURL` is `sdk/go/xkms.go:260`; the request types are re-exported at
`sdk/go/xkms.go:333` and `:345` from `pkg/api/transport/types.go:68` and `:146`.
The supported URL schemes are listed in the [Go SDK README](../../../sdk/go/README.md).

### Embedded Mode (In-Process)

For the full `XKMSServicer` interface without a network server, wrap the
service singleton with `NewEmbedded` (`sdk/go/xkms.go:250`):

```go
if err := xkms.AutoInitialize(nil); err != nil {
    log.Fatal(err)
}
defer xkms.Close()

svc, err := xkms.Get() // pkg/xkms/service.go:233
if err != nil {
    log.Fatal(err)
}

client, err := xkmssdk.NewEmbedded(svc)
if err != nil {
    log.Fatal(err)
}

resp, err := client.GenerateKey(ctx, &transport.GenerateKeyRequest{
    KeyID:   "my-local-key",
    Backend: "software",
    KeyType: "EC",
    Curve:   "P-256",
})
```

Here `xkms` is `pkg/xkms`, `xkmssdk` is `sdk/go` and `transport` is
`sdk/go/transport`.

## Service API Reference

Once initialized, `pkg/xkms` exposes these top-level functions (all in
`pkg/xkms/service.go` unless noted). Every function except the discovery
helpers takes a `context.Context` first.

### Key Operations

| Function | Description |
|----------|-------------|
| `GenerateKey(ctx, attrs)` | Generate a new key, routed by `attrs.Backend` |
| `Key(ctx, attrs)` / `KeyByID(ctx, kid)` | Retrieve a key |
| `DeleteKey(ctx, attrs)` / `DeleteKeyByID(ctx, kid)` | Delete a key |
| `ListKeys(ctx, backend...)` | List key attributes, optionally per backend |
| `RotateKey(ctx, kid)` | Rotate an existing key |

### Signing and Verification

| Function | Description |
|----------|-------------|
| `Sign(ctx, kid, data, opts)` | Sign data; `SignOptions.Hash` defaults to SHA-256 (`service.go:1582`) |
| `Verify(ctx, kid, data, sig, opts)` | Verify a signature |
| `Signer(ctx, attrs)` | Get a `crypto.Signer` for a key |

### Symmetric Encryption

| Function | Description |
|----------|-------------|
| `GenerateSymmetricKey(ctx, backend, attrs)` | Generate a symmetric key |
| `Encrypt(ctx, kid, data, opts)` | Encrypt; returns `*types.EncryptedData` |
| `Decrypt(ctx, kid, encrypted, opts)` | Decrypt a `*types.EncryptedData` |

### Certificate Operations

| Function | Description |
|----------|-------------|
| `Certificate(ctx, attrs)` / `CertificateByID(ctx, kid)` | Get a certificate |
| `SaveCertificate(ctx, attrs, cert)` / `SaveCertificateByID(ctx, kid, cert)` | Save a certificate |
| `DeleteCertificate(ctx, attrs)` | Delete a certificate |
| `CertificateChain(ctx, attrs)` / `SaveCertificateChain(ctx, attrs, chain)` | Get or save a chain |
| `TLSCertificate(ctx, attrs)` | Get a `tls.Certificate` |
| `ListCertificates(ctx, backend...)` | List certificate IDs |

### Import/Export

| Function | Description |
|----------|-------------|
| `ExportKey(ctx, kid, algorithm)` | Export a key in wrapped form |
| `ImportKey(ctx, backend, attrs, wrapped)` | Import wrapped key material |
| `CopyKey(ctx, sourceKID, destBackend, attrs)` | Copy a key between backends |
| `GetImportParameters(ctx, backend, attrs, algo)` | Get import parameters |
| `WrapKey(ctx, backend, material, params)` | Wrap key material |

### Sealing

| Function | Description |
|----------|-------------|
| `Seal(ctx, data, opts)` | Seal data with the default backend |
| `SealWithBackend(ctx, name, data, opts)` | Seal with a specific backend |
| `Unseal(ctx, sealed, opts)` | Unseal previously sealed data |
| `CanSeal(backend...)` | Check whether sealing is supported |

### Backend Discovery

| Function | Description |
|----------|-------------|
| `SupportedBackends()` | Compiled-in backend types (`registry.go:150`) |
| `IsBackendSupported(name)` | Whether a backend is compiled in (`registry.go:167`) |
| `BackendCount()` | Count of compiled-in backends (`registry.go:173`) |
| `GetBackend(name)` | A specific backend instance |
| `GetBackendInfo(name)` | Backend metadata and capabilities |
| `Backends()` | Names of initialized backends |

### Key ID Format

The string-based API uses `backend:type:algo:keyname` (`pkg/xkms/keyid.go:27-44`).
All segments except `keyname` are optional:

- `"my-key"` -- uses the default backend
- `"software:::my-key"` -- routes to the `software` backend
- `"tpm2:signing:ecdsa-p256:my-key"` -- fully qualified

## Choosing a Backend

| Use case | Backend |
|----------|---------|
| Development, testing, CI | Software |
| Desktop, edge, IoT with a TPM | TPM2 |
| Enterprise HSM or smart card | PKCS#11 |
| Cloud-hosted workloads | AWS KMS, GCP KMS, Azure Key Vault |
| Central secrets platform | HashiCorp Vault |

Per-backend capabilities are in [crypto-backends](../../../docs/crypto-backends/user.md).

## Key Management Patterns

### Key Generation

```go
// ECDSA key
ecKey, err := xkms.GenerateKey(ctx, &types.KeyAttributes{
    CN:            "ec-signing-key",
    Backend:       "software",
    KeyAlgorithm:  x509.ECDSA,
    ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
})

// RSA key
rsaKey, err := xkms.GenerateKey(ctx, &types.KeyAttributes{
    CN:            "rsa-encryption-key",
    Backend:       "software",
    KeyAlgorithm:  x509.RSA,
    RSAAttributes: &types.RSAAttributes{KeySize: 2048},
})

// Ed25519 key
edKey, err := xkms.GenerateKey(ctx, &types.KeyAttributes{
    CN:           "ed25519-signing-key",
    Backend:      "software",
    KeyAlgorithm: x509.Ed25519,
})
```

### Signing Operations

```go
sig, err := xkms.Sign(ctx, "software:::my-key", document, nil)

sig, err = xkms.Sign(ctx, "software:::my-key", document, &xkms.SignOptions{
    Hash: crypto.SHA512,
})

err = xkms.Verify(ctx, "software:::my-key", document, sig, nil)
```

### Key Rotation and Listing

```go
newKey, err := xkms.RotateKey(ctx, "software:::my-key")

allKeys, err := xkms.ListKeys(ctx)
softwareKeys, err := xkms.ListKeys(ctx, "software")
```

## Symmetric Encryption

```go
symKey, err := xkms.GenerateSymmetricKey(ctx, "software", &types.KeyAttributes{
    CN:                 "my-encryption-key",
    Backend:            "software",
    KeyType:            types.KeyTypeEncryption,
    SymmetricAlgorithm: types.SymmetricAES256GCM,
})

encrypted, err := xkms.Encrypt(ctx, "software:::my-encryption-key", plaintext, &types.EncryptOptions{
    AdditionalData: []byte("context"),
})

decrypted, err := xkms.Decrypt(ctx, "software:::my-encryption-key", encrypted, &types.DecryptOptions{
    AdditionalData: []byte("context"),
})
```

`types.SymmetricAES256GCM` is `pkg/types/types.go:477`; AES-128 and AES-192
GCM have sibling constants.

## Testing

```bash
# Unit tests
make test

# All integration tests (devcontainer)
make integration-test

# One backend
make integration-test-software
make integration-test-tpm2
make integration-test-pkcs11
make integration-test-awskms
make integration-test-gcpkms
make integration-test-azurekv
make integration-test-vault
```

Backend integration tests live in `test/integration/backend/` (software,
symmetric, TPM2) and in per-backend folders under `test/integration/`
(`pkcs11`, `awskms`, `gcpkms`, `azurekv`, `vault`, `tpm2`).

## Error Handling

```go
if err := xkms.AutoInitialize(nil); err != nil {
    var notCompiled *xkms.FeatureNotCompiledError
    switch {
    case errors.As(err, &notCompiled):
        log.Fatalf("rebuild with the named toggle: %v", err)
    case errors.Is(err, xkms.ErrNoBackendsAvailable):
        log.Fatal("no backends compiled in -- check build tags")
    default:
        log.Fatalf("initialization failed: %v", err)
    }
}
defer xkms.Close()

if _, err := xkms.GenerateKey(ctx, attrs); err != nil {
    switch {
    case errors.Is(err, xkms.ErrNotInitialized):
        log.Fatal("call xkms.AutoInitialize first")
    case errors.Is(err, xkms.ErrBackendNotFound):
        log.Fatal("backend not registered")
    default:
        log.Fatalf("key generation failed: %v", err)
    }
}
```

The sentinels are in `pkg/xkms/errors.go:31`, `:222` and `:367`.

## Server Bootstrap

For client/server deployments, a new client establishes trust in the server
and enrolls with xkey:

```bash
# Register the first admin, pinning the server's SPKI
xkey auth register --server https://kms.example.com:8443 \
    --email admin@example.com --spki-pin <sha256-pin>

# Enroll a client certificate for mTLS
xkey cert request --server https://kms.example.com:8443 --cn "alice@example.com"
```

`auth register` takes `--server`, `--email` (both required), `--spki-pin`,
`--tls-ca`, `--setup-token` and `--display-name`
(`xkey/cmd/xkey/cmd/auth.go:518-523`). `cert request` takes `--server` and
`--cn` (required), `--slot`, `--organization`, `--spki-pin`, `--profile` and
`--validity-days` (`xkey/cmd/xkey/cmd/cert.go:195-205`).

The barrier, including Shamir quorums, belongs to go-qrdb; the server unseals
it through its configured seal strategy. See the
[trust bootstrap architecture](../../../docs/trust-bootstrap/architecture.md)
for DANE, Noise and SPKI trust.

## Additional Resources

- [Crypto backends](../../../docs/crypto-backends/user.md)
- [TPM2](../../../docs/tpm2/user.md)
- [PKCS#11 backend](../../../docs/pkcs11-backend/user.md)
- [Go SDK README](../../../sdk/go/README.md)
