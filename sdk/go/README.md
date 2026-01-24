# go-keychain SDK

Go SDK for the go-keychain Key Management System.

## Installation

```bash
go get github.com/jeremyhahn/go-keychain/sdk/go
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    keychain "github.com/jeremyhahn/go-keychain/sdk/go"
)

func main() {
    // Create a client using default Unix socket
    client, err := keychain.New(nil)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    ctx := context.Background()

    // Connect to the server
    if err := client.Connect(ctx); err != nil {
        log.Fatal(err)
    }

    // Check health
    health, err := client.Health(ctx)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Server status: %s (version: %s)\n", health.Status, health.Version)

    // Generate a key
    resp, err := client.GenerateKey(ctx, &keychain.GenerateKeyRequest{
        KeyID:   "my-signing-key",
        Backend: "software",
        KeyType: "EC",
        Curve:   "P-256",
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Generated key: %s\n", resp.KeyID)

    // Sign data
    signResp, err := client.Sign(ctx, &keychain.SignRequest{
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

## Supported Protocols

| Protocol | Scheme | Description |
|----------|--------|-------------|
| Unix Socket | `unix://` | Default, fastest for local |
| gRPC | `grpc://`, `grpcs://` | High-performance RPC |
| REST | `http://`, `https://` | HTTP/HTTPS REST API |
| QUIC | `quic://` | HTTP/3 over QUIC |
| Embedded | N/A | Direct in-process calls |

## Protocol Examples

### Unix Socket (Default)

```go
client, _ := keychain.New(nil)
// or
client, _ := keychain.New(&keychain.Config{
    Protocol: keychain.ProtocolUnix,
    Address:  "/path/to/keychain.sock",
})
```

### REST API

```go
client, _ := keychain.New(&keychain.Config{
    Protocol:   keychain.ProtocolREST,
    Address:    "https://localhost:8443",
    TLSEnabled: true,
})
// or
client, _ := keychain.NewFromURL("https://localhost:8443")
```

### gRPC

```go
client, _ := keychain.New(&keychain.Config{
    Protocol: keychain.ProtocolGRPC,
    Address:  "localhost:9443",
})
// or
client, _ := keychain.NewFromURL("grpc://localhost:9443")
```

### QUIC

```go
client, _ := keychain.New(&keychain.Config{
    Protocol: keychain.ProtocolQUIC,
    Address:  "localhost:8444",
})
// or
client, _ := keychain.NewFromURL("quic://localhost:8444")
```

### Embedded (In-Process)

```go
service := myKeychainService // implements KeychainServicer
client, _ := keychain.NewEmbedded(service)
```

## TLS Configuration

```go
client, _ := keychain.New(&keychain.Config{
    Protocol:              keychain.ProtocolREST,
    Address:               "https://localhost:8443",
    TLSEnabled:            true,
    TLSCAFile:             "/path/to/ca.pem",
    TLSCertFile:           "/path/to/client.pem",  // for mTLS
    TLSKeyFile:            "/path/to/client-key.pem",
    TLSInsecureSkipVerify: false,
})
```

## Supported Backends

| Backend | Type | Description |
|---------|------|-------------|
| `software` | Software | PKCS#8 file-based keys |
| `pkcs11` | Hardware | HSM/Smart card via PKCS#11 |
| `tpm2` | Hardware | TPM 2.0 module |
| `awskms` | Cloud | AWS Key Management Service |
| `gcpkms` | Cloud | Google Cloud KMS |
| `azurekv` | Cloud | Azure Key Vault |
| `vault` | Software | HashiCorp Vault |
| `quantum` | Software | Post-quantum (ML-DSA, ML-KEM) |
| `threshold` | Software | Threshold cryptography |
| `frost` | Software | FROST signatures (RFC 9591) |

## API Coverage

The SDK provides 100% coverage of the KeychainService API:

### Lifecycle
- `Connect()` - Establish connection
- `Close()` - Close connection
- `Health()` - Check server health

### Backends
- `ListBackends()` - List available backends
- `GetBackend()` - Get backend information

### Keys
- `GenerateKey()` - Generate a new key
- `ListKeys()` - List keys in a backend
- `GetKey()` - Get key information
- `DeleteKey()` - Delete a key
- `RotateKey()` - Rotate a key

### Cryptographic Operations
- `Sign()` - Sign data
- `Verify()` - Verify signature
- `Encrypt()` - Encrypt data (symmetric)
- `Decrypt()` - Decrypt data (symmetric)
- `EncryptAsym()` - Encrypt data (asymmetric)

### Certificates
- `GetCertificate()` - Get certificate
- `SaveCertificate()` - Save certificate
- `DeleteCertificate()` - Delete certificate
- `CertificateExists()` - Check if certificate exists
- `ListCertificates()` - List certificates
- `SaveCertificateChain()` - Save certificate chain
- `GetCertificateChain()` - Get certificate chain
- `GetTLSCertificate()` - Get TLS certificate bundle

### Import/Export
- `ImportKey()` - Import a key
- `ExportKey()` - Export a key
- `GetImportParameters()` - Get import parameters
- `WrapKey()` - Wrap key material
- `UnwrapKey()` - Unwrap key material
- `CopyKey()` - Copy key between backends

### Key Versioning
- `ListKeyVersions()` - List key versions
- `EnableKeyVersion()` - Enable a version
- `DisableKeyVersion()` - Disable a version
- `EnableAllKeyVersions()` - Enable all versions
- `DisableAllKeyVersions()` - Disable all versions

### Sealing (TPM2/Hardware)
- `Seal()` - Seal data
- `Unseal()` - Unseal data
- `CanSeal()` - Check sealing capability

## Error Handling

```go
resp, err := client.GetKey(ctx, "software", "my-key")
if err != nil {
    if errors.Is(err, keychain.ErrNotConnected) {
        // Handle not connected
    }
    if errors.Is(err, keychain.ErrKeyNotFound) {
        // Handle key not found
    }
    // Handle other errors
}
```

## License

Dual-licensed under AGPL-3.0 and Commercial License.
