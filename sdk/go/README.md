# go-xkms SDK

Go SDK for the go-xkms Key Management System.

## Installation

```bash
go get github.com/jeremyhahn/go-xkms/sdk/go
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

func main() {
    // Create a client using default Unix socket
    client, err := xkms.New(nil)
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

    // Sign data
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
client, _ := xkms.New(nil)
// or
client, _ := xkms.New(&xkms.BackendConfig{
    Protocol: xkms.ProtocolUnix,
    Address:  "/path/to/xkms.sock",
})
```

### REST API

```go
client, _ := xkms.New(&xkms.BackendConfig{
    Protocol:   xkms.ProtocolREST,
    Address:    "https://localhost:8443",
    TLSEnabled: true,
})
// or
client, _ := xkms.NewFromURL("https://localhost:8443")
```

### gRPC

```go
client, _ := xkms.New(&xkms.BackendConfig{
    Protocol: xkms.ProtocolGRPC,
    Address:  "localhost:9443",
})
// or
client, _ := xkms.NewFromURL("grpc://localhost:9443")
```

### QUIC

```go
client, _ := xkms.New(&xkms.BackendConfig{
    Protocol: xkms.ProtocolQUIC,
    Address:  "localhost:8444",
})
// or
client, _ := xkms.NewFromURL("quic://localhost:8444")
```

### Embedded (In-Process)

```go
service := myXKMSService // implements XKMSServicer
client, _ := xkms.NewEmbedded(service)
```

## TLS Configuration

### Recommended: SPKI Pin (Trust-on-First-Use)

```go
// Use WithSPKIPin for trust-on-first-use without requiring a CA certificate.
// Obtain the pin via: xkmsctl spki-pin --server <address>
client, _ := xkms.NewWithOptions(
    xkms.WithProtocol(xkms.ProtocolREST),
    xkms.WithAddress("https://localhost:8443"),
    xkms.WithSPKIPin("abc123def456..."),
)
```

### Recommended: CA Certificate

```go
client, _ := xkms.New(&xkms.BackendConfig{
    Protocol:   xkms.ProtocolREST,
    Address:    "https://localhost:8443",
    TLSEnabled: true,
    TLSCAFile:  "/path/to/ca.pem",
})
```

### mTLS (Mutual TLS)

```go
client, _ := xkms.New(&xkms.BackendConfig{
    Protocol:   xkms.ProtocolREST,
    Address:    "https://localhost:8443",
    TLSEnabled: true,
    TLSCAFile:  "/path/to/ca.pem",
    TLSCertFile: "/path/to/client.pem",
    TLSKeyFile:  "/path/to/client-key.pem",
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

The SDK provides 100% coverage of the XKMSService API:

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

### PIV (Personal Identity Verification)
- `ListPIVSlots()` - List all PIV slots and their status
- `GetPIVCertificate()` - Get certificate from a PIV slot
- `StorePIVCertificate()` - Store a certificate in a PIV slot
- `DeletePIVCertificate()` - Delete certificate from a PIV slot
- `GeneratePIVKey()` - Generate a key pair in a PIV slot
- `ImportPIVCertificate()` - Import a certificate into a PIV slot
- `ExportPIVCertificate()` - Export certificate from a PIV slot
- `GeneratePIVCSR()` - Generate a CSR for a PIV slot key

### Barrier
- `BarrierInitialize()` - Initialize and seal the root encryption key
- `BarrierUnseal()` - Unseal the barrier for storage operations
- `BarrierSeal()` - Seal the barrier and zero the DEK
- `BarrierStatus()` - Get current barrier state

### PIN Management
- `SetSOPIN()` - Set the Security Officer PIN
- `SetUserPIN()` - Set the user PIN (requires SO PIN)
- `ChangeSOPIN()` - Change the Security Officer PIN
- `ChangeUserPIN()` - Change the user PIN
- `VerifySOPIN()` - Verify the Security Officer PIN
- `VerifyUserPIN()` - Verify the user PIN
- `GetLockoutStatus()` - Get PIN lockout status
- `ResetLockout()` - Reset lockout counter (requires SO PIN)

## Usage Examples

### PIV Operations

```go
// Generate a PIV key and get a CSR
resp, err := client.GeneratePIVKey(ctx, &xkms.GeneratePIVKeyRequest{
    Backend:   "pkcs11",
    Slot:      "9a",
    Algorithm: "ecdsap256",
    Subject:   "CN=My PIV Key",
})

// Generate a CSR for CA signing
csrResp, err := client.GeneratePIVCSR(ctx, &xkms.GeneratePIVCSRRequest{
    Backend: "pkcs11",
    Slot:    "9a",
    Subject: "CN=My PIV Key,O=My Org",
})

// List all PIV slots
slots, err := client.ListPIVSlots(ctx, &xkms.ListPIVSlotsRequest{
    Backend: "pkcs11",
})
```

### Barrier Operations

```go
// Initialize the barrier (first-time setup)
err := client.BarrierInitialize(ctx, &xkms.BarrierInitializeRequest{
    Secret: "my-secure-passphrase",
})

// Check barrier status
status, err := client.BarrierStatus(ctx)
fmt.Printf("Sealed: %v, Strategy: %s\n", status.Sealed, status.Strategy)

// Unseal on restart
err = client.BarrierUnseal(ctx, &xkms.BarrierUnsealRequest{
    Secret: "my-secure-passphrase",
})
```

### PIN Management

```go
// Set SO PIN (first-time setup, no current SO PIN)
err := client.SetSOPIN(ctx, &xkms.SetSOPINRequest{
    NewSoPin: "123456",
})

// Set user PIN (requires SO PIN)
err = client.SetUserPIN(ctx, &xkms.SetUserPINRequest{
    SoPin:      "123456",
    NewUserPin: "654321",
})

// Verify user PIN
err = client.VerifyUserPIN(ctx, &xkms.VerifyUserPINRequest{
    UserPin: "654321",
})

// Check lockout status
lockout, err := client.GetLockoutStatus(ctx)
fmt.Printf("Locked: %v, Attempts: %d/%d\n", lockout.IsLocked, lockout.FailedAttempts, lockout.MaxAttempts)
```

## Error Handling

```go
resp, err := client.GetKey(ctx, "software", "my-key")
if err != nil {
    if errors.Is(err, xkms.ErrNotConnected) {
        // Handle not connected
    }
    if errors.Is(err, xkms.ErrKeyNotFound) {
        // Handle key not found
    }
    // Handle other errors
}
```

## License

Dual-licensed under AGPL-3.0 and Commercial License.
