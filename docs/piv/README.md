# PIV (Personal Identity Verification)

go-xkms implements PIV certificate and key management as defined by NIST SP 800-73-4. PIV provides a standardized framework for identity credentials -- associating X.509 certificates with named key slots -- used in government and enterprise environments for authentication, digital signatures, key management, and card-based authentication.

## Architecture

PIV in go-xkms follows the same transport-agnostic, backend-agnostic design as the rest of the system. Key generation is delegated through a `PIVKeyGenerator` interface, enabling any registered backend to generate and manage PIV keys.

```
+-------------------------------------------------------------+
|                     Applications                             |
|  (Go SDK, CLI, PKCS#11 clients, REST API consumers)         |
+-------------------------------------------------------------+
                          |
                          v
+-------------------------------------------------------------+
|                  PIV Service Layer                            |
|         pkg/xkms/servicer_piv.go + piv_manager.go            |
|  - Slot validation (9a, 9c, 9d, 9e, f9, 82-95)             |
|  - Certificate CRUD per slot per backend                     |
|  - Multi-backend key generation with self-signed certs       |
|  - CSR generation                                            |
+-------------------------------------------------------------+
          |                               |
          v                               v
+----------------------+     +---------------------------+
| PIVCertificateStorage|     |    PIVKeyGenerator         |
| (certificate storage)|     |    (key generation)        |
| - File system        |     |                           |
| - TPM2 NV            |     |  PIVBackendResolver maps  |
| - PKCS#11 token      |     |  backend name --> generator|
+----------------------+     +-------------+-------------+
                                            |
                          +-----------------+-----------------+
                          |                                   |
               +----------v-----------+        +--------------v-----------+
               | softwarePIVKeyGen    |        | backendPIVKeyGen          |
               | (in-memory signers)  |        | (delegates to Backend)   |
               | piv_keygen_software  |        | piv_keygen_backend       |
               +----------------------+        | - Software (PKCS#8)      |
                                               | - TPM2                   |
                                               | - PKCS#11 / HSM          |
                                               | - AWS KMS / GCP KMS      |
                                               | - Azure Key Vault        |
                                               +--------------------------+
```

### Transport-Agnostic

All PIV operations are exposed through the `transport.Client` interface. The same operations work identically over any supported transport:

- **gRPC** -- full-featured RPC with streaming support
- **REST** -- standard HTTP JSON API under `/api/v1/piv/`
- **QUIC** -- low-latency UDP-based transport
- **Unix socket** -- local IPC with kernel-enforced access control
- **MCP** -- Model Context Protocol for AI agent integration
- **Embedded** -- in-process, zero-copy direct function calls

### Backend-Agnostic

PIV slots work with any configured key backend. Certificate storage is independent from key storage, allowing mixed deployments (for example, keys in a TPM with certificates on the file system). The PIV manager maintains a per-backend certificate store via the `PIVCertificateStorage` interface.

### Multi-Backend Key Generation

PIV key generation uses a pluggable `PIVKeyGenerator` interface to abstract how keys are created across different backends.

**Core interfaces** (defined in `pkg/xkms/piv_manager.go`):

```go
// PIVKeyGenerator generates cryptographic keys for PIV slots.
type PIVKeyGenerator interface {
    GeneratePIVKey(slot pivcert.PIVSlot, algorithm string, cn string) (crypto.Signer, error)
    GetPIVSigner(slot pivcert.PIVSlot, cn string) (crypto.Signer, error)
}

// PIVBackendResolver maps a backend name to a PIVKeyGenerator.
type PIVBackendResolver func(backendName string) (PIVKeyGenerator, error)

// PIVParentProvider is an optional interface that backends can implement
// to provide parent key attributes for PIV key generation (e.g., TPM2 PlatformSRK).
type PIVParentProvider interface {
    PIVParentAttributes() (*types.KeyAttributes, error)
}
```

**Resolution flow:**

1. `GeneratePIVKey` or `GeneratePIVCSR` is called with a `Backend` name.
2. The `PIVBackendResolver` maps the backend name to a `PIVKeyGenerator`.
3. If no resolver is configured, the PIV manager falls back to software key generation.
4. The resolved generator creates the key using backend-native operations.

**Two generator implementations:**

| Generator | Source File | Behavior |
|-----------|------------|----------|
| `softwarePIVKeyGenerator` | `piv_keygen_software.go` | Generates keys using Go's standard `crypto` library. Stores signers in memory for later CSR generation. Used as the fallback when no resolver is configured. |
| `backendPIVKeyGenerator` | `piv_keygen_backend.go` | Delegates to any `Backend` implementation (TPM2, PKCS#11, software, cloud KMS). If the backend implements `PIVParentProvider`, parent key attributes (e.g., TPM2 PlatformSRK) are automatically applied. |

**Setting up the resolver** (done by the service layer at startup):

```go
// XKMSService.InitPIVBackendResolver wires up the resolver
// to look up registered backends by name.
func (s *XKMSService) InitPIVBackendResolver() error {
    resolver := func(backendName string) (PIVKeyGenerator, error) {
        b, err := GetBackend(backendName)
        if err != nil {
            return nil, err
        }
        storeType := types.ParseStoreType(backendName)
        return newBackendPIVKeyGenerator(b, storeType), nil
    }
    return SetPIVBackendResolver(resolver)
}
```

### Supported Algorithms

All PIV key generation operations accept an `algorithm` parameter. If omitted, the default is `ecdsap256`.

| Algorithm    | Key Type | Description              |
|--------------|----------|--------------------------|
| `rsa2048`    | RSA      | 2048-bit RSA key         |
| `rsa4096`    | RSA      | 4096-bit RSA key         |
| `ecdsap256`  | ECDSA    | P-256 elliptic curve key |
| `ecdsap384`  | ECDSA    | P-384 elliptic curve key |
| `ed25519`    | Ed25519  | Ed25519 key              |

### PIVParentProvider (TPM2 Integration)

When a backend implements the optional `PIVParentProvider` interface, the `backendPIVKeyGenerator` queries it for parent key attributes before generating the key. This allows TPM2 backends to place PIV keys under a specific parent hierarchy (e.g., PlatformSRK) without coupling the PIV layer to TPM-specific details.

```
GeneratePIVKey("tpm2", "9a", "ecdsap256")
  --> PIVBackendResolver("tpm2") --> backendPIVKeyGenerator
    --> backend.(PIVParentProvider).PIVParentAttributes()
      --> returns PlatformSRK attributes
    --> backend.GenerateECDSA(attrs with parent set)
    --> backend.Signer(attrs)
```

## PIV Slots

### Primary Slots

| Slot | Hex  | Name                | Purpose                         | Key Usage             |
|------|------|---------------------|---------------------------------|-----------------------|
| 9a   | 0x9A | PIV Authentication  | Client authentication (TLS, SSH)| DigitalSignature      |
| 9c   | 0x9C | Digital Signature   | Document/code signing           | DigitalSignature, ContentCommitment |
| 9d   | 0x9D | Key Management      | Encryption, key agreement       | KeyEncipherment, DataEncipherment   |
| 9e   | 0x9E | Card Authentication | Physical access, contactless    | DigitalSignature      |

### Retired Key Management Slots

Slots `82` through `95` (20 slots) provide backward-compatible storage for previously issued key management certificates, enabling decryption of data encrypted under older keys.

## SDK Usage

The Go SDK exposes PIV operations through the `xkms.Client` interface. All examples assume a connected client.

### Listing PIV Slots

```go
resp, err := client.ListPIVSlots(ctx, &xkms.ListPIVSlotsRequest{
    Backend: "software",
})
if err != nil {
    log.Fatal(err)
}

for _, slot := range resp.Slots {
    status := "empty"
    if slot.HasCert {
        status = fmt.Sprintf("cert: %s (%s, expires %s)",
            slot.Subject, slot.Algorithm, slot.NotAfter)
    }
    fmt.Printf("  %s (%s): %s\n", slot.Slot, slot.Name, status)
}
```

### Generating a Key in a Slot

```go
resp, err := client.GeneratePIVKey(ctx, &xkms.GeneratePIVKeyRequest{
    Backend:   "tpm2",
    Slot:      "9a",
    Algorithm: "ecdsap256",
    Subject:   "CN=alice@example.com",
})
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Generated key in slot %s\n", resp.Slot)
fmt.Printf("Self-signed certificate:\n%s\n", resp.Certificate)
fmt.Printf("Public key:\n%s\n", resp.PublicKey)
```

### Importing a Certificate

```go
certPEM, _ := os.ReadFile("alice-auth.pem")

err := client.StorePIVCertificate(ctx, &xkms.StorePIVCertificateRequest{
    Backend:     "software",
    Slot:        "9a",
    Certificate: certPEM,
    Format:      "pem",
})
if err != nil {
    log.Fatal(err)
}
```

### Exporting a Certificate

```go
resp, err := client.ExportPIVCertificate(ctx, &xkms.GetPIVCertificateRequest{
    Backend: "software",
    Slot:    "9a",
    Format:  "pem",
})
if err != nil {
    log.Fatal(err)
}

os.WriteFile("exported-9a.pem", resp.Certificate, 0600)
```

### Generating a CSR

```go
resp, err := client.GeneratePIVCSR(ctx, &xkms.GeneratePIVCSRRequest{
    Backend: "software",
    Slot:    "9c",
    Subject: "CN=alice@example.com,O=ACME Corp",
})
if err != nil {
    log.Fatal(err)
}

os.WriteFile("alice-signing.csr", resp.CSR, 0600)
```

### Deleting a Certificate

```go
err := client.DeletePIVCertificate(ctx, &xkms.DeletePIVCertificateRequest{
    Backend: "software",
    Slot:    "9a",
})
```

## REST API

All PIV endpoints live under `/api/v1/piv/`. When RBAC is enabled, each endpoint requires the appropriate `piv` resource permission.

| Method   | Endpoint                               | Permission | Description                    |
|----------|----------------------------------------|------------|--------------------------------|
| `GET`    | `/api/v1/piv/slots?backend={id}`       | list       | List all PIV slots and status  |
| `GET`    | `/api/v1/piv/slots/{slot}/certificate` | read       | Retrieve certificate from slot |
| `POST`   | `/api/v1/piv/slots/{slot}/certificate` | create     | Store certificate in slot      |
| `DELETE` | `/api/v1/piv/slots/{slot}/certificate` | delete     | Delete certificate from slot   |
| `POST`   | `/api/v1/piv/slots/{slot}/generate`    | create     | Generate key pair in slot      |
| `POST`   | `/api/v1/piv/slots/{slot}/import`      | import     | Import certificate into slot   |
| `GET`    | `/api/v1/piv/slots/{slot}/export`      | export     | Export certificate from slot   |
| `POST`   | `/api/v1/piv/slots/{slot}/csr`         | create     | Generate CSR for slot key      |

Query parameters common to all endpoints:
- `backend` -- backend identifier (required)
- `format` -- certificate format, `pem` or `der` (where applicable, defaults to `pem`)

## PKCS #11 Integration

PIV certificates are automatically exposed as PKCS #11 objects when the PKCS #11 module is configured with `piv_backends`. For each occupied PIV slot, three linked objects are created:

1. **CKO_CERTIFICATE** -- the X.509 certificate (DER-encoded)
2. **CKO_PUBLIC_KEY** -- the public key extracted from the certificate
3. **CKO_PRIVATE_KEY** -- a handle for signing/decryption (key material never leaves the backend)

All three objects share the same `CKA_ID`, computed as SHA-256 of `RawSubjectPublicKeyInfo` truncated to 20 bytes.

This mapping allows standard PKCS #11 tools (pkcs11-tool, OpenSSL, SSH) to discover and use PIV credentials transparently. See [PKCS #11 PIV Integration](../pkcs11/module/piv.md) for the full object mapping and configuration details.

## References

- [NIST SP 800-73-4](https://csrc.nist.gov/publications/detail/sp/800-73/4/final) -- Interfaces for Personal Identity Verification
- [NIST SP 800-76-2](https://csrc.nist.gov/publications/detail/sp/800-76/2/final) -- Biometric Specifications for PIV
- [Certificate Storage Architecture](certificate-storage-architecture.md) -- Detailed storage design
- [PKCS #11 PIV Integration](../pkcs11/module/piv.md) -- PKCS #11 object mapping

## License

Dual-licensed under AGPL-3.0 and Commercial licenses.
