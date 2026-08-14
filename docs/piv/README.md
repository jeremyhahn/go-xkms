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

PIV key generation supports multiple output formats: self-signed certificate, public key only, CSR, or CA-signed certificate.

**Self-Signed Certificate (Default)**

```go
resp, err := client.GeneratePIVKey(ctx, &xkms.GeneratePIVKeyRequest{
    Backend:      "tpm2",
    Slot:         "9a",
    Algorithm:    "ecdsap256",
    Subject:      "CN=alice@example.com",
    Organization: "ACME Corp",
    Country:      "US",
    OutputFormat: "self-signed",
    ValidityDays: 3650,
})
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Generated key in slot %s\n", resp.Slot)
fmt.Printf("Self-signed certificate:\n%s\n", resp.Certificate)
```

**Public Key Only (No Certificate)**

```go
resp, err := client.GeneratePIVKey(ctx, &xkms.GeneratePIVKeyRequest{
    Backend:      "software",
    Slot:         "9c",
    Algorithm:    "ecdsap256",
    OutputFormat: "public-key",
})
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Public key:\n%s\n", resp.PublicKey)
```

**CSR for CA Signing**

```go
resp, err := client.GeneratePIVKey(ctx, &xkms.GeneratePIVKeyRequest{
    Backend:      "tpm2",
    Slot:         "9c",
    Algorithm:    "ecdsap256",
    Subject:      "CN=alice@example.com,O=ACME Corp,C=US",
    OutputFormat: "csr",
})
if err != nil {
    log.Fatal(err)
}

fmt.Printf("CSR:\n%s\n", resp.CSR)
```

**CA-Signed Certificate**

```go
resp, err := client.GeneratePIVKey(ctx, &xkms.GeneratePIVKeyRequest{
    Backend:      "tpm2",
    Slot:         "9d",
    Algorithm:    "ecdsap256",
    Subject:      "CN=alice@example.com",
    Organization: "ACME Corp",
    Country:      "US",
    OutputFormat: "ca-signed",
    ValidityDays: 1095,
})
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Generated CA-signed certificate in slot %s\n", resp.Slot)
fmt.Printf("Certificate:\n%s\n", resp.Certificate)
if len(resp.ChainPEM) > 0 {
    fmt.Printf("CA Chain:\n%s\n", resp.ChainPEM)
}
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

## CLI Usage

The `xkey piv generate` command supports all key generation output formats with X.509 subject configuration.

### Self-Signed Certificate (Default)

```bash
xkey piv generate 9a --algorithm ECCP256 --subject "CN=alice@example.com" \
  --organization "ACME Corp" --country "US"
```

Output:
```
Key generated in slot 9a (PIV Authentication)
Algorithm: ECCP256
PIN Policy: once
Touch Policy: never
Public Key:
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
-----END PUBLIC KEY-----
```

Self-signed certificate is automatically stored in the slot.

### Public Key Only

```bash
xkey piv generate 9c --algorithm ECCP256 --output-format public-key -o public.pem
```

Output:
```
Public key generated for slot 9c (Digital Signature)
Public key written to public.pem
```

No certificate is stored; the private key remains in the slot for future CSR generation.

### Certificate Signing Request (CSR)

```bash
xkey piv generate 9c --algorithm ECCP256 --output-format csr \
  --subject "CN=alice@example.com,O=ACME Corp,C=US" -o alice.csr
```

Output:
```
CSR generated for slot 9c (Digital Signature)
CSR written to alice.csr
```

The CSR can then be submitted to a CA for signing:

```bash
# Submit CSR to local CA
xkmsctl ca sign-csr --in alice.csr --out alice.pem --profile piv-signature

# Or to a remote xkms CA via API
curl -X POST https://xkms.example.com/api/v1/ca/sign-csr \
  -H "Content-Type: application/pkcs10" \
  --data-binary @alice.csr > alice.pem
```

### CA-Signed Certificate

```bash
xkey piv generate 9d --algorithm ECCP256 --output-format ca-signed \
  --subject "CN=alice@example.com" --organization "ACME Corp" \
  --country "US" --validity-days 1095
```

Output:
```
CA-signed certificate generated in slot 9d (Key Management)
Algorithm: ECCP256
Subject: CN=alice@example.com
Certificate:
-----BEGIN CERTIFICATE-----
MIICxzCCAa+gAwIBAgIUXxW...
-----END CERTIFICATE-----
CA Chain:
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIUI...
-----END CERTIFICATE-----
```

The certificate and CA chain are stored, and the private key is securely held in the slot.

### X.509 Subject Configuration

All generation formats support customizable X.509 subject fields:

```bash
xkey piv generate 9a \
  --subject "CN=alice@example.com" \
  --organization "ACME Corp" \
  --country "US"
```

Supported flags:
- `--subject` -- Common Name (CN) for the certificate
- `--organization` -- Organization (O) field
- `--country` -- Country code (C, 2-letter ISO code)
- `--validity-days` -- Certificate validity period (days, 0 = default)

### PIN and Touch Policies

Control access policies for the generated key:

```bash
# Require PIN for every operation
xkey piv generate 9c --algorithm ECCP256 --pin-policy always

# Cache touch for 15 seconds
xkey piv generate 9d --algorithm ECCP256 --touch-policy cached

# No PIN, always require touch
xkey piv generate 9e --algorithm ECCP256 --pin-policy never --touch-policy always
```

PIN policies: `never`, `once` (default), `always`
Touch policies: `never` (default), `cached`, `always`

### Algorithm Selection

```bash
# ECDSA P-256 (default, recommended)
xkey piv generate 9a --algorithm ECCP256

# ECDSA P-384
xkey piv generate 9a --algorithm ECCP384

# RSA 2048-bit
xkey piv generate 9c --algorithm RSA2048

# RSA 4096-bit
xkey piv generate 9d --algorithm RSA4096

# Ed25519 (signature only)
xkey piv generate 9e --algorithm ED25519
```

### Overwriting Existing Keys

By default, `xkey piv generate` will prompt for confirmation if the slot already contains a key. Use `--force` to skip confirmation:

```bash
xkey piv generate 9a --algorithm ECCP256 --force
```

## CA Integration

When generating CA-signed certificates, the system automatically signs the CSR using a configured CA profile. Two CA sources are supported:

### Local Embedded CA

The embedded User CA (stored in the trust store) is used for local signing:

```bash
xkey piv generate 9a --output-format ca-signed \
  --subject "CN=alice@example.com"
```

CA profiles for PIV slots:
- `piv-authentication` (9a) -- TLS client authentication, SSH
- `piv-signature` (9c) -- Document/code signing, extended key usage for signatures
- `piv-key-management` (9d) -- Data encryption and key agreement
- `piv-card-auth` (9e) -- Physical access, contactless authentication

### Remote xkms CA Server

Configure a remote CA server for distributed signing:

```bash
xkey piv generate 9a --ca-server https://ca.example.com \
  --spki-pin sha256/4U8EWZmYKQvb+DYJMJZvT+M3s+9TbxYq5i8E...
```

The remote server verifies the CSR and issues a certificate with the specified profile.

## Attestation for Hardware Keys

When generating keys in hardware backends (TPM2, PKCS#11), the key generation is attested. When signing a CSR with a hardware key, the attestation can be included to prove the key is hardware-backed:

```bash
xkmsctl ca sign-csr --in alice.csr \
  --attestation-format tpm2 \
  --attestation-credential /path/to/ek-cert.pem
```

Supported attestation formats:
- `tpm2` -- TPM 2.0 attestation with EK (Endorsement Key) credential
- `yubikey-piv` -- YubiKey PIV attestation certificate

The server validates the attestation chain before signing. RBAC controls which roles can submit attested CSRs:
- `admin` -- Can sign any CSR
- `operator` -- Can sign CSRs with valid hardware attestation
- `user` -- Can only sign their own CSRs

## Settings: Identity Configuration

Global default X.509 subject fields can be configured in Settings → Identity. These defaults pre-populate certificate generation dialogs:

- **Common Name (CN)** -- Subject identifier
- **Organization (O)** -- Company or organization name
- **Organizational Unit (OU)** -- Department or team
- **Country (C)** -- 2-letter ISO country code
- **State/Province (ST)** -- State or province
- **Locality (L)** -- City or locality

When generating a certificate, these defaults are merged with command-line overrides. Example:

```bash
# Uses defaults for O, C from Settings, overrides CN
xkey piv generate 9a --subject "CN=alice@example.com"
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

### Generate Key Request

```bash
POST /api/v1/piv/slots/{slot}/generate?backend={id}

{
  "algorithm": "ecdsap256",
  "subject": "CN=alice@example.com",
  "organization": "ACME Corp",
  "country": "US",
  "output_format": "self-signed",
  "validity_days": 3650
}
```

Response (self-signed):
```json
{
  "slot": "9a",
  "algorithm": "ecdsap256",
  "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
}
```

Response (public-key):
```json
{
  "slot": "9a",
  "algorithm": "ecdsap256",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
}
```

Response (csr):
```json
{
  "slot": "9c",
  "algorithm": "ecdsap256",
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----\n"
}
```

Response (ca-signed):
```json
{
  "slot": "9d",
  "algorithm": "ecdsap256",
  "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "chain_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
}
```

### Request Parameters

| Parameter       | Type    | Description                                            |
|-----------------|---------|--------------------------------------------------------|
| `algorithm`     | string  | Key algorithm: `ecdsap256`, `ecdsap384`, `rsa2048`, `rsa4096`, `ed25519` (default: `ecdsap256`) |
| `subject`       | string  | Certificate subject CN (default: slot name)            |
| `organization`  | string  | X.509 Organization (O) field                           |
| `country`       | string  | X.509 Country (C) field, 2-letter ISO code            |
| `output_format` | string  | Output format: `self-signed`, `public-key`, `csr`, `ca-signed` (default: `self-signed`) |
| `validity_days` | integer | Certificate validity (days, 0 = default)              |

Query parameters common to all endpoints:
- `backend` -- backend identifier (required)
- `format` -- certificate format, `pem` or `der` (where applicable, defaults to `pem`)

## GUI Features

### PIV Key Generation Dialog

The enhanced PIV key generation dialog in xkey supports all output formats and subject configuration:

1. **Slot Selection** -- Choose from 9a, 9c, 9d, 9e
2. **Algorithm** -- Select ECCP256 (recommended), ECCP384, RSA2048, RSA4096, or Ed25519
3. **Output Format** -- Self-signed certificate, public key only, CSR, or CA-signed
4. **Subject Fields** -- CN, Organization, Organizational Unit, Country, State/Province, Locality
5. **Validity** -- Certificate validity period in days
6. **Advanced Options** -- PIN policy, touch policy, force overwrite

Subject fields are pre-populated from Settings → Identity defaults. The dialog validates inputs and prevents invalid combinations (e.g., Ed25519 with key management slots).

### Settings Identity Configuration

Settings → Identity tab allows configuration of global X.509 subject defaults:

- **Common Name** -- Default subject CN
- **Organization** -- Default O field
- **Organizational Unit** -- Default OU field
- **Country** -- Default C field (2-letter ISO code)
- **State/Province** -- Default ST field
- **Locality** -- Default L field

These defaults are merged with overrides in the key generation dialog, allowing quick certificate creation with consistent subject information.

## PKCS #11 Integration

PIV certificates are automatically exposed as PKCS #11 objects when the PKCS #11 module is configured with `piv_backends`. For each occupied PIV slot, three linked objects are created:

1. **CKO_CERTIFICATE** -- the X.509 certificate (DER-encoded)
2. **CKO_PUBLIC_KEY** -- the public key extracted from the certificate
3. **CKO_PRIVATE_KEY** -- a handle for signing/decryption (key material never leaves the backend)

All three objects share the same `CKA_ID`, computed as SHA-256 of `RawSubjectPublicKeyInfo` truncated to 20 bytes.

This mapping allows standard PKCS #11 tools (pkcs11-tool, OpenSSL, SSH) to discover and use PIV credentials transparently. See [PKCS #11 PIV Integration](../pkcs11/module/piv.md) for the full object mapping and configuration details.

## Key Generation Output Formats

| Format       | Output             | Certificate Stored | Use Case                    |
|--------------|-------------------|--------------------|-----------------------------|
| Self-Signed  | Cert + public key | Yes (self-signed)  | Quick testing, development  |
| Public-Key   | Public key only   | No                 | Share public key, keep private |
| CSR          | PKCS#10 CSR       | No (until signed)  | Submit to CA for signing    |
| CA-Signed    | Cert + chain      | Yes (CA-signed)    | Production certificates    |

## Default Certificate Validity

- **Self-Signed** -- 10 years (3650 days)
- **CA-Signed** -- 3 years (1095 days)
- **Custom** -- Configurable via `--validity-days` flag

## Supported Algorithms by Slot

| Slot | Authentication | Signature | Encryption | Card Auth |
|------|---|---|---|---|
| 9a   | Yes | Yes | No  | No  |
| 9c   | No  | Yes | No  | No  |
| 9d   | No  | No  | Yes | No  |
| 9e   | Yes | Yes | No  | Yes |

All algorithms (ECCP256, ECCP384, RSA2048, RSA4096, Ed25519) can be used for any slot, but key usage extensions in the certificate reflect the slot's intended purpose.

## References

- [NIST SP 800-73-4](https://csrc.nist.gov/publications/detail/sp/800-73/4/final) -- Interfaces for Personal Identity Verification
- [NIST SP 800-76-2](https://csrc.nist.gov/publications/detail/sp/800-76/2/final) -- Biometric Specifications for PIV
- [Certificate Storage Architecture](certificate-storage-architecture.md) -- Detailed storage design
- [TPM 2.0 NV Certificate Storage](tpm2-nv-storage.md) -- Slot to NV index mapping and error semantics
- [PKCS #11 PIV Integration](../pkcs11/module/piv.md) -- PKCS #11 object mapping
- [CA Integration Guide](../ca/README.md) -- Certificate authority operations
- [Attestation Guide](../attestation/README.md) -- Hardware key attestation

## License

Dual-licensed under AGPL-3.0 and Commercial licenses.
