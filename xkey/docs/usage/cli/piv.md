# CLI Reference: PIV Commands

PIV commands manage Personal Identity Verification (PIV) certificates and keys across backends. PIV provides standardized smart card slots for authentication, digital signatures, key management, and card authentication, following the NIST SP 800-73 specification.

## Commands

### piv list

List all PIV slots and their current status.

```bash
xkmsctl piv list [flags]
```

Retrieves the status of every PIV slot in the specified backend, showing which slots contain certificates and which are empty.

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--backend` | string | config default | Backend to query for PIV slots (global flag) |

**Examples:**

```bash
# List all PIV slots
xkmsctl piv list

# List slots for a specific backend
xkmsctl piv list --backend pkcs11
```

---

### piv get <slot>

Retrieve the certificate stored in a PIV slot.

```bash
xkmsctl piv get <slot> [flags]
```

Returns the certificate from the specified slot in the requested format. The output includes the slot identifier, format, and certificate data.

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--format` | string | `pem` | Certificate format: `pem` or `der` |

**Examples:**

```bash
# Get certificate in PEM format (default)
xkmsctl piv get 9a

# Get certificate in DER format
xkmsctl piv get 9c --format der

# Get certificate from a retired key management slot
xkmsctl piv get 82
```

---

### piv store <slot>

Store a certificate from a file into a PIV slot.

```bash
xkmsctl piv store <slot> [flags]
```

Reads a certificate from the specified file and stores it in the given PIV slot. The certificate file must be in the format indicated by the `--format` flag.

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--cert-file` | string | | Path to certificate file (required) |
| `--format` | string | `pem` | Certificate format: `pem` or `der` |

**Examples:**

```bash
# Store a PEM certificate in the authentication slot
xkmsctl piv store 9a --cert-file /path/to/cert.pem

# Store a DER certificate in the digital signature slot
xkmsctl piv store 9c --cert-file /path/to/cert.der --format der
```

---

### piv delete <slot>

Remove the certificate from a PIV slot.

```bash
xkmsctl piv delete <slot>
```

Deletes the certificate stored in the specified PIV slot. This operation does not destroy the underlying key pair if one was generated in the slot.

**Examples:**

```bash
# Delete certificate from the authentication slot
xkmsctl piv delete 9a

# Delete certificate from a retired key management slot
xkmsctl piv delete 85
```

---

### piv generate <slot>

Generate a new key pair in a PIV slot with a self-signed certificate.

```bash
xkmsctl piv generate <slot> [flags]
```

Creates a new asymmetric key pair in the specified slot and generates a self-signed certificate for it. The algorithm defaults to ECDSA P-256 if not specified. An optional subject can be provided for the self-signed certificate.

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--algorithm` | string | `ecdsap256` | Key algorithm: `rsa2048`, `rsa4096`, `ecdsap256`, `ecdsap384`, `ed25519` |
| `--subject` | string | | Certificate subject (e.g., `CN=MyKey`) |

**Examples:**

```bash
# Generate ECDSA P-256 key (default algorithm)
xkmsctl piv generate 9a

# Generate RSA 4096-bit key with subject
xkmsctl piv generate 9c --algorithm rsa4096 --subject "CN=SigningKey,O=MyOrg"

# Generate Ed25519 key in key management slot
xkmsctl piv generate 9d --algorithm ed25519 --subject "CN=KeyMgmt"

# Generate key in a retired slot
xkmsctl piv generate 82 --algorithm ecdsap384
```

---

### piv import <slot>

Import a certificate from a file into a PIV slot.

```bash
xkmsctl piv import <slot> [flags]
```

Reads a certificate from the specified file and imports it into the given PIV slot. This is typically used to import a CA-signed certificate after generating a CSR.

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--cert-file` | string | | Path to certificate file (required) |
| `--format` | string | `pem` | Certificate format: `pem` or `der` |

**Examples:**

```bash
# Import a CA-signed PEM certificate
xkmsctl piv import 9a --cert-file /path/to/signed-cert.pem

# Import a DER-encoded certificate
xkmsctl piv import 9c --cert-file /path/to/signed-cert.der --format der
```

---

### piv export <slot>

Export the certificate from a PIV slot to stdout.

```bash
xkmsctl piv export <slot> [flags]
```

Retrieves the certificate from the specified slot and outputs it. PEM format outputs the certificate as PEM text. DER format outputs the certificate as a base64-encoded DER blob.

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--format` | string | `pem` | Certificate format: `pem` or `der` |

**Examples:**

```bash
# Export certificate in PEM format
xkmsctl piv export 9a

# Export certificate in DER format (base64-encoded)
xkmsctl piv export 9c --format der

# Export and save to file
xkmsctl piv export 9a | jq -r '.certificate' > cert.pem
```

---

### piv csr <slot>

Generate a Certificate Signing Request using the key in a PIV slot.

```bash
xkmsctl piv csr <slot> [flags]
```

Creates a PKCS#10 Certificate Signing Request signed by the private key in the specified slot. The CSR can be submitted to a Certificate Authority for signing. A key pair must already exist in the slot before generating a CSR.

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--subject` | string | | CSR subject (e.g., `CN=MyKey,O=MyOrg`) |

**Examples:**

```bash
# Generate CSR with subject
xkmsctl piv csr 9a --subject "CN=auth.example.com,O=Example Inc"

# Generate CSR and save to file
xkmsctl piv csr 9c --subject "CN=SigningKey" | jq -r '.csr' > request.csr
```

## PIV Slot Reference

| Slot | Name | Purpose |
|------|------|---------|
| `9a` | PIV Authentication | Authenticates the card holder to the system |
| `9c` | Digital Signature | Signs documents and emails (non-repudiation) |
| `9d` | Key Management | Encrypts and decrypts data, key exchange |
| `9e` | Card Authentication | Authenticates the card itself (contactless) |
| `82`-`95` | Retired Key Management | Stores previously used key management certificates (slots 82 through 95) |

## Supported Algorithms

| Algorithm | Description |
|-----------|-------------|
| `ecdsap256` | ECDSA with P-256 curve (default) |
| `ecdsap384` | ECDSA with P-384 curve |
| `ed25519` | Ed25519 (EdDSA) |
| `rsa2048` | RSA 2048-bit |
| `rsa4096` | RSA 4096-bit |

## Workflows

### Generate Key and Export CSR for CA Signing

```bash
# 1. Generate a key pair in the authentication slot
xkmsctl piv generate 9a --algorithm ecdsap256 --subject "CN=auth.example.com"

# 2. Generate a CSR for the CA
xkmsctl piv csr 9a --subject "CN=auth.example.com,O=Example Inc,C=US" | jq -r '.csr' > auth.csr

# 3. Submit auth.csr to your Certificate Authority
# (CA-specific process)
```

### Import CA-Signed Certificate

```bash
# 1. Import the signed certificate from the CA
xkmsctl piv import 9a --cert-file signed-cert.pem

# 2. Verify the certificate was stored
xkmsctl piv get 9a
```

### List Slots to Verify State

```bash
# List all slots to see which have certificates
xkmsctl piv list

# Check a specific slot
xkmsctl piv get 9a
```

### Full Lifecycle

```bash
# 1. Generate key pair with self-signed certificate
xkmsctl piv generate 9a --algorithm ecdsap256 --subject "CN=myservice"

# 2. Export the self-signed certificate (optional, for inspection)
xkmsctl piv export 9a | jq -r '.certificate'

# 3. Generate CSR for CA signing
xkmsctl piv csr 9a --subject "CN=myservice.example.com,O=MyOrg" | jq -r '.csr' > myservice.csr

# 4. (Submit CSR to CA and receive signed certificate)

# 5. Import the CA-signed certificate, replacing the self-signed one
xkmsctl piv import 9a --cert-file ca-signed-cert.pem

# 6. Verify the new certificate is in place
xkmsctl piv get 9a

# 7. List all slots to confirm overall state
xkmsctl piv list
```

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error (see stderr for details) |

Common error conditions:

- `piv get` on an empty slot returns `failed to get PIV certificate`
- `piv store` or `piv import` without `--cert-file` returns `--cert-file is required`
- `piv store` with an invalid file path returns `failed to read certificate file`
- `piv csr` on a slot with no key returns `failed to generate PIV CSR`
- `piv generate` with an unsupported algorithm returns `failed to generate PIV key`

## See Also

- [PIV Architecture](../../piv/README.md)
- [PKCS#11 Module](../../pkcs11/module/README.md)
- [Backends](../../backends/README.md)
- [Configuration Reference](../../configuration/README.md)
