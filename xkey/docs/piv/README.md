# PIV Smart Card Certificate Management

xkey includes PIV (Personal Identity Verification) certificate management compliant with NIST SP 800-73-4. Store, retrieve, export, and manage X.509 certificates in standard PIV slots using pluggable storage backends.

## Quick Start

```bash
# Store a certificate in the authentication slot
xkey piv store 9a /path/to/cert.pem

# Show certificate details
xkey piv show 9a

# List all certificates
xkey piv list
```

## PIV Slots

### Standard Slots

| Slot | Name | Purpose |
|------|------|---------|
| `9a` | PIV Authentication | Card and cardholder authentication to systems |
| `9c` | Digital Signature | Document signing and non-repudiation |
| `9d` | Key Management | Key establishment and secure key transport |
| `9e` | Card Authentication | Card authentication without cardholder interaction |

### Retired Key Management Slots

Slots `82` through `95` (20 total) store historical key management certificates for decryption of archived data.

## Command Reference

### piv store

Store a certificate in a PIV slot.

```
xkey piv store <slot> <cert-file>
```

| Argument | Description |
|----------|-------------|
| `slot` | PIV slot identifier (e.g., `9a`, `9c`, `9d`, `9e`, `82`-`95`) |
| `cert-file` | Path to PEM or DER encoded certificate file |

The certificate format is auto-detected. PEM files must contain a `CERTIFICATE` block. DER files are parsed as raw ASN.1.

**Examples:**

```bash
# Store PEM certificate in authentication slot
xkey piv store 9a /path/to/cert.pem

# Store DER certificate in digital signature slot
xkey piv store 9c /path/to/cert.der

# Store in a retired key management slot
xkey piv store 82 /path/to/old-cert.pem
```

**Output:**

```
Certificate stored in slot 9a (PIV Authentication)
  Subject:  CN=Alice
  Format:   pem
  Expires:  2027-01-31T00:00:00Z
```

### piv show

Show detailed certificate information for a slot.

```
xkey piv show <slot>
```

**Examples:**

```bash
# Show authentication certificate
xkey piv show 9a

# Show digital signature certificate
xkey piv show 9c
```

**Output:**

```
PIV Certificate - Slot 9a (PIV Authentication)
========================================

Subject:       CN=Alice,O=Example Corp
Issuer:        CN=Example CA
Serial Number: 1a2b3c
Not Before:    2025-01-01T00:00:00Z
Not After:     2027-01-01T00:00:00Z
Key Algorithm: ECDSA
Signature:     ECDSAWithSHA256
DNS Names:     alice.example.com
Key Usage:     Digital Signature
Ext Key Usage: Client Auth
Is CA:         false
```

### piv list

List all certificates in PIV slots.

```
xkey piv list [flags]
```

Aliases: `ls`

**Examples:**

```bash
# List all certificates
xkey piv list

# List with TPM2 backend
xkey piv --backend tpm2 list
```

**Output:**

```
PIV Certificates (2):

  Slot:        9a (PIV Authentication)
  Subject:     CN=Alice
  Issuer:      CN=Example CA
  Not Before:  2025-01-01T00:00:00Z
  Not After:   2027-01-01T00:00:00Z
  Algorithm:   ECDSA
  Fingerprint: a1b2c3d4...

  Slot:        9c (Digital Signature)
  Subject:     CN=Alice Signing
  Issuer:      CN=Example CA
  Not Before:  2025-06-01T00:00:00Z
  Not After:   2027-06-01T00:00:00Z
  Algorithm:   RSA
  Fingerprint: e5f6a7b8...
```

### piv export

Export a certificate from a slot.

```
xkey piv export <slot> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `pem` | Export format: `pem` or `der` |
| `--output` | (stdout) | Output file path |

**Examples:**

```bash
# Export to PEM file
xkey piv export 9a --format pem --output /tmp/cert.pem

# Export to DER file
xkey piv export 9a --format der --output /tmp/cert.der

# Export to stdout (PEM)
xkey piv export 9a --format pem
```

### piv delete

Delete a certificate from a slot.

```
xkey piv delete <slot> [flags]
```

Aliases: `rm`, `remove`

| Flag | Default | Description |
|------|---------|-------------|
| `--force` | `false` | Skip confirmation prompt |

**Examples:**

```bash
# Delete with confirmation prompt
xkey piv delete 9a

# Force delete without confirmation
xkey piv delete --force 9c
```

**Output (with prompt):**

```
Delete certificate from slot 9a (PIV Authentication)?
  Subject: Alice
  Expires: 2027-01-01T00:00:00Z

Confirm deletion [y/N]: y
Certificate deleted from slot 9a (PIV Authentication)
```

### piv status

Show PIV storage status.

```
xkey piv status
```

**Examples:**

```bash
# Show storage status
xkey piv status

# Show status for TPM2 backend
xkey piv --backend tpm2 status
```

**Output:**

```
PIV Certificate Storage Status
==============================

Key Backend:       software
Storage Type:      file
Storage Path:      /var/lib/xkey/piv

Slot Status:

  [9a] PIV Authentication
        Subject:  CN=Alice
        Expires:  2027-01-01T00:00:00Z
  [9c] Digital Signature - Empty
  [9d] Key Management - Empty
  [9e] Card Authentication - Empty

Total Certificates: 1/4
```

## Global Flags

These flags are inherited by all `piv` subcommands.

| Flag | Default | Description |
|------|---------|-------------|
| `--backend` | `software` | Key backend: `software`, `tpm2`, or `pkcs11` |
| `--piv-storage` | (matches backend) | Certificate storage override: `file`, `tpm2`, or `pkcs11` |
| `--storage-path` | `/var/lib/xkey/piv` | Path for file storage |
| `--tpm-device` | `/dev/tpmrm0` | TPM device path |
| `--pkcs11-library` | `/usr/lib/softhsm/libsofthsm2.so` | PKCS#11 library path |
| `--pkcs11-token` | | PKCS#11 token label |
| `--pkcs11-pin` | | PKCS#11 user PIN |

## Storage Backends

Certificate storage defaults to match the key backend:

| Backend | Default Storage |
|---------|----------------|
| `software` | `file` |
| `tpm2` | `tpm2` |
| `pkcs11` | `pkcs11` |

Use `--piv-storage` to override. For example, use TPM2 keys with file-based certificate storage:

```bash
xkey piv --backend tpm2 --piv-storage file list
```

### File Storage

Certificates are stored in a structured directory hierarchy:

```
<storage_path>/piv/
  certificates/
    9a.der
    9a.pem
    9c.der
    9c.pem
  metadata/
    slots.json
```

- Both DER and PEM formats are written by default
- Atomic writes via temp file + rename for data integrity
- File permissions: `0600` (certificates), `0700` (directories)
- Maximum certificate size: 16 KB

### TPM2 Storage

Certificates are stored in TPM2 Non-Volatile (NV) storage indices. Each PIV slot maps to a specific NV index offset from a configurable base index (default: `0x01C00100`).

- Maximum certificate size: 4 KB (TPM NV constraint)
- Requires TPM resource manager (`/dev/tpmrm0`)

### PKCS#11 Storage

Certificates are stored as PKCS#11 certificate objects on a hardware token.

- Maximum certificate size: 8 KB (varies by token)
- Requires PKCS#11 library path and token label

## Configuration

All flags can be set via configuration file or environment variables through Viper:

| Config Key | Flag | Environment Variable |
|------------|------|---------------------|
| `piv.backend` | `--backend` | `PIV_BACKEND` |
| `piv.storage` | `--piv-storage` | `PIV_STORAGE` |
| `piv.storage_path` | `--storage-path` | `PIV_STORAGE_PATH` |
| `piv.tpm_device` | `--tpm-device` | `PIV_TPM_DEVICE` |
| `piv.pkcs11_library` | `--pkcs11-library` | `PIV_PKCS11_LIBRARY` |
| `piv.pkcs11_token` | `--pkcs11-token` | `PIV_PKCS11_TOKEN` |
| `piv.pkcs11_pin` | `--pkcs11-pin` | `PIV_PKCS11_PIN` |

## Example Workflows

### Set Up PIV Authentication

```bash
# Generate a key pair and CSR (external tool)
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout auth.key -out auth.csr -subj "/CN=Alice"

# Sign with your CA (external tool)
openssl x509 -req -in auth.csr -CA ca.pem -CAkey ca.key \
  -CAcreateserial -out auth.pem -days 730

# Store the certificate
xkey piv store 9a auth.pem

# Verify
xkey piv show 9a
```

### Certificate Rotation

```bash
# Check current certificate expiration
xkey piv show 9a

# Store new certificate (overwrites existing)
xkey piv store 9a new-cert.pem

# Export backup
xkey piv export 9a --format pem --output /backup/9a.pem
```

### Migrate Between Backends

```bash
# Export from file storage
xkey piv export 9a --format pem --output /tmp/9a.pem
xkey piv export 9c --format pem --output /tmp/9c.pem

# Import to TPM2 storage
xkey piv --backend tpm2 store 9a /tmp/9a.pem
xkey piv --backend tpm2 store 9c /tmp/9c.pem

# Verify
xkey piv --backend tpm2 status
```
