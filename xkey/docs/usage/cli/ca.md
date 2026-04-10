# Certificate Authority CLI

The `ca` command group provides Certificate Authority (CA) operations for certificate lifecycle management, including certificate issuance, CSR signing, revocation, and CRL generation. A separate `ca tcg` subgroup handles Trusted Computing Group (TCG) device identity certificate operations for TPM enrollment.

## Table of Contents

- [Overview](#overview)
- [CA Commands](#ca-commands)
  - [bundle](#bundle)
  - [certificate](#certificate)
  - [sign-csr](#sign-csr)
  - [issue](#issue)
  - [revoke](#revoke)
  - [crl](#crl)
  - [status](#status)
- [TCG Commands](#tcg-commands)
  - [tcg issue-ek](#tcg-issue-ek)
  - [tcg issue-ak](#tcg-issue-ak)
  - [tcg sign-csr](#tcg-sign-csr)
  - [tcg enroll](#tcg-enroll)
- [Global Flags](#global-flags)
- [Multi-Protocol Usage](#multi-protocol-usage)
- [Examples](#examples)

## Overview

The `xkmsctl ca` commands interact with the XKMS Certificate Authority service for certificate lifecycle management. All CA commands communicate with the xkms server, which performs the actual cryptographic operations using its configured backend and CA key material.

All commands support multiple transport protocols. The protocol is selected via the `--server` flag (see [Multi-Protocol Usage](#multi-protocol-usage)).

## CA Commands

### bundle

Retrieve the CA certificate bundle in PEM format. The bundle contains the full CA certificate chain.

**Usage:**
```bash
xkmsctl ca bundle
```

**Flags:**

This command has no command-specific flags.

**Examples:**
```bash
# Get CA bundle and print to stdout
xkmsctl ca bundle

# Save CA bundle to a file
xkmsctl ca bundle > ca-bundle.pem

# Get CA bundle from a remote REST server
xkmsctl ca bundle --server https://xkms.example.com:8443
```

**Output:**
```
-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHCgVZU2T/MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCUV4
...
-----END CERTIFICATE-----
```

---

### certificate

Retrieve CA certificate details including subject, issuer, serial number, and validity period.

**Usage:**
```bash
xkmsctl ca certificate [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--identity` | string | `""` | CA identity/CN (empty for the default CA) |

**Examples:**
```bash
# Get default CA certificate info
xkmsctl ca certificate

# Get info for a specific CA identity
xkmsctl ca certificate --identity "Intermediate CA"

# Get CA certificate info in JSON format
xkmsctl ca certificate -o json
```

**Output (Text):**
```
CA Certificate Details:
  Subject:       CN=Example Root CA,O=Example Corp
  Issuer:        CN=Example Root CA,O=Example Corp
  Serial Number: 01AB23CD45EF6789
  Not Before:    2025-01-01T00:00:00Z
  Not After:     2035-01-01T00:00:00Z
  Is CA:         true
```

**Output (JSON):**
```json
{
  "subject": "CN=Example Root CA,O=Example Corp",
  "issuer": "CN=Example Root CA,O=Example Corp",
  "serial_number": "01AB23CD45EF6789",
  "not_before": "2025-01-01T00:00:00Z",
  "not_after": "2035-01-01T00:00:00Z",
  "is_ca": true
}
```

---

### sign-csr

Sign a Certificate Signing Request (CSR) using the CA. Reads a PEM-encoded CSR from a file and returns a signed certificate.

**Usage:**
```bash
xkmsctl ca sign-csr --csr <file> [flags]
```

**Flags:**

| Flag | Type | Default | Required | Description |
|------|------|---------|----------|-------------|
| `--csr` | string | | Yes | Path to CSR PEM file |
| `--profile` | string | `""` | No | Certificate profile (server, client, etc.) |
| `--validity` | int | `0` | No | Validity period in days (0 for CA default) |
| `--output` | string | `""` | No | Output file for signed certificate (PEM) |

**Examples:**
```bash
# Sign a CSR with default settings
xkmsctl ca sign-csr --csr request.pem

# Sign a CSR with a specific profile and validity
xkmsctl ca sign-csr --csr request.pem --profile server --validity 365

# Sign and write the certificate to a file
xkmsctl ca sign-csr --csr request.pem --output signed.pem

# Sign via gRPC and get JSON output
xkmsctl ca sign-csr --csr request.pem --server grpc://xkms.example.com:9443 -o json
```

**Output (Text, stdout):**
```
Serial Number: 5A3F8C21D6E47B90
-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHCgVZU2T/MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCUV4
...
-----END CERTIFICATE-----
```

**Output (Text, with --output):**
```
Serial Number: 5A3F8C21D6E47B90
Certificate written to: signed.pem
```

**Output (JSON, stdout):**
```json
{
  "serial_number": "5A3F8C21D6E47B90",
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
  "chain_pem": "-----BEGIN CERTIFICATE-----\n..."
}
```

**Output (JSON, with --output):**
```json
{
  "serial_number": "5A3F8C21D6E47B90",
  "cert_file": "signed.pem"
}
```

---

### issue

Issue a new certificate from the CA. The CA generates the key pair and returns the certificate, certificate chain, and private key.

**Usage:**
```bash
xkmsctl ca issue --cn <common-name> [flags]
```

**Flags:**

| Flag | Type | Default | Required | Description |
|------|------|---------|----------|-------------|
| `--cn` | string | | Yes | Common name for the certificate |
| `--profile` | string | `""` | No | Certificate profile (server, client, etc.) |
| `--org` | string | `""` | No | Organization name |
| `--sans` | string | `""` | No | Subject alternative names (comma-separated, e.g., `DNS:example.com,IP:1.2.3.4`) |
| `--validity` | int | `0` | No | Validity period in days (0 for CA default) |
| `--algorithm` | string | `""` | No | Key algorithm (ecdsa-p256, rsa2048, ed25519) |
| `--output` | string | `""` | No | Output file for certificate (PEM) |

When `--output` is specified, the private key is automatically written to `<output>.key` with permissions `0600`.

**Examples:**
```bash
# Issue a server certificate
xkmsctl ca issue --cn server.example.com --profile server

# Issue with organization and validity
xkmsctl ca issue --cn client@example.com --profile client --validity 365

# Issue with multiple SANs
xkmsctl ca issue --cn myserver \
  --sans "DNS:*.example.com,DNS:example.com,IP:192.168.1.1"

# Issue with a specific algorithm and save to files
xkmsctl ca issue --cn myserver \
  --algorithm ecdsa-p256 \
  --output server.pem

# Issue via QUIC protocol
xkmsctl ca issue --cn myserver --server quic://xkms.example.com:8444
```

**Output (Text, stdout):**
```
Serial Number: 7B2E91A4C8D05F36

--- Certificate (PEM) ---
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----

--- Chain (PEM) ---
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----

--- Private Key (PEM) ---
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----

WARNING: Keep this private key secure!
```

**Output (Text, with --output):**
```
Serial Number: 7B2E91A4C8D05F36
Certificate: server.pem
Private Key: server.pem.key
```

**Output (JSON, stdout):**
```json
{
  "serial_number": "7B2E91A4C8D05F36",
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
  "chain_pem": "-----BEGIN CERTIFICATE-----\n...",
  "private_key_pem": "-----BEGIN PRIVATE KEY-----\n..."
}
```

**Output (JSON, with --output):**
```json
{
  "serial_number": "7B2E91A4C8D05F36",
  "cert_file": "server.pem",
  "key_file": "server.pem.key"
}
```

---

### revoke

Revoke a certificate by its serial number with an optional RFC 5280 reason code.

**Usage:**
```bash
xkmsctl ca revoke --serial <hex-serial> [flags]
```

**Flags:**

| Flag | Type | Default | Required | Description |
|------|------|---------|----------|-------------|
| `--serial` | string | | Yes | Certificate serial number in hex |
| `--reason` | int | `0` | No | RFC 5280 revocation reason code |

**RFC 5280 Reason Codes:**

| Code | Reason |
|------|--------|
| 0 | Unspecified |
| 1 | Key Compromise |
| 2 | CA Compromise |
| 3 | Affiliation Changed |
| 4 | Superseded |
| 5 | Cessation of Operation |
| 6 | Certificate Hold |
| 8 | Remove from CRL |
| 9 | Privilege Withdrawn |
| 10 | AA Compromise |

**Examples:**
```bash
# Revoke with default reason (Unspecified)
xkmsctl ca revoke --serial 01AB23CD

# Revoke due to key compromise
xkmsctl ca revoke --serial 01AB23CD --reason 1

# Revoke with JSON output
xkmsctl ca revoke --serial 01AB23CD --reason 4 -o json
```

**Output (Text):**
```
Successfully revoked certificate with serial: 01AB23CD
```

**Output (JSON):**
```json
{
  "success": true,
  "message": "Successfully revoked certificate with serial: 01AB23CD"
}
```

---

### crl

Generate a Certificate Revocation List (CRL) in PEM format containing all revoked certificates.

**Usage:**
```bash
xkmsctl ca crl [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--output` | string | `""` | Output file for CRL (PEM) |

**Examples:**
```bash
# Print CRL to stdout
xkmsctl ca crl

# Save CRL to a file
xkmsctl ca crl --output revoked.crl

# Generate CRL via REST
xkmsctl ca crl --server https://xkms.example.com:8443 --output revoked.crl
```

**Output (stdout):**
```
-----BEGIN X509 CRL-----
MIIBYDCCAQYCAQEwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJRXhhbXBsZSBD
...
-----END X509 CRL-----
```

**Output (with --output):**
```
CRL written to: revoked.crl
```

---

### status

Check whether a certificate has been revoked by its serial number.

**Usage:**
```bash
xkmsctl ca status --serial <hex-serial>
```

**Flags:**

| Flag | Type | Default | Required | Description |
|------|------|---------|----------|-------------|
| `--serial` | string | | Yes | Certificate serial number in hex |

**Examples:**
```bash
# Check revocation status
xkmsctl ca status --serial 01AB23CD

# Check status with JSON output
xkmsctl ca status --serial 01AB23CD -o json
```

**Output (Text, not revoked):**
```
Certificate 01AB23CD: NOT REVOKED
```

**Output (Text, revoked):**
```
Certificate 01AB23CD: REVOKED (reason: 1)
```

**Output (JSON, not revoked):**
```json
{
  "serial_number": "01AB23CD",
  "revoked": false
}
```

**Output (JSON, revoked):**
```json
{
  "serial_number": "01AB23CD",
  "revoked": true,
  "reason": 1
}
```

---

## TCG Commands

The `xkmsctl ca tcg` subgroup provides Trusted Computing Group (TCG) certificate operations for TPM device identity management. These commands issue EK/AK certificates and handle the full device enrollment flow using TCG-CSR-IDEVID.

### tcg issue-ek

Issue a Trusted Computing Group (TCG) Endorsement Key (EK) certificate. The EK certificate attests to the identity and authenticity of a TPM's Endorsement Key, establishing a hardware root of trust.

**Usage:**
```bash
xkmsctl ca tcg issue-ek --cn <name> --ek-pub <file> [flags]
```

**Flags:**

| Flag | Type | Default | Required | Description |
|------|------|---------|----------|-------------|
| `--cn` | string | | Yes | Common name for the EK certificate |
| `--ek-pub` | string | | Yes | Path to DER-encoded EK public key file |
| `--org` | string | `""` | No | Organization name |
| `--output` | string | `""` | No | Output file for certificate (PEM) |

**Examples:**
```bash
# Issue an EK certificate
xkmsctl ca tcg issue-ek --cn "Device-001" --ek-pub ek_pub.der

# Issue with organization and save to file
xkmsctl ca tcg issue-ek \
  --cn "Device-001" \
  --ek-pub ek_pub.der \
  --org "Acme Corp" \
  --output ek_cert.pem

# Issue via gRPC with JSON output
xkmsctl ca tcg issue-ek \
  --cn "Device-001" \
  --ek-pub ek_pub.der \
  --server grpc://xkms.example.com:9443 \
  -o json
```

**Output (Text, stdout):**
```
EK Certificate Issued:
  Serial Number: A1B2C3D4E5F60718

-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHCgVZU2T/MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCUV4
...
-----END CERTIFICATE-----
```

**Output (Text, with --output):**
```
EK Certificate Issued:
  Serial Number: A1B2C3D4E5F60718
  Certificate:   ek_cert.pem
```

**Output (JSON):**
```json
{
  "serial_number": "A1B2C3D4E5F60718",
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n..."
}
```

---

### tcg issue-ak

Issue a Trusted Computing Group (TCG) Attestation Key (AK) certificate. The AK certificate attests to the identity of a TPM's Attestation Key, which is used for remote attestation and quoting operations.

**Usage:**
```bash
xkmsctl ca tcg issue-ak --cn <name> --pub <file> [flags]
```

**Flags:**

| Flag | Type | Default | Required | Description |
|------|------|---------|----------|-------------|
| `--cn` | string | | Yes | Common name for the AK certificate |
| `--pub` | string | | Yes | Path to DER-encoded public key file |
| `--org` | string | `""` | No | Organization name |
| `--output` | string | `""` | No | Output file for certificate (PEM) |

**Examples:**
```bash
# Issue an AK certificate
xkmsctl ca tcg issue-ak --cn "Device-001-AK" --pub ak_pub.der

# Issue with organization and save to file
xkmsctl ca tcg issue-ak \
  --cn "Device-001-AK" \
  --pub ak_pub.der \
  --org "Acme Corp" \
  --output ak_cert.pem
```

**Output (Text, stdout):**
```
AK Certificate Issued:
  Serial Number: B2C3D4E5F6071829

-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHCgVZU2T/MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCUV4
...
-----END CERTIFICATE-----
```

**Output (Text, with --output):**
```
AK Certificate Issued:
  Serial Number: B2C3D4E5F6071829
  Certificate:   ak_cert.pem
```

**Output (JSON):**
```json
{
  "serial_number": "B2C3D4E5F6071829",
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n..."
}
```

---

### tcg sign-csr

Sign a packed TCG_CSR_IDEVID binary to issue IAK and IDevID certificates. The TCG-CSR-IDEVID is a TCG-defined certificate signing request format for device identity enrollment, containing both IAK and IDevID public keys.

**Usage:**
```bash
xkmsctl ca tcg sign-csr --cn <name> --csr <file> [flags]
```

**Flags:**

| Flag | Type | Default | Required | Description |
|------|------|---------|----------|-------------|
| `--cn` | string | | Yes | Common name for the device identity |
| `--csr` | string | | Yes | Path to packed TCG_CSR_IDEVID binary file |
| `--org` | string | `""` | No | Organization name |
| `--output` | string | `""` | No | Output directory for certificate files (DER) |

When `--output` is specified, the command creates the directory and writes:
- `iak_cert.der` -- IAK certificate in DER format
- `idevid_cert.der` -- IDevID certificate in DER format

**Examples:**
```bash
# Sign a TCG-CSR-IDEVID
xkmsctl ca tcg sign-csr --cn "Device-001" --csr tcg_csr.bin

# Sign and write certificates to a directory
xkmsctl ca tcg sign-csr \
  --cn "Device-001" \
  --csr tcg_csr.bin \
  --output /tmp/certs/

# Sign with organization name
xkmsctl ca tcg sign-csr \
  --cn "Device-001" \
  --csr tcg_csr.bin \
  --org "Acme Corp" \
  --output /tmp/certs/
```

**Output (Text, stdout):**
```
TCG-CSR-IDEVID Signed:
  IAK Certificate:    512 bytes (DER)
  IDevID Certificate: 498 bytes (DER)

--- IAK Certificate (PEM) ---
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----

--- IDevID Certificate (PEM) ---
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
```

**Output (Text, with --output):**
```
TCG-CSR-IDEVID Signed:
  IAK Certificate:    512 bytes (DER)
  IDevID Certificate: 498 bytes (DER)
  IAK File:           /tmp/certs/iak_cert.der
  IDevID File:        /tmp/certs/idevid_cert.der
```

**Output (JSON):**
```json
{
  "iak_cert_size": 512,
  "idevid_cert_size": 498,
  "iak_cert_file": "/tmp/certs/iak_cert.der",
  "idevid_cert_file": "/tmp/certs/idevid_cert.der"
}
```

---

### tcg enroll

Perform full TCG device enrollment using a packed TCG_CSR_IDEVID. This command executes the complete enrollment flow:

1. Validates the packed CSR
2. Issues IAK and IDevID certificates
3. Creates a credential activation challenge
4. Returns certificates and challenge for the device

**Usage:**
```bash
xkmsctl ca tcg enroll --cn <name> --packed-csr <file> [flags]
```

**Flags:**

| Flag | Type | Default | Required | Description |
|------|------|---------|----------|-------------|
| `--cn` | string | | Yes | Common name for the device |
| `--packed-csr` | string | | Yes | Path to packed TCG_CSR_IDEVID binary file |
| `--org` | string | `""` | No | Organization name |
| `--output` | string | `""` | No | Output directory for enrollment files |

When `--output` is specified, the command creates the directory and writes:
- `iak_cert.der` -- IAK certificate in DER format
- `idevid_cert.der` -- IDevID certificate in DER format
- `credential_blob.bin` -- Credential activation blob (if present)
- `encrypted_secret.bin` -- Encrypted secret for activation (if present)

**Examples:**
```bash
# Enroll a TPM device
xkmsctl ca tcg enroll --cn "Device-001" --packed-csr tcg_csr.bin

# Enroll and save artifacts to a directory
xkmsctl ca tcg enroll \
  --cn "Device-001" \
  --packed-csr tcg_csr.bin \
  --output /tmp/enrollment/

# Enroll with organization via REST
xkmsctl ca tcg enroll \
  --cn "Device-001" \
  --packed-csr tcg_csr.bin \
  --org "Acme Corp" \
  --server https://xkms.example.com:8443 \
  --output /tmp/enrollment/
```

**Output (Text):**
```
Device Enrollment Complete:
  IAK Certificate:    512 bytes (DER)
  IDevID Certificate: 498 bytes (DER)
  Credential Blob:    256 bytes
  Encrypted Secret:   256 bytes
  Output Directory:   /tmp/enrollment/
```

**Output (JSON):**
```json
{
  "iak_cert_size": 512,
  "idevid_cert_size": 498,
  "credential_blob_size": 256,
  "has_challenge": true,
  "output_dir": "/tmp/enrollment/"
}
```

---

## Global Flags

All `ca` commands inherit the following persistent flags from the root command:

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--config` | | string | `""` | Config file (default `$HOME/.xkms.yaml`) |
| `--backend` | | string | `software` | Backend (software, pkcs11, tpm2, awskms, gcpkms, azurekv, vault) |
| `--key-dir` | | string | `xkms-data/keys` | Directory for key storage (file-based backends) |
| `--output` | `-o` | string | `text` | Output format (text, json, table) |
| `--verbose` | `-v` | bool | `false` | Enable verbose output |
| `--protocol` | `-P` | string | `""` | Communication protocol (embedded, rest, grpc, quic, mcp, unix) |
| `--server` | `-s` | string | `""` | Server URL (see [Multi-Protocol Usage](#multi-protocol-usage)) |
| `--tls-insecure` | | bool | `false` | Skip TLS certificate verification |
| `--tls-cert` | | string | `""` | Client certificate file for mTLS |
| `--tls-key` | | string | `""` | Client key file for mTLS |
| `--tls-ca` | | string | `""` | CA certificate file for server verification |
| `--token` | | string | `""` | JWT token for server authentication |
| `--spki-pin` | | string | `""` | Hex-encoded SHA-256 SPKI pin for server certificate verification |
| `--so-pin` | | string | `""` | Security officer PIN for privileged operations |

## Multi-Protocol Usage

All `xkmsctl ca` commands work across all six supported transport protocols. The protocol is selected via the `--server` flag or the `--protocol` flag.

**Server URL formats:**

| Protocol | URL Format | Example |
|----------|-----------|---------|
| Unix socket | `unix:///path/to/socket` | `unix:///var/run/xkms.sock` |
| REST | `http://host:port` or `https://host:port` | `https://xkms.example.com:8443` |
| gRPC | `grpc://host:port` or `grpcs://host:port` | `grpcs://xkms.example.com:9443` |
| QUIC | `quic://host:port` | `quic://xkms.example.com:8444` |
| Embedded | Use `--protocol embedded` | |
| MCP | Use `--protocol mcp` | |

**Examples:**
```bash
# Unix socket (default)
xkmsctl ca certificate

# REST over HTTPS
xkmsctl ca certificate --server https://xkms.example.com:8443

# gRPC with TLS
xkmsctl ca certificate --server grpcs://xkms.example.com:9443

# QUIC
xkmsctl ca certificate --server quic://xkms.example.com:8444

# REST with mTLS client authentication
xkmsctl ca issue --cn myserver \
  --server https://xkms.example.com:8443 \
  --tls-cert client.crt \
  --tls-key client.key \
  --tls-ca ca.crt

# Embedded (direct backend access, no server)
xkmsctl ca certificate --protocol embedded

# With SPKI pin for trust-on-first-use
xkmsctl ca bundle --server https://xkms.example.com:8443 \
  --spki-pin a1b2c3d4e5f6...
```

## Examples

### Certificate Lifecycle Management

Issue, verify, revoke, and check a certificate through its full lifecycle:

```bash
# 1. Issue a server certificate
xkmsctl ca issue \
  --cn server.example.com \
  --profile server \
  --sans "DNS:server.example.com,DNS:*.example.com" \
  --validity 365 \
  --output server.pem

# 2. View the CA certificate that signed it
xkmsctl ca certificate

# 3. Revoke the certificate (key compromise)
SERIAL=$(xkmsctl ca issue --cn temp -o json | jq -r '.serial_number')
xkmsctl ca revoke --serial "$SERIAL" --reason 1

# 4. Verify revocation status
xkmsctl ca status --serial "$SERIAL"

# 5. Generate updated CRL
xkmsctl ca crl --output current.crl
```

### Sign an External CSR

Sign a CSR generated by an external tool (e.g., OpenSSL):

```bash
# Generate CSR with OpenSSL
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout server.key -out server.csr -nodes \
  -subj "/CN=server.example.com/O=Example Corp"

# Sign with xkms CA
xkmsctl ca sign-csr \
  --csr server.csr \
  --profile server \
  --validity 365 \
  --output server.crt
```

### TPM Device Enrollment

Enroll a TPM device with the TCG CA:

```bash
# 1. Issue EK certificate for the device
xkmsctl ca tcg issue-ek \
  --cn "Factory-Device-001" \
  --ek-pub /tmp/device/ek_pub.der \
  --org "Manufacturing Inc" \
  --output /tmp/device/ek_cert.pem

# 2. Issue AK certificate
xkmsctl ca tcg issue-ak \
  --cn "Factory-Device-001-AK" \
  --pub /tmp/device/ak_pub.der \
  --org "Manufacturing Inc" \
  --output /tmp/device/ak_cert.pem

# 3. Full enrollment with credential activation
xkmsctl ca tcg enroll \
  --cn "Factory-Device-001" \
  --packed-csr /tmp/device/tcg_csr.bin \
  --org "Manufacturing Inc" \
  --output /tmp/device/enrollment/
```

### Scripted Revocation Check

Check revocation status in a script:

```bash
#!/bin/bash

SERIAL="01AB23CD"

result=$(xkmsctl ca status --serial "$SERIAL" -o json)
revoked=$(echo "$result" | jq -r '.revoked')

if [ "$revoked" = "true" ]; then
  reason=$(echo "$result" | jq -r '.reason')
  echo "Certificate $SERIAL is REVOKED (reason: $reason)"
  exit 1
else
  echo "Certificate $SERIAL is valid"
  exit 0
fi
```

## See Also

- [Certificate Management CLI](./cert.md)
- [Certificate Management Guide](../certificate-management.md)
- [Getting Started](../getting-started.md)
- [Key Management CLI](./key.md)
- [Backend Configuration](../../backends/README.md)
