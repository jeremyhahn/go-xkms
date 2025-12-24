# Certificate Management CLI

The `cert` command group provides comprehensive X.509 certificate management capabilities, including storage, retrieval, chain management, and certificate generation for both Certificate Authorities and end-entity certificates.

## Table of Contents

- [Overview](#overview)
- [Certificate Storage Commands](#certificate-storage-commands)
  - [save](#save)
  - [get](#get)
  - [delete](#delete)
  - [list](#list)
  - [exists](#exists)
- [Certificate Chain Commands](#certificate-chain-commands)
  - [save-chain](#save-chain)
  - [get-chain](#get-chain)
- [Certificate Generation Commands](#certificate-generation-commands)
  - [generate-ca](#generate-ca)
  - [issue](#issue)
- [Global Flags](#global-flags)
- [Examples](#examples)
- [Common Use Cases](#common-use-cases)

## Overview

The certificate management commands work with both local storage (using `--local` flag) and remote keychaind server. All commands support multiple output formats including text, JSON, and YAML.

Certificate operations are backend-agnostic, meaning they work consistently across all storage backends (PKCS#8, PKCS#11, TPM2, cloud KMS providers, etc.).

## Certificate Storage Commands

### save

Save an X.509 certificate to the certificate store.

**Usage:**
```bash
keychain cert save <key-id> <cert-file>
```

**Arguments:**
- `key-id`: Unique identifier for the certificate
- `cert-file`: Path to PEM-encoded certificate file

**Examples:**
```bash
# Save a certificate locally
keychain cert save --local my-server /path/to/cert.pem

# Save to remote server
keychain cert save --backend pkcs8 server-1 ./certificates/server.crt

# Save with verbose output
keychain cert save -v my-cert certificate.pem
```

**Output:**
```
Successfully saved certificate for key: my-server
```

**JSON Output:**
```bash
keychain cert save --output json my-cert cert.pem
```
```json
{
  "success": true,
  "message": "Successfully saved certificate for key: my-cert"
}
```

### get

Retrieve an X.509 certificate from the certificate store.

**Usage:**
```bash
keychain cert get <key-id>
```

**Arguments:**
- `key-id`: Unique identifier of the certificate to retrieve

**Examples:**
```bash
# Get a certificate in text format
keychain cert get my-server

# Get in JSON format
keychain cert get --output json my-server

# Get from specific backend
keychain cert get --backend tpm2 my-cert
```

**Output (Text):**
```
Subject: CN=example.com,O=Example Org
Issuer: CN=Example CA,O=Example Org
Serial: 123456789
Valid From: 2024-01-01
Valid Until: 2025-01-01

-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHCgVZU2T/MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCUV4
...
-----END CERTIFICATE-----
```

**Output (JSON):**
```json
{
  "subject": "CN=example.com,O=Example Org",
  "issuer": "CN=Example CA,O=Example Org",
  "serial_number": "123456789",
  "not_before": "2024-01-01T00:00:00Z",
  "not_after": "2025-01-01T00:00:00Z",
  "is_ca": false,
  "key_usage": ["digitalSignature", "keyEncipherment"],
  "ext_key_usage": ["serverAuth"],
  "dns_names": ["example.com", "*.example.com"],
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n..."
}
```

### delete

Delete an X.509 certificate from the certificate store.

**Usage:**
```bash
keychain cert delete <key-id>
```

**Arguments:**
- `key-id`: Unique identifier of the certificate to delete

**Examples:**
```bash
# Delete a certificate
keychain cert delete my-server

# Delete with confirmation
keychain cert delete --local old-cert

# Delete from specific backend
keychain cert delete --backend pkcs11 expired-cert
```

**Output:**
```
Successfully deleted certificate for key: my-server
```

### list

List all certificates in the certificate store.

**Usage:**
```bash
keychain cert list
```

**Examples:**
```bash
# List all certificates
keychain cert list

# List in JSON format
keychain cert list --output json

# List from specific backend
keychain cert list --backend tpm2
```

**Output (Text):**
```
Certificates:
  - server-1
  - client-auth
  - ca-root
  - intermediate-ca
```

**Output (JSON):**
```json
{
  "certificates": [
    "server-1",
    "client-auth",
    "ca-root",
    "intermediate-ca"
  ],
  "count": 4
}
```

### exists

Check if a certificate exists in the certificate store.

**Usage:**
```bash
keychain cert exists <key-id>
```

**Arguments:**
- `key-id`: Unique identifier of the certificate to check

**Examples:**
```bash
# Check if certificate exists
keychain cert exists my-server

# Check with JSON output
keychain cert exists --output json my-cert

# Use in scripts
if keychain cert exists my-server; then
  echo "Certificate found"
fi
```

**Output (Text):**
```
Certificate exists: my-server
```

**Output (JSON):**
```json
{
  "key_id": "my-server",
  "exists": true
}
```

## Certificate Chain Commands

### save-chain

Save an X.509 certificate chain to the certificate store. Certificates should be ordered from leaf to root.

**Usage:**
```bash
keychain cert save-chain <key-id> <cert-file>...
```

**Arguments:**
- `key-id`: Unique identifier for the certificate chain
- `cert-file`: One or more paths to PEM-encoded certificate files (leaf first, root last)

**Examples:**
```bash
# Save a complete chain (leaf, intermediate, root)
keychain cert save-chain server-chain \
  server.crt \
  intermediate-ca.crt \
  root-ca.crt

# Save chain locally
keychain cert save-chain --local my-chain \
  leaf.pem \
  ca.pem

# Save with verbose output to see each certificate
keychain cert save-chain -v tls-chain \
  server.crt \
  intermediate.crt \
  root.crt
```

**Output:**
```
Successfully saved certificate chain for key: server-chain (3 certificates)
```

**Verbose Output:**
```
Saving certificate chain for key: server-chain
Reading certificate 1 from: server.crt
Certificate 1 Subject: CN=server.example.com,O=Example Org
Reading certificate 2 from: intermediate-ca.crt
Certificate 2 Subject: CN=Intermediate CA,O=Example Org
Reading certificate 3 from: root-ca.crt
Certificate 3 Subject: CN=Root CA,O=Example Org
Connected to keychaind server
Successfully saved certificate chain for key: server-chain (3 certificates)
```

### get-chain

Retrieve an X.509 certificate chain from the certificate store.

**Usage:**
```bash
keychain cert get-chain <key-id>
```

**Arguments:**
- `key-id`: Unique identifier of the certificate chain to retrieve

**Examples:**
```bash
# Get certificate chain
keychain cert get-chain server-chain

# Get in JSON format
keychain cert get-chain --output json my-chain

# Get from specific backend
keychain cert get-chain --backend pkcs11 tls-chain
```

**Output (Text):**
```
Certificate Chain (3 certificates):

Certificate 1:
  Subject: CN=server.example.com,O=Example Org
  Issuer: CN=Intermediate CA,O=Example Org
  Serial: 1234567890
  Valid: 2024-01-01 to 2025-01-01

-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHCgVZU2T/MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCUV4
...
-----END CERTIFICATE-----

Certificate 2:
  Subject: CN=Intermediate CA,O=Example Org
  Issuer: CN=Root CA,O=Example Org
  Serial: 987654321
  Valid: 2024-01-01 to 2029-01-01

-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----

Certificate 3:
  Subject: CN=Root CA,O=Example Org
  Issuer: CN=Root CA,O=Example Org (self-signed)
  Serial: 555555555
  Valid: 2024-01-01 to 2034-01-01

-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
```

**Output (JSON):**
```json
{
  "chain": [
    {
      "subject": "CN=server.example.com,O=Example Org",
      "issuer": "CN=Intermediate CA,O=Example Org",
      "serial_number": "1234567890",
      "not_before": "2024-01-01T00:00:00Z",
      "not_after": "2025-01-01T00:00:00Z",
      "certificate_pem": "-----BEGIN CERTIFICATE-----\n..."
    },
    {
      "subject": "CN=Intermediate CA,O=Example Org",
      "issuer": "CN=Root CA,O=Example Org",
      "serial_number": "987654321",
      "not_before": "2024-01-01T00:00:00Z",
      "not_after": "2029-01-01T00:00:00Z",
      "certificate_pem": "-----BEGIN CERTIFICATE-----\n..."
    },
    {
      "subject": "CN=Root CA,O=Example Org",
      "issuer": "CN=Root CA,O=Example Org",
      "serial_number": "555555555",
      "not_before": "2024-01-01T00:00:00Z",
      "not_after": "2034-01-01T00:00:00Z",
      "certificate_pem": "-----BEGIN CERTIFICATE-----\n..."
    }
  ],
  "count": 3
}
```

## Certificate Generation Commands

### generate-ca

Generate a self-signed Certificate Authority (CA) certificate with private key.

**Usage:**
```bash
keychain cert generate-ca [flags]
```

**Required Flags:**
- `--cn <string>`: Common name for the CA

**Optional Flags:**
- `--org <string>`: Organization name (default: "Go Keychain")
- `--ou <string>`: Organizational unit
- `--country <string>`: Country code (e.g., "US")
- `--province <string>`: State/province
- `--locality <string>`: City/locality
- `--validity <int>`: Validity period in days (default: 3650, 10 years)
- `--key-algorithm <string>`: Key algorithm: rsa, ecdsa, ed25519 (default: "ecdsa")
- `--key-size <int>`: Key size - RSA: 2048/4096, ECDSA: 256/384/521 (default: 256)
- `--output <string>`: Output file for certificate (PEM format)
- `--key-output <string>`: Output file for private key (PEM format)

**Examples:**
```bash
# Generate CA with minimal options (output to stdout)
keychain cert generate-ca --cn "My Root CA"

# Generate CA with full details and save to files
keychain cert generate-ca \
  --cn "Example Root CA" \
  --org "Example Corporation" \
  --ou "Security" \
  --country "US" \
  --province "California" \
  --locality "San Francisco" \
  --validity 7300 \
  --output ca.crt \
  --key-output ca.key

# Generate CA with RSA 4096-bit key
keychain cert generate-ca \
  --cn "RSA Root CA" \
  --key-algorithm rsa \
  --key-size 4096 \
  --output rsa-ca.crt \
  --key-output rsa-ca.key

# Generate CA with Ed25519 (quantum-resistant ready)
keychain cert generate-ca \
  --cn "Modern CA" \
  --key-algorithm ed25519 \
  --output ed25519-ca.crt \
  --key-output ed25519-ca.key

# Generate CA with ECDSA P-384
keychain cert generate-ca \
  --cn "High Security CA" \
  --key-algorithm ecdsa \
  --key-size 384 \
  --validity 3650 \
  --output p384-ca.crt \
  --key-output p384-ca.key

# Generate and view in JSON
keychain cert generate-ca --cn "JSON CA" --output json
```

**Output (Text, without file output):**
```
CA certificate generated successfully

CA Certificate Details:
  Subject: CN=My Root CA,O=Go Keychain
  Serial: 123456789012345678901234567890
  Valid From: 2024-01-01
  Valid Until: 2034-01-01
  Is CA: true

--- CA Certificate (PEM) ---
-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHCgVZU2T/MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCUV4
...
-----END CERTIFICATE-----

--- CA Private Key (PEM) ---
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg...
-----END PRIVATE KEY-----

WARNING: Keep this private key secure!
```

**Output (Text, with file output):**
```
CA certificate generated successfully

CA Certificate Details:
  Subject: CN=Example Root CA,O=Example Corporation,OU=Security,C=US,ST=California,L=San Francisco
  Serial: 123456789012345678901234567890
  Valid From: 2024-01-01
  Valid Until: 2044-01-01
  Is CA: true

  Certificate: ca.crt
  Private Key: ca.key
```

**Output (JSON):**
```json
{
  "success": true,
  "subject": "CN=My Root CA,O=Go Keychain",
  "issuer": "CN=My Root CA,O=Go Keychain",
  "serial": "123456789012345678901234567890",
  "not_before": "2024-01-01T00:00:00Z",
  "not_after": "2034-01-01T00:00:00Z",
  "is_ca": true,
  "key_algorithm": "ecdsa",
  "certificate": "-----BEGIN CERTIFICATE-----\n...",
  "private_key": "-----BEGIN PRIVATE KEY-----\n..."
}
```

**Key Algorithm Options:**

| Algorithm | Key Size Options | Security Level | Use Case |
|-----------|-----------------|----------------|----------|
| `ecdsa` | 256, 384, 521 | High | Modern PKI (recommended) |
| `rsa` | 2048, 4096 | Medium-High | Legacy compatibility |
| `ed25519` | N/A | Very High | Modern, quantum-resistant ready |

### issue

Issue a certificate signed by an existing CA. Supports both server and client certificates with Subject Alternative Names (SANs).

**Usage:**
```bash
keychain cert issue [flags]
```

**Required Flags:**
- `--ca-cert <string>`: CA certificate file (PEM format)
- `--ca-key <string>`: CA private key file (PEM format)
- `--cn <string>`: Common name for the certificate

**Optional Flags:**
- `--type <string>`: Certificate type: server, client (default: "server")
- `--org <string>`: Organization name
- `--ou <string>`: Organizational unit
- `--country <string>`: Country code (e.g., "US")
- `--province <string>`: State/province
- `--locality <string>`: City/locality
- `--validity <int>`: Validity period in days (default: 365, 1 year)
- `--key-algorithm <string>`: Key algorithm: rsa, ecdsa, ed25519 (default: "ecdsa")
- `--key-size <int>`: Key size (default: 256)
- `--dns <string>`: DNS names (comma-separated)
- `--ip <string>`: IP addresses (comma-separated)
- `--email <string>`: Email addresses (comma-separated)
- `--output <string>`: Output file for certificate (PEM format)
- `--key-output <string>`: Output file for private key (PEM format)

**Examples:**

```bash
# Issue a basic server certificate
keychain cert issue \
  --ca-cert ca.crt \
  --ca-key ca.key \
  --cn server.example.com \
  --type server

# Issue server certificate with multiple SANs
keychain cert issue \
  --ca-cert ca.crt \
  --ca-key ca.key \
  --cn server.example.com \
  --type server \
  --dns "server.example.com,*.example.com,example.com" \
  --ip "192.168.1.10,10.0.0.5" \
  --output server.crt \
  --key-output server.key

# Issue client certificate for mTLS
keychain cert issue \
  --ca-cert ca.crt \
  --ca-key ca.key \
  --cn "client@example.com" \
  --type client \
  --email "client@example.com,admin@example.com" \
  --output client.crt \
  --key-output client.key

# Issue wildcard certificate
keychain cert issue \
  --ca-cert ca.crt \
  --ca-key ca.key \
  --cn "*.example.com" \
  --dns "*.example.com,example.com" \
  --validity 730 \
  --output wildcard.crt \
  --key-output wildcard.key

# Issue with RSA 4096-bit key
keychain cert issue \
  --ca-cert ca.crt \
  --ca-key ca.key \
  --cn secure.example.com \
  --key-algorithm rsa \
  --key-size 4096 \
  --output rsa-server.crt \
  --key-output rsa-server.key

# Issue certificate with full organization details
keychain cert issue \
  --ca-cert ca.crt \
  --ca-key ca.key \
  --cn api.example.com \
  --org "Example Corporation" \
  --ou "API Services" \
  --country "US" \
  --province "California" \
  --locality "San Francisco" \
  --dns "api.example.com,api-v2.example.com" \
  --validity 365 \
  --output api.crt \
  --key-output api.key

# Issue and view in JSON format
keychain cert issue \
  --ca-cert ca.crt \
  --ca-key ca.key \
  --cn test.example.com \
  --output json
```

**Output (Text, without file output):**
```
server certificate issued successfully

Certificate Details:
  Type: server
  Subject: CN=server.example.com
  Issuer: CN=Example Root CA,O=Example Corporation
  Serial: 987654321098765432109876543210
  Valid From: 2024-01-01
  Valid Until: 2025-01-01
  DNS Names: [server.example.com *.example.com example.com]
  IP Addresses: [192.168.1.10 10.0.0.5]

--- Certificate (PEM) ---
-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHCgVZU2T/MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCUV4
...
-----END CERTIFICATE-----

--- Private Key (PEM) ---
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg...
-----END PRIVATE KEY-----

WARNING: Keep this private key secure!
```

**Output (Text, with file output):**
```
server certificate issued successfully

Certificate Details:
  Type: server
  Subject: CN=server.example.com
  Issuer: CN=Example Root CA,O=Example Corporation
  Serial: 987654321098765432109876543210
  Valid From: 2024-01-01
  Valid Until: 2025-01-01
  DNS Names: [server.example.com *.example.com example.com]
  IP Addresses: [192.168.1.10 10.0.0.5]

  Certificate: server.crt
  Private Key: server.key
```

**Output (JSON):**
```json
{
  "success": true,
  "type": "server",
  "subject": "CN=server.example.com",
  "issuer": "CN=Example Root CA,O=Example Corporation",
  "serial": "987654321098765432109876543210",
  "not_before": "2024-01-01T00:00:00Z",
  "not_after": "2025-01-01T00:00:00Z",
  "key_algorithm": "ecdsa",
  "dns_names": ["server.example.com", "*.example.com", "example.com"],
  "ip_addresses": ["192.168.1.10", "10.0.0.5"],
  "certificate": "-----BEGIN CERTIFICATE-----\n...",
  "private_key": "-----BEGIN PRIVATE KEY-----\n..."
}
```

**Certificate Types:**

| Type | Extended Key Usage | Common Use Cases | SANs Supported |
|------|-------------------|------------------|----------------|
| `server` | serverAuth | TLS/HTTPS servers, API endpoints | DNS names, IP addresses |
| `client` | clientAuth | mTLS client authentication, API clients | Email addresses |

## Global Flags

All cert commands support these global flags:

- `--backend <string>`: Backend to use (default: "pkcs8")
- `--local`: Use local storage instead of remote server
- `--config <string>`: Path to config file
- `--output <format>`: Output format: text, json, yaml (default: "text")
- `--verbose, -v`: Enable verbose output
- `--help, -h`: Show help for command

## Examples

### Complete PKI Setup

Set up a complete PKI infrastructure with CA and multiple certificates:

```bash
# 1. Generate root CA
keychain cert generate-ca \
  --cn "Example Root CA" \
  --org "Example Corp" \
  --validity 7300 \
  --output ca.crt \
  --key-output ca.key

# 2. Issue server certificate
keychain cert issue \
  --ca-cert ca.crt \
  --ca-key ca.key \
  --cn server.example.com \
  --dns "server.example.com,*.example.com" \
  --output server.crt \
  --key-output server.key

# 3. Issue client certificate
keychain cert issue \
  --ca-cert ca.crt \
  --ca-key ca.key \
  --cn "client@example.com" \
  --type client \
  --email "client@example.com" \
  --output client.crt \
  --key-output client.key

# 4. Save certificates to keychain
keychain cert save --local ca-cert ca.crt
keychain cert save --local server-cert server.crt
keychain cert save --local client-cert client.crt

# 5. Save certificate chain
keychain cert save-chain --local server-chain server.crt ca.crt

# 6. List all certificates
keychain cert list --local

# 7. Verify certificate exists
keychain cert exists --local server-cert
```

### Renew Expired Certificate

```bash
# Check if certificate exists
if keychain cert exists old-server; then
  # Get current certificate to check expiration
  keychain cert get old-server

  # Issue new certificate with same parameters
  keychain cert issue \
    --ca-cert ca.crt \
    --ca-key ca.key \
    --cn server.example.com \
    --dns "server.example.com,*.example.com" \
    --validity 730 \
    --output new-server.crt \
    --key-output new-server.key

  # Save new certificate
  keychain cert save server-cert new-server.crt

  # Delete old certificate
  keychain cert delete old-server
fi
```

### Backup and Restore Certificates

```bash
# Backup: Export all certificates
mkdir -p cert-backup
for cert_id in $(keychain cert list --output json | jq -r '.certificates[]'); do
  keychain cert get "$cert_id" > "cert-backup/${cert_id}.pem"
done

# Restore: Import all certificates
for cert_file in cert-backup/*.pem; do
  cert_id=$(basename "$cert_file" .pem)
  keychain cert save "$cert_id" "$cert_file"
done
```

### Multi-Backend Certificate Management

```bash
# Save same certificate to multiple backends
keychain cert save --backend pkcs8 my-cert cert.pem
keychain cert save --backend tpm2 my-cert cert.pem
keychain cert save --backend pkcs11 my-cert cert.pem

# Verify certificate exists in all backends
keychain cert exists --backend pkcs8 my-cert
keychain cert exists --backend tpm2 my-cert
keychain cert exists --backend pkcs11 my-cert

# Get certificate from specific backend
keychain cert get --backend tpm2 my-cert
```

## Common Use Cases

### TLS/HTTPS Server Setup

Generate a complete TLS setup for a web server:

```bash
# Generate CA
keychain cert generate-ca \
  --cn "Internal CA" \
  --org "My Company" \
  --output internal-ca.crt \
  --key-output internal-ca.key

# Issue server certificate
keychain cert issue \
  --ca-cert internal-ca.crt \
  --ca-key internal-ca.key \
  --cn www.example.com \
  --dns "www.example.com,api.example.com,*.example.com" \
  --output server.crt \
  --key-output server.key

# Save to keychain
keychain cert save-chain web-server server.crt internal-ca.crt
```

### Mutual TLS (mTLS) Setup

Set up mTLS with client and server certificates:

```bash
# Generate CA
keychain cert generate-ca \
  --cn "mTLS CA" \
  --output mtls-ca.crt \
  --key-output mtls-ca.key

# Issue server certificate
keychain cert issue \
  --ca-cert mtls-ca.crt \
  --ca-key mtls-ca.key \
  --cn api.example.com \
  --type server \
  --output api-server.crt \
  --key-output api-server.key

# Issue client certificate
keychain cert issue \
  --ca-cert mtls-ca.crt \
  --ca-key mtls-ca.key \
  --cn "api-client@example.com" \
  --type client \
  --email "api-client@example.com" \
  --output api-client.crt \
  --key-output api-client.key

# Save to keychain
keychain cert save mtls-server api-server.crt
keychain cert save mtls-client api-client.crt
```

### Microservices Certificate Management

Manage certificates for multiple microservices:

```bash
# Generate CA
keychain cert generate-ca \
  --cn "Microservices CA" \
  --output microservices-ca.crt \
  --key-output microservices-ca.key

# Issue certificate for each service
for service in auth api gateway storage; do
  keychain cert issue \
    --ca-cert microservices-ca.crt \
    --ca-key microservices-ca.key \
    --cn "${service}.internal" \
    --dns "${service}.internal,${service}.svc.cluster.local" \
    --output "${service}.crt" \
    --key-output "${service}.key"

  keychain cert save "service-${service}" "${service}.crt"
done

# List all service certificates
keychain cert list
```

### Certificate Rotation Script

Automate certificate rotation:

```bash
#!/bin/bash

CERT_ID="my-server"
CA_CERT="ca.crt"
CA_KEY="ca.key"
CN="server.example.com"

# Check if certificate exists
if ! keychain cert exists "$CERT_ID"; then
  echo "Certificate does not exist, creating new one..."
else
  # Get current certificate expiration
  expiry=$(keychain cert get --output json "$CERT_ID" | jq -r '.not_after')
  echo "Current certificate expires: $expiry"

  # Calculate days until expiration
  # (implementation depends on date parsing)

  # Backup old certificate
  keychain cert get "$CERT_ID" > "backup-${CERT_ID}-$(date +%Y%m%d).pem"
fi

# Issue new certificate
keychain cert issue \
  --ca-cert "$CA_CERT" \
  --ca-key "$CA_KEY" \
  --cn "$CN" \
  --dns "$CN,*.$CN" \
  --output new-cert.crt \
  --key-output new-cert.key

# Save new certificate
keychain cert save "$CERT_ID" new-cert.crt

echo "Certificate rotated successfully"
```

## See Also

- [Certificate Management Guide](../certificate-management.md)
- [Getting Started](../getting-started.md)
- [Backend Configuration](../../backends/README.md)
- [Key Management CLI](./key.md)
