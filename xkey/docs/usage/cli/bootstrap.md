# Bootstrap CLI Commands

The `bootstrap` command group provides tools for secure CA bundle retrieval and DANE/TLSA record management. These commands support the bootstrap workflow where a new node obtains CA certificates before TLS is configured.

For protocol details, see the [CA Bundle Bootstrap documentation](../../ca/bootstrap.md).

## Command Tree

```
xkmsctl bootstrap
├── auto                          # Auto-bootstrap using all configured methods
├── dane
│   ├── generate-tlsa             # Generate TLSA records from a CA certificate
│   ├── verify-tlsa               # Verify a certificate against TLSA DNS records
│   └── show-tlsa                 # Display TLSA records from DNS
├── noise
│   ├── generate-key              # Generate a Noise static keypair
│   ├── show-key                  # Show public key from a private key
│   └── show-spki-pin             # Compute SPKI SHA-256 pin
└── spki
    └── show-pin                  # Compute SPKI SHA-256 pin from a certificate
```

The noise subcommands have moved from `xkmsctl noise` to `xkmsctl bootstrap noise`. The top-level `xkmsctl noise` commands have been removed and are no longer available.

---

## bootstrap auto

Perform automatic CA bundle bootstrap by trying all configured methods in priority order: DANE, Noise, SPKI, Direct.

**Usage:**

```bash
xkmsctl bootstrap auto [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--config` | string | `$HOME/.xkms.yaml` | Configuration file with bootstrap settings |
| `--output-file` | string | | Write CA bundle PEM to this file |
| `--timeout` | duration | `60s` | Overall timeout for all attempts |
| `--per-method-timeout` | duration | `15s` | Timeout per individual method |
| `--method-order` | string | `dane,noise,spki,direct` | Comma-separated priority order |

**Example:**

```bash
xkmsctl bootstrap auto \
  --output-file /etc/xkms/ca-bundle.pem \
  --per-method-timeout 10s
```

**Output:**

```
Trying method: dane... failed (dane: no TLSA records found)
Trying method: noise... success
CA bundle written to /etc/xkms/ca-bundle.pem (3 certificates, 4521 bytes)
```

**Exit Codes:**

- `0` -- CA bundle retrieved and written successfully
- `1` -- All methods failed or configuration error

---

## bootstrap dane generate-tlsa

Generate TLSA DNS records from a CA certificate for publication in a DNSSEC-signed zone.

**Usage:**

```bash
xkmsctl bootstrap dane generate-tlsa [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--cert-file` | string | (required) | Path to PEM-encoded CA certificate |
| `--hostname` | string | (required) | Server hostname for TLSA record |
| `--port` | uint16 | (required) | Server port for TLSA record |
| `--usage` | uint8 | `2` | Certificate Usage (0-3, default: DANE-TA) |
| `--selector` | uint8 | `1` | Selector (0=full cert, 1=SPKI) |
| `--matching-type` | uint8 | `1` | Matching Type (0=exact, 1=SHA-256, 2=SHA-512) |
| `--all` | bool | `false` | Generate all common DANE-TA variants |

**Examples:**

Generate the recommended 2 1 1 record:

```bash
xkmsctl bootstrap dane generate-tlsa \
  --cert-file /etc/xkms/ca.pem \
  --hostname kms.example.com \
  --port 8443
```

**Output:**

```
_8443._tcp.kms.example.com. IN TLSA 2 1 1 a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
```

Generate all four common DANE-TA variants:

```bash
xkmsctl bootstrap dane generate-tlsa \
  --cert-file /etc/xkms/ca.pem \
  --hostname kms.example.com \
  --port 8443 \
  --all
```

**Output:**

```
_8443._tcp.kms.example.com. IN TLSA 2 0 1 f0e1d2c3b4a5f6e7d8c9b0a1...
_8443._tcp.kms.example.com. IN TLSA 2 1 1 a1b2c3d4e5f6a7b8c9d0e1f2...
_8443._tcp.kms.example.com. IN TLSA 2 0 2 e3d4c5b6a7f8e9d0c1b2a3f4...
_8443._tcp.kms.example.com. IN TLSA 2 1 2 b7c8d9e0f1a2b3c4d5e6f7a8...
```

Generate with custom parameters:

```bash
xkmsctl bootstrap dane generate-tlsa \
  --cert-file /etc/xkms/ca.pem \
  --hostname kms.example.com \
  --port 8443 \
  --usage 2 --selector 0 --matching-type 2
```

**Exit Codes:**

- `0` -- TLSA record(s) generated successfully
- `1` -- Certificate parse error, missing flags, or unsupported parameters

---

## bootstrap dane verify-tlsa

Verify a certificate against TLSA records retrieved from DNS.

**Usage:**

```bash
xkmsctl bootstrap dane verify-tlsa [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--cert-file` | string | | Path to PEM certificate to verify |
| `--server` | string | | Server address (host:port) to fetch certificate from |
| `--hostname` | string | | Hostname for TLSA lookup (default: from cert or server) |
| `--port` | uint16 | | Port for TLSA lookup (default: from server address) |
| `--dns-server` | string | | DNS resolver address (default: system resolver) |
| `--no-dnssec` | bool | `false` | Skip DNSSEC AD flag validation (testing only) |

One of `--cert-file` or `--server` is required.

**Examples:**

Verify a local certificate file:

```bash
xkmsctl bootstrap dane verify-tlsa \
  --cert-file /etc/xkms/ca.pem \
  --hostname kms.example.com \
  --port 8443
```

Verify a running server's certificate:

```bash
xkmsctl bootstrap dane verify-tlsa \
  --server kms.example.com:8443
```

**Output (success):**

```
TLSA verification: OK
  Hostname:  kms.example.com
  Port:      8443
  Records:   2
  Matched:   _8443._tcp.kms.example.com. TLSA 2 1 1
  DNSSEC:    validated (AD=1)
```

**Output (failure):**

```
TLSA verification: FAILED
  Hostname:  kms.example.com
  Port:      8443
  Records:   1
  Error:     dane: TLSA verification failed
```

**Exit Codes:**

- `0` -- Verification succeeded
- `1` -- Verification failed, DNS lookup error, or missing flags

---

## bootstrap dane show-tlsa

Query and display TLSA records from DNS for a given hostname and port.

**Usage:**

```bash
xkmsctl bootstrap dane show-tlsa [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--hostname` | string | (required) | Hostname for TLSA lookup |
| `--port` | uint16 | (required) | Port for TLSA lookup |
| `--dns-server` | string | | DNS resolver address (default: system resolver) |
| `--no-dnssec` | bool | `false` | Skip DNSSEC AD flag validation (testing only) |

**Example:**

```bash
xkmsctl bootstrap dane show-tlsa \
  --hostname kms.example.com \
  --port 8443
```

**Output:**

```
TLSA records for _8443._tcp.kms.example.com:

  Record 1:
    Usage:         2 (DANE-TA)
    Selector:      1 (SPKI)
    Matching Type: 1 (SHA-256)
    Cert Data:     a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
    DNSSEC:        validated (AD=1)
```

**Exit Codes:**

- `0` -- Records found and displayed
- `1` -- No records found, DNS error, or DNSSEC validation failed

---

## bootstrap noise generate-key

Generate a new Curve25519 static keypair for the Noise_NK bootstrap protocol.

**Usage:**

```bash
xkmsctl bootstrap noise generate-key [flags]
```

**Flags:**

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--output` | `-o` | string | | Write private key to file with 0600 permissions |

**Examples:**

```bash
# Print both keys to stdout
xkmsctl bootstrap noise generate-key

# Write private key to file
xkmsctl bootstrap noise generate-key --output /etc/xkms/noise-static.key
```

**Output:**

```
Private key: 3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b
Public key:  a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
```

**Exit Codes:**

- `0` -- Key generated successfully
- `1` -- Generation or file write failed

---

## bootstrap noise show-key

Derive and display the public key from a Noise static private key.

**Usage:**

```bash
xkmsctl bootstrap noise show-key [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--key-file` | string | | Path to hex-encoded private key file |
| `--key-hex` | string | | Hex-encoded private key string |

One of `--key-file` or `--key-hex` is required.

**Example:**

```bash
xkmsctl bootstrap noise show-key --key-file /etc/xkms/noise-static.key
```

**Output:**

```
Public key: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
```

**Exit Codes:**

- `0` -- Key decoded and displayed
- `1` -- Missing flag, file error, or invalid key

---

## bootstrap noise show-spki-pin

Compute the SHA-256 SPKI pin from a TLS certificate for SPKI-pinned TLS bootstrap.

**Usage:**

```bash
xkmsctl bootstrap noise show-spki-pin [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--cert-file` | string | | Path to PEM certificate file |
| `--server` | string | | Server address (host:port) to connect and retrieve certificate |

One of `--cert-file` or `--server` is required.

**Examples:**

```bash
# From a certificate file
xkmsctl bootstrap noise show-spki-pin --cert-file /etc/xkms/server.pem

# From a running server
xkmsctl bootstrap noise show-spki-pin --server kms.example.com:8443
```

**Output (from file):**

```
SPKI SHA-256 pin: e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6
Subject:          CN=kms.example.com,O=Example Corp
```

**Output (from server):**

```
SPKI SHA-256 pin: e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6
Subject:          CN=kms.example.com,O=Example Corp
Issuer:           CN=Example Intermediate CA,O=Example Corp
Not Before:       2025-01-15 00:00:00
Not After:        2026-01-15 23:59:59
```

**Exit Codes:**

- `0` -- Pin computed and displayed
- `1` -- File error, connection failure, or parse error

---

## bootstrap spki show-pin

Compute the SHA-256 SPKI pin from a certificate. This is an alias for `bootstrap noise show-spki-pin`.

**Usage:**

```bash
xkmsctl bootstrap spki show-pin [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--cert-file` | string | | Path to PEM certificate file |
| `--server` | string | | Server address (host:port) to connect and retrieve certificate |

**Example:**

```bash
xkmsctl bootstrap spki show-pin --cert-file /etc/xkms/server.pem
```

**Exit Codes:**

- `0` -- Pin computed and displayed
- `1` -- File error, connection failure, or parse error

---

## Common Workflows

### DANE Bootstrap Setup

Generate TLSA records and publish them in DNS:

```bash
# 1. Generate TLSA record from your CA certificate
xkmsctl bootstrap dane generate-tlsa \
  --cert-file /etc/xkms/ca.pem \
  --hostname kms.example.com \
  --port 8443

# 2. Add the output to your DNS zone file, sign with DNSSEC

# 3. Verify the record is published and DNSSEC-validated
xkmsctl bootstrap dane show-tlsa \
  --hostname kms.example.com \
  --port 8443

# 4. Verify end-to-end
xkmsctl bootstrap dane verify-tlsa \
  --cert-file /etc/xkms/ca.pem \
  --hostname kms.example.com \
  --port 8443
```

### Auto Bootstrap (New Node Enrollment)

Use auto-bootstrap to try all configured methods:

```bash
xkmsctl bootstrap auto \
  --output-file /etc/xkms/ca-bundle.pem
```

### Noise Bootstrap Setup

Generate keys and configure the server:

```bash
# On the server
xkmsctl bootstrap noise generate-key \
  --output /etc/xkms/noise-static.key

# Distribute the public key to clients out-of-band
```

### Certificate Rotation

When rotating certificates, pre-publish the new TLSA record:

```bash
# Generate record for the new certificate
xkmsctl bootstrap dane generate-tlsa \
  --cert-file /etc/xkms/ca-new.pem \
  --hostname kms.example.com \
  --port 8443

# Add to DNS alongside the existing record
# Wait for TTL expiry, then remove the old record
```

## See Also

- [CA Bundle Bootstrap](../../ca/bootstrap.md) -- Protocol documentation
- [DANE/TLSA Concepts](../../ca/dane.md) -- RFC 6698 details and security properties
- [Bootstrap Configuration](../../configuration/bootstrap.md) -- YAML configuration reference
