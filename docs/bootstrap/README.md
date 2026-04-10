# Bootstrap Architecture

go-xkms implements a secure bootstrap workflow for establishing trust between clients and servers without pre-existing PKI infrastructure.

## Trust Bootstrapping Methods

Three methods are available, tried in priority order by `xkmsctl bootstrap auto`:

### 1. DANE (DNS-Based Authentication of Named Entities)

Uses DNSSEC-signed TLSA records (RFC 6698) to authenticate the server's CA certificate.

```bash
xkmsctl bootstrap dane generate-tlsa --cert-file /etc/xkms/ca.pem \
  --hostname kms.example.com --port 8443
```

### 2. Noise Protocol (Noise_NK)

Uses a pre-shared Curve25519 public key to establish an encrypted channel and retrieve the CA bundle. The server's Noise static key is distributed out-of-band.

```bash
xkmsctl bootstrap noise generate-key --output /etc/xkms/noise-static.key
xkmsctl bootstrap auto --server-url https://kms.example.com:8443 --noise-key <hex-pubkey>
```

### 3. SPKI Pinning (Trust-on-First-Use)

Uses the SHA-256 hash of the server's Subject Public Key Info for certificate pinning. The pin is printed by the server on first boot.

```bash
xkey auth register --server https://kms.example.com:8443 --spki-pin e5f6a7b8...
```

## Auto-Bootstrap Flow

The `bootstrap auto` command tries configured methods in priority order (DANE, Noise, SPKI). The first method that succeeds writes the CA bundle.

```bash
xkmsctl bootstrap auto --server-url https://kms.example.com:8443 \
  --dane-hostname kms.example.com --bundle-output /etc/xkms/ca-bundle.pem
```

### Flags

| Flag | Description |
|------|-------------|
| `--server-url` | xkms server URL (e.g., `https://kms.example.com:8443`) |
| `--dane-hostname` | Hostname for DANE/TLSA verification |
| `--dane-dns-server` | DNS server for DANE lookups (e.g., `8.8.8.8:53`) |
| `--noise-key` | Hex-encoded Noise static public key of the server |
| `--noise-addr` | Noise bootstrap server address (`host:port`) |
| `--spki-pin` | Hex-encoded SHA-256 SPKI pin of server certificate |
| `--bundle-output` | Path to write CA bundle file (default: stdout) |

## Server First Boot

On first start, the server outputs three pieces of information:

1. **Setup Token** -- One-time JWT with 15-minute TTL for initial admin registration
2. **SPKI Pin** -- SHA-256 hash of the server's TLS certificate public key
3. **Hostname** -- Server address and port

## Custodian Setup

Custodian groups manage Shamir secret sharing for barrier operations.

```bash
# Create a group with 3-of-5 threshold
xkmsctl custodian create --name "Production Ops" --threshold 3 --total 5

# Add members
xkmsctl custodian add-member --group-id <id> --user-id user-1 --username alice
xkmsctl custodian add-member --group-id <id> --user-id user-2 --username bob
xkmsctl custodian add-member --group-id <id> --user-id user-3 --username carol

# Distribute shares to all members
xkmsctl custodian distribute --group-id <id>
```

Each member receives one Shamir share via their configured delivery method.

## Share Distribution and Barrier Unsealing

Custodians receive and manage their shares locally in `~/.xkey/shares/`, encrypted by the local barrier when active.

```bash
# Custodian polls server for assigned shares
xkey share receive --server grpc://kms.example.com:9090

# List locally stored shares
xkey share list

# Import/export shares for offline transfer or backup
xkey share import --file /tmp/share-1.json
xkey share export --server grpc://kms.example.com:9090 --group-id <id> --file /tmp/share.json
```

Custodians submit their shares to unseal the server barrier:

```bash
xkey share unseal --server grpc://kms.example.com:9090 --group-id <id>
```

The server reports progress. Once the threshold is reached, the barrier is unsealed and key operations resume.

## Client Certificate Enrollment

After the barrier is unsealed, clients enroll for mTLS certificates:

```bash
xkey cert request --server https://kms.example.com:8443 \
  --cn "alice@example.com" --spki-pin e5f6a7b8...
```

The private key never leaves the client device. Only the CSR (public key) is sent to the server CA.

## Multi-Tenant Barriers

Each tenant can have an independent barrier with its own custodian quorum:

```bash
xkmsctl tenant create --id acme --name "Acme Corporation"
xkmsctl tenant barrier-init --id acme --threshold 3 --shares 5
xkmsctl tenant barrier-unseal --id acme --share <base64-share>
xkmsctl tenant barrier-status --id acme
```

Tenant barriers are isolated -- cross-tenant access is denied.

## See Also

- [Getting Started](../usage/getting-started.md) -- End-to-end setup walkthrough
- [xkey auth](../usage/cli/auth.md) -- Authentication commands
- [xkey share](../usage/cli/share.md) -- Share management commands
