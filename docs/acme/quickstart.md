# Quickstart Guide

Get started with go-xkms in 5 minutes.

## Prerequisites

- Go 1.25+
- Docker (for integration tests)
- A domain name (for production use)

## Quick Setup

### 1. Build

```bash
make build
```

This creates:
- `bin/trusted-acme-server` - ACME server
- `bin/trusted-acme-client` - ACME client (for testing)

### 2. Zero Config Start (Development)

The server runs without any configuration file - keys are auto-created via go-xkms:

```bash
# Start with all defaults
# - Listens on :8443 (HTTPS, TLS 1.3)
# - Auto-creates Root + Intermediate CA keys (ECDSA P-256)
# - Uses in-memory storage
./bin/trusted-acme-server
```

### 3. Configuration Options

Configuration priority (lowest to highest):
1. Built-in defaults
2. Config file (`/etc/trustedca/config.yaml`)
3. Environment variables (`TRUSTEDCA_*`)
4. CLI flags

```bash
# Override via environment variables
TRUSTEDCA_SERVER_HTTPS_ADDR=:443 \
TRUSTEDCA_LOGGING_LEVEL=debug \
./bin/trusted-acme-server

# Override via CLI flags (highest priority)
./bin/trusted-acme-server --https-addr :443 --log-level debug

# Use explicit config file
./bin/trusted-acme-server --config /etc/trustedca/config.yaml
```

### 4. Verify

Check the ACME directory (use `-k` to skip TLS verification for self-signed cert):

```bash
curl -sk https://localhost:8443/acme/directory | jq
```

Expected response:
```json
{
  "newNonce": "https://localhost:8443/acme/new-nonce",
  "newAccount": "https://localhost:8443/acme/new-account",
  "newOrder": "https://localhost:8443/acme/new-order",
  "revokeCert": "https://localhost:8443/acme/revoke-cert",
  "keyChange": "https://localhost:8443/acme/key-change"
}
```

## Configuration File

Create `/etc/trustedca/config.yaml` (or `./config/config.yaml` for local dev):

```yaml
# All keys managed by go-xkms - NO filesystem key paths!
# TLS 1.3 enforced by default

server:
  https_addr: ":8443"
  admin_addr: ":9443"
  external_url: "https://acme.example.com"
  tls:
    min_version: "1.3"
    max_version: "1.3"

logging:
  level: info
  format: json

ca:
  selected: 1  # Use Intermediate CA for signing
  auto_import_issuing_ca: true
  default_validity: 365

storage:
  backend: memory  # memory, filesystem, s3, azure, gcp

challenges:
  http01:
    enabled: true
  dns01:
    enabled: true
  enroll_01:
    enabled: true
  endorse_01:
    enabled: true
  device_attest_01:
    enabled: true
```

## Issue Your First Certificate

### Using certbot

```bash
# Install certbot
apt-get install certbot  # or brew install certbot

# Register account (use --no-verify-ssl for self-signed CA cert)
certbot register --server https://localhost:8443/acme/directory \
  --agree-tos --email admin@example.com --no-verify-ssl

# Request certificate (HTTP-01 challenge)
certbot certonly --standalone \
  --server https://localhost:8443/acme/directory \
  -d example.com --no-verify-ssl
```

### Using the Built-in Client

```bash
./bin/trusted-acme-client \
  --server https://localhost:8443 \
  --domain example.com \
  --challenge http-01 \
  --insecure  # Skip TLS verification for self-signed CA
```

## Docker Deployment

### Quick Start with Docker

```bash
# Build image
make docker-build

# Run with default config (HTTPS on :8443)
docker run -d -p 8443:8443 \
  -v $(pwd)/data:/var/lib/trustedca \
  go-xkms:latest
```

### Docker Compose

```yaml
version: '3.8'
services:
  acme-server:
    image: go-xkms:latest
    ports:
      - "8443:8443"
      - "9443:9443"
    volumes:
      - ./config.yaml:/etc/trustedca/config.yaml
      - acme-data:/var/lib/trustedca
    environment:
      - TRUSTEDCA_SERVER_EXTERNAL_URL=https://acme.example.com

volumes:
  acme-data:
```

## Monitoring

go-xkms exposes Prometheus metrics:

```bash
# View metrics (via HTTPS)
curl -sk https://localhost:8443/metrics
```

Key metrics include:
- `acme_requests_total` - Total requests by endpoint and status
- `acme_certificates_issued_total` - Certificates issued
- `acme_challenges_completed_total` - Challenge validations
- `acme_request_duration_seconds` - Request latency

## Keystore Backends

The CA uses [go-xkms](https://github.com/jeremyhahn/go-xkms) for all key operations:

| Backend | Description |
|---------|-------------|
| `software` | Software keystore (default) |
| `tpm2` | Hardware TPM 2.0 |
| `pkcs11` | HSM/SmartCard via PKCS#11 |

## Next Steps

| Topic | Documentation |
|-------|---------------|
| All challenge types | [ACME README](acme/README.md) |
| DNS-01 providers | [DNS-01 Providers](acme/dns-01-providers.md) |
| ACME client | [Client Documentation](acme/client.md) |
| Multi-tenancy | [Multi-tenancy Guide](multi-tenancy.md) |
| QRDB clustering | [QRDB Architecture](qrdb/architecture.md) |
| Admin API | [Admin API](admin/README.md) |
| Monitoring | [Monitoring Guide](deployment/monitoring.md) |
| Architecture | [Architecture Overview](architecture.md) |

## Common Issues

### TLS Connection Refused

The server now requires HTTPS. Use `https://` URLs and `-k` or `--insecure` flags for self-signed certificates:
```bash
curl -sk https://localhost:8443/acme/directory
```

### Port Already in Use

Change the port via environment variable or CLI:
```bash
TRUSTEDCA_SERVER_HTTPS_ADDR=:9443 ./bin/trusted-acme-server
# or
./bin/trusted-acme-server --https-addr :9443
```

### Challenge Validation Failed

For HTTP-01 challenges, ensure:
1. Port 80 is accessible from the internet
2. Your domain resolves to your server's IP
3. No firewall blocking port 80

For DNS-01 challenges:
1. Configure a DNS provider (see [DNS-01 Providers](acme/dns-01-providers.md))
2. Set provider credentials via environment variables
3. Ensure TXT record propagation

Example with Cloudflare:
```bash
export CLOUDFLARE_DNS_API_TOKEN="your-api-token"
./bin/trusted-acme-client \
  --server https://localhost:8443 \
  --domain example.com \
  --challenge dns-01 \
  --provider cloudflare
```

## Development Mode

Run integration tests:
```bash
make integration-test
```
