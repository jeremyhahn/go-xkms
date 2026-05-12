# trusted-acme-server

RFC 8555 compliant ACME server with TLS 1.3 and multi-protocol Admin API.

## Overview

`trusted-acme-server` is a full-featured ACME server that issues and manages X.509 certificates:

- RFC 8555 compliant ACME protocol implementation
- **HTTPS with TLS 1.3 enforced by default**
- Keys managed via go-xkms (no filesystem key paths)
- Multi-protocol Admin API (REST, gRPC, QUIC, MCP, Unix socket)
- Viper configuration (config file, ENV vars, CLI flags)
- TPM-based device enrollment (enroll-01, device-attest-01)
- Rate limiting per RFC 8555 Section 6.6

## Installation

```bash
# Build from source
make build-server

# Or build optimized binary
make dist-server

# Build Docker image
make docker-build
```

## Quick Start

```bash
# Start with all defaults (HTTPS :8443, TLS 1.3, auto-create CA keys)
trusted-acme-server

# Override via environment variables
TRUSTEDCA_SERVER_HTTPS_ADDR=:443 trusted-acme-server

# Override via CLI flags
trusted-acme-server --https-addr :443 --log-level debug

# Use config file
trusted-acme-server --config /etc/trustedca/config.yaml

# Start with Admin API enabled
trusted-acme-server --admin-enabled
```

## Configuration

Configuration priority (lowest to highest):
1. Built-in defaults
2. Config file (`/etc/trustedca/config.yaml`)
3. Environment variables (`TRUSTEDCA_*`)
4. CLI flags

### Config File Locations

The server searches for `config.yaml` in these locations (first found wins):
1. `/etc/trustedca/` - System config (production)
2. `$HOME/.trustedca/` - User config
3. `./config/` - Local config directory
4. `.` - Current directory

### Command-Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | (auto-search) | Config file path |
| `--https-addr` | `:8443` | HTTPS server address (TLS 1.3) |
| `--admin-addr` | `:9443` | Admin API address |
| `--external-url` | `""` | External URL for ACME directory |
| `--log-level` | `info` | Log level: debug, info, warn, error |
| `--log-format` | `json` | Log format: json, text |
| `--storage-path` | `/var/lib/trustedca/data` | Storage path for ACME data |
| `--admin-enabled` | `false` | Enable Admin API on all protocols |
| `-v, --version` | | Print version |

#### Environment Variables (Additional Settings)

Rate limiting and admin addresses are configured via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `TRUSTEDCA_RATE_LIMIT_REQUESTS` | `20` | Max requests per interval per client |
| `TRUSTEDCA_RATE_LIMIT_INTERVAL` | `1s` | Rate limit interval |
| `TRUSTEDCA_ADMIN_REST_ADDR` | `:9443` | Admin REST/HTTPS server address |
| `TRUSTEDCA_ADMIN_GRPC_ADDR` | `:9444` | Admin gRPC server address |
| `TRUSTEDCA_ADMIN_QUIC_ADDR` | `:9445` | Admin QUIC/HTTP3 server address |
| `TRUSTEDCA_ADMIN_MCP_ADDR` | `:9446` | Admin MCP server address |
| `TRUSTEDCA_ADMIN_GRPC_UNIX_PATH` | `/run/trustedca-grpc.sock` | Admin gRPC Unix socket path |

### Environment Variables

All configuration can be set via environment variables with the `TRUSTEDCA_` prefix:

| Variable | Description |
|----------|-------------|
| `TRUSTEDCA_SERVER_HTTPS_ADDR` | HTTPS listen address |
| `TRUSTEDCA_SERVER_ADMIN_ADDR` | Admin API address |
| `TRUSTEDCA_SERVER_EXTERNAL_URL` | External URL for ACME endpoints |
| `TRUSTEDCA_LOGGING_LEVEL` | Log level |
| `TRUSTEDCA_LOGGING_FORMAT` | Log format (json, text) |
| `TRUSTEDCA_STORAGE_BACKEND` | Storage backend (memory, filesystem, s3) |
| `TRUSTEDCA_CA_SELECTED` | CA identity index (0=Root, 1=Intermediate) |
| `TRUSTEDCA_CA_DEFAULT_VALIDITY` | Default certificate validity (days) |

### Example Config File

```yaml
# /etc/trustedca/config.yaml
# All keys managed by go-xkms - NO filesystem key paths!

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

rate_limit:
  requests: 20
  interval: "1s"

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

admin:
  enabled: false
  rest_addr: ":9443"
  grpc_addr: ":9444"
  quic_addr: ":9445"
  mcp_addr: ":9446"
```

## TLS Configuration

The server **enforces TLS 1.3** for all HTTPS connections. The TLS certificate is obtained from the CA via go-xkms - no filesystem certificate paths are required.

```go
// TLS 1.3 is enforced by default
tlsConfig.MinVersion = tls.VersionTLS13
tlsConfig.MaxVersion = tls.VersionTLS13
```

Supported TLS 1.3 cipher suites (Go default):
- TLS_AES_128_GCM_SHA256
- TLS_AES_256_GCM_SHA384
- TLS_CHACHA20_POLY1305_SHA256

## ACME Endpoints

All ACME endpoints are served under `/acme/` via HTTPS:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/acme/directory` | GET | ACME directory (RFC 8555 Section 7.1.1) |
| `/acme/new-nonce` | HEAD, GET | Request new nonce (RFC 8555 Section 7.2) |
| `/acme/new-account` | POST | Create account (RFC 8555 Section 7.3) |
| `/acme/account/{id}` | POST | Account management (RFC 8555 Section 7.3.2) |
| `/acme/new-order` | POST | Create order (RFC 8555 Section 7.4) |
| `/acme/order/{id}` | POST, GET | Get order status (RFC 8555 Section 7.4) |
| `/acme/order/{id}/finalize` | POST | Finalize order (RFC 8555 Section 7.4) |
| `/acme/authz/{id}` | POST, GET | Authorization (RFC 8555 Section 7.5) |
| `/acme/challenge/{id}` | POST, GET | Challenge (RFC 8555 Section 7.5.1) |
| `/acme/cert/{id}` | POST, GET | Download certificate (RFC 8555 Section 7.4.2) |
| `/acme/revoke-cert` | POST | Revoke certificate (RFC 8555 Section 7.6) |
| `/acme/key-change` | POST | Key rollover (RFC 8555 Section 7.3.5) |
| `/acme/orders/{id}` | POST, GET | List account orders |
| `/acme/ca-bundle` | GET | Download CA certificate bundle |

## Operational Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check (returns "healthy") |
| `/ready` | GET | Readiness check (returns "ready") |
| `/metrics` | GET | Prometheus metrics |

## Supported Challenge Types

| Challenge | Description |
|-----------|-------------|
| `http-01` | HTTP validation (RFC 8555 Section 8.3) |
| `dns-01` | DNS validation (RFC 8555 Section 8.4) |
| `enroll-01` | TPM device enrollment (TCG spec) |
| `endorse-01` | EK certificate provisioning |
| `device-attest-01` | TPM remote attestation |

## Keystore Backends

The CA uses [go-xkms](https://github.com/jeremyhahn/go-xkms) for all key operations:

| Backend | Description |
|---------|-------------|
| `pkcs8` | Software keystore (default) |
| `tpm2` | Hardware TPM 2.0 |
| `pkcs11` | HSM/SmartCard via PKCS#11 |

## Admin API

When `--admin-enabled` is set, the server exposes administrative operations via multiple protocols:

| Protocol | Default Address | Use Case |
|----------|-----------------|----------|
| REST | `:9443` | Web clients, external integrations |
| gRPC | `:9444` | High-performance service-to-service |
| QUIC | `:9445` | Low-latency, mobile clients |
| MCP | `:9446` | AI/LLM integration |
| Unix | `/run/trustedca-grpc.sock` | Local CLI (`cactl`), gRPC over UDS |

### Admin Operations

- **Status**: Get CA status and statistics
- **Certificates**: List, get, revoke certificates
- **Accounts**: List, get, disable accounts
- **Tenants**: Multi-tenant CRUD operations
- **EAB**: External Account Binding management
- **Policies**: ABAC policy management

Use the [`cactl`](cactl.md) CLI to interact with the Admin API.

## Docker Deployment

```bash
# Build image
make docker-build

# Run container (HTTPS on :8443)
docker run -d \
  -p 8443:8443 \
  -v /data/trustedca:/var/lib/trustedca \
  go-trusted-ca:latest

# With Admin API enabled
docker run -d \
  -p 8443:8443 \
  -p 9443:9443 \
  -p 9444:9444 \
  -v /data/trustedca:/var/lib/trustedca \
  -e TRUSTEDCA_SERVER_EXTERNAL_URL=https://acme.example.com \
  go-trusted-ca:latest \
  --admin-enabled
```

## Prometheus Metrics

Available at `/metrics` (via HTTPS):

| Metric | Type | Description |
|--------|------|-------------|
| `acme_requests_total` | Counter | Total ACME requests by endpoint |
| `acme_request_duration_seconds` | Histogram | Request latency |
| `acme_certificates_issued_total` | Counter | Certificates issued |
| `acme_challenges_validated_total` | Counter | Challenges validated by type |
| `acme_rate_limit_exceeded_total` | Counter | Rate limit violations |

## Examples

### Basic ACME Server

```bash
# Start server on default port :8443
trusted-acme-server

# Test directory endpoint (skip TLS verification for self-signed cert)
curl -sk https://localhost:8443/acme/directory
```

### Production Setup

```bash
# Start with explicit config
trusted-acme-server \
  --config /etc/trustedca/config.yaml \
  --https-addr :443 \
  --admin-enabled \
  --log-level info
```

### Override with Environment Variables

```bash
TRUSTEDCA_SERVER_HTTPS_ADDR=:443 \
TRUSTEDCA_SERVER_EXTERNAL_URL=https://acme.example.com \
TRUSTEDCA_LOGGING_LEVEL=debug \
trusted-acme-server
```

## See Also

- [ACME Documentation](../acme/README.md)
- [Admin API Reference](../admin/api-reference.md)
- [cactl CLI](cactl.md)
- [Protocol Documentation](../protocols/README.md)
- [Configuration Reference](../acme/configuration.md)
