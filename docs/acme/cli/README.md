# CLI Tools

go-trusted-ca provides three CLI binaries for certificate authority operations.

## Tools Overview

| Binary | Description | Location |
|--------|-------------|----------|
| `cactl` | CA administration tool | `cmd/cactl/` |
| `trusted-acme-server` | ACME server | `cmd/trusted-acme-server/` |
| `trusted-acme-client` | ACME client | `cmd/trusted-acme-client/` |

## Building

```bash
# Build all binaries
make build

# Build individual binaries
make build-cactl
make build-server
make build-client

# Build optimized distribution binaries
make dist
```

## Installation

```bash
# Install to ~/.local/bin/
make install
```

---

## cactl

Multi-protocol CA administration tool supporting Unix socket, REST, gRPC, QUIC, and MCP transports.

### Commands

| Command | Description |
|---------|-------------|
| `status` | Get CA status |
| `stats` | Get CA statistics |
| `cert` | Certificate operations |
| `account` | Account operations |
| `tenant` | Tenant management |
| `tenant eab` | External Account Binding operations |
| `tenant policy` | ABAC policy operations |
| `version` | Show version |

### Global Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--address` | `-a` | `/run/trusted-ca-grpc.sock` | Server address |
| `--transport` | `-t` | `unix` | Protocol: unix, rest, grpc, quic, mcp |
| `--timeout` | | `30s` | Request timeout |
| `--output` | `-o` | `table` | Output format: table, json, yaml |
| `--config` | `-c` | | Config file path |
| `--tls-cert` | | | Client TLS certificate |
| `--tls-key` | | | Client TLS private key |
| `--tls-ca` | | | CA certificate for verification |
| `--token` | | | Authentication token |
| `--log-level` | | `info` | Log level: debug, info, warn, error |

### Examples

```bash
# Get CA status via Unix socket (default)
cactl status

# Get status via REST API
cactl -t rest -a https://localhost:8443 status

# List certificates as JSON
cactl cert list -o json

# Create a tenant via gRPC
cactl -t grpc -a localhost:9443 tenant create --name "example"

# Create EAB credential
cactl tenant eab create tenant-123 --contact "admin@example.com"
```

---

## trusted-acme-server

RFC 8555 compliant ACME server with HTTPS/TLS 1.3 and optional multi-protocol Admin API.

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | (auto-search) | Config file path |
| `--https-addr` | `:8443` | HTTPS listen address (TLS 1.3) |
| `--admin-addr` | `:9443` | Admin API address |
| `--external-url` | `""` | External URL for ACME directory |
| `--log-level` | `info` | Log level: debug, info, warn, error |
| `--log-format` | `json` | Log format: json, text |
| `--storage-path` | `/var/lib/trustedca/data` | Storage path for ACME data |
| `--admin-enabled` | `false` | Enable Admin API |
| `-v, --version` | | Print version |

### Environment Variables

All other settings are configured via environment variables with the `TRUSTEDCA_` prefix:

| Variable | Default | Description |
|----------|---------|-------------|
| `TRUSTEDCA_RATE_LIMIT_REQUESTS` | `20` | Max requests per interval |
| `TRUSTEDCA_RATE_LIMIT_INTERVAL` | `1s` | Rate limit interval |
| `TRUSTEDCA_ADMIN_REST_ADDR` | `:9443` | Admin REST address |
| `TRUSTEDCA_ADMIN_GRPC_ADDR` | `:9444` | Admin gRPC address |
| `TRUSTEDCA_ADMIN_QUIC_ADDR` | `:9445` | Admin QUIC address |
| `TRUSTEDCA_ADMIN_MCP_ADDR` | `:9446` | Admin MCP address |
| `TRUSTEDCA_ADMIN_GRPC_UNIX_PATH` | `/run/trustedca-grpc.sock` | Admin gRPC Unix socket path |

### Examples

```bash
# Start ACME server with defaults (HTTPS :8443, TLS 1.3)
trusted-acme-server

# Start with Admin API enabled
trusted-acme-server --admin-enabled

# Custom storage path
trusted-acme-server --storage-path /data/acme

# Override via environment variables
TRUSTEDCA_ADMIN_ENABLED=true TRUSTEDCA_RATE_LIMIT_REQUESTS=100 trusted-acme-server
```

---

## trusted-acme-client

ACME client for certificate operations and TPM device enrollment.

### Subcommands

| Command | Description |
|---------|-------------|
| `register` | Register ACME account |
| `request` | Request certificate |
| `renew` | Renew certificate |
| `revoke` | Revoke certificate |
| `service` | Run as auto-renewal daemon |
| `device-enroll` | TPM device enrollment (enroll-01) |
| `device-attest` | TPM device attestation (device-attest-01) |

### Global Flags

| Flag | Description |
|------|-------------|
| `--config` | Config file path (YAML/JSON) |
| `--log-level` | Log level: debug, info, warn, error |
| `--log-format` | Log format: json, text |
| `--version` | Print version |

### Examples

```bash
# Register an account
trusted-acme-client register --email admin@example.com

# Request a certificate
trusted-acme-client request --domain example.com --challenge http-01

# Renew a certificate
trusted-acme-client renew --cert certificate.pem

# Revoke a certificate
trusted-acme-client revoke --cert certificate.pem --reason 1

# Run auto-renewal service
trusted-acme-client service
```

---

## Related Documentation

- [ACME Documentation](../acme/README.md)
- [Admin API Reference](../admin/api-reference.md)
- [Configuration Guide](../deployment/)
