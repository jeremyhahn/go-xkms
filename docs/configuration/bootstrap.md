# Bootstrap Configuration

This document covers the YAML configuration for secure CA bundle bootstrapping. Bootstrap enables new nodes to obtain CA certificates before TLS is configured.

For protocol details, see the [CA Bundle Bootstrap documentation](../ca/bootstrap.md).

## Server-Side Configuration

The server-side configuration controls the Noise_NK bootstrap listener and SPKI pin availability.

### Full Example

```yaml
server:
  host: "0.0.0.0"
  rest_port: 8443
  grpc_port: 9090
  noise_port: 8445

protocols:
  noise: true

bootstrap:
  noise:
    enabled: true
    static_key_file: /etc/xkms/noise-static.key
    # static_key_hex: "3a4b5c6d..."  # Alternative: inline hex key
    max_connections: 100
    read_timeout: "10s"
    write_timeout: "10s"
  spki:
    enabled: true
    pin_sha256: "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6"
```

### Server Fields

#### `server.noise_port`

TCP port for the Noise_NK bootstrap listener.

| Property | Value |
|----------|-------|
| Type | int |
| Default | 8445 |
| YAML key | `server.noise_port` |
| Environment | `XKMS_NOISE_PORT` |
| Required | Yes, when `protocols.noise` is true |

The port must be in the range 1-65535. It should be distinct from `rest_port`, `grpc_port`, `quic_port`, and `mcp_port`.

#### `protocols.noise`

Enables the Noise_NK bootstrap protocol listener.

| Property | Value |
|----------|-------|
| Type | bool |
| Default | false |
| YAML key | `protocols.noise` |
| Required | No |

When true, the server starts a TCP listener on `noise_port` that accepts Noise_NK handshakes for CA bundle distribution. The `bootstrap.noise` section must also be configured.

### Bootstrap Noise Fields

#### `bootstrap.noise.enabled`

Controls whether the Noise bootstrap handler is active.

| Property | Value |
|----------|-------|
| Type | bool |
| Default | false |
| YAML key | `bootstrap.noise.enabled` |
| Environment | `XKMS_NOISE_ENABLED` |
| Required | No |

Both `protocols.noise` and `bootstrap.noise.enabled` must be true for the Noise bootstrap server to accept connections.

#### `bootstrap.noise.static_key_file`

Path to a file containing the hex-encoded Noise static private key (64 hex characters on a single line).

| Property | Value |
|----------|-------|
| Type | string |
| Default | (none) |
| YAML key | `bootstrap.noise.static_key_file` |
| Environment | `XKMS_NOISE_STATIC_KEY_FILE` |
| Required | One of `static_key_file` or `static_key_hex` |

The file should have restrictive permissions (0600). Generate the key with:

```bash
xkmsctl bootstrap noise generate-key --output /etc/xkms/noise-static.key
```

#### `bootstrap.noise.static_key_hex`

Inline hex-encoded Noise static private key (64 hex characters).

| Property | Value |
|----------|-------|
| Type | string |
| Default | (none) |
| YAML key | `bootstrap.noise.static_key_hex` |
| Environment | `XKMS_NOISE_STATIC_KEY` |
| Required | One of `static_key_file` or `static_key_hex` |

If both `static_key_file` and `static_key_hex` are set, `static_key_file` takes precedence. Inline keys are convenient for containerized deployments where the key is injected via environment variable.

#### `bootstrap.noise.max_connections`

Maximum number of concurrent Noise bootstrap connections.

| Property | Value |
|----------|-------|
| Type | int |
| Default | 100 |
| YAML key | `bootstrap.noise.max_connections` |
| Required | No |

Connections exceeding this limit are immediately closed. This prevents resource exhaustion during high-volume enrollment periods.

#### `bootstrap.noise.read_timeout`

Deadline for reading a complete frame from a client.

| Property | Value |
|----------|-------|
| Type | string (Go duration) |
| Default | `10s` |
| YAML key | `bootstrap.noise.read_timeout` |
| Required | No |

Uses Go duration format: `5s`, `100ms`, `1m`, etc.

#### `bootstrap.noise.write_timeout`

Deadline for writing a complete frame to a client.

| Property | Value |
|----------|-------|
| Type | string (Go duration) |
| Default | `10s` |
| YAML key | `bootstrap.noise.write_timeout` |
| Required | No |

Uses Go duration format: `5s`, `100ms`, `1m`, etc.

### Bootstrap SPKI Fields

#### `bootstrap.spki.enabled`

Controls whether the SPKI-pinned TLS bootstrap endpoint is available on the REST API.

| Property | Value |
|----------|-------|
| Type | bool |
| Default | false |
| YAML key | `bootstrap.spki.enabled` |
| Required | No |

When enabled, the REST API serves the CA bundle at `/api/v1/ca/bundle`. Clients using SPKI-pinned TLS connect to this dedicated bootstrap endpoint to retrieve the bundle before TLS trust is established.

#### `bootstrap.spki.pin_sha256`

The hex-encoded SHA-256 hash of the server's SubjectPublicKeyInfo. This value is distributed to clients for SPKI pin verification.

| Property | Value |
|----------|-------|
| Type | string (64 hex characters) |
| Default | (none) |
| YAML key | `bootstrap.spki.pin_sha256` |
| Environment | `XKMS_SPKI_PIN` |
| Required | No (computed from server certificate) |

This field is informational on the server side. It is primarily used in documentation and provisioning templates to record which pin value should be distributed to clients.

Compute the pin with:

```bash
xkmsctl bootstrap noise show-spki-pin --cert-file /etc/xkms/server.pem
```

## Client-Side Configuration

Client-side configuration is used by SDK consumers to configure the bootstrapper. These fields are typically set in the application's own configuration file, not in the xkmsd server config.

### Full Example

```yaml
bootstrap:
  noise:
    enabled: true
    server_addr: "kms.example.com:8445"
    server_static_key: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
    connect_timeout: "10s"
    operation_timeout: "30s"
  spki:
    enabled: false
    server_url: "https://kms.example.com:8443"
    pin_sha256: "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6"
    connect_timeout: "10s"
```

### Client Noise Fields

#### `bootstrap.noise.server_addr`

Address of the Noise bootstrap server in `host:port` format.

| Property | Value |
|----------|-------|
| Type | string |
| Default | (none) |
| Required | Yes, when `bootstrap.noise.enabled` is true |

Example: `"kms.example.com:8445"`, `"10.0.0.1:8445"`

#### `bootstrap.noise.server_static_key`

Hex-encoded 32-byte Curve25519 public key of the server (64 hex characters).

| Property | Value |
|----------|-------|
| Type | string |
| Default | (none) |
| Required | Yes, when `bootstrap.noise.enabled` is true |

This is the server's **public** key, not the private key. Obtain it from the server administrator or by running `xkmsctl bootstrap noise show-key` on the server.

#### `bootstrap.noise.connect_timeout`

TCP connection timeout for the initial connection to the bootstrap server.

| Property | Value |
|----------|-------|
| Type | string (Go duration) |
| Default | `10s` |
| Required | No |

#### `bootstrap.noise.operation_timeout`

Timeout for the full bootstrap operation including handshake and CA bundle retrieval.

| Property | Value |
|----------|-------|
| Type | string (Go duration) |
| Default | `30s` |
| Required | No |

### Client SPKI Fields

#### `bootstrap.spki.server_url`

Base URL of the xkms server for SPKI-pinned HTTPS bootstrap.

| Property | Value |
|----------|-------|
| Type | string |
| Default | (none) |
| Required | Yes, when `bootstrap.spki.enabled` is true |

Must use the `https://` scheme. Example: `"https://kms.example.com:8443"`

The bootstrap client appends `/api/v1/ca/bundle` to this URL automatically.

#### `bootstrap.spki.pin_sha256`

Hex-encoded SHA-256 hash of the server's SubjectPublicKeyInfo (64 hex characters).

| Property | Value |
|----------|-------|
| Type | string |
| Default | (none) |
| Required | Yes, when `bootstrap.spki.enabled` is true |

Compute the pin with `xkmsctl bootstrap noise show-spki-pin`.

#### `bootstrap.spki.connect_timeout`

HTTP request timeout for the SPKI-pinned TLS connection.

| Property | Value |
|----------|-------|
| Type | string (Go duration) |
| Default | `10s` |
| Required | No |

## Environment Variable Reference

All server-side bootstrap settings can be overridden with environment variables:

| Variable | Config Path | Description |
|----------|-------------|-------------|
| `XKMS_NOISE_ENABLED` | `bootstrap.noise.enabled` | Enable Noise bootstrap (`true`/`false`) |
| `XKMS_NOISE_STATIC_KEY` | `bootstrap.noise.static_key_hex` | Inline Noise static private key (hex) |
| `XKMS_NOISE_STATIC_KEY_FILE` | `bootstrap.noise.static_key_file` | Path to Noise static private key file |
| `XKMS_NOISE_PORT` | `server.noise_port` | Noise bootstrap TCP port |
| `XKMS_SPKI_PIN` | `bootstrap.spki.pin_sha256` | SPKI SHA-256 pin (also enables SPKI) |

Environment variables take precedence over YAML file values.

## Example Configurations

### Development (Local)

Minimal configuration for local development:

```yaml
server:
  host: "127.0.0.1"
  rest_port: 8443
  noise_port: 8445

protocols:
  noise: true

bootstrap:
  noise:
    enabled: true
    static_key_hex: "3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b"
```

### Production (File-Based Key)

Production configuration with key stored on disk:

```yaml
server:
  host: "0.0.0.0"
  rest_port: 8443
  grpc_port: 9090
  noise_port: 8445

protocols:
  rest: true
  grpc: true
  noise: true

bootstrap:
  noise:
    enabled: true
    static_key_file: /etc/xkms/noise-static.key
    max_connections: 50
    read_timeout: "5s"
    write_timeout: "5s"
  spki:
    enabled: true
    pin_sha256: "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6"
```

### Container Deployment (Environment Variables)

When running in a container, inject the key via environment:

```bash
docker run -e XKMS_NOISE_ENABLED=true \
           -e XKMS_NOISE_STATIC_KEY="3a4b5c6d..." \
           -e XKMS_NOISE_PORT=8445 \
           -p 8443:8443 \
           -p 8445:8445 \
           xkmsd
```

### Noise-Only Bootstrap (No SPKI)

If all clients use Noise_NK and SPKI fallback is not needed:

```yaml
server:
  noise_port: 8445

protocols:
  noise: true

bootstrap:
  noise:
    enabled: true
    static_key_file: /etc/xkms/noise-static.key
  spki:
    enabled: false
```

### SPKI-Only Bootstrap (No Noise)

If the deployment only needs SPKI-pinned TLS (e.g., all traffic must go through HTTPS proxies):

```yaml
server:
  rest_port: 8443

protocols:
  rest: true

bootstrap:
  noise:
    enabled: false
  spki:
    enabled: true
    pin_sha256: "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6"
```

## DANE Configuration

### Server-Side DANE Fields

#### `bootstrap.dane.enabled`

Controls whether the DANE/TLSA bootstrap path is advertised and available.

| Property | Value |
|----------|-------|
| Type | bool |
| Default | false |
| YAML key | `bootstrap.dane.enabled` |
| Environment | `XKMS_DANE_ENABLED` |
| Required | No |

When enabled, clients using DANE bootstrap can fetch the CA bundle over HTTPS and verify it against TLSA DNS records. No special server-side listener is needed -- the existing REST API serves the bundle at `/api/v1/ca/bundle`.

#### `bootstrap.dane.hostname`

The hostname published in TLSA DNS records. This is the hostname clients use for TLSA lookups.

| Property | Value |
|----------|-------|
| Type | string |
| Default | (none) |
| YAML key | `bootstrap.dane.hostname` |
| Environment | `XKMS_DANE_HOSTNAME` |
| Required | Yes, when `bootstrap.dane.enabled` is true |

Must match the DNS name where TLSA records are published (e.g., `kms.example.com`).

#### `bootstrap.dane.port`

The port number published in TLSA DNS records. This forms the `_<port>._tcp.<hostname>` query name.

| Property | Value |
|----------|-------|
| Type | uint16 |
| Default | (none; typically matches `rest_port`) |
| YAML key | `bootstrap.dane.port` |
| Environment | `XKMS_DANE_PORT` |
| Required | Yes, when `bootstrap.dane.enabled` is true |

#### `bootstrap.dane.dns_server`

DNS resolver address for TLSA lookups. When empty, the system resolver from `/etc/resolv.conf` is used.

| Property | Value |
|----------|-------|
| Type | string |
| Default | (system resolver) |
| YAML key | `bootstrap.dane.dns_server` |
| Environment | `XKMS_DANE_DNS_SERVER` |
| Required | No |

Format: `host:port` (e.g., `8.8.8.8:53`). If the port is omitted, port 53 is used.

### Client-Side DANE Fields

Client-side DANE configuration is used by SDK consumers. These fields are set in the application's own configuration file.

DNSSEC validation is always required for DANE bootstrap. DANE without DNSSEC provides no security guarantees, so the bootstrapper unconditionally enforces the Authenticated Data (AD) flag in DNS responses.

```yaml
bootstrap:
  dane:
    enabled: true
    server_url: "https://kms.example.com:8443"
    hostname: "kms.example.com"    # Optional: extracted from server_url
    port: 8443                      # Optional: extracted from server_url
    dns_server: "8.8.8.8:53"       # Optional: uses system resolver
    dns_over_tls: false             # Optional: enable DNS-over-TLS
    connect_timeout: "10s"          # Optional: default 10s
```

#### `bootstrap.dane.server_url`

Base URL of the xkms server for HTTPS CA bundle retrieval.

| Property | Value |
|----------|-------|
| Type | string |
| Default | (none) |
| Required | Yes, when `bootstrap.dane.enabled` is true |

Must use the `https://` scheme. The bootstrap client appends `/api/v1/ca/bundle` automatically.

#### `bootstrap.dane.dns_over_tls`

Enables DNS-over-TLS (DoT) for TLSA lookups on port 853.

| Property | Value |
|----------|-------|
| Type | bool |
| Default | false |
| Required | No |

When enabled, DNS queries are encrypted. Use with a DoT-capable resolver (e.g., `1.1.1.1`, `8.8.8.8`).

## AutoBootstrap Configuration

The AutoBootstrapper tries multiple bootstrap methods in priority order, returning the first successful result.

### Full Example

```yaml
bootstrap:
  auto:
    enabled: true
    method_order: ["dane", "noise", "spki", "direct"]
    per_method_timeout: "15s"
  dane:
    enabled: true
    server_url: "https://kms.example.com:8443"
    dns_server: "8.8.8.8:53"
  noise:
    enabled: true
    server_addr: "kms.example.com:8445"
    server_static_key: "a1b2c3d4e5f6..."
  spki:
    enabled: true
    server_url: "https://kms.example.com:8443"
    pin_sha256: "e5f6a7b8c9d0..."
  direct:
    enabled: true
    server_url: "https://kms.example.com:8443"
```

### AutoBootstrap Fields

#### `bootstrap.auto.method_order`

Priority order for bootstrap method attempts.

| Property | Value |
|----------|-------|
| Type | list of strings |
| Default | `["dane", "noise", "spki", "direct"]` |
| YAML key | `bootstrap.auto.method_order` |
| Required | No |

Valid method names: `dane`, `noise`, `spki`, `direct`. Methods whose configuration is nil are skipped.

#### `bootstrap.auto.per_method_timeout`

Timeout applied to each individual bootstrap method attempt.

| Property | Value |
|----------|-------|
| Type | string (Go duration) |
| Default | `15s` |
| YAML key | `bootstrap.auto.per_method_timeout` |
| Required | No |

If a method does not complete within this timeout, it fails and the next method is tried.

## DANE Environment Variables

| Variable | Config Path | Description |
|----------|-------------|-------------|
| `XKMS_DANE_ENABLED` | `bootstrap.dane.enabled` | Enable DANE bootstrap (`true`/`false`) |
| `XKMS_DANE_HOSTNAME` | `bootstrap.dane.hostname` | TLSA DNS lookup hostname |
| `XKMS_DANE_PORT` | `bootstrap.dane.port` | TLSA DNS lookup port |
| `XKMS_DANE_DNS_SERVER` | `bootstrap.dane.dns_server` | DNS resolver address |

## Example Configurations

### DANE + Auto Bootstrap (Recommended Production)

```yaml
server:
  host: "0.0.0.0"
  rest_port: 8443
  grpc_port: 9090
  noise_port: 8445

protocols:
  rest: true
  grpc: true
  noise: true

bootstrap:
  dane:
    enabled: true
    hostname: "kms.example.com"
    port: 8443
  noise:
    enabled: true
    static_key_file: /etc/xkms/noise-static.key
    max_connections: 50
  spki:
    enabled: true
    pin_sha256: "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6"
```

### DANE-Only Bootstrap

When all clients have DNSSEC-capable resolvers and no pre-shared keys are desired:

```yaml
server:
  rest_port: 8443

protocols:
  rest: true

bootstrap:
  dane:
    enabled: true
    hostname: "kms.example.com"
    port: 8443
  noise:
    enabled: false
  spki:
    enabled: false
```

### Client Auto Bootstrap Configuration

```yaml
bootstrap:
  auto:
    enabled: true
    per_method_timeout: "10s"
  dane:
    enabled: true
    server_url: "https://kms.example.com:8443"
  noise:
    enabled: true
    server_addr: "kms.example.com:8445"
    server_static_key: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
```

### Container Deployment with DANE

```bash
docker run -e XKMS_DANE_ENABLED=true \
           -e XKMS_DANE_HOSTNAME="kms.example.com" \
           -e XKMS_DANE_PORT=8443 \
           -e XKMS_NOISE_ENABLED=true \
           -e XKMS_NOISE_STATIC_KEY="3a4b5c6d..." \
           -p 8443:8443 \
           -p 8445:8445 \
           xkmsd
```

## See Also

- [CA Bundle Bootstrap](../ca/bootstrap.md) -- Protocol details, security properties, and SDK API
- [Integration Guide](../ca/bootstrap-integration.md) -- Project-specific usage for go-xkms, xkey, go-trusted-ca, and go-trusted-platform
- [DANE/TLSA Concepts](../ca/dane.md) -- RFC 6698 details, DNSSEC trust chain, and record format
- [Bootstrap CLI Commands](../usage/cli/bootstrap.md) -- CLI reference for DANE and other bootstrap commands
- [Noise CLI Commands](../usage/cli/noise.md) -- Key generation and SPKI pin tools (legacy path)
- [Configuration Overview](./README.md) -- All configuration topics
