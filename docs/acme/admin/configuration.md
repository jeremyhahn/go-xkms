# Admin API Configuration

Complete configuration reference for the Admin API server.

> **Correction (go-xkms#942):** there is no `TRUSTEDCA_*` environment
> prefix and no standalone `admin.*` multi-protocol listener config in this
> repository — both are pre-merge go-trusted-ca documentation that was
> never adapted. The ACME admin surface (`pkg/acme/admin`) is mounted on
> `xkmsd`'s own unified mTLS listener by `finalizeAdminModule`
> (`cmd/xkmsd/admin.go:130`), under the `/admin` and `/api/v1/tenants`
> path prefixes — it is not a separately configured REST/gRPC/QUIC/MCP
> port set. The environment prefix for every `xkmsd` setting, ACME
> included, is `XKMS_` (`pkg/config/load.go:39`). The tables below citing
> a `TRUSTEDCA_ADMIN_*` variable or an `admin.*` YAML key have not been
> verified against `pkg/config` and should not be treated as a working
> configuration reference; see
> [`../../acme-issuance/engineering.md`](../../acme-issuance/engineering.md)
> §Configuration and [`../../xkmsd-configuration/`](../../xkmsd-configuration/)
> for the verified surface.

## Overview

The Admin API is configured via Viper with support for config files, environment variables, and CLI flags. All keys are managed by [go-xkms](https://github.com/jeremyhahn/go-xkms) - no filesystem key paths required.

**Configuration priority (lowest to highest):**
1. Built-in defaults
2. Config file
3. Environment variables (`XKMS_*` — see correction above; not `TRUSTEDCA_*`)
4. CLI flags

## Configuration Structure

```yaml
admin:
  # Server settings
  enabled: true
  rest_addr: ":9443"
  grpc_addr: ":9444"
  quic_addr: ":9445"
  mcp_addr: ":9446"

  # TLS configuration - TLS 1.3 enforced by default
  # Certificates managed by go-xkms, NOT filesystem!
  tls:
    min_version: "1.3"
    max_version: "1.3"

  # Authentication
  auth:
    qrdb:
      endpoint: "https://qrdb.example.com:8443"
      tenant_id: "default"

  # Rate limiting
  rate_limit:
    enabled: true
    requests_per_minute: 100
    burst: 20

  # Logging
  logging:
    level: "info"
    format: "json"
    include_request_body: false
```

## Server Configuration

### Basic Settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enabled` | bool | `false` | Enable/disable Admin API |
| `rest_addr` | string | `":9443"` | REST/HTTPS address (TLS 1.3) |
| `grpc_addr` | string | `":9444"` | gRPC address |
| `quic_addr` | string | `":9445"` | QUIC/HTTP3 address |
| `mcp_addr` | string | `":9446"` | MCP address |
| `grpc_unix_path` | string | `/run/trustedca-grpc.sock` | gRPC Unix socket |

```yaml
admin:
  enabled: true
  rest_addr: ":9443"
  grpc_addr: ":9444"
  quic_addr: ":9445"
  mcp_addr: ":9446"
```

**Environment Variables:** none of this section's keys have a verified
environment-variable form — see the correction at the top of this page.

### TLS Configuration

The Admin API **enforces TLS 1.3** by default. TLS certificates are obtained from the CA via go-xkms - no filesystem certificate paths required.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `tls.min_version` | string | `"1.3"` | Minimum TLS version (enforced 1.3) |
| `tls.max_version` | string | `"1.3"` | Maximum TLS version (enforced 1.3) |
| `tls.client_auth` | string | `"none"` | Client authentication mode |

```yaml
admin:
  tls:
    min_version: "1.3"
    max_version: "1.3"
    client_auth: "require"  # none, request, require, verify
```

**TLS 1.3 Cipher Suites (Go default):**
- TLS_AES_128_GCM_SHA256
- TLS_AES_256_GCM_SHA384
- TLS_CHACHA20_POLY1305_SHA256

**Client Authentication Modes:**

| Mode | Description |
|------|-------------|
| `none` | No client certificate required |
| `request` | Request client certificate but don't require |
| `require` | Require client certificate |
| `verify` | Require and verify client certificate |

**Environment Variables:** none of this section's keys have a verified
environment-variable form — see the correction at the top of this page.

## Authentication Configuration

### QRDB Authentication

Integration with QRDB Auth for JWT token validation:

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `auth.qrdb.endpoint` | string | - | QRDB Auth endpoint URL |
| `auth.qrdb.tenant_id` | string | `"default"` | Default tenant ID |
| `auth.qrdb.timeout` | duration | `"30s"` | Request timeout |
| `auth.qrdb.tls.enabled` | bool | `true` | Enable TLS to QRDB |
| `auth.qrdb.tls.ca_file` | string | - | QRDB CA certificate |
| `auth.qrdb.tls.skip_verify` | bool | `false` | Skip TLS verification (dev only) |

```yaml
admin:
  auth:
    qrdb:
      endpoint: "https://qrdb.example.com:8443"
      tenant_id: "default"
      timeout: "30s"
      tls:
        enabled: true
        ca_file: "/etc/acme/qrdb-ca.crt"
        skip_verify: false
```

**Environment Variables:**
```bash
ADMIN_AUTH_QRDB_ENDPOINT="https://qrdb.example.com:8443"
ADMIN_AUTH_QRDB_TENANT_ID="default"
ADMIN_AUTH_QRDB_TIMEOUT="30s"
ADMIN_AUTH_QRDB_TLS_ENABLED=true
ADMIN_AUTH_QRDB_TLS_CA_FILE="/etc/acme/qrdb-ca.crt"
```

### Token Configuration

JWT token validation settings:

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `auth.token.issuer` | string | - | Expected token issuer |
| `auth.token.audience` | string | - | Expected token audience |
| `auth.token.clock_skew` | duration | `"1m"` | Allowed clock skew |
| `auth.token.jwks_url` | string | - | JWKS endpoint URL |
| `auth.token.jwks_refresh` | duration | `"1h"` | JWKS refresh interval |

```yaml
admin:
  auth:
    token:
      issuer: "https://auth.example.com"
      audience: "go-xkms-admin"
      clock_skew: "1m"
      jwks_url: "https://auth.example.com/.well-known/jwks.json"
      jwks_refresh: "1h"
```

## Authorization Configuration

### RBAC Settings

Role-based access control configuration:

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `authz.rbac.enabled` | bool | `true` | Enable RBAC |
| `authz.rbac.default_role` | string | `"viewer"` | Default role for authenticated users |
| `authz.rbac.cache_ttl` | duration | `"5m"` | Policy cache TTL |
| `authz.rbac.cache_size` | int | `1000` | Policy cache max entries |
| `authz.rbac.default_policies` | bool | `true` | Create default policies for new tenants |

```yaml
admin:
  authz:
    rbac:
      enabled: true
      default_role: "viewer"
      cache_ttl: "5m"
      cache_size: 1000
      default_policies: true
```

## Rate Limiting

Protect the Admin API from abuse with rate limiting:

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `rate_limit.enabled` | bool | `true` | Enable rate limiting |
| `rate_limit.requests_per_minute` | int | `100` | Max requests per minute |
| `rate_limit.burst` | int | `20` | Burst allowance |
| `rate_limit.by` | string | `"ip"` | Rate limit key (ip, user, tenant) |
| `rate_limit.whitelist` | []string | - | IPs exempt from rate limiting |

```yaml
admin:
  rate_limit:
    enabled: true
    requests_per_minute: 100
    burst: 20
    by: "ip"
    whitelist:
      - "10.0.0.0/8"
      - "192.168.0.0/16"
```

**Per-Endpoint Rate Limits:**

```yaml
admin:
  rate_limit:
    endpoints:
      # Higher limit for read operations
      "/admin/certificates":
        requests_per_minute: 200
        burst: 40
      # Lower limit for write operations
      "/admin/certificates/*/revoke":
        requests_per_minute: 10
        burst: 2
      # Strict limit for tenant creation
      "/api/v1/tenants":
        requests_per_minute: 5
        burst: 1
```

**Environment Variables:**
```bash
ADMIN_RATE_LIMIT_ENABLED=true
ADMIN_RATE_LIMIT_REQUESTS_PER_MINUTE=100
ADMIN_RATE_LIMIT_BURST=20
ADMIN_RATE_LIMIT_BY="ip"
```

## Logging Configuration

### Log Settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `logging.level` | string | `"info"` | Log level |
| `logging.format` | string | `"json"` | Log format (json, text) |
| `logging.output` | string | `"stdout"` | Log output (stdout, stderr, file) |
| `logging.file` | string | - | Log file path (if output is file) |
| `logging.max_size` | int | `100` | Max log file size in MB |
| `logging.max_backups` | int | `3` | Max number of backup files |
| `logging.max_age` | int | `28` | Max age in days |
| `logging.compress` | bool | `true` | Compress backup files |

```yaml
admin:
  logging:
    level: "info"
    format: "json"
    output: "file"
    file: "/var/log/acme/admin.log"
    max_size: 100
    max_backups: 3
    max_age: 28
    compress: true
```

**Log Levels:**

| Level | Description |
|-------|-------------|
| `debug` | Detailed debugging information |
| `info` | Informational messages |
| `warn` | Warning messages |
| `error` | Error messages |

**Environment Variables:**
```bash
ADMIN_LOGGING_LEVEL="info"
ADMIN_LOGGING_FORMAT="json"
ADMIN_LOGGING_OUTPUT="stdout"
```

### Request Logging

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `logging.request.enabled` | bool | `true` | Enable request logging |
| `logging.request.include_body` | bool | `false` | Include request body |
| `logging.request.include_headers` | bool | `false` | Include request headers |
| `logging.request.exclude_paths` | []string | - | Paths to exclude from logging |
| `logging.request.sensitive_headers` | []string | - | Headers to redact |

```yaml
admin:
  logging:
    request:
      enabled: true
      include_body: false
      include_headers: false
      exclude_paths:
        - "/health"
        - "/ready"
        - "/metrics"
      sensitive_headers:
        - "Authorization"
        - "X-API-Key"
```

### Audit Logging

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `logging.audit.enabled` | bool | `true` | Enable audit logging |
| `logging.audit.output` | string | `"file"` | Audit log output |
| `logging.audit.file` | string | - | Audit log file path |
| `logging.audit.include_response` | bool | `false` | Include response data |

```yaml
admin:
  logging:
    audit:
      enabled: true
      output: "file"
      file: "/var/log/acme/audit.log"
      include_response: false
```

## CORS Configuration

Cross-Origin Resource Sharing settings:

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `cors.enabled` | bool | `false` | Enable CORS |
| `cors.allowed_origins` | []string | - | Allowed origins |
| `cors.allowed_methods` | []string | - | Allowed HTTP methods |
| `cors.allowed_headers` | []string | - | Allowed headers |
| `cors.exposed_headers` | []string | - | Exposed headers |
| `cors.allow_credentials` | bool | `false` | Allow credentials |
| `cors.max_age` | int | `3600` | Preflight cache duration |

```yaml
admin:
  cors:
    enabled: true
    allowed_origins:
      - "https://admin.example.com"
      - "https://dashboard.example.com"
    allowed_methods:
      - "GET"
      - "POST"
      - "PUT"
      - "DELETE"
      - "OPTIONS"
    allowed_headers:
      - "Authorization"
      - "Content-Type"
      - "X-Request-ID"
    exposed_headers:
      - "X-Request-ID"
      - "X-Rate-Limit-Remaining"
    allow_credentials: true
    max_age: 3600
```

## Health Check Configuration

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `health.enabled` | bool | `true` | Enable health endpoints |
| `health.path` | string | `"/health"` | Health check path |
| `health.ready_path` | string | `"/ready"` | Readiness check path |

```yaml
admin:
  health:
    enabled: true
    path: "/health"
    ready_path: "/ready"
```

## Metrics Configuration

Prometheus metrics endpoint:

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `metrics.enabled` | bool | `true` | Enable metrics endpoint |
| `metrics.path` | string | `"/metrics"` | Metrics path |
| `metrics.include_request_duration` | bool | `true` | Include request duration histogram |
| `metrics.include_request_size` | bool | `true` | Include request size histogram |

```yaml
admin:
  metrics:
    enabled: true
    path: "/metrics"
    include_request_duration: true
    include_request_size: true
```

## Complete Configuration Example

Unverified — see the correction at the top of this page; there is no
`/etc/trustedca/` config path in this repository.

```yaml
# All keys managed by go-xkms - NO filesystem key paths!
# TLS 1.3 enforced by default

admin:
  # Server - multi-protocol support
  enabled: true
  rest_addr: ":9443"
  grpc_addr: ":9444"
  quic_addr: ":9445"
  mcp_addr: ":9446"
  grpc_unix_path: "/run/trustedca-grpc.sock"

  # TLS - TLS 1.3 enforced, certificates from go-xkms
  tls:
    min_version: "1.3"
    max_version: "1.3"
    client_auth: "none"

  # Authentication
  auth:
    qrdb:
      endpoint: "https://qrdb.example.com:8443"
      tenant_id: "default"
      timeout: "30s"
    token:
      issuer: "https://auth.example.com"
      audience: "go-xkms-admin"
      clock_skew: "1m"

  # Authorization
  authz:
    rbac:
      enabled: true
      default_role: "viewer"
      cache_ttl: "5m"
      cache_size: 1000
      default_policies: true

  # Rate limiting
  rate_limit:
    enabled: true
    requests_per_minute: 100
    burst: 20
    by: "ip"
    whitelist:
      - "10.0.0.0/8"

  # Logging
  logging:
    level: "info"
    format: "json"
    output: "stdout"
    request:
      enabled: true
      include_body: false
      exclude_paths:
        - "/health"
        - "/metrics"
    audit:
      enabled: true
      output: "file"
      file: "/var/log/acme/audit.log"

  # CORS
  cors:
    enabled: true
    allowed_origins:
      - "https://admin.example.com"
    allowed_methods:
      - "GET"
      - "POST"
      - "PUT"
      - "DELETE"
      - "OPTIONS"
    allowed_headers:
      - "Authorization"
      - "Content-Type"
    allow_credentials: true

  # Health checks
  health:
    enabled: true
    path: "/health"
    ready_path: "/ready"

  # Metrics
  metrics:
    enabled: true
    path: "/metrics"
```

## Environment Variables Reference

There is no `TRUSTEDCA_` prefix, and none of the `admin.*` paths below
have a verified environment-variable form. The real environment prefix for
every `xkmsd` setting is `XKMS_` (`pkg/config/load.go:39`); see the
correction at the top of this page.

## Configuration Best Practices

### Production Checklist

- [x] TLS 1.3 enforced (default - no action needed)
- [x] Certificates managed by go-xkms (no filesystem paths)
- [ ] Client authentication configured if needed (mTLS)
- [ ] QRDB Auth endpoint configured
- [ ] Rate limiting enabled
- [ ] Audit logging enabled
- [ ] CORS restricted to known origins
- [ ] Log level set to `info` or `warn`
- [ ] Metrics endpoint secured or disabled

### Security Recommendations

1. **TLS 1.3 is enforced** - older TLS versions are rejected
2. **Use go-xkms** for all key storage - never store keys on filesystem
3. **Enable rate limiting** to prevent abuse
4. **Configure audit logging** for compliance
5. **Restrict CORS origins** to trusted domains
6. **Secure metrics endpoint** or disable if not needed
7. **Use multi-protocol access** with appropriate authentication per protocol
