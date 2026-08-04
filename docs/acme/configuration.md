# ACME Configuration Reference

Complete configuration reference for the go-xkms ACME server.

## Overview

The ACME server is configured via Viper with support for config files, environment variables, and CLI flags. All keys are managed by [go-xkms](https://github.com/jeremyhahn/go-xkms) - no filesystem key paths required.

**Configuration priority (lowest to highest):**
1. Built-in defaults
2. Config file (`/etc/trustedca/config.yaml`)
3. Environment variables (`TRUSTEDCA_*`)
4. CLI flags

## Configuration Hierarchy

```
ACME Server Configuration
    |
    +-- server:                    # HTTPS server settings (TLS 1.3)
    |   +-- https_addr
    |   +-- external_url
    |   +-- terms_of_service
    |   +-- tls
    |
    +-- challenges:                # Challenge type settings
    |   +-- http01
    |   +-- dns01
    |   +-- device_attest_01
    |   +-- enroll_01
    |   +-- endorse_01
    |
    +-- storage:                   # Storage backend settings
    |   +-- backend
    |   +-- objstore
    |
    +-- external_account_binding:  # EAB settings
    |   +-- required
    |   +-- endorse_required
    |   +-- device_id_meta_key
    |
    +-- caa:                       # CAA validation settings
    |   +-- enabled
    |   +-- identities
    |
    +-- rate_limiting:             # Rate limit settings
    |   +-- enabled
    |   +-- requests_per_second
    |
    +-- nonce:                     # Nonce settings
        +-- expiration
```

## Server Configuration

### Basic Server Settings

The server **enforces TLS 1.3** for all HTTPS connections. TLS certificates are obtained from the CA via go-xkms - no filesystem certificate paths required.

```yaml
server:
  # HTTPS listen address (TLS 1.3 enforced)
  # Format: "host:port" or ":port"
  https_addr: ":8443"

  # External URL for ACME endpoints (required for production)
  # This URL is used in ACME responses for resource URLs
  external_url: "https://acme.example.com"

  # Terms of Service URL (optional)
  # Displayed in directory metadata
  terms_of_service: "https://example.com/terms"

  # TLS configuration - TLS 1.3 enforced by default
  # Certificates are managed by go-xkms, NOT filesystem!
  tls:
    min_version: "1.3"
    max_version: "1.3"
```

### Server Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `https_addr` | string | `:8443` | HTTPS listen address (TLS 1.3) |
| `external_url` | string | `""` | Base URL for ACME endpoints |
| `terms_of_service` | string | `""` | URL to terms of service |
| `tls.min_version` | string | `"1.3"` | Minimum TLS version (enforced 1.3) |
| `tls.max_version` | string | `"1.3"` | Maximum TLS version (enforced 1.3) |

### TLS 1.3 Enforcement

TLS 1.3 is enforced by default with these cipher suites (Go default):
- TLS_AES_128_GCM_SHA256
- TLS_AES_256_GCM_SHA384
- TLS_CHACHA20_POLY1305_SHA256

```go
// TLS 1.3 is enforced in code
tlsConfig.MinVersion = tls.VersionTLS13
tlsConfig.MaxVersion = tls.VersionTLS13
```

## Challenge Configuration

### HTTP-01 Challenge

```yaml
acme:
  challenges:
    http01:
      # Enable HTTP-01 challenge type
      enabled: true

      # Port for HTTP validation requests
      # Default: "80"
      port: "80"

      # Timeout for HTTP requests
      timeout: "10s"

      # Custom resolver for DNS lookups (optional)
      # resolver: "8.8.8.8:53"
```

### DNS-01 Challenge

```yaml
acme:
  challenges:
    dns01:
      # Enable DNS-01 challenge type
      enabled: true

      # Timeout for DNS queries
      timeout: "5s"

      # DNS resolvers to use
      resolvers:
        - "8.8.8.8:53"
        - "1.1.1.1:53"

      # TTL for TXT records (seconds)
      ttl: 300

      # Propagation delay before verification
      propagation_delay: "60s"
```

### Device-Attest-01 Challenge

```yaml
acme:
  challenges:
    device_attest_01:
      # Enable device-attest-01 challenge type
      enabled: true

      # Port for attestation requests
      port: "8080"

      # Supported attestation formats
      formats:
        - "tpm"

      # PCR indices to verify in attestation
      pcr_indices:
        - 0
        - 1
        - 2
        - 3
        - 7

      # Require AK certificate chain validation
      require_ak_chain: true
```

### Enroll-01 Challenge

```yaml
acme:
  challenges:
    enroll_01:
      # Enable enroll-01 challenge type (TCG-CSR-IDevID)
      enabled: true

      # Port for enrollment requests
      port: "8080"

      # Timeout for credential activation
      activation_timeout: "30s"

      # Require EK certificate validation
      require_ek_cert: true
```

### Endorse-01 Challenge

```yaml
acme:
  challenges:
    endorse_01:
      # Enable endorse-01 challenge type (EK certificate issuance)
      enabled: true

      # Require External Account Binding for endorse-01
      # When true, only pre-authorized accounts can request EK certificates
      eab_required: true
```

### Challenge Options Summary

| Challenge | Option | Type | Default | Description |
|-----------|--------|------|---------|-------------|
| http01 | `enabled` | bool | true | Enable HTTP-01 |
| http01 | `port` | string | "80" | Validation port |
| http01 | `timeout` | duration | "10s" | Request timeout |
| dns01 | `enabled` | bool | true | Enable DNS-01 |
| dns01 | `timeout` | duration | "5s" | Query timeout |
| dns01 | `ttl` | int | 300 | TXT record TTL |
| device_attest_01 | `enabled` | bool | true | Enable attestation |
| device_attest_01 | `pcr_indices` | []int | [0,1,2,3,7] | PCRs to verify |
| enroll_01 | `enabled` | bool | true | Enable enrollment |
| enroll_01 | `require_ek_cert` | bool | true | Require EK cert |
| endorse_01 | `enabled` | bool | true | Enable EK issuance |
| endorse_01 | `eab_required` | bool | true | Require EAB |

## Storage Configuration

### Object Store Backend

```yaml
acme:
  storage:
    # Storage backend type
    backend: "objstore"

    # Base path for storage
    path: "/var/lib/acme"

    # Object store configuration
    objstore:
      # Storage type: local, s3, gcs, azure
      type: "local"

      # Local storage options
      local:
        path: "/var/lib/acme/data"

      # S3 storage options (if type: s3)
      s3:
        bucket: "acme-storage"
        region: "us-east-1"
        access_key: "${AWS_ACCESS_KEY_ID}"
        secret_key: "${AWS_SECRET_ACCESS_KEY}"

      # Serialization codec: json, cbor, msgpack
      # Uses go-codec library for pluggable serialization
      codec: "json"

      # Read buffer size
      read_buffer_size: 50
```

### Storage Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `backend` | string | "objstore" | Storage backend type |
| `path` | string | "/var/lib/acme" | Base storage path |
| `objstore.type` | string | "local" | Object store type |
| `objstore.codec` | string | "json" | Serialization codec (json, cbor, msgpack) |
| `objstore.read_buffer_size` | int | 50 | Read buffer size |

### Codec Configuration

The storage layer uses go-codec for pluggable serialization:

| Codec | Format | Description |
|-------|--------|-------------|
| `json` | Text | Human readable, default format |
| `cbor` | Binary | Compact, efficient for large datasets |
| `msgpack` | Binary | High performance, cross-language support |

```go
import (
    "github.com/jeremyhahn/go-codec"
    "github.com/jeremyhahn/go-xkms/pkg/acme/storage"
    "github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
)

// Create codec
c := storage.NewCodec(codec.CBOR)

// Create DAO with codec
accountDAO := objstore.NewAccountDAO(objStore, c)
orderDAO := objstore.NewOrderDAO(objStore, c, accountID)
```

## External Account Binding

```yaml
acme:
  external_account_binding:
    # Require EAB for all new accounts
    # Per RFC 8555 Section 7.3.4
    required: false

    # Require EAB specifically for endorse-01 challenges
    # Provides explicit authorization for EK certificate issuance
    endorse_required: true

    # Metadata key for device ID validation in EAB
    # Used to validate device identity during endorse-01
    # Common values: "device_id", "ek_pubkey_hash", "serial_number"
    device_id_meta_key: "ek_pubkey_hash"

    # EAB key algorithm
    # Options: hmac-sha256, hmac-sha384, hmac-sha512
    algorithm: "hmac-sha256"

    # EAB expiration time (0 = never expires)
    expiration: "24h"
```

### EAB Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `required` | bool | false | Require EAB for all accounts |
| `endorse_required` | bool | true | Require EAB for endorse-01 |
| `device_id_meta_key` | string | "" | Metadata key for device ID |
| `algorithm` | string | "hmac-sha256" | MAC algorithm for EAB |
| `expiration` | duration | "24h" | EAB credential expiration |

## CAA Validation

```yaml
acme:
  caa:
    # Enable CAA validation before certificate issuance
    # Per RFC 8659
    enabled: true

    # CAA identities for this CA
    # These are matched against CAA DNS records
    identities:
      - "acme.example.com"
      - "example.com"

    # DNS resolvers for CAA lookups
    resolvers:
      - "8.8.8.8:53"
      - "1.1.1.1:53"

    # Timeout for CAA lookups
    timeout: "5s"

    # Treat lookup failures as:
    # "allow" - allow issuance if CAA lookup fails
    # "deny" - deny issuance if CAA lookup fails
    lookup_failure_mode: "deny"
```

### CAA Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | true | Enable CAA validation |
| `identities` | []string | [] | CA identities for CAA matching |
| `resolvers` | []string | system | DNS resolvers for CAA |
| `timeout` | duration | "5s" | Lookup timeout |
| `lookup_failure_mode` | string | "deny" | Action on lookup failure |

## Rate Limiting

```yaml
acme:
  rate_limiting:
    # Enable rate limiting
    enabled: true

    # Global rate limits
    global:
      requests_per_second: 100
      burst: 50

    # Per-account rate limits
    per_account:
      requests_per_second: 20
      burst: 10

    # Per-IP rate limits
    per_ip:
      requests_per_second: 50
      burst: 25

    # Endpoint-specific limits
    endpoints:
      new_account:
        requests_per_hour: 10
        burst: 5
      new_order:
        requests_per_hour: 300
        burst: 50
      finalize:
        requests_per_hour: 300
        burst: 50
```

### Rate Limit Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | true | Enable rate limiting |
| `global.requests_per_second` | int | 100 | Global RPS limit |
| `per_account.requests_per_second` | int | 20 | Per-account RPS |
| `per_ip.requests_per_second` | int | 50 | Per-IP RPS |

## Nonce Configuration

```yaml
acme:
  nonce:
    # Nonce expiration time
    # Nonces older than this are rejected
    expiration: "10m"

    # Nonce size in bytes
    size: 16

    # Maximum nonces to store
    # Oldest nonces evicted when limit reached
    max_count: 100000
```

### Nonce Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `expiration` | duration | "10m" | Nonce validity period |
| `size` | int | 16 | Nonce size in bytes |
| `max_count` | int | 100000 | Maximum stored nonces |

## Multi-Tenant Configuration

```yaml
acme:
  multi_tenant:
    # Enable multi-tenant mode
    enabled: true

    # Tenant isolation level
    # "account" - tenants share storage, isolated by account
    # "storage" - tenants have separate storage partitions
    isolation: "account"

    # Default tenant for accounts without EAB
    default_tenant: "default"

    # KMS configuration for tenant CA keys
    kms:
      # KMS backend type - uses go-xkms directly
      type: "xkms"
```

## Logging Configuration

```yaml
acme:
  logging:
    # Log level: debug, info, warn, error
    level: "info"

    # Log format: json, text
    format: "json"

    # Include request IDs in logs
    include_request_id: true

    # Log file path (empty = stdout)
    file: ""

    # Log rotation
    rotation:
      max_size_mb: 100
      max_backups: 5
      max_age_days: 30
```

## Metrics Configuration

```yaml
acme:
  metrics:
    # Enable Prometheus metrics
    enabled: true

    # Metrics endpoint path
    path: "/metrics"

    # Include detailed per-endpoint metrics
    detailed: true

    # Histogram buckets for latency metrics
    latency_buckets:
      - 0.001
      - 0.005
      - 0.01
      - 0.05
      - 0.1
      - 0.5
      - 1.0
      - 5.0
```

## Complete Configuration Example

```yaml
# /etc/trustedca/config.yaml
# All keys managed by go-xkms - NO filesystem key paths!
# TLS 1.3 enforced by default

server:
  # HTTPS listen address (TLS 1.3 enforced)
  https_addr: ":8443"

  # Admin API address
  admin_addr: ":9443"

  # External URL for ACME endpoints
  external_url: "https://acme.example.com"

  # TLS configuration - TLS 1.3 enforced
  tls:
    min_version: "1.3"
    max_version: "1.3"

logging:
  level: info
  format: json

ca:
  # Which CA identity to use for signing (0=Root, 1=Intermediate)
  selected: 1
  auto_import_issuing_ca: true
  default_validity: 365

storage:
  # Backend: memory, filesystem, s3, azure, gcp
  backend: memory

challenges:
  http01:
    enabled: true
    port: "80"
    timeout: "10s"
  dns01:
    enabled: true
    timeout: "5s"
    ttl: 300
  device_attest_01:
    enabled: true
    formats:
      - "tpm"
    require_ak_chain: true
  enroll_01:
    enabled: true
    require_ek_cert: true
  endorse_01:
    enabled: true
    eab_required: true

external_account_binding:
  required: false
  endorse_required: true
  device_id_meta_key: "ek_pubkey_hash"
  algorithm: "hmac-sha256"
  expiration: "24h"

caa:
  enabled: true
  identities:
    - "acme.example.com"
  resolvers:
    - "8.8.8.8:53"
  timeout: "5s"
  lookup_failure_mode: "deny"

rate_limit:
  requests: 20
  interval: "1s"

nonce:
  expiration: "10m"
  size: 16
  max_count: 100000

admin:
  enabled: false
  rest_addr: ":9443"
  grpc_addr: ":9444"
  quic_addr: ":9445"
  mcp_addr: ":9446"
```

## Programmatic Configuration

The ACME server can also be configured programmatically:

```go
import (
    "github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
    "github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
)

// Create storage factory
storageFactory, err := objstore.NewFactory(&objstore.Config{
    Path:       "/var/lib/acme",
    Serializer: "json",
})

// Create challenge map
challengeMap := map[string]common.ChallengeVerifierFunc{
    "http-01":         http01.Verify,
    "dns-01":          dns01.Verify,
    "enroll-01":       enroll01.Verify,
    "endorse-01":      endorse01.Verify,
    "device-attest-01": deviceattest01.Verify,
}

// Create REST service
params := &handlers.Params{
    BaseRESTURI:             "https://acme.example.com",
    CA:                      certificateAuthority,
    CAAIdentities:           []string{"acme.example.com"},
    CAAValidator:            caaValidator,
    ChallengeMap:            challengeMap,
    EndorseEABRequired:      true,
    EndorseDeviceIDMetaKey:  "ek_pubkey_hash",
    ExternalAccountRequired: false,
    Logger:                  slog.Default(),
    StorageFactory:          storageFactory,
    TermsOfService:          "https://example.com/terms",
    OrderFinalizeHooks:      hookRegistry,
    KMSService:              kmsService,
}

service, err := handlers.NewRestService(params)
```

### Params Structure

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `BaseRESTURI` | string | Yes | Base URL for ACME endpoints |
| `CA` | CertificateAuthority | Yes | CA for certificate operations |
| `CAAIdentities` | []string | No | CAA identities |
| `CAAValidator` | CAAValidatorInterface | No | CAA validator |
| `ChallengeMap` | map[string]ChallengeVerifierFunc | No | Challenge verifiers |
| `EndorseEABRequired` | bool | No | Require EAB for endorse-01 |
| `EndorseDeviceIDMetaKey` | string | No | EAB metadata key for device ID |
| `ExternalAccountRequired` | bool | No | Require EAB for all accounts |
| `Logger` | *slog.Logger | Yes | Structured logger |
| `StorageFactory` | storage.Factory | Yes | Storage factory |
| `TermsOfService` | string | No | Terms of service URL |
| `OrderFinalizeHooks` | *OrderFinalizeHookRegistry | No | Finalization hooks |
| `KMSService` | xkms.KMSService | No | KMS for tenant CA signing |

## Environment Variables

All configuration can be set via environment variables with the `TRUSTEDCA_` prefix:

```bash
# Override via environment variables
TRUSTEDCA_SERVER_HTTPS_ADDR=:443 \
TRUSTEDCA_SERVER_EXTERNAL_URL=https://acme.example.com \
TRUSTEDCA_LOGGING_LEVEL=debug \
trusted-acme-server
```

| Variable | Description |
|----------|-------------|
| `TRUSTEDCA_SERVER_HTTPS_ADDR` | HTTPS listen address |
| `TRUSTEDCA_SERVER_ADMIN_ADDR` | Admin API address |
| `TRUSTEDCA_SERVER_EXTERNAL_URL` | External URL for ACME endpoints |
| `TRUSTEDCA_LOGGING_LEVEL` | Log level (debug, info, warn, error) |
| `TRUSTEDCA_LOGGING_FORMAT` | Log format (json, text) |
| `TRUSTEDCA_STORAGE_BACKEND` | Storage backend (memory, filesystem, s3) |
| `TRUSTEDCA_CA_SELECTED` | CA identity index (0=Root, 1=Intermediate) |
| `TRUSTEDCA_CA_DEFAULT_VALIDITY` | Default certificate validity (days) |

### S3 Storage Variables

For S3 storage backend:

```bash
export TRUSTEDCA_STORAGE_BACKEND=s3
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_REGION="us-east-1"
```

## See Also

- [README](README.md) - Module overview
- [Architecture](architecture.md) - System architecture
- [Challenges](challenges.md) - Challenge configuration details
- [API Reference](api-reference.md) - HTTP API documentation
