# Audit Logging

Production-grade audit logging for security-relevant operations in the Certificate Authority and ACME server.

## Overview

The audit system tracks comprehensive security-relevant events including certificate lifecycle, account management, authorization validation, TPM attestation, and authentication failures. All events are logged as structured JSON with automatic rotation and configurable retention policies.

## Key Features

| Feature | Description |
|---------|-------------|
| **Structured Logging** | JSON, CBOR, or MsgPack format with automatic rotation |
| **Configurable Codec** | Pluggable serialization via go-codec library |
| **Buffered Writes** | High performance with configurable flush intervals |
| **Thread-Safe** | Concurrent logging from multiple goroutines |
| **Retention Policies** | Configurable log age and size limits |
| **HTTP Middleware** | Automatic request auditing |
| **Context Propagation** | Request correlation via context |

## Event Types

| Event Type | Description |
|------------|-------------|
| `CERTIFICATE_ISSUED` | Certificate successfully issued |
| `CERTIFICATE_REVOKED` | Certificate revoked |
| `CERTIFICATE_RENEWED` | Certificate renewed |
| `ACCOUNT_CREATED` | New ACME account registered |
| `ACCOUNT_UPDATED` | Account details updated |
| `ACCOUNT_DEACTIVATED` | Account deactivated |
| `KEY_CHANGE` | Account key rotated |
| `AUTHORIZATION_CREATED` | New authorization created |
| `CHALLENGE_COMPLETED` | Challenge validation successful |
| `CHALLENGE_FAILED` | Challenge validation failed |
| `TPM_ENROLLED` | TPM device enrolled |
| `TPM_ATTESTED` | TPM attestation verified |
| `AUTH_FAILURE` | Authentication failure |

## Quick Start

### Configuration

```yaml
audit:
  enabled: true
  log_path: "/var/log/acme/audit.log"
  max_size_mb: 100
  max_age_days: 365
  format: "json"           # json, cbor, or msgpack
  buffer_size: 100
  flush_interval_seconds: 5
```

### Codec Support

The audit logger supports multiple serialization formats via go-codec:

| Format | Description | Use Case |
|--------|-------------|----------|
| `json` | JSON text format (default) | Human readable, log analysis tools |
| `cbor` | CBOR binary format | Compact storage, machine processing |
| `msgpack` | MessagePack binary format | High performance, cross-language |

```go
import (
    "github.com/jeremyhahn/go-codec"
    "github.com/jeremyhahn/go-trusted-ca/pkg/audit"
)

// Create codec for binary logging
c := audit.NewCodec(codec.CBOR)

// Create logger with custom codec
logger, err := audit.NewFileAuditLoggerWithCodec(config, c)
```

### Usage

```go
import "github.com/jeremyhahn/go-trusted-ca/pkg/audit"

// Create audit logger
config := &audit.Config{
    Enabled:              true,
    LogPath:              "/var/log/acme/audit.log",
    MaxSizeMB:            100,
    MaxAgeDays:           365,
    Format:               "json",
    BufferSize:           100,
    FlushIntervalSeconds: 5,
}

logger, err := audit.NewFileAuditLogger(config)
if err != nil {
    log.Fatal(err)
}
defer logger.Close()

// Log a certificate issuance
ctx := context.Background()
err = audit.LogCertificateIssued(
    ctx, logger,
    "account:123",
    "order:456",
    "example.com",
    90,
    "ABC123",
)
```

## Documentation

| Document | Description |
|----------|-------------|
| [Configuration](configuration.md) | Audit logging configuration reference |
| [Event Types](event-types.md) | Complete list of audit event types |
| [Integration](integration.md) | Integrating with SIEM and log systems |

## Log Format

All audit events are written as structured JSON:

```json
{
  "timestamp": "2025-01-15T10:30:00Z",
  "event_type": "CERTIFICATE_ISSUED",
  "actor": "account:123",
  "resource": "order:456",
  "action": "finalize",
  "result": "success",
  "request_id": "req-123",
  "source_ip": "192.168.1.1",
  "details": {
    "common_name": "example.com",
    "validity_days": 90,
    "serial_number": "ABC123"
  }
}
```

## HTTP Middleware

```go
// Add audit middleware to HTTP server
auditMiddleware := audit.NewHTTPMiddleware(logger)
handler := auditMiddleware.Wrap(yourHandler)
```

The middleware automatically logs:
- Request method and path
- Response status code
- Request duration
- Client IP address
- Request ID for correlation

## Security Considerations

- Store audit logs on separate storage from application data
- Use append-only storage when possible
- Implement log integrity verification (hashing/signing)
- Set appropriate file permissions (read-only for non-audit processes)
- Forward logs to centralized SIEM for analysis
- Retain logs per regulatory requirements (often 1-7 years)
