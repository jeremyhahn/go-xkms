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

These are the exact values accepted by the `event_type` query filter.

| Event Type | Description |
|------------|-------------|
| `CERTIFICATE_ISSUED` | Certificate successfully issued |
| `CERTIFICATE_REVOKED` | Certificate revoked |
| `CERTIFICATE_RENEWED` | Certificate renewed |
| `CERTIFICATE_SIGNED` | CSR signed |
| `ACCOUNT_CREATED` | New ACME account registered |
| `ACCOUNT_UPDATED` | Account details updated |
| `ACCOUNT_DEACTIVATED` | Account deactivated |
| `ACCOUNT_KEY_CHANGED` | Account key rolled over |
| `ORDER_CREATED` | Order created |
| `ORDER_FINALIZED` | Order finalized |
| `ORDER_CANCELED` | Order canceled |
| `AUTHORIZATION_CREATED` | New authorization created |
| `AUTHORIZATION_VALIDATED` | Authorization validated |
| `AUTHORIZATION_DEACTIVATED` | Authorization deactivated |
| `CHALLENGE_INITIATED` | Challenge started |
| `CHALLENGE_COMPLETED` | Challenge validation successful |
| `CHALLENGE_FAILED` | Challenge validation failed |
| `CHALLENGE_VALIDATED` | Challenge verified |
| `CA_INITIALIZED` | CA brought up |
| `CA_KEY_ROTATED` | CA signing key rotated |
| `CA_CRL_GENERATED` | CRL generated |
| `CA_CROSS_SIGN` | Cross-signature issued |
| `AUTHENTICATION_FAILED` | Authentication failure (including a rejected EAB) |
| `AUTHORIZATION_FAILED` | Authorization refused |
| `INVALID_SIGNATURE` | JWS signature verification failed |
| `INVALID_NONCE` | Replayed or unknown nonce |
| `RATE_LIMIT_EXCEEDED` | Rate limit hit |
| `TPM_ENROLLMENT` | TPM device enrolled (enroll-01) |
| `TPM_ATTESTATION` | TPM attestation verified |
| `DEVICE_ATTESTATION` | Device attestation verified |
| `ENDORSEMENT_VERIFIED` | Endorsement key verified |

## Quick Start

### Configuration

The audit trail is configured under the daemon's `acme` section. It is **on by
default**: an absent `audit` block means the trail runs with the defaults below,
not that it is off.

```yaml
acme:
  enabled: true
  data_dir: /var/lib/xkms/acme
  audit:
    enabled: true                 # omit to keep the trail on; false is a compliance gap
    log_path: ""                  # default: "<acme.data_dir>/audit.log"
    max_size_mb: 100              # rotate the live log at this size
    max_age_days: 365             # retain rotated backups for this long
    max_backups: 10               # retain at most this many backups
    buffer_size: 100              # events queued before writes become synchronous
    flush_interval_seconds: 5     # how often queued events are forced to disk
    compress: false               # gzip rotated backups (read back transparently)
    format: json                  # only json is supported; it is the queryable format
```

| Key | Default | Notes |
|-----|---------|-------|
| `enabled` | `true` | Tri-state: omitting the key leaves the trail on. Setting it to `false` is reported by `Config.ComplianceGaps()` and the daemon refuses to start or reload with it; there is no override. |
| `log_path` | `<acme.data_dir>/audit.log` | Rotated backups are written alongside it as `audit-<timestamp>.log[.gz]`. |
| `max_size_mb` | `100` | Negative values are rejected at config validation. |
| `max_age_days` | `365` | Shortest retention the supported regimes accept. |
| `max_backups` | `10` | |
| `buffer_size` | `100` | Events are never dropped; a full buffer makes the emitting request write through. |
| `flush_interval_seconds` | `5` | |
| `compress` | `false` | The query API decompresses `.gz` backups transparently. |
| `format` | `json` | Any other value is rejected: the admin query API can only read line-delimited JSON. |

**Fail-closed start-up.** The trail is opened before the keystore, the CA, and
the listener. If it is enabled and the log file cannot be created, `xkmsd` fails
to start with `ErrACMEAuditLogger` rather than running a CA that silently
records nothing.

An embedded `TrustedCA` (`pkg/acme/client`) carries the same section as
`config.audit` and `DefaultTrustedCAConfig()` enables it.

### Codec Support

`pkg/acme/audit` can serialize events as JSON, CBOR, or MessagePack, but a
deployed trail is always JSON: it is the only format the admin query API can
read back, so `acme.audit.format` rejects anything else. The binary codecs
remain available for embedders that ship their own reader.

| Format | Description | Queryable via `/admin/audit` |
|--------|-------------|------------------------------|
| `json` | JSON text, one document per line (default) | Yes |
| `cbor` | CBOR binary | No |
| `msgpack` | MessagePack binary | No |

### Usage

```go
import "github.com/jeremyhahn/go-xkms/pkg/acme/audit"

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

## Querying the trail

The admin API exposes the trail at `GET /admin/audit`. The endpoint is served by
`pkg/acme/admin` and reads the same log file the ACME server writes, including
rotated and gzipped backups.

```
GET /admin/audit?event_type=CERTIFICATE_ISSUED&per_page=50
```

### Filters and paging

All parameters are optional and combine with AND. Events are returned most
recently recorded first.

| Parameter | Description |
|-----------|-------------|
| `page` | 1-based page number (default `1`) |
| `per_page` | Page size (default `25`, capped at `100`) |
| `event_type` | Exact event type, e.g. `CERTIFICATE_REVOKED` |
| `actor` | Exact actor, e.g. `account:12345` |
| `resource` | Exact resource, e.g. `certificate:4242` |
| `action` | Exact action, e.g. `issue`, `revoke`, `key_rollover` |
| `result` | `success`, `failure`, or `pending` |
| `request_id` | Correlates every event recorded for one request |
| `start_time` / `end_time` | RFC 3339 bounds on the event timestamp |

Response body:

```json
{
  "items": [ { "timestamp": "...", "event_type": "CERTIFICATE_REVOKED", "...": "..." } ],
  "total": 128,
  "page": 1,
  "per_page": 25
}
```

`total` is the number of events matching the filter across the whole trail, not
the size of the page.

### Status codes

| Status | Meaning |
|--------|---------|
| `200` | A page of events (possibly empty, when the filter matched nothing) |
| `400` | `end_time` precedes `start_time`, an unparsable timestamp, or `page * per_page` beyond the 10,000-event query window |
| `501` | **No audit trail is configured.** The endpoint never reports "no events" for a server whose trail it cannot read |

The `501` is deliberate: an empty `200` would be indistinguishable from a CA
that issued nothing, so a deployment with `acme.audit.enabled: false` gets an
explicit "unavailable" answer instead.

### Bounded memory

A query streams the rotated backups oldest first, then the live log, retaining
only the requested page plus the events it skips. Requests whose page plus
offset exceed 10,000 events are rejected with `400` rather than being served by
reading the whole trail into memory.

### Tamper verification

Log lines written through the checksum writer carry a checksum prefix. During a
query each such line is verified before it is returned:

- A line that fails its checksum, is truncated, or cannot be decoded is **never
  served as a trustworthy record**. It is counted instead.
- The count is reported in the query result as `Malformed` and logged as a
  warning (`audit trail contains records that could not be decoded`).
- A non-zero count means the trail is damaged or truncated and should be
  investigated; the surviving records are still returned so the remaining
  evidence is not lost.

## What is recorded

The ACME server emits these events at the decision points below.

| Handler | Event | Actor / Resource |
|---------|-------|------------------|
| `new-account` | `ACCOUNT_CREATED` | `system` / `account:<id>` |
| `new-account` (EAB rejected) | `AUTHENTICATION_FAILED` | `unknown` / `authentication` |
| `new-order` | `ORDER_CREATED` | `account:<id>` / `order:<id>` |
| `finalize` | `CERTIFICATE_ISSUED` | `account:<id>` / `order:<id>` |
| `finalize` (enroll-01) | `TPM_ENROLLMENT` + `CERTIFICATE_ISSUED` | `account:<id>` / `device:<permanent-id>` |
| `revoke-cert` | `CERTIFICATE_REVOKED` | `account:<id>` / `certificate:<serial>` |
| `revoke-cert` (unauthorized) | `AUTHORIZATION_FAILED` | `account:<id>` / `certificate:<serial>` |
| `key-change` | `ACCOUNT_KEY_CHANGED` | `account:<id>` / `account:<id>` |

Issuance is recorded as soon as the CA signs, before delivery hooks run: a hook
failure can abort the response but cannot unsign a certificate, and a trail that
omitted it would be wrong.

Every event carries the request's correlation ID (the client's `X-Request-ID`
when supplied, otherwise a generated one), the client address (honouring
`X-Forwarded-For` / `X-Real-IP`), and the user agent.

## Documentation

| Document | Description |
|----------|-------------|
| Configuration | Planned. Audit logging configuration currently lives in [../configuration.md](../configuration.md). |
| Event Types | Planned. The event type constants are the reference until then. |
| Integration | Planned. No SIEM integration guide has been written. |

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

`HTTPMiddleware` is an optional request-level decorator, separate from the
per-operation events the ACME handlers record. It is not installed by default,
because it logs every request including directory and nonce fetches.

```go
// Wrap a handler so every request is also audited
handler := audit.HTTPMiddleware(logger)(yourHandler)
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
