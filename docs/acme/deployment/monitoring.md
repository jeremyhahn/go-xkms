# Monitoring and Observability

Set up comprehensive monitoring for go-xkms using Prometheus, Grafana, and alerting.

## Prometheus Metrics

### Enabling Metrics

Metrics are enabled by default on port 9090:

```yaml
metrics:
  enabled: true
  addr: ":9090"
  path: "/metrics"
```

### Available Metrics

#### Request Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `acme_requests_total` | Counter | Total requests by endpoint and status |
| `acme_request_duration_seconds` | Histogram | Request latency distribution |
| `acme_active_requests` | Gauge | Currently processing requests |

#### Certificate Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `acme_certificates_issued_total` | Counter | Total certificates issued |
| `acme_certificates_revoked_total` | Counter | Total certificates revoked |
| `acme_certificate_issuance_duration_seconds` | Histogram | Certificate issuance time |
| `acme_certificates_expiring_soon` | Gauge | Certificates expiring within 30 days |

#### Challenge Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `acme_challenges_completed_total` | Counter | Challenges by type and status |
| `acme_pending_challenges` | Gauge | Currently pending challenges |
| `acme_challenge_validation_duration_seconds` | Histogram | Challenge validation time |

#### ACME Operations

| Metric | Type | Description |
|--------|------|-------------|
| `acme_active_orders` | Gauge | Currently processing orders |
| `acme_accounts_total` | Gauge | Total registered accounts |
| `acme_nonces_issued_total` | Counter | Total nonces issued |

#### Error Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `acme_errors_total` | Counter | Errors by type (client_error, server_error) |
| `acme_certificate_issuance_failures_total` | Counter | Certificate issuance failures |

#### System Metrics

Standard Go metrics are also exposed:

| Metric | Type | Description |
|--------|------|-------------|
| `go_goroutines` | Gauge | Number of goroutines |
| `go_memstats_heap_alloc_bytes` | Gauge | Heap memory allocated |
| `process_cpu_seconds_total` | Counter | CPU time used |
| `process_open_fds` | Gauge | Open file descriptors |

#### Cluster Metrics (HA Mode)

| Metric | Type | Description |
|--------|------|-------------|
| `raft_leader` | Gauge | 1 if this node is leader |
| `raft_term` | Gauge | Current Raft term |
| `raft_applied_index` | Gauge | Last applied log index |
| `raft_peers` | Gauge | Number of cluster peers |

### Scrape Configuration

Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: 'trusted-ca'
    static_configs:
      - targets: ['trusted-ca:9090']
    metrics_path: /metrics
    scrape_interval: 30s
    scrape_timeout: 10s
```

For Docker Compose with file-based service discovery:

```yaml
scrape_configs:
  - job_name: 'trusted-ca'
    file_sd_configs:
      - files:
          - /etc/prometheus/targets/trusted-ca.json
        refresh_interval: 30s
```

Example target file (`trusted-ca.json`):

```json
[
  {
    "targets": ["trusted-ca:9090"],
    "labels": {
      "service": "trusted-ca",
      "environment": "production"
    }
  }
]
```

## Grafana Dashboard

### Importing the Dashboard

The pre-built dashboard is at `/deploy/grafana/dashboard.json`.

To import:

1. Open Grafana
2. Go to Dashboards > Import
3. Upload `dashboard.json` or paste its contents
4. Select your Prometheus datasource
5. Click Import

### Dashboard Panels

The dashboard includes the following sections:

#### Overview Row

- Request Rate (req/s)
- Certificates Issued (total)
- Active Orders
- Pending Challenges
- Error Rate (gauge)
- Certificates Expiring Soon

#### Request Metrics Row

- Requests per Second by Endpoint
- Request Latency (p50, p95, p99)
- Error Rate (4xx, 5xx)
- Request Latency Heatmap

#### ACME Operations Row

- New Accounts Created
- Orders Created
- Active Orders Over Time
- Certificates Issued / Revoked
- Certificate Issuance Duration

#### Challenge Validation Row

- Challenge Completions by Type
- Challenge Success Rate (gauge)
- Pending Challenges Over Time

#### Errors Row

- Errors by Type
- Errors by Endpoint

#### System Resources Row

- Memory Usage
- CPU Usage
- Goroutines
- GC Duration
- File Descriptors

#### Health and Uptime Row

- Server Uptime
- Health Status
- Go Version
- Go Threads
- Server Availability

### Dashboard Variables

The dashboard includes these variables:

- `datasource`: Prometheus datasource selector
- `instance`: Filter by instance (supports multi-select)

### Customizing the Dashboard

Clone and modify:

```bash
# Export current dashboard
curl -s "http://grafana:3000/api/dashboards/uid/go-xkms-acme" \
  -H "Authorization: Bearer ${GRAFANA_API_KEY}" | jq .dashboard > my-dashboard.json

# Edit and re-import
```

## Health Checks

### Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/health` | General health check |
| `/health/live` | Liveness probe (process alive) |
| `/health/ready` | Readiness probe (can accept traffic) |

### Response Format

```json
{
  "status": "healthy",
  "checks": {
    "storage": "ok",
    "ca": "ok",
    "raft": "leader"
  },
  "version": "1.0.0",
  "uptime": "24h15m30s"
}
```

### Integration with Load Balancers

```bash
# Health check command
curl -f http://localhost:8080/health/ready || exit 1
```

AWS ALB health check:

```yaml
HealthCheckPath: /health/ready
HealthCheckIntervalSeconds: 30
HealthyThresholdCount: 2
UnhealthyThresholdCount: 3
```

## Alerting

### Prometheus Alerting Rules

The ServiceMonitor includes alerting rules:

```yaml
groups:
  - name: trusted-ca.rules
    rules:
      # Server down
      - alert: TrustedCADown
        expr: up{job="trusted-ca"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Trusted CA ACME server is down"

      # High error rate
      - alert: TrustedCAHighErrorRate
        expr: |
          sum(rate(http_requests_total{job="trusted-ca",status=~"5.."}[5m]))
          / sum(rate(http_requests_total{job="trusted-ca"}[5m])) > 0.05
        for: 5m
        labels:
          severity: warning

      # Certificate issuance failures
      - alert: TrustedCACertificateIssuanceFailures
        expr: |
          increase(acme_certificate_issuance_failures_total[1h]) > 10
        for: 5m
        labels:
          severity: warning

      # No Raft leader
      - alert: TrustedCARaftNoLeader
        expr: sum(raft_leader{job="trusted-ca"}) == 0
        for: 2m
        labels:
          severity: critical

      # High memory usage
      - alert: TrustedCAHighMemoryUsage
        expr: |
          process_resident_memory_bytes{job="trusted-ca"}
          / 1073741824 > 0.9
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Memory usage above 90%"

      # Storage almost full
      - alert: TrustedCAStorageAlmostFull
        expr: |
          node_filesystem_avail_bytes{mountpoint="/var/lib/trusted-acme"}
          / node_filesystem_size_bytes{mountpoint="/var/lib/trusted-acme"} < 0.1
        for: 5m
        labels:
          severity: warning
```

### Recommended Alerts

| Alert | Severity | Condition |
|-------|----------|-----------|
| Server Down | Critical | Server unreachable for 5m |
| High Error Rate | Warning | >5% error rate for 5m |
| No Raft Leader | Critical | No leader for 2m |
| Certificate Failures | Warning | >10 failures in 1h |
| High Memory | Warning | >90% memory usage |
| Storage Full | Warning | <10% storage remaining |
| High Latency | Warning | p99 latency >5s |

### Alertmanager Configuration

Example Alertmanager config:

```yaml
route:
  group_by: ['alertname', 'severity']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  receiver: 'default-receiver'

  routes:
    - match:
        severity: critical
      receiver: 'pagerduty'
    - match:
        severity: warning
      receiver: 'slack'

receivers:
  - name: 'default-receiver'
    email_configs:
      - to: 'ops@example.com'

  - name: 'pagerduty'
    pagerduty_configs:
      - service_key: '${PAGERDUTY_KEY}'

  - name: 'slack'
    slack_configs:
      - api_url: '${SLACK_WEBHOOK}'
        channel: '#alerts'
```

## Logging

### Log Configuration

```yaml
logging:
  level: "info"        # debug, info, warn, error
  format: "json"       # json or text
  file: "/var/log/trusted-acme/server.log"
  max_size_mb: 100
  max_backups: 5
  max_age_days: 30
```

### Log Format

JSON format for easy parsing:

```json
{
  "level": "info",
  "ts": "2024-01-15T10:30:00.123Z",
  "caller": "server/handler.go:45",
  "msg": "Certificate issued",
  "account_id": "acc_123",
  "order_id": "ord_456",
  "domains": ["example.com"],
  "duration_ms": 150
}
```

### Log Aggregation

#### Docker Compose with Loki

```yaml
# promtail-config.yaml
server:
  http_listen_port: 9080
positions:
  filename: /tmp/positions.yaml
clients:
  - url: http://loki:3100/loki/api/v1/push
scrape_configs:
  - job_name: trusted-ca
    static_configs:
      - targets:
          - localhost
        labels:
          job: trusted-ca
          __path__: /var/log/trusted-acme/*.log
```

Docker Compose service:

```yaml
promtail:
  image: grafana/promtail:latest
  volumes:
    - ./promtail-config.yaml:/etc/promtail/config.yaml
    - trusted-ca-logs:/var/log/trusted-acme:ro
  command: -config.file=/etc/promtail/config.yaml
```

#### ELK Stack

```yaml
# Filebeat configuration
filebeat.inputs:
  - type: container
    paths:
      - /var/log/containers/trusted-ca-*.log
    processors:
      - decode_json_fields:
          fields: ["message"]

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "trusted-ca-%{+yyyy.MM.dd}"
```

## SLA Monitoring

### Key SLIs

| SLI | Target | Measurement |
|-----|--------|-------------|
| Availability | 99.9% | `avg_over_time(up[30d])` |
| Latency (p99) | <500ms | `histogram_quantile(0.99, ...)` |
| Error Rate | <0.1% | `rate(errors) / rate(requests)` |
| Certificate Issuance | <10s | `histogram_quantile(0.99, issuance_duration)` |

### SLO Dashboard Queries

```promql
# Availability (30 day)
avg_over_time(up{job="trusted-ca"}[30d]) * 100

# Error budget remaining
(1 - (
  sum(increase(acme_errors_total[30d]))
  / sum(increase(acme_requests_total[30d]))
)) * 100

# Latency SLO (% requests under 500ms)
sum(rate(acme_request_duration_seconds_bucket{le="0.5"}[5m]))
/ sum(rate(acme_request_duration_seconds_count[5m])) * 100
```

## Troubleshooting Monitoring Issues

### Metrics Not Appearing

1. Verify metrics endpoint:
   ```bash
   curl http://localhost:9090/metrics
   ```

2. Check Prometheus targets:
   ```bash
   curl http://prometheus:9090/api/v1/targets
   ```

3. Verify ServiceMonitor labels match Prometheus selector

### Dashboard Not Loading

1. Check datasource connection
2. Verify Prometheus has data: `acme_requests_total`
3. Check time range selection

### Alerts Not Firing

1. Verify alerting rules loaded:
   ```bash
   curl http://prometheus:9090/api/v1/rules
   ```

2. Check Alertmanager configuration
3. Verify receiver webhooks are accessible

See [Troubleshooting Guide](troubleshooting.md) for more solutions.
