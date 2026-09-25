# Operations Runbook

This runbook provides standard operating procedures for managing go-xkms deployments in production environments.

## Table of Contents

- [Daily Operations](#daily-operations)
- [Certificate Management](#certificate-management)
- [CA Key Operations](#ca-key-operations)
- [Backup and Recovery](#backup-and-recovery)
- [Monitoring and Alerting](#monitoring-and-alerting)
- [Incident Response](#incident-response)
- [Maintenance Procedures](#maintenance-procedures)
- [Security Operations](#security-operations)

## Daily Operations

### Health Check Procedure

Perform daily health checks to ensure system stability.

**Automated Check (recommended)**

```bash
#!/bin/bash
# /usr/local/bin/daily-health-check.sh

set -euo pipefail

ENDPOINT="https://acme.example.com"
ALERT_EMAIL="ops@example.com"

# Check health endpoint
if ! curl -sf "${ENDPOINT}/health" > /dev/null; then
    echo "CRITICAL: Health check failed" | mail -s "ACME Server Alert" "${ALERT_EMAIL}"
    exit 1
fi

# Check certificate expiry
EXPIRY_DAYS=$(curl -sf "${ENDPOINT}/admin/status" \
    -H "Authorization: Bearer ${ADMIN_KEY}" \
    | jq -r '.data.intermediate_ca_expiry_days // 365')

if [ "${EXPIRY_DAYS}" -lt 30 ]; then
    echo "WARNING: CA cert expires in ${EXPIRY_DAYS} days" | mail -s "ACME CA Expiry Warning" "${ALERT_EMAIL}"
fi

# Check disk usage
DISK_USAGE=$(df /var/lib/trusted-acme | tail -1 | awk '{print $5}' | tr -d '%')
if [ "${DISK_USAGE}" -gt 80 ]; then
    echo "WARNING: Disk usage at ${DISK_USAGE}%" | mail -s "ACME Disk Warning" "${ALERT_EMAIL}"
fi

echo "Health check passed"
```

**Manual Check Procedure**

1. Verify service status:
```bash
# Docker Compose
docker compose ps

# Bare metal
systemctl status trusted-acme
```

2. Check application logs for errors:
```bash
# Look for errors in last hour
grep -i error /var/log/trusted-acme/server.log | tail -20

# Or via Docker Compose
docker compose logs --since=1h | grep -i error
```

3. Verify metrics endpoint:
```bash
curl -s http://localhost:9091/metrics | grep -E "^trustedca_"
```

4. Check pending orders:
```bash
curl -s -H "Authorization: Bearer ${ADMIN_KEY}" \
    "https://acme.example.com/admin/orders?status=pending" | jq '.data | length'
```

### Log Review

Review logs daily for anomalies.

**Key Log Patterns**

| Pattern | Severity | Action |
|---------|----------|--------|
| `rate limit exceeded` | Normal | Monitor frequency |
| `challenge validation failed` | Normal | Check client config |
| `storage error` | Warning | Check disk/storage |
| `CA key operation failed` | Critical | Investigate immediately |
| `unauthorized access attempt` | Warning | Review source IPs |

**Log Analysis Commands**

```bash
# Count errors by type (last 24h)
grep -h "error" /var/log/trusted-acme/*.log | \
    awk -F'"' '/error_type/ {print $4}' | sort | uniq -c | sort -rn

# Top 10 requesting IPs
grep -h "request" /var/log/trusted-acme/*.log | \
    awk -F'"' '/remote_addr/ {print $4}' | sort | uniq -c | sort -rn | head -10

# Failed authentication attempts
grep -h "unauthorized" /var/log/trusted-acme/*.log | wc -l
```

## Certificate Management

### List Certificates

```bash
# Via Admin API
curl -s -H "Authorization: Bearer ${ADMIN_KEY}" \
    "https://acme.example.com/admin/certificates?per_page=100" | jq '.data'

# Filter by status
curl -s -H "Authorization: Bearer ${ADMIN_KEY}" \
    "https://acme.example.com/admin/certificates?status=valid" | jq '.data | length'
```

### Find Expiring Certificates

```bash
# Certificates expiring in 30 days
curl -s -H "Authorization: Bearer ${ADMIN_KEY}" \
    "https://acme.example.com/admin/certificates/expiring?days=30" | jq '.data'

# Generate report
curl -s -H "Authorization: Bearer ${ADMIN_KEY}" \
    "https://acme.example.com/admin/certificates/expiring?days=30" | \
    jq -r '.data[] | [.serial_number, .subject, .not_after] | @csv' > expiring-certs.csv
```

### Revoke Certificate

**Standard Revocation**

```bash
# Revoke by serial number
SERIAL="123456789"
curl -X POST -H "Authorization: Bearer ${ADMIN_KEY}" \
    -H "Content-Type: application/json" \
    -d '{"reason": "cessationOfOperation"}' \
    "https://acme.example.com/admin/certificates/${SERIAL}/revoke"
```

**Emergency Revocation (Key Compromise)**

```bash
# Revoke with keyCompromise reason
SERIAL="123456789"
curl -X POST -H "Authorization: Bearer ${ADMIN_KEY}" \
    -H "Content-Type: application/json" \
    -d '{"reason": "keyCompromise"}' \
    "https://acme.example.com/admin/certificates/${SERIAL}/revoke"

# Regenerate CRL immediately
curl -X POST -H "Authorization: Bearer ${ADMIN_KEY}" \
    "https://acme.example.com/admin/ca/crl/regenerate"
```

**Revocation Reasons (RFC 5280)**

| Reason | Code | Use Case |
|--------|------|----------|
| unspecified | 0 | Default |
| keyCompromise | 1 | Private key leaked |
| caCompromise | 2 | CA key compromised |
| affiliationChanged | 3 | Organization change |
| superseded | 4 | Replaced by new cert |
| cessationOfOperation | 5 | Service discontinued |
| certificateHold | 6 | Temporary suspension |
| privilegeWithdrawn | 9 | Access revoked |

### Download Certificate

```bash
# Download by serial
SERIAL="123456789"
curl -H "Authorization: Bearer ${ADMIN_KEY}" \
    "https://acme.example.com/admin/certificates/${SERIAL}/download" > cert.pem

# Verify certificate
openssl x509 -in cert.pem -text -noout
```

## CA Key Operations

### View CA Status

```bash
curl -s -H "Authorization: Bearer ${ADMIN_KEY}" \
    "https://acme.example.com/admin/status" | jq '.data'
```

### Rotate Intermediate CA

**Pre-rotation Checklist**

- [ ] Schedule maintenance window
- [ ] Notify stakeholders
- [ ] Verify backup of current CA
- [ ] Test rotation in staging
- [ ] Prepare rollback plan

**Rotation Procedure**

1. Create new intermediate CA:
```bash
curl -X POST -H "Authorization: Bearer ${ADMIN_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
        "common_name": "Trusted CA Intermediate v2",
        "key_algorithm": "EC-P384",
        "validity_years": 10
    }' \
    "https://acme.example.com/admin/ca/intermediate"
```

2. Verify new CA:
```bash
curl -s -H "Authorization: Bearer ${ADMIN_KEY}" \
    "https://acme.example.com/admin/ca/intermediate/v2" | jq
```

3. Set as default (after testing):
```bash
curl -X PUT -H "Authorization: Bearer ${ADMIN_KEY}" \
    -H "Content-Type: application/json" \
    -d '{"intermediate_ca_id": "v2"}' \
    "https://acme.example.com/admin/ca/default"
```

4. Mark old CA for rotation:
```bash
curl -X PUT -H "Authorization: Bearer ${ADMIN_KEY}" \
    -H "Content-Type: application/json" \
    -d '{"status": "pending-rotation"}' \
    "https://acme.example.com/admin/ca/intermediate/v1/status"
```

### CRL Management

```bash
# View current CRL
curl -s "https://acme.example.com/crl" | openssl crl -inform DER -text -noout

# Force CRL regeneration
curl -X POST -H "Authorization: Bearer ${ADMIN_KEY}" \
    "https://acme.example.com/admin/ca/crl/regenerate"

# Check CRL status
curl -s -H "Authorization: Bearer ${ADMIN_KEY}" \
    "https://acme.example.com/admin/ca/crl/status" | jq
```

### OCSP Responder

```bash
# Test OCSP
SERIAL="123456789"
openssl ocsp -issuer intermediate.pem -serial "${SERIAL}" \
    -url https://ocsp.example.com -resp_text

# Check OCSP responder status
curl -s -H "Authorization: Bearer ${ADMIN_KEY}" \
    "https://acme.example.com/admin/ocsp/status" | jq
```

## Backup and Recovery

### Backup Procedure

**Full Backup**

```bash
#!/bin/bash
# /usr/local/bin/full-backup.sh

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/var/backups/trusted-acme/${TIMESTAMP}"

mkdir -p "${BACKUP_DIR}"

# Export configuration
cp /etc/trusted-acme/config.yaml "${BACKUP_DIR}/config.yaml"
cp /etc/trusted-acme/.env "${BACKUP_DIR}/env.backup" 2>/dev/null || true

# Backup data volume
docker compose exec trusted-ca tar czf - /var/lib/trusted-acme > "${BACKUP_DIR}/data.tar.gz"

# Create manifest
cat > "${BACKUP_DIR}/manifest.json" << EOF
{
    "timestamp": "${TIMESTAMP}",
    "version": "$(docker compose exec trusted-ca cat /app/VERSION 2>/dev/null || echo 'unknown')",
    "type": "full"
}
EOF

# Compress
tar czf "/var/backups/trusted-acme/backup_${TIMESTAMP}.tar.gz" -C "${BACKUP_DIR}" .
rm -rf "${BACKUP_DIR}"

echo "Backup completed: /var/backups/trusted-acme/backup_${TIMESTAMP}.tar.gz"
```

**Incremental Backup**

```bash
#!/bin/bash
# Incremental backup using rsync

BACKUP_DIR="/var/backups/trusted-acme/incremental"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

rsync -av --link-dest="${BACKUP_DIR}/latest" \
    /var/lib/trusted-acme/ \
    "${BACKUP_DIR}/${TIMESTAMP}/"

ln -snf "${BACKUP_DIR}/${TIMESTAMP}" "${BACKUP_DIR}/latest"
```

### Recovery Procedure

**Full Recovery**

```bash
#!/bin/bash
# /usr/local/bin/full-restore.sh

BACKUP_FILE=$1

if [ -z "${BACKUP_FILE}" ]; then
    echo "Usage: $0 <backup-file>"
    exit 1
fi

# Extract backup
RESTORE_DIR=$(mktemp -d)
tar xzf "${BACKUP_FILE}" -C "${RESTORE_DIR}"

# Stop service
docker compose down

# Restore configuration
cp "${RESTORE_DIR}/config.yaml" /etc/trusted-acme/config.yaml
cp "${RESTORE_DIR}/env.backup" /etc/trusted-acme/.env 2>/dev/null || true

# Restore data
docker run --rm -v trusted-ca-data:/var/lib/trusted-acme \
    -v "${RESTORE_DIR}:/backup" alpine \
    tar xzf /backup/data.tar.gz -C /

# Start service
docker compose up -d

# Cleanup
rm -rf "${RESTORE_DIR}"

echo "Restore completed"
```

**Verify Recovery**

```bash
# Check service health
docker compose ps
curl -k https://acme.example.com/health

# Verify CA status
curl -s -H "Authorization: Bearer ${ADMIN_KEY}" \
    "https://acme.example.com/admin/status" | jq

# Test certificate issuance
certbot certonly --dry-run --standalone -d test.example.com \
    --server https://acme.example.com/acme/directory
```

## Monitoring and Alerting

### Key Metrics

| Metric | Warning | Critical | Action |
|--------|---------|----------|--------|
| `trustedca_requests_total{status="5xx"}` rate | > 1/min | > 10/min | Check logs |
| `trustedca_request_duration_seconds` p99 | > 5s | > 30s | Check resources |
| `trustedca_certificates_issued_total` rate | Abnormal pattern | - | Investigate |
| `trustedca_ca_certificate_expiry_days` | < 60 | < 30 | Plan rotation |
| `trustedca_storage_used_bytes` | > 80% | > 95% | Expand storage |

### Alerting Rules

```yaml
# prometheus-rules.yaml
groups:
  - name: trusted-ca-alerts
    rules:
      # Service availability
      - alert: TrustedCADown
        expr: up{job="trusted-ca"} == 0
        for: 5m
        labels:
          severity: critical
          team: platform
        annotations:
          summary: "Trusted CA service is down"
          runbook: "https://wiki.example.com/runbooks/trusted-ca-down"

      # High error rate
      - alert: TrustedCAHighErrorRate
        expr: |
          sum(rate(trustedca_requests_total{status=~"5.."}[5m]))
          /
          sum(rate(trustedca_requests_total[5m])) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Trusted CA error rate > 5%"

      # Certificate expiry
      - alert: TrustedCACertExpiring
        expr: trustedca_ca_certificate_expiry_days < 30
        for: 1h
        labels:
          severity: critical
        annotations:
          summary: "CA certificate expires in {{ $value }} days"

      # Disk space
      - alert: TrustedCADiskFull
        expr: |
          (trustedca_storage_used_bytes / trustedca_storage_total_bytes) > 0.9
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Trusted CA disk usage > 90%"
```

### Dashboard Panels

**Grafana Dashboard JSON (excerpt)**

```json
{
  "panels": [
    {
      "title": "Request Rate",
      "type": "graph",
      "targets": [
        {
          "expr": "sum(rate(trustedca_requests_total[5m])) by (path)",
          "legendFormat": "{{ path }}"
        }
      ]
    },
    {
      "title": "Error Rate",
      "type": "graph",
      "targets": [
        {
          "expr": "sum(rate(trustedca_requests_total{status=~\"5..\"}[5m]))",
          "legendFormat": "5xx errors"
        }
      ]
    },
    {
      "title": "Certificates Issued",
      "type": "stat",
      "targets": [
        {
          "expr": "sum(increase(trustedca_certificates_issued_total[24h]))"
        }
      ]
    },
    {
      "title": "CA Certificate Expiry",
      "type": "gauge",
      "targets": [
        {
          "expr": "trustedca_ca_certificate_expiry_days"
        }
      ],
      "thresholds": {
        "mode": "absolute",
        "steps": [
          {"color": "red", "value": 0},
          {"color": "yellow", "value": 30},
          {"color": "green", "value": 90}
        ]
      }
    }
  ]
}
```

## Incident Response

### Severity Levels

| Level | Criteria | Response Time | Notification |
|-------|----------|---------------|--------------|
| P1 - Critical | Service down, CA compromised | Immediate | Page on-call |
| P2 - High | Degraded service, high error rate | 15 min | Slack + email |
| P3 - Medium | Non-critical issue, single user | 1 hour | Slack |
| P4 - Low | Minor issue, cosmetic | 8 hours | Ticket |

### Incident Playbooks

#### Service Down (P1)

1. **Verify outage**
```bash
curl -w "%{http_code}" -o /dev/null -s https://acme.example.com/health
```

2. **Check infrastructure**
```bash
# Docker Compose
docker compose ps
docker compose logs --tail=100
```

3. **Check resources**
```bash
docker stats trusted-ca --no-stream
```

4. **Restart if needed**
```bash
# Docker Compose
docker compose restart

# Bare metal
systemctl restart trusted-acme
```

5. **Document and escalate**

#### CA Key Compromise (P1)

**Immediate Actions (< 5 minutes)**

1. **Revoke CA certificate**
```bash
# Mark CA as compromised
curl -X PUT -H "Authorization: Bearer ${ADMIN_KEY}" \
    -d '{"status": "revoked", "reason": "keyCompromise"}' \
    "https://acme.example.com/admin/ca/intermediate/status"
```

2. **Regenerate CRL**
```bash
curl -X POST -H "Authorization: Bearer ${ADMIN_KEY}" \
    "https://acme.example.com/admin/ca/crl/regenerate"
```

3. **Notify stakeholders**
   - Security team
   - Certificate holders
   - Management

**Recovery Actions**

1. Generate new CA keys (on secure system)
2. Issue new CA certificate
3. Revoke all certificates issued by compromised CA
4. Reissue certificates to affected users
5. Post-incident review

### Communication Templates

**Initial Notification**

```
Subject: [P1] Trusted CA Service Incident

An incident affecting the Trusted CA service has been detected.

Impact: [Describe impact]
Status: Investigation in progress
ETA: [Estimated resolution time]

Updates will be posted to #ops-incidents channel.

Incident Commander: [Name]
```

**Resolution Notification**

```
Subject: [RESOLVED] Trusted CA Service Incident

The Trusted CA incident has been resolved.

Root Cause: [Brief description]
Resolution: [What was done]
Duration: [Start time] - [End time]

A post-incident review will be scheduled.
```

## Maintenance Procedures

### Scheduled Maintenance Window

**Pre-maintenance Checklist**

- [ ] Maintenance window approved
- [ ] Stakeholders notified (48h advance)
- [ ] Backup completed
- [ ] Rollback plan documented
- [ ] Monitoring silenced
- [ ] On-call notified

**Maintenance Procedure**

```bash
# 1. Create backup
/usr/local/bin/full-backup.sh

# 2. Silence alerts
# (via Alertmanager or monitoring tool)

# 3. Stop the service
docker compose stop trusted-ca

# 4. Perform maintenance
# ...

# 5. Start the service
docker compose up -d trusted-ca

# 6. Verify health
curl https://acme.example.com/health

# 7. Un-silence alerts

# 8. Update status page
```

### Version Upgrade

1. **Review release notes**
2. **Test in staging**
3. **Schedule maintenance window**
4. **Backup current state**
5. **Upgrade**

```bash
# Docker Compose
# Update image tag in docker-compose.yml or .env
docker compose pull trusted-ca
docker compose up -d trusted-ca

# Verify
docker compose ps
curl https://acme.example.com/admin/status
```

6. **Verify functionality**
7. **Update documentation**

### Database Maintenance

There is no `trusted-acme-server` binary, and neither `xkmsd` nor `xkmsctl`
has a `maintenance vacuum`/`reindex`/`analyze` subcommand. ACME protocol
state (accounts, orders, authorizations, challenges) persists through
`pkg/acme/storage` over `go-qrdb/sdk/go`
([`../../acme-issuance/engineering.md`](../../acme-issuance/engineering.md)
§Persistence); storage compaction and maintenance are go-qrdb's own
operational surface, not an ACME-server command.

## Security Operations

### Audit Log Review

Review audit logs weekly for security events.

```bash
# Extract audit events
grep "audit" /var/log/trusted-acme/server.log | \
    jq -r '[.timestamp, .user, .action, .resource] | @csv' > audit_report.csv

# Look for suspicious patterns
# - Multiple failed auth attempts
# - Unusual certificate requests
# - Admin API access from unexpected IPs
```

### Access Review

Perform quarterly access review.

```bash
# List API keys
curl -s -H "Authorization: Bearer ${ADMIN_KEY}" \
    "https://acme.example.com/admin/api-keys" | jq

# Review EAB tokens
curl -s -H "Authorization: Bearer ${ADMIN_KEY}" \
    "https://acme.example.com/admin/eab?status=active" | jq

# Check account activity
curl -s -H "Authorization: Bearer ${ADMIN_KEY}" \
    "https://acme.example.com/admin/accounts" | \
    jq '.data[] | select(.order_count == 0)'
```

### Key Rotation

**API Key Rotation**

```bash
# Generate new key
NEW_KEY=$(openssl rand -base64 32)

# Update configuration in .env file
sed -i "s/ADMIN_SUPER_ADMIN_KEY=.*/ADMIN_SUPER_ADMIN_KEY=${NEW_KEY}/" /etc/trusted-acme/.env

# Restart to pick up new key
docker compose restart trusted-ca

# Distribute new key securely
# Update automation/scripts with new key
```

**TLS Certificate Rotation**

```bash
# Generate new TLS cert
certbot renew --cert-name acme.example.com

# Copy new certificates to the correct location
cp /etc/letsencrypt/live/acme.example.com/fullchain.pem /etc/trusted-acme/tls/server.crt
cp /etc/letsencrypt/live/acme.example.com/privkey.pem /etc/trusted-acme/tls/server.key

# Restart
docker compose restart trusted-ca
```

### Security Scanning

```bash
# Scan container image
trivy image go-xkms:latest

# Scan Docker Compose configuration
docker compose config --quiet && echo "Configuration valid"

# Check for exposed secrets
gitleaks detect --source .
```

## Appendix

### Useful Commands Reference

| Task | Command |
|------|---------|
| View logs | `docker compose logs -f trusted-ca` |
| Shell access | `docker compose exec trusted-ca /bin/sh` |
| Port mapping | Configure in docker-compose.yml ports section |
| Scale | `docker compose up -d --scale trusted-ca=N` |
| Restart | `docker compose restart trusted-ca` |
| View config | `cat /etc/trusted-acme/config.yaml` |
| View env vars | `docker compose exec trusted-ca env` |

### Contact Information

| Role | Contact | Escalation |
|------|---------|------------|
| On-call Engineer | PagerDuty | Auto |
| Platform Team Lead | Slack @platform-lead | P1/P2 |
| Security Team | security@example.com | Key compromise |
| Management | Slack #leadership | P1 |
