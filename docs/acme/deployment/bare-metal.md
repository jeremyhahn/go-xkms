# Bare-Metal Deployment Guide

Deploy go-xkms ACME server on traditional server infrastructure without containers.

## Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 512 MB | 2+ GB |
| Disk | 10 GB SSD | 50+ GB SSD |
| OS | Linux (kernel 4.15+) | Ubuntu 22.04 LTS / RHEL 9 |

### Software Requirements

- Go 1.21+ (for building from source)
- systemd (process management)
- TPM 2.0 (optional, for TPM-backed key storage)

## Installation Methods

### Pre-built Binary

Download the latest release:

```bash
# Set version
VERSION=1.0.0
ARCH=amd64  # or arm64

# Download binary
curl -LO https://github.com/jeremyhahn/go-xkms/releases/download/v${VERSION}/trusted-acme-server-linux-${ARCH}

# Download checksum
curl -LO https://github.com/jeremyhahn/go-xkms/releases/download/v${VERSION}/checksums.txt

# Verify checksum
sha256sum -c checksums.txt --ignore-missing

# Install binary
sudo install -m 755 trusted-acme-server-linux-${ARCH} /usr/local/bin/trusted-acme-server
```

### Build from Source

```bash
# Clone repository
git clone https://github.com/jeremyhahn/go-xkms.git
cd go-xkms

# Build
make build

# Install
sudo install -m 755 bin/trusted-acme-server /usr/local/bin/
```

### Package Installation (Debian/Ubuntu)

```bash
# Add repository
echo "deb [signed-by=/usr/share/keyrings/trustedca.gpg] https://packages.trustedca.io/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/trustedca.list

# Import GPG key
curl -fsSL https://packages.trustedca.io/gpg | sudo gpg --dearmor -o /usr/share/keyrings/trustedca.gpg

# Install
sudo apt update
sudo apt install trusted-acme-server
```

### Package Installation (RHEL/CentOS)

```bash
# Add repository
sudo tee /etc/yum.repos.d/trustedca.repo << 'EOF'
[trustedca]
name=Trusted CA Repository
baseurl=https://packages.trustedca.io/rpm
enabled=1
gpgcheck=1
gpgkey=https://packages.trustedca.io/gpg
EOF

# Install
sudo dnf install trusted-acme-server
```

## System Configuration

### Create User and Group

```bash
# Create system user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin acme

# Create directories
sudo mkdir -p /etc/trusted-acme
sudo mkdir -p /var/lib/trusted-acme/{storage,ca,logs}
sudo mkdir -p /var/log/trusted-acme

# Set ownership
sudo chown -R acme:acme /var/lib/trusted-acme
sudo chown -R acme:acme /var/log/trusted-acme
sudo chown root:acme /etc/trusted-acme
sudo chmod 750 /etc/trusted-acme
sudo chmod 700 /var/lib/trusted-acme/ca
```

### Configuration File

Create `/etc/trusted-acme/config.yaml`:

```yaml
# Server configuration
server:
  # HTTP address for ACME protocol
  http_addr: ":8080"

  # HTTPS address (primary)
  https_addr: ":8443"

  # gRPC address
  grpc_addr: ":9443"

  # External URL (how clients reach this server)
  external_url: "https://acme.example.com"

  # TLS configuration
  tls:
    enabled: true
    cert_file: "/etc/trusted-acme/tls/server.crt"
    key_file: "/etc/trusted-acme/tls/server.key"
    ca_file: "/etc/trusted-acme/tls/ca.crt"
    min_version: "TLS1.2"
    cipher_suites:
      - "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
      - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
      - "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"
      - "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"

  # Request limits
  read_timeout: 30s
  write_timeout: 30s
  max_header_bytes: 1048576

# Storage configuration
storage:
  # ACME data directory
  acme_dir: "/var/lib/trusted-acme/storage"

  # CA data directory
  ca_dir: "/var/lib/trusted-acme/ca"

  # Backend type (local, s3, gcs)
  backend: "local"

# CA configuration
ca:
  # Root CA settings
  root:
    common_name: "Trusted CA Root"
    organization: "Your Organization"
    country: "US"
    key_algorithm: "EC-P384"
    validity_years: 20

  # Intermediate CA settings
  intermediate:
    common_name: "Trusted CA Intermediate"
    organization: "Your Organization"
    country: "US"
    key_algorithm: "EC-P384"
    validity_years: 10

  # Certificate issuance settings
  certificates:
    default_validity_days: 90
    max_validity_days: 365
    allowed_key_algorithms:
      - "RSA-2048"
      - "RSA-4096"
      - "EC-P256"
      - "EC-P384"
      - "Ed25519"

  # CRL settings
  crl:
    validity_days: 7
    next_update_days: 1

  # OCSP settings
  ocsp:
    enabled: true
    responder_url: "https://ocsp.example.com"

# ACME protocol settings
acme:
  # Terms of service URL
  terms_of_service: "https://acme.example.com/terms"

  # Website URL
  website: "https://acme.example.com"

  # CAA identity
  caa_identities:
    - "acme.example.com"

  # Require external account binding
  external_account_required: false

  # Order expiry
  order_expiry: 168h  # 7 days

  # Challenge types
  challenges:
    http-01:
      enabled: true
    dns-01:
      enabled: true
    device-attest-01:
      enabled: true
    endorse-01:
      enabled: true
    enroll-01:
      enabled: true

# Rate limiting
rate_limit:
  enabled: true
  requests_per_second: 10
  burst: 50
  # Per-account limits
  new_orders_per_account: 300
  new_orders_per_account_period: 3h
  certificates_per_domain: 50
  certificates_per_domain_period: 168h

# Admin API settings
admin:
  enabled: true
  addr: ":9090"
  # API keys (use environment variables in production)
  # Roles are go-qrdb's canonical system roles: so, admin, operator, user,
  # auditor, custodian. There is no ACME-specific role vocabulary.
  api_keys:
    - key: "${ADMIN_SO_KEY}"
      role: so
    - key: "${ADMIN_OPERATOR_KEY}"
      role: operator
    - key: "${ADMIN_AUDITOR_KEY}"
      role: auditor

# Logging
logging:
  level: "info"  # debug, info, warn, error
  format: "json"  # json, text
  output: "/var/log/trusted-acme/server.log"

# Metrics
metrics:
  enabled: true
  addr: ":9091"
  path: "/metrics"

# Health checks
health:
  enabled: true
  path: "/health"
```

Set permissions:

```bash
sudo chmod 640 /etc/trusted-acme/config.yaml
sudo chown root:acme /etc/trusted-acme/config.yaml
```

### Environment Variables

Create `/etc/trusted-acme/env`:

```bash
# Admin API keys (generate with: openssl rand -base64 32)
ADMIN_SO_KEY="your-security-officer-key-here"
ADMIN_OPERATOR_KEY="your-operator-key-here"
ADMIN_AUDITOR_KEY="your-auditor-key-here"

# Optional: TPM configuration
TPM_DEVICE="/dev/tpmrm0"

# Optional: HSM configuration
# PKCS11_MODULE="/usr/lib/softhsm/libsofthsm2.so"
# HSM_SLOT=0
# HSM_PIN_FILE="/etc/trusted-acme/hsm-pin"
```

Set permissions:

```bash
sudo chmod 600 /etc/trusted-acme/env
sudo chown root:acme /etc/trusted-acme/env
```

### TLS Certificates

Generate or install TLS certificates:

```bash
# Create TLS directory
sudo mkdir -p /etc/trusted-acme/tls

# Option 1: Self-signed for testing
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 \
  -keyout server.key -out server.crt -days 365 -nodes \
  -subj "/CN=acme.example.com"

# Copy to config directory
sudo cp server.crt server.key /etc/trusted-acme/tls/
sudo chmod 600 /etc/trusted-acme/tls/server.key
sudo chown acme:acme /etc/trusted-acme/tls/*

# Option 2: Using Let's Encrypt with certbot
sudo certbot certonly --standalone -d acme.example.com

# Link certificates
sudo ln -s /etc/letsencrypt/live/acme.example.com/fullchain.pem /etc/trusted-acme/tls/server.crt
sudo ln -s /etc/letsencrypt/live/acme.example.com/privkey.pem /etc/trusted-acme/tls/server.key
```

## Systemd Service

Create `/etc/systemd/system/trusted-acme.service`:

```ini
[Unit]
Description=Trusted ACME Certificate Authority
Documentation=https://github.com/jeremyhahn/go-xkms
After=network.target

[Service]
Type=notify
User=acme
Group=acme
EnvironmentFile=/etc/trusted-acme/env
ExecStart=/usr/local/bin/trusted-acme-server serve --config /etc/trusted-acme/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
TimeoutStartSec=30
TimeoutStopSec=30

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true

# Allow write to data directories
ReadWritePaths=/var/lib/trusted-acme
ReadWritePaths=/var/log/trusted-acme

# Allow binding to privileged ports (if needed)
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=trusted-acme

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable trusted-acme
sudo systemctl start trusted-acme
```

### Verify Service

```bash
# Check status
sudo systemctl status trusted-acme

# View logs
sudo journalctl -u trusted-acme -f

# Test health endpoint
curl -k https://localhost:8443/health

# Test ACME directory
curl -k https://localhost:8443/acme/directory
```

## Firewall Configuration

### UFW (Ubuntu)

```bash
# Allow ACME HTTP (if using http-01 challenge)
sudo ufw allow 80/tcp comment "ACME HTTP-01"

# Allow ACME HTTPS
sudo ufw allow 8443/tcp comment "ACME HTTPS"

# Allow gRPC
sudo ufw allow 9443/tcp comment "ACME gRPC"

# Allow admin (restrict to management network)
sudo ufw allow from 10.0.0.0/8 to any port 9090 comment "ACME Admin"

# Allow metrics (restrict to monitoring)
sudo ufw allow from 10.0.0.0/8 to any port 9091 comment "ACME Metrics"

# Enable firewall
sudo ufw enable
```

### firewalld (RHEL/CentOS)

```bash
# Create service definition
sudo tee /etc/firewalld/services/trusted-acme.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>Trusted ACME</short>
  <description>Trusted ACME Certificate Authority</description>
  <port protocol="tcp" port="80"/>
  <port protocol="tcp" port="8443"/>
  <port protocol="tcp" port="9443"/>
</service>
EOF

# Reload and add service
sudo firewall-cmd --reload
sudo firewall-cmd --permanent --add-service=trusted-acme
sudo firewall-cmd --reload

# Add admin/metrics for specific zone
sudo firewall-cmd --permanent --zone=internal --add-port=9090/tcp
sudo firewall-cmd --permanent --zone=internal --add-port=9091/tcp
sudo firewall-cmd --reload
```

### iptables

```bash
# Allow ACME ports
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 9443 -j ACCEPT

# Restrict admin to management network
sudo iptables -A INPUT -p tcp --dport 9090 -s 10.0.0.0/8 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 9090 -j DROP

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

## Reverse Proxy Setup

### Nginx

Install and configure nginx as a reverse proxy:

```bash
sudo apt install nginx
```

Create `/etc/nginx/sites-available/acme`:

```nginx
# Upstream for ACME server
upstream acme_backend {
    server 127.0.0.1:8443;
    keepalive 32;
}

# HTTP redirect and ACME HTTP-01 challenge
server {
    listen 80;
    listen [::]:80;
    server_name acme.example.com;

    # ACME HTTP-01 challenge (proxy to backend)
    location /.well-known/acme-challenge/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Redirect all other traffic to HTTPS
    location / {
        return 301 https://$host$request_uri;
    }
}

# HTTPS for ACME protocol
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name acme.example.com;

    # TLS configuration
    ssl_certificate /etc/letsencrypt/live/acme.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/acme.example.com/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    # Modern TLS configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000" always;

    # Proxy settings
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_connect_timeout 10s;
    proxy_send_timeout 30s;
    proxy_read_timeout 30s;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=acme:10m rate=10r/s;
    limit_req zone=acme burst=20 nodelay;

    # ACME endpoints
    location /acme/ {
        proxy_pass https://acme_backend;
    }

    # Health check
    location /health {
        proxy_pass https://acme_backend;
    }

    # Block admin access via public interface
    location /admin/ {
        return 403;
    }
}

# Admin interface (internal only)
server {
    listen 127.0.0.1:9090 ssl http2;
    server_name localhost;

    ssl_certificate /etc/trusted-acme/tls/server.crt;
    ssl_certificate_key /etc/trusted-acme/tls/server.key;

    location / {
        proxy_pass http://127.0.0.1:9090;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

Enable and test:

```bash
sudo ln -s /etc/nginx/sites-available/acme /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### HAProxy

Create `/etc/haproxy/haproxy.cfg`:

```haproxy
global
    maxconn 4096
    log /dev/log local0
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11
    tune.ssl.default-dh-param 2048

defaults
    mode http
    log global
    option httplog
    option dontlognull
    timeout connect 5s
    timeout client 30s
    timeout server 30s
    retries 3

frontend http_front
    bind *:80
    mode http

    # ACL for ACME HTTP-01 challenge
    acl is_acme_challenge path_beg /.well-known/acme-challenge/

    # Route challenge to backend
    use_backend acme_http if is_acme_challenge

    # Redirect everything else to HTTPS
    redirect scheme https code 301 if !is_acme_challenge

frontend https_front
    bind *:443 ssl crt /etc/haproxy/certs/acme.pem
    mode http

    # Rate limiting
    stick-table type ip size 100k expire 30s store http_req_rate(10s)
    http-request track-sc0 src
    http-request deny deny_status 429 if { sc_http_req_rate(0) gt 100 }

    # Headers
    http-request set-header X-Forwarded-Proto https
    http-request set-header X-Real-IP %[src]

    # Block admin via public interface
    acl is_admin path_beg /admin
    http-request deny if is_admin

    default_backend acme_https

backend acme_http
    mode http
    server acme1 127.0.0.1:8080 check

backend acme_https
    mode http
    option httpchk GET /health
    http-check expect status 200
    server acme1 127.0.0.1:8443 ssl verify none check
```

## Log Rotation

Create `/etc/logrotate.d/trusted-acme`:

```
/var/log/trusted-acme/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 acme acme
    postrotate
        systemctl reload trusted-acme > /dev/null 2>&1 || true
    endscript
}
```

## Monitoring Integration

### Prometheus

Add to Prometheus configuration:

```yaml
scrape_configs:
  - job_name: 'trusted-acme'
    scheme: http
    static_configs:
      - targets: ['acme.example.com:9091']
    metrics_path: /metrics
    scrape_interval: 15s
```

### Alertmanager Rules

Create alerting rules:

```yaml
groups:
  - name: trusted-acme
    rules:
      - alert: TrustedACMEDown
        expr: up{job="trusted-acme"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Trusted ACME server is down"

      - alert: TrustedACMEHighLatency
        expr: histogram_quantile(0.99, rate(http_request_duration_seconds_bucket{job="trusted-acme"}[5m])) > 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Trusted ACME high latency"

      - alert: TrustedACMEHighErrorRate
        expr: rate(http_requests_total{job="trusted-acme",status=~"5.."}[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Trusted ACME high error rate"

      - alert: TrustedACMECertExpiringSoon
        expr: trustedca_ca_certificate_expiry_days < 30
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "CA certificate expiring in {{ $value }} days"
```

## High Availability Setup

For HA without Kubernetes, use multiple servers with shared storage.

### Shared Storage with NFS

```bash
# On NFS server
sudo apt install nfs-kernel-server
sudo mkdir -p /srv/trusted-acme-data
sudo chown nobody:nogroup /srv/trusted-acme-data
echo "/srv/trusted-acme-data 10.0.0.0/24(rw,sync,no_subtree_check)" | sudo tee -a /etc/exports
sudo exportfs -ra

# On ACME servers
sudo apt install nfs-common
sudo mkdir -p /var/lib/trusted-acme
echo "nfs-server:/srv/trusted-acme-data /var/lib/trusted-acme nfs defaults,_netdev 0 0" | sudo tee -a /etc/fstab
sudo mount -a
```

### Load Balancer Configuration

Configure HAProxy or nginx on a separate server to load balance between ACME servers.

### Raft Cluster Mode

For built-in HA with Raft consensus:

```yaml
# config.yaml on each node
cluster:
  enabled: true
  node_id: 1  # Unique per node (1, 2, 3)
  raft_addr: "10.0.0.1:2380"
  peers:
    - "10.0.0.1:2380"
    - "10.0.0.2:2380"
    - "10.0.0.3:2380"
  data_dir: "/var/lib/trusted-acme/raft"
```

## Backup and Recovery

### Backup Script

Create `/usr/local/bin/trusted-acme-backup`:

```bash
#!/bin/bash
set -euo pipefail

BACKUP_DIR="/var/backups/trusted-acme"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/backup_${TIMESTAMP}.tar.gz"

# Create backup directory
mkdir -p "${BACKUP_DIR}"

# Stop service for consistent backup
systemctl stop trusted-acme

# Create backup
tar -czf "${BACKUP_FILE}" \
    /var/lib/trusted-acme \
    /etc/trusted-acme

# Start service
systemctl start trusted-acme

# Rotate old backups (keep 7 days)
find "${BACKUP_DIR}" -name "backup_*.tar.gz" -mtime +7 -delete

# Optional: Upload to remote storage
# aws s3 cp "${BACKUP_FILE}" s3://backups/trusted-acme/

echo "Backup completed: ${BACKUP_FILE}"
```

### Scheduled Backup

```bash
# Add to crontab
sudo crontab -e
# Add line:
0 2 * * * /usr/local/bin/trusted-acme-backup >> /var/log/trusted-acme/backup.log 2>&1
```

### Recovery

```bash
# Stop service
sudo systemctl stop trusted-acme

# Restore from backup
sudo tar -xzf /var/backups/trusted-acme/backup_20240115_020000.tar.gz -C /

# Fix permissions
sudo chown -R acme:acme /var/lib/trusted-acme
sudo chown root:acme /etc/trusted-acme

# Start service
sudo systemctl start trusted-acme
```

## Upgrading

### Standard Upgrade

```bash
# Download new version
VERSION=1.1.0
curl -LO https://github.com/jeremyhahn/go-xkms/releases/download/v${VERSION}/trusted-acme-server-linux-amd64

# Verify checksum
curl -LO https://github.com/jeremyhahn/go-xkms/releases/download/v${VERSION}/checksums.txt
sha256sum -c checksums.txt --ignore-missing

# Stop service
sudo systemctl stop trusted-acme

# Backup current binary
sudo cp /usr/local/bin/trusted-acme-server /usr/local/bin/trusted-acme-server.bak

# Install new binary
sudo install -m 755 trusted-acme-server-linux-amd64 /usr/local/bin/trusted-acme-server

# Start service
sudo systemctl start trusted-acme

# Verify
trusted-acme-server version
curl -k https://localhost:8443/health
```

### Rollback

```bash
sudo systemctl stop trusted-acme
sudo mv /usr/local/bin/trusted-acme-server.bak /usr/local/bin/trusted-acme-server
sudo systemctl start trusted-acme
```

## Security Hardening

### File Permissions Audit

```bash
# Verify permissions
ls -la /etc/trusted-acme/
# drwxr-x--- root acme
# -rw-r----- root acme config.yaml
# -rw------- root acme env

ls -la /var/lib/trusted-acme/
# drwxr-x--- acme acme storage/
# drwx------ acme acme ca/
```

### SELinux (RHEL/CentOS)

```bash
# Create policy module
sudo ausearch -c 'trusted-acme' --raw | audit2allow -M trusted-acme
sudo semodule -i trusted-acme.pp

# Label directories
sudo semanage fcontext -a -t etc_t "/etc/trusted-acme(/.*)?"
sudo semanage fcontext -a -t var_lib_t "/var/lib/trusted-acme(/.*)?"
sudo restorecon -Rv /etc/trusted-acme /var/lib/trusted-acme
```

### AppArmor (Ubuntu)

Create `/etc/apparmor.d/usr.local.bin.trusted-acme-server`:

```
#include <tunables/global>

/usr/local/bin/trusted-acme-server {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>

  # Binary
  /usr/local/bin/trusted-acme-server mr,

  # Configuration
  /etc/trusted-acme/ r,
  /etc/trusted-acme/** r,

  # Data
  /var/lib/trusted-acme/ rw,
  /var/lib/trusted-acme/** rwk,

  # Logs
  /var/log/trusted-acme/ rw,
  /var/log/trusted-acme/** rw,

  # Network
  network inet stream,
  network inet6 stream,

  # TPM access (if used)
  /dev/tpmrm0 rw,
}
```

Load profile:

```bash
sudo apparmor_parser -r /etc/apparmor.d/usr.local.bin.trusted-acme-server
```

## Troubleshooting

See [Troubleshooting Guide](troubleshooting.md) for common issues and solutions.

### Quick Diagnostics

```bash
# Service status
sudo systemctl status trusted-acme

# Recent logs
sudo journalctl -u trusted-acme -n 100

# Configuration test
trusted-acme-server validate --config /etc/trusted-acme/config.yaml

# Network connectivity
curl -v https://localhost:8443/acme/directory

# Port bindings
sudo ss -tlnp | grep trusted

# File permissions
sudo -u acme ls /var/lib/trusted-acme/ca/
```
