# Security Hardening

Security best practices and hardening guidelines for go-trusted-ca deployments.

## TLS Configuration

### Server TLS

Enable HTTPS for production deployments:

```yaml
server:
  http_addr: ":8080"      # Internal/redirect
  https_addr: ":8443"     # Primary HTTPS

  tls:
    enabled: true
    cert_file: "/etc/trusted-acme/tls/server.crt"
    key_file: "/etc/trusted-acme/tls/server.key"
    ca_file: "/etc/trusted-acme/tls/ca.crt"
```

### Generating TLS Certificates

Using OpenSSL:

```bash
# Generate CA key and certificate
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha384 -days 3650 \
  -out ca.crt \
  -subj "/C=US/O=Your Organization/CN=Trusted CA Root"

# Generate server key
openssl genrsa -out server.key 4096

# Create certificate signing request
openssl req -new -key server.key \
  -out server.csr \
  -subj "/C=US/O=Your Organization/CN=acme.example.com"

# Create SAN extension file
cat > san.cnf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = acme.example.com
DNS.2 = *.acme.example.com
IP.1 = 10.0.0.1
EOF

# Sign certificate
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 -sha384 \
  -extfile san.cnf -extensions v3_req
```

### TLS Cipher Suites

The server uses secure cipher suites by default. For custom configuration:

```yaml
server:
  tls:
    min_version: "TLS1.2"    # Minimum TLS 1.2
    cipher_suites:
      - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
      - "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
      - "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
      - "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
```

### Client Certificate Authentication (mTLS)

For admin API access:

```yaml
admin:
  tls:
    enabled: true
    cert_file: "/etc/trusted-acme/tls/admin.crt"
    key_file: "/etc/trusted-acme/tls/admin.key"
    client_ca_file: "/etc/trusted-acme/tls/client-ca.crt"
    require_client_cert: true
```

## Network Security

### Firewall Rules

Required ports:

| Port | Protocol | Direction | Purpose |
|------|----------|-----------|---------|
| 80 | TCP | Inbound | HTTP-01 challenge validation |
| 443 | TCP | Inbound | HTTPS API |
| 8080 | TCP | Internal | HTTP API |
| 8081 | TCP | Internal | Admin API |
| 2380 | TCP | Internal | Raft peer communication |
| 9090 | TCP | Internal | Prometheus metrics |

Example iptables rules:

```bash
# Allow ACME traffic
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Restrict admin API to internal network
iptables -A INPUT -p tcp --dport 8081 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 8081 -j DROP

# Allow Raft from cluster peers only
iptables -A INPUT -p tcp --dport 2380 -s 10.0.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 2380 -j DROP
```

### Docker Network Isolation

Use Docker networks to isolate services:

```yaml
# docker-compose.yml
networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
    internal: true  # No external access

services:
  trusted-ca:
    networks:
      - frontend
      - backend

  storage:
    networks:
      - backend  # Only accessible from backend network
```

### Rate Limiting

Configure rate limiting to prevent abuse:

```yaml
rate_limit:
  # Maximum requests per interval per client IP
  requests: 20
  # Interval duration
  interval: "1s"

  # Per-endpoint limits (optional)
  endpoints:
    new_account:
      requests: 5
      interval: "1m"
    new_order:
      requests: 10
      interval: "1m"
```

At reverse proxy level (NGINX):

```nginx
# nginx.conf
limit_req_zone $binary_remote_addr zone=acme:10m rate=10r/s;
limit_conn_zone $binary_remote_addr zone=addr:10m;

server {
    location / {
        limit_req zone=acme burst=20 nodelay;
        limit_conn addr 5;
        proxy_pass http://trusted-ca:8080;
    }
}
```

## Key Protection

### CA Key Security

The CA private keys are the most critical assets. Protection measures:

1. **File System Permissions**

```bash
# Restrict access to CA directory
chmod 700 /var/lib/trusted-acme/ca
chmod 600 /var/lib/trusted-acme/ca/*.key

# Set ownership
chown -R acme:acme /var/lib/trusted-acme/ca
```

2. **Encryption at Rest**

Keys are encrypted using the seal mechanism:

```yaml
seal:
  # Shamir's Secret Sharing
  threshold: 2    # Minimum shares to unseal
  shares: 3       # Total shares
  kdf: "argon2id" # Key derivation function
```

3. **HSM Integration** (Future)

For hardware security:

```yaml
ca:
  keystore:
    type: "hsm"
    hsm:
      library: "/usr/lib/softhsm/libsofthsm2.so"
      slot: 0
      pin: "${HSM_PIN}"
```

### API Key Management

1. **Generate Strong Keys**

```bash
# Generate 256-bit random key
openssl rand -base64 32
```

2. **Rotate Keys Regularly**

```bash
# Generate new key
NEW_KEY=$(openssl rand -base64 32)

# Update environment configuration
sed -i "s/ADMIN_SUPER_ADMIN_KEY=.*/ADMIN_SUPER_ADMIN_KEY=${NEW_KEY}/" /etc/trusted-acme/.env

# Restart containers to pick up new key
docker compose restart trusted-ca
```

3. **Use External Secret Management**

For production, use:

- HashiCorp Vault
- AWS Secrets Manager
- Docker Secrets (Swarm mode)

Example with Vault Agent:

```yaml
# docker-compose.yml with Vault Agent sidecar
services:
  vault-agent:
    image: hashicorp/vault
    command: agent -config=/etc/vault/agent.hcl
    volumes:
      - ./vault-agent.hcl:/etc/vault/agent.hcl
      - secrets:/secrets

  trusted-ca:
    depends_on:
      - vault-agent
    volumes:
      - secrets:/run/secrets:ro
    environment:
      - ADMIN_SUPER_ADMIN_KEY_FILE=/run/secrets/admin-key

volumes:
  secrets:
```

### Seal/Unseal Keys

For cluster mode, seal keys protect the CA:

1. **Distribute Keys**
   - Generate 3 shares, require 2 to unseal
   - Distribute to different key holders
   - Store in separate secure locations

2. **Secure Storage**
   - Never store all shares together
   - Use hardware security (YubiKey, TPM)
   - Maintain offline backups

3. **Unsealing Process**

```bash
# Unseal with key 1
curl -X POST https://acme.example.com/admin/unseal \
  -H "Content-Type: application/json" \
  -d '{"key": "share-1-base64-encoded"}'

# Unseal with key 2
curl -X POST https://acme.example.com/admin/unseal \
  -H "Content-Type: application/json" \
  -d '{"key": "share-2-base64-encoded"}'

# Verify sealed status
curl https://acme.example.com/admin/seal-status
```

## Container Security

### Non-Root Execution

The container runs as a non-root user:

```dockerfile
# Create non-root user
RUN addgroup -S acme && adduser -S acme -G acme

# Switch to non-root
USER acme
```

### Read-Only Root Filesystem

```yaml
# docker-compose.yml
services:
  trusted-ca:
    read_only: true
    tmpfs:
      - /tmp
    volumes:
      - trusted-ca-data:/var/lib/trusted-acme
```

### Drop Capabilities

```yaml
# docker-compose.yml
services:
  trusted-ca:
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
```

### Seccomp Profile

```yaml
# docker-compose.yml
services:
  trusted-ca:
    security_opt:
      - seccomp:unconfined  # Or use custom profile
      # - seccomp:/path/to/seccomp-profile.json
```

## Audit Logging

Enable comprehensive audit logging:

```yaml
audit:
  enabled: true
  file: "/var/log/trusted-acme/audit.log"

  events:
    - certificate.issued
    - certificate.revoked
    - account.created
    - account.deactivated
    - tenant.created
    - tenant.updated
    - eab.created
    - eab.used
    - admin.login
    - admin.action
    - unseal.attempt
```

### Log Format

Audit logs are JSON-formatted:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "event": "certificate.issued",
  "account_id": "acc_123",
  "order_id": "ord_456",
  "domains": ["example.com"],
  "challenge_type": "http-01",
  "client_ip": "203.0.113.1",
  "user_agent": "certbot/2.0.0"
}
```

### Log Retention

```yaml
logging:
  file: "/var/log/trusted-acme/server.log"
  max_size_mb: 100
  max_backups: 5
  max_age_days: 30
```

### Log Shipping

Ship logs to a SIEM for analysis:

```yaml
# docker-compose.yml with Fluentd sidecar
services:
  fluentd:
    image: fluent/fluentd:v1.16
    volumes:
      - ./fluentd.conf:/fluentd/etc/fluent.conf
      - trusted-ca-logs:/var/log/trusted-acme:ro
    depends_on:
      - trusted-ca

  trusted-ca:
    volumes:
      - trusted-ca-logs:/var/log/trusted-acme

volumes:
  trusted-ca-logs:
```

Fluentd configuration:

```
# fluentd.conf
<source>
  @type tail
  path /var/log/trusted-acme/audit.log
  pos_file /fluentd/log/audit.pos
  tag trusted-ca.audit
  <parse>
    @type json
  </parse>
</source>

<match trusted-ca.**>
  @type elasticsearch
  host elasticsearch
  port 9200
  index_name trusted-ca
</match>
```

## Security Checklist

### Pre-Deployment

- [ ] TLS certificates generated with strong algorithms (EC-P384 or RSA-4096)
- [ ] API keys generated with sufficient entropy (256-bit)
- [ ] Network policies configured
- [ ] Firewall rules applied
- [ ] Storage encryption enabled
- [ ] Audit logging configured

### Deployment

- [ ] Running as non-root user
- [ ] Read-only root filesystem
- [ ] All capabilities dropped
- [ ] Resource limits set
- [ ] Health checks configured
- [ ] Secrets mounted as files (not env vars)

### Post-Deployment

- [ ] Verify TLS configuration (`nmap --script ssl-enum-ciphers`)
- [ ] Verify rate limiting working
- [ ] Test audit log generation
- [ ] Verify network isolation
- [ ] Document key holder assignments
- [ ] Schedule key rotation

### Ongoing

- [ ] Monitor audit logs for anomalies
- [ ] Review access patterns
- [ ] Rotate API keys quarterly
- [ ] Update TLS certificates before expiry
- [ ] Apply security patches promptly
- [ ] Conduct periodic security reviews

## Compliance Considerations

### FIPS 140-3

For FIPS compliance:

```yaml
ca:
  fips_mode: true
  root:
    key_algorithm: "EC-P384"  # FIPS-approved
  intermediate:
    key_algorithm: "EC-P384"
```

### SOC 2

Key controls:

- Enable audit logging
- Implement access controls (API keys with roles)
- Configure log retention
- Document change management
- Maintain incident response procedures

### PCI DSS

If issuing certificates for payment systems:

- Use strong cryptography (Section 4)
- Implement access controls (Section 7, 8)
- Maintain audit trails (Section 10)
- Regular security testing (Section 11)
