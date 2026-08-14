# Troubleshooting Guide

Common issues and solutions for go-xkms deployments.

## Startup Problems

### Server Fails to Start

#### Error: "listen tcp :8080: bind: address already in use"

**Cause:** Another process is using the port.

**Solution:**

```bash
# Find process using port
lsof -i :8080
# or
netstat -tlnp | grep 8080

# Kill the process or change port in config
server:
  http_addr: ":8443"
```

#### Error: "failed to load config: open /etc/trusted-acme/config.yaml: no such file"

**Cause:** Configuration file not found.

**Solution:**

```bash
# Verify file exists
ls -la /etc/trusted-acme/config.yaml

# Create default config
cat > /etc/trusted-acme/config.yaml << 'EOF'
server:
  http_addr: ":8080"
  external_url: "http://localhost:8080"
storage:
  acme_dir: "/var/lib/trusted-acme/storage"
  ca_dir: "/var/lib/trusted-acme/ca"
EOF

# For Docker, verify volume mount
docker run -v $(pwd)/config.yaml:/etc/trusted-acme/config.yaml ...
```

#### Error: "failed to initialize CA: permission denied"

**Cause:** Storage directory not writable.

**Solution:**

```bash
# Create directories with correct permissions
mkdir -p /var/lib/trusted-acme/{storage,ca}
chown -R acme:acme /var/lib/trusted-acme
chmod 700 /var/lib/trusted-acme/ca

# For Docker, check volume ownership
docker run --user $(id -u):$(id -g) ...
```

#### Error: "failed to generate CA keys: crypto/ecdsa: invalid public key"

**Cause:** Corrupted key storage or unsupported algorithm.

**Solution:**

```bash
# Remove corrupted keys (WARNING: This resets the CA!)
rm -rf /var/lib/trusted-acme/ca/*

# Verify algorithm in config
ca:
  root:
    key_algorithm: "EC-P384"  # Use supported algorithm
```

### Docker Container Not Starting

#### Container Restart Loop

**Cause:** Application crashing on startup.

**Solution:**

```bash
# Check logs
docker compose logs trusted-ca

# Check container status
docker compose ps

# Common causes:
# - Config file parsing error
# - Storage permission issues
# - Missing environment variables
```

#### Container Exited

**Cause:** Various issues causing immediate exit.

**Solution:**

```bash
# Check exit code and logs
docker compose logs trusted-ca --tail=50

# Common causes and solutions:
# - Port conflict: Check if port is in use
lsof -i :8080

# - Volume permissions
ls -la /var/lib/trusted-acme

# - Configuration errors
docker compose config --quiet
```

#### Image Pull Failed

**Cause:** Cannot pull container image.

**Solution:**

```bash
# Verify image exists
docker pull go-xkms:latest

# For private registry, login first
docker login registry.example.com

# Check docker-compose.yml for correct image name
```

## Certificate Issuance Failures

### Error: "order not ready: challenge failed"

**Cause:** Challenge validation failed.

**Solution:**

1. Check challenge type and requirements
2. Verify domain DNS resolution
3. Check firewall rules

See [Challenge Validation Issues](#challenge-validation-issues) below.

### Error: "CSR validation failed: invalid key algorithm"

**Cause:** CSR uses unsupported key algorithm.

**Solution:**

```yaml
# Verify allowed algorithms in config
ca:
  certificates:
    allowed_key_algorithms:
      - "RSA-2048"
      - "RSA-4096"
      - "EC-P256"
      - "EC-P384"
```

### Error: "rate limit exceeded"

**Cause:** Too many requests from client.

**Solution:**

```bash
# Wait for rate limit window to pass

# Adjust rate limits if needed
rate_limit:
  requests: 50
  interval: "1s"
```

### Error: "account not found" or "unauthorized"

**Cause:** Invalid account key or account deactivated.

**Solution:**

```bash
# Register new account
certbot register --server https://acme.example.com/acme/directory

# Check account status via Admin API
curl -H "Authorization: Bearer $ADMIN_KEY" \
  https://acme.example.com/admin/accounts/$ACCOUNT_ID
```

## Challenge Validation Issues

### HTTP-01 Challenge Failures

#### Error: "connection refused"

**Cause:** Port 80 not accessible.

**Solution:**

```bash
# Verify port 80 is open
nc -vz your-domain.com 80

# Check firewall
iptables -L -n | grep 80

# Ensure server is running on port 80
# (not just the ACME server, but also challenge responder)
```

#### Error: "connection timeout"

**Cause:** Firewall blocking or DNS issues.

**Solution:**

```bash
# Verify DNS resolution
dig your-domain.com

# Check if IP is reachable
curl -v http://your-domain.com/.well-known/acme-challenge/test

# Check for CDN/proxy issues
# Some CDNs cache challenge responses incorrectly
```

#### Error: "invalid response"

**Cause:** Wrong token returned.

**Solution:**

```bash
# Verify token URL is accessible
curl http://your-domain.com/.well-known/acme-challenge/$TOKEN

# Check for redirect issues (HTTP->HTTPS redirect can break HTTP-01)
curl -L -v http://your-domain.com/.well-known/acme-challenge/$TOKEN
```

### DNS-01 Challenge Failures

#### Error: "DNS record not found"

**Cause:** TXT record not propagated.

**Solution:**

```bash
# Check DNS propagation
dig TXT _acme-challenge.your-domain.com

# Use multiple DNS servers
dig @8.8.8.8 TXT _acme-challenge.your-domain.com
dig @1.1.1.1 TXT _acme-challenge.your-domain.com

# Wait for propagation (can take up to 48 hours)
```

#### Error: "incorrect TXT record value"

**Cause:** Wrong value in DNS record.

**Solution:**

```bash
# Verify expected value from ACME server
# Check order/authorization for expected token

# Verify current DNS value
dig TXT _acme-challenge.your-domain.com +short
```

### Device-Attest-01 Failures

#### Error: "attestation verification failed"

**Cause:** Invalid TPM attestation.

**Solution:**

```bash
# Verify TPM is properly initialized
tpm2_getcap properties-fixed

# Check EK certificate chain
# Ensure manufacturer CA is trusted
```

## Cluster Problems

### Raft Leader Election Issues

#### Error: "no Raft leader elected"

**Cause:** Cluster cannot form quorum.

**Solution:**

```bash
# Check all nodes are running
docker compose ps

# Verify peer connectivity
docker compose exec trusted-ca-1 nc -vz trusted-ca-2 2380

# Check Raft logs
docker compose logs trusted-ca-1 | grep -i raft
```

#### Error: "peer connection refused"

**Cause:** Network configuration blocking Raft traffic.

**Solution:**

```bash
# Verify Docker network exists
docker network ls | grep trusted-ca

# Check container connectivity
docker compose exec trusted-ca-1 ping -c 1 trusted-ca-2

# Test health endpoint
docker compose exec trusted-ca-1 wget -T5 -q -O- http://trusted-ca-2:8080/health
```

### Split-Brain Scenario

**Cause:** Network partition causing multiple leaders.

**Solution:**

```bash
# Identify current leaders
for i in 1 2 3; do
  echo "Node $i:"
  docker compose exec trusted-ca-$i wget -q -O- http://localhost:9090/metrics | grep raft_leader
done

# If multiple leaders, restart minority partition
docker compose restart trusted-ca-2
```

### Data Inconsistency

**Cause:** Raft log corruption or incomplete sync.

**Solution:**

```bash
# Check Raft indices
for i in 1 2 3; do
  echo "Node $i:"
  docker compose exec trusted-ca-$i wget -q -O- http://localhost:9090/metrics | grep raft_applied_index
done

# Force re-sync by removing and re-joining node
docker compose stop trusted-ca-3
docker volume rm trusted-ca_data-3
docker compose up -d trusted-ca-3
# Node will recreate with fresh storage and sync from leader
```

## Performance Issues

### High Latency

**Cause:** Various.

**Solution:**

```bash
# Check resource usage
docker stats trusted-ca --no-stream

# Increase resources if needed (update docker-compose.yml)
# services:
#   trusted-ca:
#     deploy:
#       resources:
#         limits:
#           cpus: '2'
#           memory: 1G

# Check storage latency
docker compose exec trusted-ca \
  dd if=/dev/zero of=/var/lib/trusted-acme/test bs=1M count=100 oflag=sync

# Enable debug logging temporarily
docker compose exec trusted-ca sh -c "export ACME_LOG_LEVEL=debug"
# Or update .env and restart
```

### High Memory Usage

**Cause:** Memory leak or cache buildup.

**Solution:**

```bash
# Check memory metrics
docker compose exec trusted-ca \
  wget -q -O- http://localhost:9090/metrics | grep go_memstats

# Force garbage collection (restart container)
docker compose restart trusted-ca

# Reduce cache sizes in config if applicable
```

### Connection Timeouts

**Cause:** Network issues or slow backend.

**Solution:**

```bash
# Check network connectivity
docker compose exec trusted-ca wget -T5 -q -O- https://example.com

# Check DNS resolution
docker compose exec trusted-ca nslookup example.com

# For nginx reverse proxy, increase timeouts
# proxy_read_timeout 120s;
```

## Storage Issues

### Volume Not Available

**Cause:** Docker volume not created or corrupted.

**Solution:**

```bash
# Check volume exists
docker volume ls | grep trusted-ca

# Inspect volume
docker volume inspect trusted-ca-data

# Create volume if missing
docker volume create trusted-ca-data
```

### Disk Full

**Cause:** Storage capacity exceeded.

**Solution:**

```bash
# Check disk usage
docker compose exec trusted-ca df -h /var/lib/trusted-acme

# Clean up old data
docker compose exec trusted-ca \
  find /var/lib/trusted-acme/storage -type f -mtime +90 -delete

# Prune unused Docker resources
docker system prune -f
```

## TLS/Certificate Issues

### Error: "x509: certificate signed by unknown authority"

**Cause:** CA not trusted.

**Solution:**

```bash
# Add CA to trust store
cp ca.crt /usr/local/share/ca-certificates/
update-ca-certificates

# For Docker, mount CA certificate
# volumes:
#   - ./ca.crt:/etc/ssl/certs/trusted-ca.crt:ro
```

### Error: "x509: certificate has expired"

**Cause:** Expired certificate.

**Solution:**

```bash
# Check certificate expiry
openssl x509 -in /etc/trusted-acme/tls/server.crt -noout -dates

# Generate new certificate
# ... (follow TLS configuration in security.md)

# Restart to pick up new certificate
docker compose restart trusted-ca
```

## Admin API Issues

### Error: "unauthorized"

**Cause:** Invalid or missing API key.

**Solution:**

```bash
# Verify API key in environment
docker compose exec trusted-ca env | grep ADMIN_SUPER_ADMIN_KEY

# Or check .env file
grep ADMIN_SUPER_ADMIN_KEY /etc/trusted-acme/.env

# Test with correct header
curl -H "Authorization: Bearer $API_KEY" \
  https://acme.example.com/admin/health
```

### Error: "forbidden"

**Cause:** Insufficient permissions for role.

**Solution:**

```bash
# Check role in config
admin:
  api_keys:
    - key: "${ADMIN_OPERATOR_KEY}"
      role: operator  # May not hold the resource:action the route requires

# Use an so or admin key, or grant the missing permission in go-qrdb
```

## Debugging Commands

### Docker

```bash
# Interactive shell
docker exec -it trusted-ca /bin/sh

# View logs
docker logs -f trusted-ca

# Check process
docker exec trusted-ca ps aux

# Network debugging
docker exec trusted-ca wget -q -O- http://localhost:8080/health
```

### Docker Compose

```bash
# Container shell
docker compose exec trusted-ca /bin/sh

# Logs
docker compose logs -f trusted-ca

# Logs with timestamps
docker compose logs -t trusted-ca

# Resource usage
docker stats trusted-ca

# Network debugging
docker compose exec trusted-ca ping -c 3 google.com
docker compose exec trusted-ca nslookup example.com
```

### Common Debug Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/health` | Overall health |
| `/health/live` | Liveness check |
| `/health/ready` | Readiness check |
| `/metrics` | Prometheus metrics |
| `/acme/directory` | ACME directory |

## Getting Help

If issues persist:

1. Enable debug logging: `ACME_LOG_LEVEL=debug`
2. Collect logs and metrics
3. Check GitHub issues
4. Open a new issue with:
   - go-xkms version
   - Deployment method (Docker/Docker Compose/Bare metal)
   - Configuration (sanitized)
   - Full error logs
   - Steps to reproduce
