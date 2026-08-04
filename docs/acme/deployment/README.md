# Deployment Guide

Comprehensive deployment documentation for go-xkms ACME server.

## Deployment Options

| Method | Use Case | Complexity | HA Support |
|--------|----------|------------|------------|
| [Docker](docker.md) | Development, small deployments | Low | No |
| [Docker Compose](docker.md#docker-compose) | Production with monitoring | Low-Medium | Yes (Raft) |
| [Bare Metal](bare-metal.md) | Direct binary deployment | Medium | Yes (Raft) |

## Quick Links

- [Docker Deployment](docker.md) - Container-based deployment
- [Bare Metal Deployment](bare-metal.md) - Direct binary installation
- [Security Hardening](security.md) - TLS, network security, key protection
- [Monitoring](monitoring.md) - Prometheus, Grafana, alerting
- [Troubleshooting](troubleshooting.md) - Common issues and solutions

## Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 1 core | 2+ cores |
| Memory | 128 MB | 512 MB+ |
| Storage | 1 GB | 10+ GB |
| Network | Port 80/443 accessible | Dedicated subnet |

### Software Requirements

- Go 1.21+ (for building from source)
- Docker 20.10+ (for container deployment)

### Network Requirements

For ACME HTTP-01 challenge validation:

- Port 80 must be accessible from the internet
- Domain must resolve to your server's IP address

For ACME DNS-01 challenge validation:

- DNS provider API credentials
- TXT record creation capability

## Architecture Overview

```
                    +------------------+
                    |   Load Balancer  |
                    |   (Optional)     |
                    +--------+---------+
                             |
              +--------------+--------------+
              |              |              |
     +--------+--------+  +--+---+  +-------+-------+
     |  ACME Server 1  |  | ...  |  |  ACME Server N |
     |  (Leader)       |  |      |  |  (Follower)    |
     +--------+--------+  +------+  +-------+--------+
              |                             |
              +--------------+--------------+
                             |
                    +--------+--------+
                    |   QRDB          |
                    |   (Embedded KV) |
                    +-----------------+
```

### Single-Node Deployment

- Suitable for development, testing, and small-scale production
- Local file system storage
- No high availability

### Cluster Deployment

- 3-node Raft consensus cluster
- Automatic leader election
- Data replication across nodes
- Tolerates 1 node failure

## Configuration

### Minimal Configuration

```yaml
server:
  http_addr: ":8080"
  external_url: "http://localhost:8080"

storage:
  acme_dir: "/var/lib/trusted-acme/storage"
  ca_dir: "/var/lib/trusted-acme/ca"

ca:
  root:
    common_name: "My Root CA"
    organization: "My Organization"
    validity_years: 10
    key_algorithm: "EC-P384"
  intermediate:
    common_name: "My Intermediate CA"
    organization: "My Organization"
    validity_years: 5
    key_algorithm: "EC-P384"

challenges:
  http01:
    enabled: true
```

### Production Configuration

See the complete configuration files:

- `/config/config.yaml` - Single-node configuration
- `/config/config-cluster.yaml` - Cluster configuration

## Quick Start

### Option 1: Docker (Fastest)

```bash
# Build image
make docker-build

# Run container
docker run -d -p 8080:8080 \
  -v $(pwd)/data:/var/lib/trusted-acme \
  go-xkms:latest
```

### Option 2: Binary

```bash
# Build
make build

# Create config
cp config/config.yaml /etc/trusted-acme/config.yaml
# Edit config as needed

# Run
./bin/trusted-acme-server --config /etc/trusted-acme/config.yaml
```

## Verification

After deployment, verify the server is running:

```bash
# Check ACME directory endpoint
curl -s http://localhost:8080/acme/directory | jq

# Expected response
{
  "newNonce": "http://localhost:8080/acme/new-nonce",
  "newAccount": "http://localhost:8080/acme/new-account",
  "newOrder": "http://localhost:8080/acme/new-order",
  "revokeCert": "http://localhost:8080/acme/revoke-cert",
  "keyChange": "http://localhost:8080/acme/key-change"
}
```

## Next Steps

1. [Configure TLS](security.md#tls-configuration) for production
2. [Set up monitoring](monitoring.md) with Prometheus and Grafana
3. [Review security hardening](security.md) recommendations
4. Issue your first certificate using [certbot](../quickstart.md#using-certbot)

## Support Matrix

| Feature | Docker | Docker Compose (HA) | Bare Metal |
|---------|--------|---------------------|------------|
| HTTP-01 Challenge | Yes | Yes | Yes |
| DNS-01 Challenge | Yes | Yes | Yes |
| device-attest-01 | Yes | Yes | Yes |
| enroll-01 (TPM) | Yes | Yes | Yes |
| endorse-01 (EK) | Yes | Yes | Yes |
| Multi-tenancy | Yes | Yes | Yes |
| Admin API | Yes | Yes | Yes |
| Prometheus Metrics | Yes | Yes | Yes |
| High Availability | No | Yes (Raft) | Yes (Raft) |
| Automatic Failover | No | Yes | Yes |
