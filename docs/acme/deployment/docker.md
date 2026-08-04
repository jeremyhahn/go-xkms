# Docker Deployment

Deploy go-xkms ACME server using Docker containers.

## Building the Image

### From Source

```bash
# Clone repository
git clone https://github.com/jeremyhahn/go-xkms.git
cd go-xkms

# Build image
make docker-build

# Or build directly
docker build -t go-xkms:latest .
```

### Multi-Architecture Build

```bash
# Build for multiple architectures
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t go-xkms:latest \
  --push .
```

## Dockerfile Overview

The Dockerfile uses a multi-stage build for minimal image size:

```dockerfile
# Build stage - compiles Go binaries
FROM golang:alpine AS builder
# ... build steps ...

# Runtime stage - minimal Alpine image
FROM alpine:3.21
# ... runtime configuration ...
```

**Key features:**

- Multi-stage build for small image size (~20MB)
- Non-root user execution (acme:acme)
- Health check included
- Minimal attack surface

**Exposed ports:**

| Port | Purpose |
|------|---------|
| 8080 | ACME HTTP API |
| 8443 | ACME HTTPS API |
| 8081 | Admin API |

## Running Single-Node

### Basic Usage

```bash
# Run with defaults
docker run -d \
  --name trusted-ca \
  -p 8080:8080 \
  go-xkms:latest
```

### With Persistent Storage

```bash
# Create data directory
mkdir -p ./trusted-ca-data

# Run with volume mount
docker run -d \
  --name trusted-ca \
  -p 8080:8080 \
  -v $(pwd)/trusted-ca-data:/var/lib/trusted-acme \
  go-xkms:latest
```

### With Custom Configuration

```bash
# Create config file
cat > config.yaml << 'EOF'
server:
  http_addr: ":8080"
  external_url: "https://acme.example.com"

storage:
  acme_dir: "/var/lib/trusted-acme/storage"
  ca_dir: "/var/lib/trusted-acme/ca"

ca:
  root:
    common_name: "My Root CA"
    organization: "My Organization"
    validity_years: 20
    key_algorithm: "EC-P384"
  intermediate:
    common_name: "My Intermediate CA"
    organization: "My Organization"
    validity_years: 10
    key_algorithm: "EC-P384"

challenges:
  http01:
    enabled: true
  dns01:
    enabled: true
EOF

# Run with config
docker run -d \
  --name trusted-ca \
  -p 8080:8080 \
  -v $(pwd)/config.yaml:/etc/trusted-acme/config.yaml:ro \
  -v $(pwd)/trusted-ca-data:/var/lib/trusted-acme \
  go-xkms:latest \
  --config /etc/trusted-acme/config.yaml
```

## Docker Compose

### Basic Deployment

```yaml
# docker-compose.yml
version: '3.8'
services:
  acme-server:
    image: go-xkms:latest
    container_name: trusted-ca
    ports:
      - "8080:8080"
      - "8081:8081"
    volumes:
      - ./config.yaml:/etc/trusted-acme/config.yaml:ro
      - acme-data:/var/lib/trusted-acme
    command: ["--config", "/etc/trusted-acme/config.yaml"]
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 5s

volumes:
  acme-data:
```

### With TLS and Admin API

```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  acme-server:
    image: go-xkms:latest
    container_name: trusted-ca
    ports:
      - "8080:8080"
      - "8443:8443"
      - "8081:8081"
    volumes:
      - ./config.yaml:/etc/trusted-acme/config.yaml:ro
      - ./certs:/etc/trusted-acme/tls:ro
      - acme-data:/var/lib/trusted-acme
    environment:
      - ACME_LOG_LEVEL=info
      - ADMIN_SUPER_ADMIN_KEY=${ADMIN_SUPER_ADMIN_KEY}
      - ADMIN_OPERATOR_KEY=${ADMIN_OPERATOR_KEY}
      - ADMIN_VIEWER_KEY=${ADMIN_VIEWER_KEY}
    command: ["--config", "/etc/trusted-acme/config.yaml"]
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 5s

volumes:
  acme-data:
```

### With Reverse Proxy (Traefik)

```yaml
# docker-compose.traefik.yml
version: '3.8'
services:
  traefik:
    image: traefik:v3.0
    container_name: traefik
    command:
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.letsencrypt.acme.httpchallenge=true"
      - "--certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web"
      - "--certificatesresolvers.letsencrypt.acme.email=admin@example.com"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - letsencrypt:/letsencrypt

  acme-server:
    image: go-xkms:latest
    container_name: trusted-ca
    volumes:
      - ./config.yaml:/etc/trusted-acme/config.yaml:ro
      - acme-data:/var/lib/trusted-acme
    command: ["--config", "/etc/trusted-acme/config.yaml"]
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.acme.rule=Host(`acme.example.com`)"
      - "traefik.http.routers.acme.entrypoints=websecure"
      - "traefik.http.routers.acme.tls.certresolver=letsencrypt"
      - "traefik.http.services.acme.loadbalancer.server.port=8080"
    restart: unless-stopped

volumes:
  acme-data:
  letsencrypt:
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ACME_STORAGE_DIR` | `/var/lib/trusted-acme/storage` | ACME data storage path |
| `ACME_LOG_LEVEL` | `info` | Log level (debug, info, warn, error) |
| `ADMIN_SUPER_ADMIN_KEY` | - | Super admin API key |
| `ADMIN_OPERATOR_KEY` | - | Operator API key |
| `ADMIN_VIEWER_KEY` | - | Viewer API key |

## Volume Mounts

| Container Path | Purpose | Mode |
|----------------|---------|------|
| `/etc/trusted-acme/config.yaml` | Configuration file | ro |
| `/etc/trusted-acme/tls/` | TLS certificates | ro |
| `/var/lib/trusted-acme/` | Persistent data | rw |
| `/var/log/trusted-acme/` | Log files | rw |

## Container Management

### View Logs

```bash
# Follow logs
docker logs -f trusted-ca

# Last 100 lines
docker logs --tail 100 trusted-ca
```

### Execute Commands

```bash
# Interactive shell
docker exec -it trusted-ca /bin/sh

# Check health
docker exec trusted-ca wget -q -O- http://localhost:8080/health

# View configuration
docker exec trusted-ca cat /etc/trusted-acme/config.yaml
```

### Backup Data

```bash
# Stop container
docker stop trusted-ca

# Create backup
docker run --rm \
  -v trusted-ca-data:/data:ro \
  -v $(pwd)/backup:/backup \
  alpine tar czf /backup/trusted-ca-$(date +%Y%m%d).tar.gz -C /data .

# Start container
docker start trusted-ca
```

### Restore Data

```bash
# Stop container
docker stop trusted-ca

# Restore backup
docker run --rm \
  -v trusted-ca-data:/data \
  -v $(pwd)/backup:/backup:ro \
  alpine tar xzf /backup/trusted-ca-20240101.tar.gz -C /data

# Start container
docker start trusted-ca
```

## Upgrading

### Rolling Update (Zero Downtime)

For production deployments with a load balancer:

```bash
# Pull new image
docker pull go-xkms:latest

# Start new container
docker run -d \
  --name trusted-ca-new \
  -p 8081:8080 \
  -v $(pwd)/config.yaml:/etc/trusted-acme/config.yaml:ro \
  -v acme-data:/var/lib/trusted-acme \
  go-xkms:latest \
  --config /etc/trusted-acme/config.yaml

# Wait for health check
sleep 10

# Switch load balancer to new container
# ...

# Stop old container
docker stop trusted-ca

# Rename containers
docker rename trusted-ca trusted-ca-old
docker rename trusted-ca-new trusted-ca

# Clean up
docker rm trusted-ca-old
```

### Docker Compose Update

```bash
# Pull new images
docker-compose pull

# Recreate containers
docker-compose up -d --force-recreate

# Remove old images
docker image prune -f
```

## Security Considerations

### Run as Non-Root

The default Dockerfile runs as a non-root user. Verify:

```bash
docker exec trusted-ca id
# uid=1000(acme) gid=1000(acme) groups=1000(acme)
```

### Read-Only Root Filesystem

For enhanced security:

```bash
docker run -d \
  --name trusted-ca \
  --read-only \
  --tmpfs /tmp \
  -p 8080:8080 \
  -v $(pwd)/config.yaml:/etc/trusted-acme/config.yaml:ro \
  -v acme-data:/var/lib/trusted-acme \
  go-xkms:latest
```

### Resource Limits

```bash
docker run -d \
  --name trusted-ca \
  --memory="512m" \
  --cpus="1" \
  --pids-limit=100 \
  -p 8080:8080 \
  -v acme-data:/var/lib/trusted-acme \
  go-xkms:latest
```

### Network Isolation

```bash
# Create dedicated network
docker network create --driver bridge trusted-ca-net

# Run with network
docker run -d \
  --name trusted-ca \
  --network trusted-ca-net \
  -p 8080:8080 \
  go-xkms:latest
```

## Troubleshooting

### Container Fails to Start

```bash
# Check logs
docker logs trusted-ca

# Common issues:
# - Config file not found: Check volume mount path
# - Permission denied: Check file ownership
# - Port already in use: Change host port mapping
```

### Health Check Failing

```bash
# Manual health check
docker exec trusted-ca wget -q -O- http://localhost:8080/health

# Check if process is running
docker exec trusted-ca ps aux
```

### Storage Issues

```bash
# Check volume
docker volume inspect acme-data

# Check disk space
docker exec trusted-ca df -h /var/lib/trusted-acme
```

See [Troubleshooting Guide](troubleshooting.md) for more solutions.
