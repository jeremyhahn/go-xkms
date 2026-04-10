# Docker Quick Start Guide

Get go-xkms running in Docker in 5 minutes.

## Prerequisites

- Docker 20.10+ with buildx support
- Docker Compose 2.0+
- Make (optional, for convenience)

## Quick Start

### 1. Build the Unified Server

```bash
# Using Make
make docker-build-server

# Or directly with Docker
docker build -t go-xkms/server:latest -f Dockerfile.server .
```

### 2. Create a Minimal Config

```bash
mkdir -p configs
cat > configs/config.yaml <<'EOF'
server:
  host: 0.0.0.0
  rest_port: 8443

protocols:
  rest: true
  grpc: false
  quic: false
  mcp: false

logging:
  level: info
  format: json

tls:
  enabled: false  # Disable TLS for quick testing

auth:
  enabled: false  # Disable auth for quick testing

health:
  enabled: true
  path: /health

storage:
  backend: file
  path: /var/lib/xkms/metadata

default_backend: software

backends:
  software:
    enabled: true
    path: /var/lib/xkms/keys
EOF
```

### 3. Run the Server

```bash
docker run -d --name xkms \
  -p 8443:8443 \
  -v $(PWD)/configs:/etc/xkms:ro \
  go-xkms/server:latest
```

### 4. Test the Server

```bash
# Check health
curl http://localhost:8443/health

# View logs
docker logs xkms

# Follow logs
docker logs -f xkms
```

### 5. Stop and Clean Up

```bash
docker stop xkms
docker rm xkms
```

## Production Deployment

### 1. Generate TLS Certificates

```bash
# Create certificates directory
mkdir -p configs/certs

# Generate self-signed certificate (for testing)
openssl req -x509 -newkey rsa:4096 \
  -keyout configs/certs/server.key \
  -out configs/certs/server.crt \
  -days 365 -nodes \
  -subj "/CN=localhost"
```

### 2. Create Production Config

```bash
cp examples/config/config-server.yaml configs/config.yaml
# Edit configs/config.yaml and set:
# - tls.enabled: true
# - tls.cert_file: /etc/xkms/certs/server.crt
# - tls.key_file: /etc/xkms/certs/server.key
# - auth.enabled: true
```

### 3. Run with Docker Compose

```bash
# Build and start
make compose-prod-build
make compose-prod-up

# View logs
make compose-prod-logs

# Stop
make compose-prod-down
```

## Common Use Cases

### REST API Only

```bash
make docker-build-rest
make docker-run-rest

# Access at https://localhost:8445
curl -k https://localhost:8445/health
```

### gRPC Only

```bash
make docker-build-grpc
make docker-run-grpc

# Connect at localhost:9445
```

### All Protocols (Unified Server)

```bash
make docker-build-server
make docker-run-server

# REST:  https://localhost:8443
# gRPC:  localhost:9443
# QUIC:  localhost:8444
# MCP:   localhost:9444
```

### CLI Tool

```bash
make docker-build-cli

# Run commands
docker run --rm \
  -v $(PWD)/configs:/etc/xkms:ro \
  go-xkms/cli:latest \
  --help
```

## Troubleshooting

### Port Already in Use

```bash
# Check what's using the port
sudo lsof -i :8443

# Use different port
docker run -d -p 9443:8443 go-xkms/server:latest
```

### Permission Denied

```bash
# Fix config ownership
chown -R 1000:1000 configs/

# Or run as root (not recommended)
docker run --user root ...
```

### Container Won't Start

```bash
# Check logs
docker logs xkms

# Run interactively
docker run -it --rm \
  -v $(PWD)/configs:/etc/xkms:ro \
  go-xkms/server:latest \
  sh
```

### Health Check Fails

```bash
# Check if server is listening
docker exec xkms netstat -tlnp

# Test health endpoint directly
docker exec xkms wget -O- http://localhost:8443/health
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| KEYSTORE_CONFIG | /etc/xkms/config.yaml | Config file path |

```bash
docker run -d \
  -e KEYSTORE_CONFIG=/custom/path/config.yaml \
  go-xkms/server:latest
```

## Volume Mounts

### Configuration (Read-Only)

```bash
-v $(PWD)/configs:/etc/xkms:ro
```

### Persistent Data

```bash
-v xkms-data:/var/lib/xkms
```

### Certificates

```bash
-v $(PWD)/configs/certs:/etc/xkms/certs:ro
```

## Make Targets

All Docker commands are available as Make targets:

```bash
# Build images
make docker-build-all
make docker-build-server
make docker-build-rest
make docker-build-grpc
make docker-build-cli

# Run containers
make docker-run-server
make docker-run-rest
make docker-run-grpc

# View logs
make docker-logs

# Stop containers
make docker-stop-all

# Clean up
make docker-clean-production

# Docker Compose (production)
make compose-prod-build
make compose-prod-up
make compose-prod-down
make compose-prod-logs

# Help
make docker-help
```

## Next Steps

- Read [docker.md](docker.md) for complete documentation
- Review [configuration examples](../../examples/config/)
- Configure [TLS and mTLS](docker.md#security-considerations)
- Setup [cloud backends](docker.md#backends) (AWS KMS, GCP KMS, Azure KV)
- Deploy to [Kubernetes](../kubernetes.md)

## Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose](https://docs.docker.com/compose/)
- [go-xkms Documentation](README.md)
