# Docker Deployment Guide

This guide covers building and deploying go-keychain using Docker containers.

## Available Images

go-keychain provides six production-ready Docker images:

1. **Dockerfile.server** - Unified server (all protocols: REST, gRPC, QUIC, MCP)
2. **Dockerfile.rest** - REST-only server
3. **Dockerfile.grpc** - gRPC-only server
4. **Dockerfile.quic** - QUIC-only server
5. **Dockerfile.mcp** - MCP-only server
6. **Dockerfile.cli** - CLI tool

All images follow security best practices:
- Multi-stage builds for minimal image size
- Non-root user (appuser, UID 1000)
- Alpine Linux base for security
- All backend support enabled (PKCS#8, TPM2, PKCS#11, AWS KMS, GCP KMS, Azure KV, Vault)

## Quick Start

### Build All Images

```bash
make docker-build-all
```

### Build Individual Images

```bash
make docker-build-server  # Unified server
make docker-build-rest    # REST-only
make docker-build-grpc    # gRPC-only
make docker-build-quic    # QUIC-only
make docker-build-mcp     # MCP-only
make docker-build-cli     # CLI tool
```

### Run Containers

```bash
# Run unified server (all protocols)
make docker-run-server

# Run REST-only server
make docker-run-rest

# Run gRPC-only server
make docker-run-grpc
```

## Docker Compose

### Development Environment

The default `docker-compose.yml` provides a development environment with:
- SWTPM (TPM 2.0 simulator)
- SoftHSM (PKCS#11 simulator)
- Integration test runner
- Development shell

```bash
# Start development environment
make compose-up

# Run integration tests
make compose-integration

# Start interactive shell
make compose-dev

# Stop all services
make compose-down
```

### Production Environment

The `docker-compose.production.yml` provides production services:

```bash
# Build production images
make compose-prod-build

# Start production services
make compose-prod-up

# View logs
make compose-prod-logs

# Show service status
make compose-prod-ps

# Stop services
make compose-prod-down
```

## Port Mappings

### Default Ports

| Service | Protocol | Port | Description |
|---------|----------|------|-------------|
| REST    | HTTPS    | 8443 | REST API endpoint |
| gRPC    | TLS      | 9443 | gRPC endpoint |
| QUIC    | UDP      | 8444 | QUIC endpoint |
| MCP     | TLS      | 9444 | MCP endpoint |

### Docker Compose Ports

When running multiple services, ports are mapped to avoid conflicts:

| Service | External Port | Internal Port |
|---------|--------------|---------------|
| Unified Server (REST) | 8443 | 8443 |
| Unified Server (gRPC) | 9443 | 9443 |
| Unified Server (QUIC) | 8444 | 8444 |
| Unified Server (MCP)  | 9444 | 9444 |
| REST-only | 8445 | 8443 |
| gRPC-only | 9445 | 9443 |
| QUIC-only | 8446 | 8444 |
| MCP-only  | 9446 | 9444 |

## Configuration

### Volume Mounts

All containers expect configuration in `/etc/keychain/config.yaml`:

```bash
docker run -d \
  -v $(PWD)/configs:/etc/keychain:ro \
  -p 8443:8443 \
  go-keychain/server:latest
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| KEYSTORE_CONFIG | /etc/keychain/config.yaml | Path to config file |

### Data Persistence

Mount volumes for persistent data:

```bash
docker run -d \
  -v keychain-data:/var/lib/keychain \
  -v $(PWD)/configs:/etc/keychain:ro \
  go-keychain/server:latest
```

## Configuration Files

Create protocol-specific configuration files in `configs/`:

### configs/config.yaml (Unified Server)

```yaml
server:
  host: 0.0.0.0
  rest_port: 8443
  grpc_port: 9443
  quic_port: 8444
  mcp_port: 9444

protocols:
  rest: true
  grpc: true
  quic: true
  mcp: true

tls:
  enabled: true
  cert_file: /etc/keychain/server.crt
  key_file: /etc/keychain/server.key

default_backend: pkcs8

backends:
  pkcs8:
    enabled: true
    path: /var/lib/keychain/keys
```

### configs/config-rest.yaml (REST-only)

```yaml
server:
  host: 0.0.0.0
  rest_port: 8443

protocols:
  rest: true
  grpc: false
  quic: false
  mcp: false

# ... rest of config same as above
```

### configs/config-grpc.yaml (gRPC-only)

```yaml
server:
  host: 0.0.0.0
  grpc_port: 9443

protocols:
  rest: false
  grpc: true
  quic: false
  mcp: false

# ... rest of config same as above
```

## Build Arguments

### Version Information

Build with version metadata:

```bash
docker build \
  --build-arg VERSION=v1.0.0 \
  --build-arg COMMIT=$(git rev-parse --short HEAD) \
  -t go-keychain/server:v1.0.0 \
  -f Dockerfile.server .
```

The Makefile automatically sets these:

```bash
VERSION=v1.0.0 make docker-build-server
```

## Multi-Architecture Builds

Build for multiple architectures (amd64, arm64):

```bash
# Setup buildx
make docker-buildx-setup

# Build and push multi-arch image
make docker-build-multiarch
```

## Registry Publishing

### Configure Registry

Set your registry in Makefile or environment:

```bash
export DOCKER_REGISTRY=ghcr.io/your-org
make docker-build-all
make docker-push-all
```

### Push Individual Images

```bash
docker push ghcr.io/your-org/go-keychain-server:latest
docker push ghcr.io/your-org/go-keychain-rest:latest
docker push ghcr.io/your-org/go-keychain-grpc:latest
```

## Health Checks

All server images include health checks:

```bash
# Check container health
docker ps
docker inspect keychain-server | grep -A 10 Health
```

### REST Health Endpoint

```bash
curl -k https://localhost:8443/health
```

## Security Considerations

### Non-Root User

All images run as non-root user `appuser` (UID 1000):

```dockerfile
USER appuser
```

### TLS/mTLS

Always use TLS in production:

```yaml
tls:
  enabled: true
  cert_file: /etc/keychain/server.crt
  key_file: /etc/keychain/server.key
  client_auth: require_and_verify
  client_cas:
    - /etc/keychain/client-ca.crt
```

### Secrets Management

Never commit secrets to the repository. Use:
- Docker secrets
- Kubernetes secrets
- Environment variables
- Mounted volumes (read-only)

```bash
docker run -d \
  -v /secure/path/certs:/etc/keychain:ro \
  --secret server_key \
  go-keychain/server:latest
```

## Troubleshooting

### View Logs

```bash
# Docker logs
docker logs keychain-server

# Follow logs
docker logs -f keychain-server

# Docker Compose logs
make compose-prod-logs
```

### Container Shell

Access running container:

```bash
docker exec -it keychain-server sh
```

### Verify Binary

Check server version:

```bash
docker run --rm go-keychain/server:latest --version
```

### Check Health

```bash
# REST health check
curl -k https://localhost:8443/health

# Container health status
docker inspect --format='{{.State.Health.Status}}' keychain-server
```

## Performance Tuning

### Resource Limits

Set resource limits in docker-compose.yml:

```yaml
services:
  keychain-server:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 1G
        reservations:
          cpus: '1'
          memory: 512M
```

### Network Configuration

For production, use custom networks:

```yaml
networks:
  keychain-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16
```

## Makefile Targets

All Docker-related targets are in `Makefile.docker`:

```bash
# Include in main Makefile
include Makefile.docker

# View all Docker targets
make docker-help
```

### Available Targets

| Target | Description |
|--------|-------------|
| docker-build-all | Build all production images |
| docker-build-server | Build unified server image |
| docker-build-rest | Build REST-only image |
| docker-build-grpc | Build gRPC-only image |
| docker-build-quic | Build QUIC-only image |
| docker-build-mcp | Build MCP-only image |
| docker-build-cli | Build CLI image |
| docker-push-all | Push all images to registry |
| docker-run-server | Run unified server locally |
| docker-run-rest | Run REST server locally |
| docker-run-grpc | Run gRPC server locally |
| docker-stop-all | Stop all containers |
| docker-clean-production | Remove all production images |
| compose-prod-up | Start production services |
| compose-prod-down | Stop production services |
| compose-prod-build | Build production images |
| compose-prod-logs | View service logs |

## Examples

### Running Unified Server

```bash
# Build image
make docker-build-server

# Create config
mkdir -p configs
cat > configs/config.yaml <<EOF
server:
  host: 0.0.0.0
protocols:
  rest: true
  grpc: true
default_backend: pkcs8
backends:
  pkcs8:
    enabled: true
    path: /var/lib/keychain/keys
EOF

# Run container
docker run -d --name keychain \
  -p 8443:8443 -p 9443:9443 \
  -v $(PWD)/configs:/etc/keychain:ro \
  -v keychain-data:/var/lib/keychain \
  go-keychain/server:latest

# Check health
curl -k https://localhost:8443/health

# View logs
docker logs -f keychain
```

### Running REST-Only Server

```bash
make docker-build-rest
make docker-run-rest

# Access REST API
curl -k https://localhost:8445/health
```

### Using CLI Tool

```bash
# Build CLI image
make docker-build-cli

# Run CLI command
docker run --rm \
  -v $(PWD)/configs:/etc/keychain:ro \
  go-keychain/cli:latest \
  keys list

# Interactive shell
docker run -it --rm \
  -v $(PWD)/configs:/etc/keychain:ro \
  go-keychain/cli:latest \
  sh
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Docker Build

on:
  push:
    tags:
      - 'v*'

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build images
        run: make docker-build-all

      - name: Push images
        run: make docker-push-all
```

### GitLab CI Example

```yaml
docker-build:
  stage: build
  script:
    - make docker-build-all
    - make docker-push-all
  only:
    - tags
```

## References

- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [Docker Security](https://docs.docker.com/engine/security/)
- [Multi-stage Builds](https://docs.docker.com/build/building/multi-stage/)
- [Docker Compose](https://docs.docker.com/compose/)
