# Docker Quick Start Guide

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: building and running the go-xkms server and CLI images with the Makefile's `docker-build-*` targets.

Get go-xkms running in Docker in 5 minutes.

## Prerequisites

- Docker 20.10+ with buildx support
- Docker Compose 2.0+
- Make

## Quick Start

### 1. Build the Unified Server

```bash
make docker-build-server
```

This tags `go-xkms-server:<VERSION>` and `go-xkms-server:latest`
(`Makefile:3499`). Build through Make rather than with a bare `docker build`:
the target stages the private-module credential and hands it to BuildKit as
the `gomodauth` secret (see [docker.md](docker.md#building-images)).

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

# Network protocols always require datastore.mode "standalone" and
# tls.enabled: the embedded qrdb node is the unified API server, and its
# transports are TLS-only. Omitting cert_file/key_file below is fine for quick
# testing -- a persisted bootstrap self-signed certificate serves until a CA
# composes.
tls:
  enabled: true

auth:
  enabled: false  # Disable auth for quick testing

health:
  enabled: true
  path: /health

datastore:
  engine: pebble
  mode: standalone
  path: /var/lib/xkms/metadata

default_backend: software

backends:
  software:
    enabled: true
    path: /var/lib/xkms/keys
EOF
```

The `datastore` keys are `DatastoreConfig` (`pkg/config/config.go:687`);
`datastore.path` is required in standalone mode for every engine.

### 3. Run the Server

```bash
docker run -d --name xkms \
  -p 8443:8443 \
  -v $(PWD)/configs:/etc/xkms:ro \
  -v xkms-data:/var/lib/xkms \
  go-xkms-server:latest
```

### 4. Test the Server

```bash
# Check health (TLS is mandatory; -k accepts the bootstrap self-signed cert)
curl -k https://localhost:8443/health

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

`docker-compose.production.yml` runs images the Make targets built; it has no
`compose-*` Make targets of its own.

```bash
# Build the images the compose file references
make docker-build-all

# Start
docker compose -f docker-compose.production.yml up -d

# View logs
docker compose -f docker-compose.production.yml logs -f

# Stop
docker compose -f docker-compose.production.yml down
```

## Common Use Cases

### REST API Only

```bash
make docker-build-rest
docker compose -f docker-compose.production.yml up -d xkms-rest

# Published at https://localhost:8445
curl -k https://localhost:8445/health
```

`xkms-rest` sits behind the `rest-only` compose profile; naming the service
starts it. Its `KEYSTORE_CONFIG=/etc/xkms/config-rest.yaml` is not read (see
[Configuration File](#configuration-file)), so it loads
`/etc/xkms/config.yaml`: put a REST-only config there.

### gRPC Only

The gRPC image's default command passes `--port` and `--data-dir`, which
`xkmsd` does not accept (its flags are `cmd/xkmsd/main.go:105-110`). Pass the
config flag yourself:

```bash
make docker-build-grpc
docker run -d --name xkms-grpc \
  -p 9445:9443 \
  -v $(PWD)/configs:/etc/xkms:ro \
  go-xkms-grpc:latest \
  --config /etc/xkms/config.yaml

# Published at localhost:9445
```

### All Protocols (Unified Server)

```bash
make docker-build-server
docker compose -f docker-compose.production.yml up -d xkms-server

# REST:  https://localhost:8443
# gRPC:  localhost:9443
# QUIC:  HTTP/3 on https://localhost:8443 (via Alt-Svc, same port as REST)
# MCP:   localhost:9444
```

### CLI Tool

```bash
make docker-build-cli

# The image's entrypoint is xkmsctl; arguments go straight to it
docker run --rm \
  -v $(PWD)/configs:/etc/xkms:ro \
  go-xkms-cli:latest \
  --help
```

## Troubleshooting

### Port Already in Use

```bash
# Check what's using the port
sudo lsof -i :8443

# Use different port
docker run -d -p 9443:8443 go-xkms-server:latest
```

### Permission Denied

The images run as `appuser` (UID 1000).

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

# Open a shell instead of starting xkmsd (the entrypoint is /app/xkmsd)
docker run -it --rm \
  -v $(PWD)/configs:/etc/xkms:ro \
  --entrypoint sh \
  go-xkms-server:latest
```

### Health Check Fails

The image's own `HEALTHCHECK` probes `curl -fsSk https://localhost:8443/health`
(`Dockerfile.server:134`).

```bash
# Health status as Docker sees it
docker inspect --format='{{.State.Health.Status}}' xkms

# Run the same probe inside the container
docker exec xkms curl -fsSk https://localhost:8443/health
```

## Configuration File

The server images start `xkmsd --config /etc/xkms/config.yaml` (the
Dockerfile's `CMD`). To use another path, pass the flag as the container
command:

```bash
docker run -d \
  -v $(PWD)/configs:/custom/path:ro \
  go-xkms-server:latest \
  --config /custom/path/config.yaml
```

The images also set `KEYSTORE_CONFIG`, but nothing reads it: changing it does
not move the config file.

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

```bash
# Build images
make docker-build-all
make docker-build-server
make docker-build-rest
make docker-build-grpc
make docker-build-quic
make docker-build-mcp
make docker-build-cli
```

There are no `docker-run-*`, `docker-logs`, `docker-stop-all`,
`docker-clean-production`, `compose-prod-*` or `docker-help` targets: run
and stop the images with `docker` or `docker compose` as shown above.
`docker-stop` and `docker-clean` exist but manage the integration-test
container, not these images.

## Next Steps

- Read [docker.md](docker.md) for complete documentation
- Review [configuration examples](../../examples/config/)
- Configure [TLS and mTLS](docker.md#security-considerations)
- Deploy as a service: [deploy/README.md](../../deploy/README.md) covers the systemd and OpenRC units. There is no Kubernetes manifest or guide in the repository yet.

## Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose](https://docs.docker.com/compose/)
- [go-xkms Documentation](../README.md)
