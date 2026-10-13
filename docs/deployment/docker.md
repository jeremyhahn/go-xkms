# Docker Deployment Guide

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: the six Dockerfiles, `docker-compose.production.yml` and the development compose environment.

This guide covers building and deploying go-xkms using Docker containers.

## Available Images

go-xkms provides six production-ready Docker images:

1. **Dockerfile.server** - Unified server (all protocols: REST, gRPC, QUIC, MCP)
2. **Dockerfile.rest** - REST-only server
3. **Dockerfile.grpc** - gRPC-only server
4. **Dockerfile.quic** - Builds the same `xkmsd` binary as the other images;
   with the standalone QUIC server package removed, QUIC now rides the REST
   listener as HTTP/3, so this profile no longer isolates a distinct
   listener the way REST-only/gRPC-only/MCP-only do
5. **Dockerfile.mcp** - MCP-only server
6. **Dockerfile.cli** - CLI tool

All images follow security best practices:
- Multi-stage builds for minimal image size
- Non-root user (appuser, UID 1000)
- `debian:bookworm-slim` runtime base, matching the builder's libc. The
  binaries are built with `CGO_ENABLED=1` (required for PKCS#11) under
  `golang:1.27.2-bookworm`, so they are glibc-linked and cannot execute on a
  musl base such as Alpine. Each runtime stage runs `apt-get upgrade` so a
  rebuild picks up security advisories rather than freezing the base's
  packages.
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

There are no `docker-run-*` targets. Run an image with `docker run`, or start
its service from `docker-compose.production.yml` (see below):

```bash
# Unified server (all protocols)
docker run -d --name xkms-server \
  -p 8443:8443 -p 9443:9443 -p 9444:9444 \
  -v $(PWD)/configs:/etc/xkms:ro \
  -v xkms-data:/var/lib/xkms \
  go-xkms-server:latest
```

Each image is tagged `go-xkms-<profile>:<VERSION>` and
`go-xkms-<profile>:latest` (`Makefile:3497-3579`).

The gRPC image's default command passes `--port` and `--data-dir`, which
`xkmsd` does not accept (`cmd/xkmsd/main.go:105-110`); run it with
`--config /etc/xkms/config.yaml` as the container command.

## Docker Compose

### Development Environment

The default `docker-compose.yml` provides a development environment with:
- SWTPM (TPM 2.0 simulator)
- SoftHSM (PKCS#11 simulator)
- Integration test runner (`integration-test`)
- Unit test runner (`unit-test`)
- Development shell (`dev`)

```bash
# Start development environment
make compose-up

# Run unit tests
make compose-test

# Run integration tests
make compose-integration

# Start interactive shell
make compose-dev

# Stop all services
make compose-down
```

### Production Environment

`docker-compose.production.yml` runs the images built above; it does not
build them itself (see "Building Images" below for why):

```bash
# Build the images the compose file references
make docker-build-all

# Start production services
docker compose -f docker-compose.production.yml up -d

# The protocol-specific services sit behind the rest-only, grpc-only,
# quic-only and mcp-only profiles; start one by naming it
docker compose -f docker-compose.production.yml up -d xkms-rest

# View logs
docker compose -f docker-compose.production.yml logs -f

# Show service status
docker compose -f docker-compose.production.yml ps

# Stop services
docker compose -f docker-compose.production.yml down
```

### Building Images

Production images embed private `github.com/jeremyhahn/*` Go modules, fetched
during `go mod download` with the in-house module credential. Each
`docker-build-*` Make target stages that credential to a gitignored file via
`stage-gomodauth` and hands it to BuildKit as a build secret
(`--secret id=gomodauth`); the Dockerfiles never see it any other way.

Build the images with the Make targets, not `docker compose build`:

```bash
make docker-build-server   # unified server
make docker-build-rest     # REST-only
make docker-build-grpc     # gRPC-only
make docker-build-quic     # QUIC-only
make docker-build-mcp      # MCP-only
make docker-build-all      # all of the above
```

`docker compose -f docker-compose.production.yml build` (and an accidental
`docker compose up` before the images exist) is intentionally unsupported:
compose has no equivalent secret-injection step, so building through it would
fail on the first private module with an opaque authentication error instead
of an actionable one. The `build:` block in `docker-compose.production.yml`
instead points at `Dockerfile.compose-build-unsupported`, a stub that fails
immediately with a message naming the correct `docker-build-*` target. The
`image:` tags in that compose file match what the Make targets produce
(`go-xkms-server:${VERSION:-latest}`, etc.), so `docker compose up` uses the
Make-built image once it exists.

## Port Mappings

### Default Ports

| Service | Protocol | Port | Description |
|---------|----------|------|-------------|
| REST    | HTTPS    | 8443 | REST API endpoint (also serves QUIC/HTTP3 via `Alt-Svc`) |
| gRPC    | TLS      | 9443 | gRPC endpoint |
| MCP     | TLS      | 9444 | MCP endpoint (Streamable HTTP, served by the embedded qrdb node) |

QUIC has no port of its own: it is HTTP/3 served on the REST port above,
advertised via the `Alt-Svc` response header. There is no separate QUIC
server package or container profile.

### Docker Compose Ports

When running multiple services, ports are mapped to avoid conflicts:

| Service | External Port | Internal Port |
|---------|--------------|---------------|
| Unified Server (REST + QUIC/HTTP3) | 8443 | 8443 |
| Unified Server (gRPC) | 9443 | 9443 |
| Unified Server (MCP)  | 9444 | 9444 |
| REST-only | 8445 | 8443 |
| gRPC-only | 9445 | 9443 |
| MCP-only  | 9446 | 9444 |

## Configuration

### Volume Mounts

The server images start `xkmsd --config /etc/xkms/config.yaml` (each
Dockerfile's `CMD`; the gRPC image is the exception noted above):

```bash
docker run -d \
  -v $(PWD)/configs:/etc/xkms:ro \
  -p 8443:8443 \
  go-xkms-server:latest
```

### Config Path

To read the config from elsewhere, pass `--config <path>` as the container
command. Every image, and every service in `docker-compose.production.yml`,
also sets `KEYSTORE_CONFIG`, but no code reads it: the per-protocol compose
services' `config-rest.yaml`, `config-grpc.yaml`, `config-quic.yaml` and
`config-mcp.yaml` values have no effect, and those services load
`/etc/xkms/config.yaml`.

### Data Persistence

Mount volumes for persistent data:

```bash
docker run -d \
  -v xkms-data:/var/lib/xkms \
  -v $(PWD)/configs:/etc/xkms:ro \
  go-xkms-server:latest
```

## Configuration Files

Create protocol-specific configuration files in `configs/`:

### configs/config.yaml (Unified Server)

```yaml
server:
  host: 0.0.0.0
  rest_port: 8443
  grpc_port: 9443
  quic_port: 8444  # vestigial -- QUIC is served as HTTP/3 on rest_port
  mcp_port: 9444

protocols:
  rest: true
  grpc: true
  quic: true
  mcp: true

tls:
  enabled: true
  cert_file: /etc/xkms/server.crt
  key_file: /etc/xkms/server.key

# Network protocols require the embedded qrdb node: datastore.mode
# "standalone", with datastore.path set.
datastore:
  engine: pebble
  mode: standalone
  path: /var/lib/xkms/metadata

default_backend: software

backends:
  software:
    enabled: true
    path: /var/lib/xkms/keys
```

The complete versions of these files are in `examples/config/`
(`config-server.yaml`, `config-rest.yaml`, `config-grpc.yaml`, ...). Whatever
the file is called on the host, the container reads it as
`/etc/xkms/config.yaml`.

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

The `docker-build-*` targets pass `VERSION`, `GIT_COMMIT` and `BUILD_DATE`
as build arguments. Only `Dockerfile.cli` declares any (`ARG VERSION`,
`COMMIT`, `DATE`), and of those only `VERSION` matches what Make passes. The
server Dockerfiles declare no `ARG`, so their binaries report version `dev`.

## Multi-Architecture Builds and Registry Publishing

There are no Make targets for multi-architecture builds or for pushing
images. The `docker-build-*` targets build for the local architecture and
load the result into the local Docker image store; tag and push with
`docker` yourself:

```bash
docker tag go-xkms-server:latest ghcr.io/your-org/go-xkms-server:latest
docker push ghcr.io/your-org/go-xkms-server:latest
```

Published release images are built by `.github/workflows/release.yml`; see
[release engineering](../release-engineering/user.md).

## Health Checks

Every server image declares a `HEALTHCHECK`. The unified and REST images
probe `curl -fsSk https://localhost:8443/health` (`Dockerfile.server:134`,
`Dockerfile.rest:125`); the gRPC, QUIC and MCP images look for their port in
`netstat` output (`Dockerfile.grpc:121`, `Dockerfile.quic:121`,
`Dockerfile.mcp:121`).

```bash
# Check container health
docker ps
docker inspect xkms-server | grep -A 10 Health
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
  cert_file: /etc/xkms/server.crt
  key_file: /etc/xkms/server.key
  client_auth: require_and_verify
  client_cas:
    - /etc/xkms/client-ca.crt
```

### Secrets Management

Never commit secrets to the repository. Use:
- Docker secrets
- Kubernetes secrets
- Environment variables
- Mounted volumes (read-only)

```bash
docker run -d \
  -v /secure/path/certs:/etc/xkms/certs:ro \
  -v $(PWD)/configs:/etc/xkms:ro \
  go-xkms-server:latest
```

`docker run` has no `--secret` flag; Docker secrets are a Swarm and Compose
feature, mounted under `/run/secrets/`.

## Troubleshooting

### View Logs

```bash
# Docker logs
docker logs xkms-server

# Follow logs
docker logs -f xkms-server

# Docker Compose logs
docker compose -f docker-compose.production.yml logs -f
```

### Container Shell

Access running container:

```bash
docker exec -it xkms-server sh
```

### Verify Binary

Check server version:

```bash
docker run --rm go-xkms-server:latest --version   # reports "dev"; see Build Arguments
```

### Check Health

```bash
# REST health check
curl -k https://localhost:8443/health

# Container health status
docker inspect --format='{{.State.Health.Status}}' xkms-server
```

## Performance Tuning

### Resource Limits

Set resource limits in `docker-compose.production.yml` (it sets none today):

```yaml
services:
  xkms-server:
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
  xkms-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16
```

## Makefile Targets

The Docker targets live in the top-level `Makefile`; there is no separate
`Makefile.docker`. `make help` lists every target.

### Available Targets

| Target | Description |
|--------|-------------|
| docker-build-all | Build all six images below |
| docker-build-server | Build the unified server image (`go-xkms-server`) |
| docker-build-rest | Build the REST-only image (`go-xkms-rest`) |
| docker-build-grpc | Build the gRPC-only image (`go-xkms-grpc`) |
| docker-build-quic | Build the QUIC image (`go-xkms-quic`) |
| docker-build-mcp | Build the MCP-only image (`go-xkms-mcp`) |
| docker-build-cli | Build the CLI image (`go-xkms-cli`) |
| docker-build, docker-run, docker-test, docker-stop, docker-clean | The integration-test image and container (`Dockerfile`), not the deployment images |
| compose-up, compose-down, compose-test, compose-integration, compose-dev | The development `docker-compose.yml` environment |

`docker-compose.production.yml` has no corresponding `compose-*` Make
targets; drive it directly with `docker compose -f
docker-compose.production.yml <up|down|logs|ps>` after building images with
the targets above (see "Building Images").

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
tls:
  enabled: true
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

# Run container
docker run -d --name xkms \
  -p 8443:8443 -p 9443:9443 \
  -v $(PWD)/configs:/etc/xkms:ro \
  -v xkms-data:/var/lib/xkms \
  go-xkms-server:latest

# Check health
curl -k https://localhost:8443/health

# View logs
docker logs -f xkms
```

### Running REST-Only Server

```bash
make docker-build-rest
docker compose -f docker-compose.production.yml up -d xkms-rest

# Access REST API
curl -k https://localhost:8445/health
```

### Using CLI Tool

The CLI image's entrypoint is `xkmsctl` (installed as
`/usr/local/bin/xkms-cli`), so arguments go straight to it:

```bash
# Build CLI image
make docker-build-cli

# Run CLI command
docker run --rm \
  -v $(PWD)/configs:/etc/xkms:ro \
  go-xkms-cli:latest \
  key list --help

# Interactive shell
docker run -it --rm \
  -v $(PWD)/configs:/etc/xkms:ro \
  --entrypoint sh \
  go-xkms-cli:latest
```

## References

- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [Docker Security](https://docs.docker.com/engine/security/)
- [Multi-stage Builds](https://docs.docker.com/build/building/multi-stage/)
- [Docker Compose](https://docs.docker.com/compose/)
