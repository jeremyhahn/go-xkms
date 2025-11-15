# Docker Quick Start Guide

Get started with SWTPM and SoftHSM testing in minutes.

## Prerequisites

- Docker Engine 20.10+
- Docker Compose v2+
- 2GB free disk space
- 4GB RAM recommended

## Quick Start

### 1. Build All Images

```bash
make compose-build
```

This builds:
- SWTPM TPM 2.0 simulator (~50MB)
- SoftHSM PKCS#11 library (~30MB)
- Integration test container (~200MB)

**Build time**: 5-10 minutes (first time)

### 2. Start Services

```bash
make compose-up
```

This starts:
- SWTPM on ports 2321 (commands) and 2322 (control)
- SoftHSM with persistent token storage
- Network bridge for inter-container communication

### 3. Run Tests

```bash
# Unit tests (fast, no Docker services required)
make test

# Integration tests (requires SWTPM and SoftHSM)
make compose-integration

# Full integration tests with test-specific config
make compose-test-integration
```

### 4. Development Shell

```bash
make compose-dev
```

Inside the container:

```bash
# Test TPM connection
nc -zv swtpm 2321

# List SoftHSM library
ls -la /usr/local/lib/softhsm/

# Run specific test
go test -v -run TestTPMKeyCreation ./test/integration/...

# Exit
exit
```

### 5. Stop Services

```bash
make compose-down
```

## Common Tasks

### View Service Logs

```bash
# All services
make compose-logs

# SWTPM only
make compose-logs-swtpm

# SoftHSM only
make compose-logs-softhsm
```

### Check Service Status

```bash
make compose-ps
```

Expected output:

```
NAME                    IMAGE                         STATUS          PORTS
go-keychain-swtpm       go-keychain-swtpm:latest     Up (healthy)    0.0.0.0:2321-2322->2321-2322/tcp
go-keychain-softhsm     go-keychain-softhsm:latest   Up (healthy)
```

### Rebuild Specific Service

```bash
# Rebuild SWTPM
make compose-build-swtpm

# Rebuild SoftHSM
make compose-build-softhsm
```

### Clean Everything

```bash
# Stop services and remove volumes
make compose-down

# Remove all Docker resources (images, containers, volumes)
make compose-clean
```

## Troubleshooting

### Port Already in Use

If port 2321 or 2322 is already in use:

```bash
# Find process using port
sudo lsof -i :2321

# Stop existing service
sudo systemctl stop swtpm  # or kill process
```

Or modify `docker-compose.yml` to use different ports:

```yaml
ports:
  - "12321:2321"  # Use port 12321 instead
  - "12322:2322"
```

### SWTPM Not Responding

```bash
# Check SWTPM health
docker inspect go-keychain-swtpm --format='{{.State.Health.Status}}'

# Restart SWTPM
docker compose restart swtpm

# View detailed logs
docker compose logs --tail=100 swtpm
```

### SoftHSM Library Not Found

```bash
# Verify library exists
docker compose exec softhsm ls -la /usr/local/lib/softhsm/

# Check configuration
docker compose exec softhsm cat /home/softhsm/softhsm2.conf

# Rebuild SoftHSM
make compose-build-softhsm
docker compose up -d softhsm
```

### Integration Tests Failing

```bash
# Check all services are healthy
make compose-ps

# Restart services
make compose-down && make compose-up

# Wait for health checks
sleep 10

# Run tests again
make compose-integration
```

### Clean Start

If everything is broken, start fresh:

```bash
# Nuclear option: remove everything
make compose-clean

# Rebuild from scratch
make compose-build

# Start services
make compose-up

# Run tests
make compose-integration
```

## Performance Tips

### Speed Up Builds

```bash
# Use BuildKit for faster builds
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

# Rebuild with cache
make compose-build
```

### Reduce Build Time

- Images use multi-stage builds (already optimized)
- Go modules are cached in named volumes
- Only rebuild when Dockerfiles change

### Speed Up Tests

```bash
# Run specific test package
docker compose run --rm integration-test go test -v ./test/integration/tpm/...

# Run single test
docker compose run --rm integration-test go test -v -run TestTPMKeyCreation ./test/integration/...

# Skip slow tests
docker compose run --rm integration-test go test -v -short ./test/integration/...
```

## Next Steps

1. Read full documentation: `/home/jhahn/sources/go-keychain/test/docker/README.md`
2. Review test examples: `/home/jhahn/sources/go-keychain/test/integration/`
3. Explore Makefile targets: `make help`
4. Check project README: `/home/jhahn/sources/go-keychain/README.md`

## Useful Commands

```bash
# Show all make targets
make help

# View service resource usage
docker stats go-keychain-swtpm go-keychain-softhsm

# Execute command in running service
docker compose exec swtpm nc -zv localhost 2321
docker compose exec softhsm softhsm2-util --show-slots

# Copy files from service
docker compose cp softhsm:/tokens ./tokens-backup

# View network details
docker network inspect go-keychain_keychain-test

# Prune unused Docker resources
docker system prune -a --volumes
```

## Support

- Issues: Create GitHub issue with logs and steps to reproduce
- Logs: Always include output from `make compose-logs`
- Version: Include Docker/Compose versions (`docker --version`, `docker compose version`)
