# Docker Infrastructure

Complete Docker infrastructure for SWTPM and SoftHSM testing environments.

## Overview

This directory contains Docker configurations for:
- **SWTPM**: Software TPM 2.0 simulator for testing TPM-based key operations
- **SoftHSM**: Software PKCS#11 implementation for testing HSM-based key operations

## Architecture

### SWTPM Service
- **Base Image**: Alpine 3.22.1
- **Build Type**: Multi-stage (builder + runtime)
- **Ports**: 2321 (TPM commands), 2322 (TPM control)
- **Components**:
  - libtpms (commit: b4d81572c15b504a4e60b4b46c91d3ec0a92c79e)
  - SWTPM (commit: 665486b8179fef6eba845e8437acd2da6ae2634e)
- **Security**: Runs as non-root user (tpm:tpm, UID/GID 1000)

### SoftHSM Service
- **Base Image**: Alpine 3.22.1
- **Build Type**: Multi-stage (builder + runtime)
- **Version**: SoftHSM v2.6.1
- **Token Storage**: /tokens (persistent volume)
- **Security**: Runs as non-root user (softhsm:softhsm, UID/GID 1000)

## Usage

### Build All Services

```bash
docker compose build
```

### Build Individual Services

```bash
# Build SWTPM only
docker compose build swtpm

# Build SoftHSM only
docker compose build softhsm
```

### Start Services

```bash
# Start all services
docker compose up -d

# Start specific services
docker compose up -d swtpm softhsm

# View logs
docker compose logs -f swtpm
docker compose logs -f softhsm
```

### Run Integration Tests

```bash
# Using main docker-compose.yml
docker compose run --rm integration-test

# Using test configuration
docker compose -f docker-compose.yml -f test/docker/docker-compose.test.yml up --abort-on-container-exit

# Run specific test
docker compose run --rm integration-test go test -v -run TestTPM ./test/integration/...
```

### Development Shell

```bash
# Start interactive development shell with all services
docker compose run --rm dev

# Inside the container, you have access to:
# - SWTPM at tcp://swtpm:2321
# - SoftHSM library at /usr/local/lib/softhsm/libsofthsm2.so
```

### Stop Services

```bash
# Stop all services
docker compose down

# Stop and remove volumes
docker compose down -v
```

## Service Configuration

### SWTPM Environment Variables

- `TPM_DEVICE_PATH`: tcp://swtpm:2321
- `TPM_USE_SIMULATOR`: true
- `TPM_SIM_HOST`: swtpm
- `TPM_SIM_PORT`: 2321
- `TPM2TOOLS_TCTI`: mssim:host=swtpm,port=2321

### SoftHSM Environment Variables

- `SOFTHSM2_CONF`: /home/softhsm/softhsm2.conf
- `PKCS11_LIBRARY`: /usr/local/lib/softhsm/libsofthsm2.so
- `PKCS11_TOKEN`: test-token

## Volume Management

### Named Volumes

- `swtpm-data`: Persistent TPM state
- `softhsm-tokens`: Persistent PKCS#11 tokens
- `go-build-cache`: Go build cache (test configuration only)
- `go-mod-cache`: Go module cache (test configuration only)

### Inspect Volumes

```bash
# List volumes
docker volume ls

# Inspect volume
docker volume inspect go-keychain_swtpm-data
docker volume inspect go-keychain_softhsm-tokens

# Remove volumes
docker volume rm go-keychain_swtpm-data go-keychain_softhsm-tokens
```

## Health Checks

### SWTPM Health Check
- **Command**: `nc -z localhost 2321`
- **Interval**: 5s
- **Timeout**: 3s
- **Retries**: 5

### SoftHSM Health Check
- **Command**: `test -f /usr/local/lib/softhsm/libsofthsm2.so`
- **Interval**: 10s
- **Timeout**: 3s
- **Retries**: 3

### Check Service Health

```bash
# Check all services
docker compose ps

# Check specific service
docker inspect go-keychain-swtpm --format='{{.State.Health.Status}}'
docker inspect go-keychain-softhsm --format='{{.State.Health.Status}}'
```

## Troubleshooting

### SWTPM Connection Issues

```bash
# Test SWTPM connectivity
docker compose exec swtpm nc -zv localhost 2321

# View SWTPM logs
docker compose logs swtpm

# Test from host
nc -zv localhost 2321
```

### SoftHSM Library Issues

```bash
# Verify library exists
docker compose exec softhsm ls -la /usr/local/lib/softhsm/

# Check configuration
docker compose exec softhsm cat /home/softhsm/softhsm2.conf

# List tokens
docker compose exec softhsm softhsm2-util --show-slots
```

### Service Not Starting

```bash
# Check container logs
docker compose logs --tail=50 swtpm
docker compose logs --tail=50 softhsm

# Check container status
docker compose ps -a

# Rebuild from scratch
docker compose down -v
docker compose build --no-cache
docker compose up -d
```

### Port Conflicts

If ports 2321 or 2322 are already in use:

```bash
# Check what's using the port
sudo netstat -tlnp | grep 2321
sudo lsof -i :2321

# Modify docker-compose.yml to use different host ports
ports:
  - "12321:2321"  # Use port 12321 on host
  - "12322:2322"  # Use port 12322 on host
```

## Performance Optimization

### Image Size Optimization
- Multi-stage builds reduce image size by 70-80%
- Only runtime dependencies included in final image
- SWTPM image: ~50MB (vs ~200MB without multi-stage)
- SoftHSM image: ~30MB (vs ~150MB without multi-stage)

### Build Cache Optimization
- Layer ordering optimizes cache hits
- Dependencies installed before source code
- Test configuration includes Go build/module caches

### Network Performance
- Bridge network for container-to-container communication
- No unnecessary port exposures
- Health checks ensure services are ready before tests run

## Security Considerations

### Non-Root Users
All services run as non-root users:
- SWTPM: tpm (UID 1000)
- SoftHSM: softhsm (UID 1000)

### Minimal Attack Surface
- Minimal Alpine base images
- Only necessary runtime dependencies
- No unnecessary tools or shells in runtime images

### Network Isolation
- Services communicate via dedicated bridge network
- No direct host access except exposed ports
- Integration tests isolated from host system

## CI/CD Integration

### GitHub Actions Example

```yaml
- name: Build Docker images
  run: docker compose build

- name: Run integration tests
  run: |
    docker compose -f docker-compose.yml -f test/docker/docker-compose.test.yml up \
      --abort-on-container-exit \
      --exit-code-from integration-test
```

### GitLab CI Example

```yaml
test:
  image: test/docker/compose:latest
  services:
    - docker:dind
  script:
    - docker compose build
    - docker compose -f docker-compose.yml -f test/docker/docker-compose.test.yml up --abort-on-container-exit
```

## Best Practices

1. **Always use health checks**: Ensure services are ready before running tests
2. **Use named volumes**: Persist data across container restarts
3. **Layer caching**: Order Dockerfile instructions for optimal cache usage
4. **Multi-stage builds**: Keep runtime images minimal
5. **Non-root users**: Run services with least privilege
6. **Clean up**: Remove volumes when not needed to save disk space

## References

- [SWTPM GitHub](https://github.com/stefanberger/swtpm)
- [libtpms GitHub](https://github.com/stefanberger/libtpms)
- [SoftHSM GitHub](https://github.com/opendnssec/SoftHSMv2)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
