# Docker Infrastructure Summary

Complete Docker infrastructure for SWTPM and SoftHSM testing environments.

## Overview

This infrastructure provides production-ready containerized testing environments for:
- **TPM 2.0 operations** via SWTPM simulator
- **PKCS#11 operations** via SoftHSM library
- **Integration testing** with real services

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                       Docker Infrastructure                    │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │    SWTPM     │  │   SoftHSM    │  │  Integration Tests   │  │
│  │  Container   │  │  Container   │  │     Container        │  │
│  ├──────────────┤  ├──────────────┤  ├──────────────────────┤  │
│  │ Alpine 3.22  │  │ Alpine 3.22  │  │   Go Environment     │  │
│  │              │  │              │  │                      │  │
│  │ Port: 2321   │  │ Library:     │  │ Depends on:          │  │
│  │       2322   │  │ libsofthsm2  │  │  - swtpm (healthy)   │  │
│  │              │  │              │  │  - softhsm (healthy) │  │
│  │ User: tpm    │  │ User: softhsm│  │                      │  │
│  │ UID:  1000   │  │ UID:  1000   │  │ Env:                 │  │
│  └──────┬───────┘  └──────┬───────┘  │  TPM_DEVICE_PATH     │  │
│         │                 │          │  PKCS11_LIBRARY      │  │
│         │                 │          └──────────┬───────────┘  │
│         │                 │                     │              │
│  ┌──────▼─────────────────▼─────────────────────▼───────────┐  │
│  │              Docker Bridge Network                       │  │
│  │              (keychain-test)                             │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                │
│  ┌──────────────┐  ┌──────────────┐                            │
│  │ swtpm-data   │  │ softhsm-     │                            │
│  │ (volume)     │  │ tokens       │                            │
│  │              │  │ (volume)     │                            │
│  └──────────────┘  └──────────────┘                            │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

## Components

### 1. SWTPM Service (`docker/swtpm/`)

**Purpose**: Software TPM 2.0 simulator for testing TPM operations

**Specifications**:
- Base: Alpine 3.22.1
- Build: Multi-stage (builder + runtime)
- Size: ~50MB (runtime)
- Ports: 2321 (commands), 2322 (control)
- User: tpm:tpm (UID/GID 1000)
- Volume: `/var/lib/swtpm/tpmstate`

**Components**:
- libtpms: commit `b4d81572c15b504a4e60b4b46c91d3ec0a92c79e`
- SWTPM: commit `665486b8179fef6eba845e8437acd2da6ae2634e`

**Health Check**:
- Command: `nc -z localhost 2321`
- Interval: 5s
- Timeout: 3s
- Retries: 5

### 2. SoftHSM Service (`docker/softhsm/`)

**Purpose**: Software PKCS#11 implementation for testing HSM operations

**Specifications**:
- Base: Alpine 3.22.1
- Build: Multi-stage (builder + runtime)
- Size: ~30MB (runtime)
- Version: SoftHSM v2.6.1
- User: softhsm:softhsm (UID/GID 1000)
- Volume: `/tokens`

**Configuration**:
- Location: `/home/softhsm/softhsm2.conf`
- Token directory: `/tokens`
- Backend: file
- Log level: INFO

**Health Check**:
- Command: `test -f /usr/local/lib/softhsm/libsofthsm2.so`
- Interval: 10s
- Timeout: 3s
- Retries: 3

### 3. Integration Test Service

**Purpose**: Run integration tests against SWTPM and SoftHSM services

**Specifications**:
- Base: Custom Go environment
- Depends on: SWTPM (healthy), SoftHSM (healthy)
- Volumes: Source code, tokens, TPM state
- Environment: Full TPM and PKCS#11 configuration

**Environment Variables**:
```bash
# TPM Configuration
TPM_DEVICE_PATH=tcp://swtpm:2321
TPM_USE_SIMULATOR=true
TPM_SIM_HOST=swtpm
TPM_SIM_PORT=2321
TPM2TOOLS_TCTI=mssim:host=swtpm,port=2321

# PKCS#11 Configuration
PKCS11_LIBRARY=/usr/local/lib/softhsm/libsofthsm2.so
PKCS11_TOKEN=test-token
SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf
```

## Files

```
test/docker/
├── swtpm/
│   └── Dockerfile              # SWTPM multi-stage build
├── softhsm/
│   ├── Dockerfile              # SoftHSM multi-stage build
│   └── softhsm2.conf           # SoftHSM configuration
├── docker-compose.test.yml     # Test-specific configuration
├── test-infrastructure.sh      # Infrastructure validation script
├── README.md                   # Full documentation
├── QUICKSTART.md               # Quick start guide
└── DOCKER-INFRASTRUCTURE.md    # This file
```

## Usage

### Quick Commands

```bash
# Build all images
make compose-build

# Start services
make compose-up

# Run integration tests
make compose-integration

# Development shell
make compose-dev

# Stop services
make compose-down

# Clean everything
make compose-clean
```

### Manual Docker Compose

```bash
# Build specific service
docker compose build swtpm
docker compose build softhsm

# Start services
docker compose up -d

# View logs
docker compose logs -f swtpm
docker compose logs -f softhsm

# Check status
docker compose ps

# Run tests with test config
docker compose -f docker-compose.yml -f test/docker/docker-compose.test.yml up --abort-on-container-exit

# Stop and clean
docker compose down -v
```

## Performance

### Build Times (First Build)

- SWTPM: ~3-5 minutes
- SoftHSM: ~2-3 minutes
- Integration test image: ~2-3 minutes
- **Total**: ~7-11 minutes

### Build Times (Cached)

- SWTPM: ~10-20 seconds
- SoftHSM: ~10-15 seconds
- Integration test image: ~5-10 seconds
- **Total**: ~25-45 seconds

### Image Sizes

- SWTPM runtime: ~50MB (vs ~200MB without multi-stage)
- SoftHSM runtime: ~30MB (vs ~150MB without multi-stage)
- Integration test: ~200MB
- **Total**: ~280MB

### Runtime Performance

- SWTPM startup: ~1-2 seconds
- SoftHSM startup: <1 second
- Health checks: 5-10 seconds
- Integration tests: depends on test suite

## Security

### Non-Root Users

All services run as non-root:
- SWTPM: `tpm:tpm` (UID 1000)
- SoftHSM: `softhsm:softhsm` (UID 1000)

### Minimal Attack Surface

- Alpine Linux base (minimal)
- Multi-stage builds (no build tools in runtime)
- Only necessary runtime dependencies
- No unnecessary tools or shells

### Network Isolation

- Dedicated bridge network
- No host network access
- Only necessary ports exposed
- Container-to-container communication only

## Testing

### Validation Script

```bash
# Run infrastructure tests
./test/docker/test-infrastructure.sh
```

Tests include:
- Docker installation
- Image builds
- Service startup
- Health checks
- Port accessibility
- Volume creation
- Network configuration
- Log output

### Manual Testing

```bash
# Test SWTPM connectivity
nc -zv localhost 2321

# Test SoftHSM library
docker compose exec softhsm ls -la /usr/local/lib/softhsm/

# Test from integration container
docker compose run --rm dev sh -c "nc -zv swtpm 2321"
```

## CI/CD Integration

### Makefile Targets

All Docker operations available via Makefile:

```bash
make compose-build              # Build all images
make compose-build-swtpm        # Build SWTPM only
make compose-build-softhsm      # Build SoftHSM only
make compose-up                 # Start services
make compose-down               # Stop services
make compose-test               # Run unit tests
make compose-integration        # Run integration tests
make compose-test-integration   # Run with test config
make compose-dev                # Development shell
make compose-logs               # View all logs
make compose-logs-swtpm         # View SWTPM logs
make compose-logs-softhsm       # View SoftHSM logs
make compose-ps                 # Show service status
make compose-clean              # Clean all resources
```

### GitHub Actions Example

```yaml
name: Integration Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build Docker images
        run: make compose-build

      - name: Run integration tests
        run: make compose-test-integration

      - name: Upload logs on failure
        if: failure()
        uses: actions/upload-artifact@v3
        with:
          name: docker-logs
          path: |
            /tmp/*.log
```

## Troubleshooting

### Common Issues

1. **Port conflicts**: Ports 2321/2322 already in use
   - Solution: Change ports in `docker-compose.yml`

2. **Build failures**: Network issues during git clone
   - Solution: Check internet connection, try `--no-cache`

3. **Health checks failing**: Services not ready
   - Solution: Wait longer, check logs

4. **Volume permission issues**: Cannot write to volumes
   - Solution: Services run as UID 1000, ensure proper permissions

### Debug Commands

```bash
# Check Docker system
docker system info
docker system df

# Inspect containers
docker inspect go-keychain-swtpm
docker inspect go-keychain-softhsm

# View detailed logs
docker compose logs --tail=100 swtpm
docker compose logs --tail=100 softhsm

# Execute commands in containers
docker compose exec swtpm /bin/sh
docker compose exec softhsm /bin/sh

# Check volumes
docker volume inspect go-keychain_swtpm-data
docker volume inspect go-keychain_softhsm-tokens
```

## Best Practices

1. **Use health checks**: Always wait for services to be healthy
2. **Use named volumes**: Persist data across restarts
3. **Use multi-stage builds**: Keep images minimal
4. **Run as non-root**: Follow least privilege principle
5. **Clean up regularly**: Remove unused volumes and images
6. **Version control**: Pin specific commits/versions
7. **Test infrastructure**: Run validation script regularly

## Maintenance

### Updates

To update to newer versions:

1. Edit `test/docker/swtpm/Dockerfile` - update commit hash
2. Edit `test/docker/softhsm/Dockerfile` - update version tag
3. Rebuild: `make compose-build --no-cache`
4. Test: `./test/docker/test-infrastructure.sh`
5. Commit changes

### Monitoring

```bash
# Monitor resource usage
docker stats go-keychain-swtpm go-keychain-softhsm

# View service health
watch -n 1 'docker compose ps'

# Tail logs in real-time
docker compose logs -f --tail=100
```

## References

- [SWTPM Documentation](https://github.com/stefanberger/swtpm)
- [libtpms Documentation](https://github.com/stefanberger/libtpms)
- [SoftHSM Documentation](https://github.com/opendnssec/SoftHSMv2)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Alpine Linux Documentation](https://alpinelinux.org/about/)

## Support

For issues:
1. Check `test/docker/QUICKSTART.md` for common problems
2. Run `./test/docker/test-infrastructure.sh` for diagnostics
3. Review logs: `make compose-logs`
4. Create GitHub issue with full logs and environment details
