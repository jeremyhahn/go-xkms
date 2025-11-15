# Docker Integration Testing Guide

This document describes how to use Docker for integration testing of go-keychain across all backends.

## Overview

Each backend has its own Docker-based integration test environment in `test/integration/{backend}/`. This provides:
- Consistent, isolated test environments
- No host system modifications required
- Reliable, repeatable test execution
- All dependencies included (SoftHSM, SWTPM, LocalStack, Vault, etc.)

## Test Organization

Each backend directory contains:

```
test/integration/{backend}/
├── docker-compose.yml    # Service definitions
├── Dockerfile            # Test container image
└── *_integration_test.go # Integration tests
```

Supported backends:
- **pkcs8**: Software key storage
- **pkcs11**: SoftHSM2 hardware simulation
- **tpm2**: SWTPM simulator
- **awskms**: LocalStack AWS emulation
- **gcpkms**: Mock GCP client
- **azurekv**: Mock Azure client
- **vault**: HashiCorp Vault server

## Quick Start

### Run All Integration Tests

```bash
# Run all backend integration tests
make integration-test
```

This sequentially runs integration tests for all backends:
1. PKCS#8
2. PKCS#11/SoftHSM
3. TPM2/SWTPM
4. AWS KMS/LocalStack
5. GCP KMS (mock)
6. Azure Key Vault (mock)
7. HashiCorp Vault

### Run Individual Backend Tests

```bash
# PKCS#8
make integration-test-pkcs8

# PKCS#11/SoftHSM
make integration-test-pkcs11

# TPM2/SWTPM
make integration-test-tpm2

# AWS KMS/LocalStack
make integration-test-awskms

# GCP KMS (mock)
make integration-test-gcpkms

# Azure Key Vault (mock)
make integration-test-azurekv

# HashiCorp Vault
make integration-test-vault
```

## Backend-Specific Details

### PKCS#8 (Software)

No special dependencies. Tests pure Go key operations.

```bash
cd test/integration/pkcs8
docker-compose run --rm test
```

### PKCS#11 (SoftHSM)

Uses SoftHSM2 to simulate HSM hardware.

**Configuration:**
- Token Label: test-token
- Slot: 0
- PIN: 1234

```bash
cd test/integration/pkcs11
docker-compose run --rm test
```

### TPM2 (SWTPM)

Uses SWTPM software TPM simulator.

**Configuration:**
- TPM Version: 2.0
- Socket: /var/lib/swtpm/swtpm-sock

```bash
cd test/integration/tpm2
docker-compose up -d tpm-simulator
docker-compose run --rm test
docker-compose down -v
```

### AWS KMS (LocalStack)

Uses LocalStack to emulate AWS KMS.

**Configuration:**
- Endpoint: http://localstack:4566
- Region: us-east-1
- Credentials: test/test

```bash
cd test/integration/awskms
docker-compose up -d localstack
docker-compose run --rm test
docker-compose down -v
```

### GCP KMS (Mock)

Uses mock client for GCP KMS operations.

```bash
cd test/integration/gcpkms
docker-compose run --rm test
```

### Azure Key Vault (Mock)

Uses mock client for Azure Key Vault operations.

```bash
cd test/integration/azurekv
docker-compose run --rm test
```

### HashiCorp Vault

Uses real Vault server in dev mode.

**Configuration:**
- Endpoint: http://vault:8200
- Token: root

```bash
cd test/integration/vault
docker-compose up -d vault
docker-compose run --rm test
docker-compose down -v
```

## Docker Compose Files

Each backend has a `docker-compose.yml` that defines:

1. **Service dependencies** (e.g., LocalStack, Vault server)
2. **Test container** with proper environment
3. **Volume mounts** for source code
4. **Network configuration** for service communication

Example structure (AWS KMS):

```yaml
version: '3.8'
services:
  localstack:
    image: localstack/localstack:latest
    environment:
      - SERVICES=kms
      - DEBUG=1
    ports:
      - "4566:4566"

  test:
    build: .
    depends_on:
      - localstack
    environment:
      - AWS_ENDPOINT=http://localstack:4566
      - AWS_REGION=us-east-1
    volumes:
      - ../../../:/workspace
    working_dir: /workspace
    command: go test -v -tags integration ./test/integration/awskms/...
```

## Manual Testing

For interactive debugging:

```bash
# Navigate to backend directory
cd test/integration/pkcs11

# Start services
docker-compose up -d

# Run tests interactively
docker-compose run --rm test /bin/bash

# Inside container:
go test -v ./test/integration/pkcs11/...

# Cleanup
docker-compose down -v
```

## Test Execution Flow

When you run `make integration-test-{backend}`:

1. **Cleanup**: `docker-compose down -v` removes old containers
2. **Start Services**: Dependent services start (if needed)
3. **Build Test Image**: Docker builds test container
4. **Run Tests**: Test container executes integration tests
5. **Cleanup**: `docker-compose down -v` removes containers and volumes

This ensures:
- Clean slate for each test run
- No state pollution between runs
- Isolated test environments

## Troubleshooting

### Tests Failing

```bash
# Check Docker is running
docker ps

# Clean up old containers
cd test/integration/{backend}
docker-compose down -v

# Rebuild images
docker-compose build --no-cache

# Check logs
docker-compose logs
```

### Service Not Starting

```bash
# Check service health
docker-compose ps

# View service logs
docker-compose logs {service-name}

# Example: LocalStack not starting
docker-compose logs localstack
```

### Permission Issues

```bash
# Ensure proper volume permissions
docker-compose down -v

# Remove any cached volumes
docker volume prune

# Rebuild and retry
docker-compose build --no-cache
docker-compose run --rm test
```

### Network Issues

```bash
# Check network connectivity
docker-compose exec test ping localstack

# Inspect network
docker network ls
docker network inspect {network-name}
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Integration Tests

on: [push, pull_request]

jobs:
  integration-test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        backend: [pkcs8, pkcs11, tpm2, awskms, gcpkms, azurekv, vault]
    steps:
      - uses: actions/checkout@v3

      - name: Run ${{ matrix.backend }} integration tests
        run: make integration-test-${{ matrix.backend }}

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: test-results-${{ matrix.backend }}
          path: test-results/
```

## Performance

### Test Execution Times

Approximate times per backend:
- **PKCS#8**: 30 seconds
- **PKCS#11**: 45 seconds (SoftHSM initialization)
- **TPM2**: 60 seconds (SWTPM startup)
- **AWS KMS**: 90 seconds (LocalStack startup)
- **GCP KMS**: 30 seconds (mock)
- **Azure KV**: 30 seconds (mock)
- **Vault**: 60 seconds (Vault initialization)

**Total**: ~6-8 minutes for all backends

### Resource Requirements

Per test container:
- **CPU**: 1 core
- **Memory**: 512MB-1GB
- **Disk**: 100MB-500MB per backend

## Best Practices

1. **Always clean up**: Run `docker-compose down -v` after tests
2. **Use make targets**: Easier and more consistent than manual commands
3. **Test locally before CI**: Verify tests pass before pushing
4. **Check logs on failure**: `docker-compose logs` provides debugging info
5. **Rebuild on dependency changes**: Use `--no-cache` when needed
6. **Run individual backends**: Faster feedback during development

## Summary

Docker-based integration testing provides:

- **Consistency**: Same environment every time
- **Isolation**: No host system modifications
- **Completeness**: All dependencies included
- **Automation**: Simple make targets
- **Reliability**: Repeatable results

Run all tests:
```bash
make integration-test
```

Or test individual backends:
```bash
make integration-test-{backend}
```

For more details on specific backends, see [Integration Tests](integration-tests.md).
