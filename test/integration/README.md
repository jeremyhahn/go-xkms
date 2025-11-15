# Integration Tests

This directory contains integration tests for all go-keychain backends. Each backend has its own subdirectory with dedicated Docker configuration for isolated testing.

## Structure

```
test/integration/
├── README.md           # This file
├── common/             # Common test utilities
├── pkcs8/              # Software keys (PKCS#8)
├── pkcs11/             # Hardware Security Module (SoftHSM2)
├── tpm2/               # Trusted Platform Module 2.0 (simulator)
├── awskms/             # AWS KMS (LocalStack)
├── gcpkms/             # Google Cloud KMS (emulator)
├── azurekv/            # Azure Key Vault (Azurite)
├── vault/              # HashiCorp Vault (Transit engine)
└── api/                # API integration tests (REST, gRPC, CLI, MCP)
```

Each backend directory contains:
- `*_test.go` - Integration test file
- `Dockerfile` - Test container configuration
- `docker-compose.yml` - Service orchestration

## Running Tests

### Individual Backend

Run tests for a specific backend:

```bash
# From project root
make integration-test-pkcs8
make integration-test-pkcs11
make integration-test-tpm2
make integration-test-awskms
make integration-test-gcpkms
make integration-test-azurekv
make integration-test-vault
```

Or from within a backend directory:

```bash
cd test/integration/pkcs8
docker-compose up --build --abort-on-container-exit
docker-compose down -v
```

### All Backends

Run all integration tests:

```bash
make integration-test
```

## Backend Details

### PKCS#8 (Software Keys)
- **Service**: None (pure software)
- **Purpose**: Test software-based key storage
- **Tags**: `integration pkcs8`

### PKCS#11 (SoftHSM2)
- **Service**: SoftHSM2 (software HSM emulator)
- **Purpose**: Test PKCS#11 interface with hardware security module
- **Tags**: `integration pkcs11`
- **Port**: N/A (local library)

### TPM2 (Simulator)
- **Service**: IBM TPM 2.0 Simulator
- **Purpose**: Test TPM 2.0 hardware integration
- **Tags**: `integration tpm2`
- **Ports**: 2321 (command), 2322 (platform)

### AWS KMS (LocalStack)
- **Service**: LocalStack
- **Purpose**: Test AWS KMS cloud integration
- **Tags**: `integration awskms`
- **Port**: 4566

### GCP KMS (Emulator)
- **Service**: Google Cloud KMS Emulator
- **Purpose**: Test GCP KMS cloud integration
- **Tags**: `integration gcpkms`
- **Port**: 8085

### Azure Key Vault (Azurite)
- **Service**: Azurite (Azure Storage Emulator)
- **Purpose**: Test Azure Key Vault integration
- **Tags**: `integration azurekv`
- **Ports**: 10000 (blob), 10001 (queue), 10002 (table)

### HashiCorp Vault
- **Service**: Vault (dev mode)
- **Purpose**: Test Vault Transit engine integration
- **Tags**: `integration vault`
- **Port**: 8200

## Test Isolation

Each backend test runs in complete isolation:
- Dedicated Docker network per backend
- Separate service containers
- Independent test execution
- Automatic cleanup after tests

## Best Practices

1. **Always use `docker-compose down -v`** to clean up volumes
2. **Run tests from project root** using Make targets
3. **Check service health** before running tests
4. **Review logs** if tests fail: `docker-compose logs service-name`
5. **Keep tests idempotent** - they should pass repeatedly

## Troubleshooting

### Test Failures

1. Check service health:
   ```bash
   cd test/integration/{backend}
   docker-compose up -d {service}
   docker-compose ps
   docker-compose logs {service}
   ```

2. Verify network connectivity:
   ```bash
   docker-compose exec test ping {service}
   ```

3. Clean and rebuild:
   ```bash
   docker-compose down -v
   docker-compose build --no-cache
   docker-compose up
   ```

### Port Conflicts

If you see port binding errors, stop conflicting services:
```bash
# Check what's using the port
sudo lsof -i :PORT
# Or use different port in docker-compose.yml
```

### Build Cache Issues

Clear Docker build cache:
```bash
docker builder prune -a
```

## Contributing

When adding new backend tests:

1. Create directory: `test/integration/{backend}/`
2. Add test file: `{backend}_test.go` with build tag `//go:build integration && {backend}`
3. Create `Dockerfile` based on existing patterns
4. Create `docker-compose.yml` with service + test container
5. Update root `Makefile` with `integration-test-{backend}` target
6. Add backend to `integration-test` dependencies
7. Update this README

## References

- [Go Testing](https://golang.org/pkg/testing/)
- [Docker Compose](https://docs.docker.com/compose/)
- [Build Tags](https://pkg.go.dev/cmd/go#hdr-Build_constraints)
