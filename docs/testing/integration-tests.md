# Integration Tests

This document describes how to run integration tests for all go-keychain backends.

## Overview

The go-keychain library includes comprehensive integration tests for all backends. Tests are organized by backend in `test/integration/{backend}/` with Docker-based execution for consistency and isolation.

**Test Statistics:**
- Total: 151 tests passing
- Coverage: 74.9%
- Backends: 10 (PKCS#8, AES, PKCS#11, SmartCard-HSM, TPM2, YubiKey, AWS KMS, GCP KMS, Azure KV, Vault)

## Test Strategy

- **Unit Tests** (`make test`): Run fast, in-memory tests with no system modifications
- **Integration Tests** (`make integration-test`): Run Docker-based tests with real services

Integration tests use Docker Compose to provide:
- Isolated test environments
- Consistent dependencies (SoftHSM, SWTPM, LocalStack, etc.)
- No host system modifications
- Repeatable test execution

## Test Structure

Each backend has its own directory under `test/integration/`:

```
test/integration/
├── common/                    # Shared test utilities
├── pkcs8/                     # PKCS#8 software backend
│   ├── docker-compose.yml
│   ├── Dockerfile
│   └── pkcs8_integration_test.go
├── pkcs11/                    # PKCS#11/SoftHSM
│   ├── docker-compose.yml
│   ├── Dockerfile
│   └── pkcs11_integration_test.go
├── tpm2/                      # TPM2 simulator
│   ├── docker-compose.yml
│   ├── Dockerfile
│   └── tpm2_integration_test.go
├── awskms/                    # AWS KMS/LocalStack
│   ├── docker-compose.yml
│   ├── Dockerfile
│   └── awskms_integration_test.go
├── gcpkms/                    # GCP KMS (mock)
│   ├── docker-compose.yml
│   ├── Dockerfile
│   └── gcpkms_integration_test.go
├── azurekv/                   # Azure Key Vault (mock)
│   ├── docker-compose.yml
│   ├── Dockerfile
│   └── azurekv_integration_test.go
└── vault/                     # HashiCorp Vault
    ├── docker-compose.yml
    ├── Dockerfile
    └── vault_integration_test.go
```

## Running Tests

### All Integration Tests

```bash
make integration-test
```

This runs all backend integration tests sequentially.

### Individual Backend Tests

```bash
# PKCS#8 software backend
make integration-test-pkcs8

# PKCS#11/SoftHSM
make integration-test-pkcs11

# TPM2 simulator
make integration-test-tpm2

# AWS KMS with LocalStack
make integration-test-awskms

# GCP KMS with mock
make integration-test-gcpkms

# Azure Key Vault with mock
make integration-test-azurekv

# HashiCorp Vault
make integration-test-vault
```


## PKCS#8 Integration Tests

### What It Tests
- RSA key generation (2048, 3072, 4096 bits)
- ECDSA key generation (P-256, P-384, P-521)
- Ed25519 key generation
- Signing and verification
- Key storage and retrieval
- Error handling

### Running

```bash
make integration-test-pkcs8
```

### Manual Execution

```bash
cd test/integration/pkcs8
docker-compose run --rm test
docker-compose down -v
```


## PKCS#11/SoftHSM Integration Tests

### What It Tests
- SoftHSM token initialization
- RSA key generation in HSM
- ECDSA key generation in HSM
- Signing operations via HSM
- Key listing and attributes
- Error handling with HSM

### Running

```bash
make integration-test-pkcs11
```

### Manual Execution

```bash
cd test/integration/pkcs11
docker-compose run --rm test
docker-compose down -v
```

### SoftHSM Configuration
- Token Label: test-token
- Slot: 0
- SO PIN: 1234
- User PIN: 1234


## TPM2 Integration Tests

### What It Tests
- TPM2 simulator initialization
- RSA key generation in TPM
- ECDSA key generation in TPM
- Signing operations via TPM
- Key persistence in TPM
- Error handling with TPM

### Running

```bash
make integration-test-tpm2
```

### Manual Execution

```bash
cd test/integration/tpm2
docker-compose up -d tpm-simulator
docker-compose run --rm test
docker-compose down -v
```

### SWTPM Configuration
- TPM Version: 2.0
- Socket: /var/lib/swtpm/swtpm-sock
- State Directory: /var/lib/swtpm/state


## AWS KMS Integration Tests

### What It Tests
- AWS KMS key creation (using LocalStack)
- RSA and ECDSA key operations
- Signing via KMS
- Key management operations
- Error handling

### Running

```bash
make integration-test-awskms
```

### Manual Execution

```bash
cd test/integration/awskms
docker-compose up -d localstack
docker-compose run --rm test
docker-compose down -v
```

### LocalStack Configuration
- Endpoint: http://localstack:4566
- Region: us-east-1
- Credentials: test/test (auto-configured)

**Note:** These tests use LocalStack, not real AWS. No AWS credentials or costs required.


## Google Cloud KMS Integration Tests

### What It Tests
- GCP KMS key operations (using mock client)
- RSA and ECDSA key generation
- Signing operations
- Key management
- Error handling

### Running

```bash
make integration-test-gcpkms
```

### Manual Execution

```bash
cd test/integration/gcpkms
docker-compose run --rm test
docker-compose down -v
```

**Note:** These tests use a mock client, not real GCP. No GCP credentials required.



## Azure Key Vault Integration Tests

### What It Tests
- Azure Key Vault operations (using mock client)
- RSA and ECDSA key generation
- Signing operations
- Key management
- Error handling

### Running

```bash
make integration-test-azurekv
```

### Manual Execution

```bash
cd test/integration/azurekv
docker-compose run --rm test
docker-compose down -v
```

**Note:** These tests use a mock client, not real Azure. No Azure credentials required.



## HashiCorp Vault Integration Tests

### What It Tests
- Vault transit engine operations
- Key generation and management
- Signing and verification
- Secret management
- Error handling

### Running

```bash
make integration-test-vault
```

### Manual Execution

```bash
cd test/integration/vault
docker-compose up -d vault
docker-compose run --rm test
docker-compose down -v
```

### Vault Configuration
- Endpoint: http://vault:8200
- Root Token: root (dev mode)
- Transit Engine: Enabled automatically


## Troubleshooting

### Tests Failing

If integration tests fail:

1. **Check Docker is running**: `docker ps`
2. **Clean up old containers**: `docker-compose down -v`
3. **Rebuild images**: `docker-compose build --no-cache`
4. **Check logs**: `docker-compose logs`

### Permission Errors

If you encounter permission errors:

1. Ensure Docker has proper permissions
2. Check file ownership in test directories
3. Run `docker-compose down -v` to clean up volumes

### Slow Tests

Integration tests run in Docker and may take several minutes:
- PKCS#8: ~30 seconds
- PKCS#11/SoftHSM: ~45 seconds
- TPM2: ~60 seconds (simulator startup)
- AWS KMS/LocalStack: ~90 seconds (LocalStack initialization)
- GCP KMS: ~30 seconds (mock)
- Azure KV: ~30 seconds (mock)
- Vault: ~60 seconds (Vault initialization)

Total time for all backends: ~6-8 minutes


## Summary

Integration tests validate all backend implementations:

- **151 tests** passing across 7 backends
- **74.9%** code coverage
- **Docker-based** for consistency
- **No host modifications** required
- **Automated** via make targets

Run all tests with:
```bash
make integration-test
```

Or test individual backends as needed.
